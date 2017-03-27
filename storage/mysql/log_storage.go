// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	rnd "math/rand"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	spb "github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/cache"
	"github.com/google/trillian/storage/storagepb"
	"github.com/google/trillian/util"
)

const (
	getTreePropertiesSQL  = "SELECT DuplicatePolicy FROM Trees WHERE TreeId=?"
	selectQueuedLeavesSQL = `SELECT LeafIdentityHash,MerkleLeafHash,Bucket,QueueTimestampNanos
			FROM Unsequenced
			WHERE TreeID=?
			AND Bucket IN(<placeholder>)
			AND QueueTimestampNanos<=?
			ORDER BY QueueTimestampNanos,LeafIdentityHash ASC LIMIT ?`
	insertUnsequencedLeafSQL = `INSERT INTO LeafData(TreeId,LeafIdentityHash,LeafDataProto)
			VALUES(?,?,?) ON DUPLICATE KEY UPDATE LeafIdentityHash=LeafIdentityHash`
	insertUnsequencedLeafSQLNoDuplicates = `INSERT INTO LeafData(TreeId,LeafIdentityHash,LeafDataProto)
			VALUES(?,?,?)`
	insertUnsequencedEntrySQL = `INSERT INTO Unsequenced(TreeId,Bucket,LeafIdentityHash,MerkleLeafHash,QueueTimestampNanos)
			VALUES(?,?,?,?,?)`
	insertSequencedLeafSQL = `INSERT INTO SequencedLeafData(TreeId,LeafIdentityHash,MerkleLeafHash,SequenceNumber)
			VALUES(?,?,?,?)`
	selectSequencedLeafCountSQL  = "SELECT COUNT(*) FROM SequencedLeafData WHERE TreeId=?"
	selectLatestSignedLogRootSQL = `SELECT TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature
			FROM TreeHead WHERE TreeId=?
			ORDER BY TreeHeadTimestamp DESC LIMIT 1`

	// These statements need to be expanded to provide the correct number of parameter placeholders.
	deleteUnsequencedSQL   = "DELETE FROM Unsequenced WHERE LeafIdentityHash IN (<placeholder>) AND TreeId = ?"
	deleteOneUnsequencedSQL = "DELETE FROM Unsequenced WHERE TreeId=? AND Bucket=? AND QueueTimestampNanos=? AND MerkleLeafHash=?"

	selectLeavesByIndexSQL = `SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafDataProto,s.SequenceNumber
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.SequenceNumber IN (` + placeholderSQL + `) AND l.TreeId = ? AND s.TreeId = l.TreeId`
	selectLeavesByMerkleHashSQL = `SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafDataProto,s.SequenceNumber
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.MerkleLeafHash IN (` + placeholderSQL + `) AND l.TreeId = ? AND s.TreeId = l.TreeId`
	// TODO(drysdale): rework the code so the dummy hash isn't needed (e.g. this assumes hash size is 32)
	dummyMerkleLeafHash = "00000000000000000000000000000000"
	// This statement returns a dummy Merkle leaf hash value (which must be
	// of the right size) so that its signature matches that of the other
	// leaf-selection statements.
	selectLeavesByLeafIdentityHashSQL = `SELECT '` + dummyMerkleLeafHash + `',l.LeafIdentityHash,l.LeafDataProto,-1
			FROM LeafData l
			WHERE l.LeafIdentityHash IN (` + placeholderSQL + `) AND l.TreeId = ?`

	// Same as above except with leaves ordered by sequence so we only incur this cost when necessary
	orderBySequenceNumberSQL                     = " ORDER BY s.SequenceNumber"
	selectLeavesByMerkleHashOrderedBySequenceSQL = selectLeavesByMerkleHashSQL + orderBySequenceNumberSQL

	numByteValues                                = 256
	deleteBatchSize                              = 100
)

// Turns on latency logging for some operations
const logLatency bool = true

var defaultLogStrata = []int{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}

type mySQLLogStorage struct {
	*mySQLTreeStorage
	// TODO(Martin2112): Currently applies to all trees. Possibly allow it to be set per tree
	config     *storagepb.LogStorageConfig
	timeSource util.TimeSource
}

// NewLogStorage creates a mySQLLogStorage instance for the specified MySQL URL.
func NewLogStorage(db *sql.DB, config *storagepb.LogStorageConfig, timeSource util.TimeSource) storage.LogStorage {
	return &mySQLLogStorage{
		mySQLTreeStorage: newTreeStorage(db),
		config:           config,
		timeSource:       timeSource,
	}
}

func (m *mySQLLogStorage) CheckDatabaseAccessible(ctx context.Context) error {
	return checkDatabaseAccessible(ctx, m.db)
}

func (m *mySQLLogStorage) getLeavesByIndexStmt(num int) (*sql.Stmt, error) {
	return m.getStmt(selectLeavesByIndexSQL, num, "?", "?")
}

func (m *mySQLLogStorage) getLeavesByMerkleHashStmt(num int, orderBySequence bool) (*sql.Stmt, error) {
	if orderBySequence {
		return m.getStmt(selectLeavesByMerkleHashOrderedBySequenceSQL, num, "?", "?")
	}

	return m.getStmt(selectLeavesByMerkleHashSQL, num, "?", "?")
}

func (m *mySQLLogStorage) getDeleteUnsequencedStmt(num int) (*sql.Stmt, error) {
	return m.getStmt(deleteUnsequencedSQL, num, "?", "?")
}

func (m *mySQLLogStorage) getDeleteOneUnsequencedStmt() (*sql.Stmt, error) {
	return m.getStmt(deleteOneUnsequencedSQL, 1, "?", "?")
}

func getActiveLogIDsInternal(tx *sql.Tx, sql string) ([]int64, error) {
	rows, err := tx.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logIDs := make([]int64, 0)
	for rows.Next() {
		var treeID int64
		if err := rows.Scan(&treeID); err != nil {
			return nil, err
		}
		logIDs = append(logIDs, treeID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logIDs, nil
}

func getActiveLogIDs(tx *sql.Tx) ([]int64, error) {
	return getActiveLogIDsInternal(tx, selectActiveLogsSQL)
}

func getActiveLogIDsWithPendingWork(tx *sql.Tx) ([]int64, error) {
	return getActiveLogIDsInternal(tx, selectActiveLogsWithUnsequencedSQL)
}

// readOnlyLogTX implements storage.ReadOnlyLogTX
type readOnlyLogTX struct {
	tx *sql.Tx
}

func (m *mySQLLogStorage) Snapshot(ctx context.Context) (storage.ReadOnlyLogTX, error) {
	tx, err := m.db.Begin()
	if err != nil {
		glog.Warningf("Could not start ReadOnlyLogTX: %s", err)
		return nil, err
	}
	return &readOnlyLogTX{tx}, nil
}

func (t *readOnlyLogTX) Commit() error {
	return t.tx.Commit()
}

func (t *readOnlyLogTX) Rollback() error {
	return t.tx.Rollback()
}

func (t *readOnlyLogTX) Close() error {
	if err := t.Rollback(); err != nil && err != sql.ErrTxDone {
		glog.Warningf("Rollback error on Close(): %v", err)
		return err
	}
	return nil
}

func (t *readOnlyLogTX) GetActiveLogIDs() ([]int64, error) {
	return getActiveLogIDs(t.tx)
}

func (t *readOnlyLogTX) GetActiveLogIDsWithPendingWork() ([]int64, error) {
	return getActiveLogIDsWithPendingWork(t.tx)
}

func (m *mySQLLogStorage) hasher(treeID int64) (merkle.TreeHasher, error) {
	// TODO: read hash algorithm from storage.
	return merkle.Factory(merkle.RFC6962SHA256Type)
}

func (m *mySQLLogStorage) beginInternal(ctx context.Context, treeID int64) (storage.LogTreeTX, error) {
	// TODO(codingllama): Validate treeType
	var duplicatePolicy string
	if err := m.db.QueryRow(getTreePropertiesSQL, treeID).Scan(&duplicatePolicy); err != nil {
		return nil, fmt.Errorf("failed to get tree row for treeID %v: %s", treeID, err)
	}
	policy, ok := duplicatePolicyMap[duplicatePolicy]
	if !ok {
		return nil, fmt.Errorf("unknown DuplicatePolicy: %v", duplicatePolicy)
	}

	hasher, err := m.hasher(treeID)
	if err != nil {
		return nil, err
	}

	ttx, err := m.beginTreeTx(ctx, treeID, hasher.Size(), defaultLogStrata, cache.PopulateLogSubtreeNodes(hasher), cache.PrepareLogSubtreeWrite())
	if err != nil {
		return nil, err
	}

	ltx := &logTreeTX{
		treeTX:          ttx,
		ls:              m,
		duplicatePolicy: policy,
	}

	ltx.root, err = ltx.fetchLatestRoot()
	if err != nil {
		ttx.Rollback()
		return nil, err
	}
	ltx.treeTX.writeRevision = ltx.root.TreeRevision + 1

	return ltx, nil
}

func (m *mySQLLogStorage) BeginForTree(ctx context.Context, treeID int64) (storage.LogTreeTX, error) {
	return m.beginInternal(ctx, treeID)
}

func (m *mySQLLogStorage) SnapshotForTree(ctx context.Context, treeID int64) (storage.ReadOnlyLogTreeTX, error) {
	tx, err := m.beginInternal(ctx, treeID)
	if err != nil {
		return nil, err
	}
	return tx.(storage.ReadOnlyLogTreeTX), err
}

type logTreeTX struct {
	treeTX
	ls              *mySQLLogStorage
	root            trillian.SignedLogRoot
	duplicatePolicy trillian.DuplicatePolicy
}

func (t *logTreeTX) ReadRevision() int64 {
	return t.root.TreeRevision
}

func (t *logTreeTX) WriteRevision() int64 {
	return t.treeTX.writeRevision
}

// dequeuedLeaf is used internally and contains some data that is not exposed to the client
type dequeuedLeaf struct {
	bucket int
	queueTimestampNanos int64
	merkleLeafHash []byte
}

func (t *logTreeTX) DequeueLeaves(limit int, cutoffTime time.Time) ([]*trillian.LogLeaf, error) {
	// Get a list of buckets we'll try to take from. The idea is that queueing and dequeuing
	// will be updating different ranges of the key space at any time. On some storage
	// platforms this allows for reduced write contention.
	now := t.ls.timeSource.Now().UTC().Unix()
	buckets := genDequeueBuckets(now, t.ls.config, rnd.Intn(numByteValues))

	// Marshall the arguments for the query inc. potentially variable number of buckets
	args := make([]interface{}, 0, len(buckets)+3)
	args = append(args, interface{}(t.treeID))

	for _, bucket := range buckets {
		args = append(args, interface{}(bucket))
	}

	args = append(args, interface{}(cutoffTime.UnixNano()))
	args = append(args, interface{}(limit))

	start := t.ls.timeSource.Now()

	tmpl, err := t.ls.getStmt(selectQueuedLeavesSQL, len(buckets), "?", "?")
	if err != nil {
		glog.Warningf("Failed to prepare dequeue select: %s", err)
		return nil, err
	}

	leaves := make([]*trillian.LogLeaf, 0, limit)
	dql := make([]dequeuedLeaf, 0, limit)
	stx := t.tx.Stmt(tmpl)
	rows, err := stx.Query(args...)
	if err != nil {
		glog.Warningf("Failed to select rows for dequeue: %s", err)
		return nil, err
	}

	ldq := t.ls.timeSource.Now()
	t.logLatency("Select Leaves", start)

	defer rows.Close()

	for rows.Next() {
		var leafIDHash []byte
		var merkleHash []byte
		var dqBucket int
		var qtNanos int64

		err := rows.Scan(&leafIDHash, &merkleHash, &dqBucket, &qtNanos)

		if err != nil {
			glog.Warningf("Error scanning queued rows: %s", err)
			return nil, err
		}

		if len(leafIDHash) != t.hashSizeBytes {
			return nil, errors.New("Dequeued a leaf with incorrect hash size")
		}

		// Note: the LeafData and ExtraData being nil here is OK as this is only used by the
		// sequencer. The sequencer only writes to the SequencedLeafData table and the client
		// supplied data was already written to LeafData as part of queueing the leaf.
		leaf := &trillian.LogLeaf{
			LeafIdentityHash: leafIDHash,
			MerkleLeafHash:   merkleHash,
		}
		leaves = append(leaves, leaf)
		dql = append(dql, dequeuedLeaf{bucket:dqBucket, queueTimestampNanos:qtNanos, merkleLeafHash:merkleHash})
	}

	lsc := t.ls.timeSource.Now()
	t.logLatency("Scan Leaves", ldq)

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	// The convention is that if leaf processing succeeds (by committing this tx)
	// then the unsequenced entries for them are removed
	if len(leaves) > 0 {
		err = t.removeSequencedLeaves2(dql)
	}

	t.logLatency("Delete Leaves", lsc)

	if err != nil {
		return nil, err
	}

	return leaves, nil
}

func (t *logTreeTX) QueueLeaves(leaves []*trillian.LogLeaf, queueTimestamp time.Time) error {
	// Don't accept batches if any of the leaves are invalid.
	for _, leaf := range leaves {
		if len(leaf.LeafIdentityHash) != t.hashSizeBytes {
			return fmt.Errorf("queued leaf must have a leaf ID hash of length %d", t.hashSizeBytes)
		}
	}

	// If the log does not allow duplicates we prevent the insert of such a leaf from
	// succeeding. If duplicates are allowed multiple sequenced leaves will share the same
	// leaf data in the database.
	var insertSQL string

	if t.duplicatePolicy == trillian.DuplicatePolicy_DUPLICATES_ALLOWED {
		insertSQL = insertUnsequencedLeafSQL
	} else {
		insertSQL = insertUnsequencedLeafSQLNoDuplicates
	}

	// Insert in order of the hash values in the leaves.
	orderedLeaves := make([]*trillian.LogLeaf, len(leaves))
	copy(orderedLeaves, leaves)
	sort.Sort(byLeafIdentityHash(orderedLeaves))

	// These accumulate the time spent on each type of insert
	var ldDur time.Duration
	var usDur time.Duration

	lTmpl, err := t.ts.getStmt(insertSQL, 1, "?", "?")
	if err != nil {
		return err
	}
	uTmpl, err := t.ts.getStmt(insertUnsequencedEntrySQL, 1, "?", "?")
	if err != nil {
		return err
	}

	lStmt := t.tx.Stmt(lTmpl)
	uStmt := t.tx.Stmt(uTmpl)

	now := t.ls.timeSource.Now().UTC().Unix()
	for i, leaf := range orderedLeaves {
		// Create the unsequenced leaf data entry. We don't use INSERT IGNORE because this
		// can suppress errors unrelated to key collisions. We don't use REPLACE because
		// if there's ever a hash collision it will do the wrong thing and it also
		// causes a DELETE / INSERT, which is undesirable.
		leafProto := storagepb.LeafDataProto{LeafValue: leaf.LeafValue, ExtraData: leaf.ExtraData}
		leafData, err := proto.Marshal(&leafProto)
		if err != nil {
			return err
		}
		preIns := t.ls.timeSource.Now()
		_, err = lStmt.Exec(t.treeID, leaf.LeafIdentityHash, leafData)
		ldDur += t.ls.timeSource.Now().Sub(preIns)
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate entry") {
				return storage.Error{
					ErrType: storage.DuplicateLeaf,
					Cause:   err,
					Detail:  fmt.Sprintf("IdentityHash: %x", leaf.LeafIdentityHash),
				}
			}
			glog.Warningf("Error inserting %d into LeafData: %s", i, err)
			return err
		}

		// Create the work queue entry
		bucket := getQueueBucket(now, t.ls.config, leaf.MerkleLeafHash[0])

		preIns = t.ls.timeSource.Now()
		_, err = uStmt.Exec(t.treeID, bucket, leaf.LeafIdentityHash, leaf.MerkleLeafHash,
			queueTimestamp.UnixNano())
		usDur += t.ls.timeSource.Now().Sub(preIns)

		if err != nil {
			glog.Warningf("Error inserting into Unsequenced: %s", err)
			return fmt.Errorf("Unsequenced: %v", err)
		}
	}

	t.logLatencyQps("insert LeafData", ldDur, len(leaves))
	t.logLatencyQps("insert Unsequenced", usDur, len(leaves))

	return nil
}

func (t *logTreeTX) GetSequencedLeafCount() (int64, error) {
	var sequencedLeafCount int64

	err := t.tx.QueryRow(selectSequencedLeafCountSQL, t.treeID).Scan(&sequencedLeafCount)

	if err != nil {
		glog.Warningf("Error getting sequenced leaf count: %s", err)
	}

	return sequencedLeafCount, err
}

func (t *logTreeTX) GetLeavesByIndex(leaves []int64) ([]*trillian.LogLeaf, error) {
	tmpl, err := t.ls.getLeavesByIndexStmt(len(leaves))
	if err != nil {
		return nil, err
	}
	stx := t.tx.Stmt(tmpl)
	var args []interface{}
	for _, nodeID := range leaves {
		args = append(args, interface{}(int64(nodeID)))
	}
	args = append(args, interface{}(t.treeID))
	rows, err := stx.Query(args...)
	if err != nil {
		glog.Warningf("Failed to get leaves by idx: %s", err)
		return nil, err
	}

	ret := make([]*trillian.LogLeaf, 0, len(leaves))
	defer rows.Close()
	for rows.Next() {
		var leafProtoData []byte
		var leafProto storagepb.LeafDataProto

		leaf := &trillian.LogLeaf{}
		if err := rows.Scan(
			&leaf.MerkleLeafHash,
			&leaf.LeafIdentityHash,
			&leafProtoData,
			&leaf.LeafIndex); err != nil {
			glog.Warningf("Failed to scan merkle leaves: %s", err)
			return nil, err
		}

		// Unpack the leaf data and extra data proto
		if err := proto.Unmarshal(leafProtoData, &leafProto); err != nil {
			return nil, err
		}

		leaf.LeafValue = leafProto.LeafValue
		leaf.ExtraData = leafProto.ExtraData
		ret = append(ret, leaf)
	}

	if got, want := len(ret), len(leaves); got != want {
		return nil, fmt.Errorf("len(ret): %d, want %d", got, want)
	}
	return ret, nil
}

func (t *logTreeTX) GetLeavesByHash(leafHashes [][]byte, orderBySequence bool) ([]*trillian.LogLeaf, error) {
	tmpl, err := t.ls.getLeavesByMerkleHashStmt(len(leafHashes), orderBySequence)
	if err != nil {
		return nil, err
	}

	return t.getLeavesByHashInternal(leafHashes, tmpl, "merkle")
}

func (t *logTreeTX) LatestSignedLogRoot() (trillian.SignedLogRoot, error) {
	return t.root, nil
}

// fetchLatestRoot reads the latest SignedLogRoot from the DB and returns it.
func (t *logTreeTX) fetchLatestRoot() (trillian.SignedLogRoot, error) {
	var timestamp, treeSize, treeRevision int64
	var rootHash, rootSignatureBytes []byte
	var rootSignature spb.DigitallySigned

	err := t.tx.QueryRow(
		selectLatestSignedLogRootSQL, t.treeID).Scan(
		&timestamp, &treeSize, &rootHash, &treeRevision, &rootSignatureBytes)

	// It's possible there are no roots for this tree yet
	if err == sql.ErrNoRows {
		return trillian.SignedLogRoot{}, nil
	}

	err = proto.Unmarshal(rootSignatureBytes, &rootSignature)

	if err != nil {
		glog.Warningf("Failed to unmarshall root signature: %v", err)
		return trillian.SignedLogRoot{}, err
	}

	return trillian.SignedLogRoot{
		RootHash:       rootHash,
		TimestampNanos: timestamp,
		TreeRevision:   treeRevision,
		Signature:      &rootSignature,
		LogId:          t.treeID,
		TreeSize:       treeSize,
	}, nil
}

func (t *logTreeTX) StoreSignedLogRoot(root trillian.SignedLogRoot) error {
	signatureBytes, err := proto.Marshal(root.Signature)

	if err != nil {
		glog.Warningf("Failed to marshal root signature: %v %v", root.Signature, err)
		return err
	}

	res, err := t.tx.Exec(insertTreeHeadSQL, t.treeID, root.TimestampNanos, root.TreeSize,
		root.RootHash, root.TreeRevision, signatureBytes)

	if err != nil {
		glog.Warningf("Failed to store signed root: %s", err)
	}

	return checkResultOkAndRowCountIs(res, err, 1)
}

func (t *logTreeTX) UpdateSequencedLeaves(leaves []*trillian.LogLeaf) error {
	// TODO: In theory we can do this with CASE / WHEN in one SQL statement but it's more fiddly
	// and can be implemented later if necessary
	for _, leaf := range leaves {
		// This should fail on insert but catch it early
		if len(leaf.LeafIdentityHash) != t.hashSizeBytes {
			return errors.New("Sequenced leaf has incorrect hash size")
		}

		_, err := t.tx.Exec(insertSequencedLeafSQL, t.treeID, leaf.LeafIdentityHash, leaf.MerkleLeafHash,
			leaf.LeafIndex)

		if err != nil {
			glog.Warningf("Failed to update sequenced leaves: %s", err)
			return err
		}
	}

	return nil
}

// removeSequencedLeaves removes the passed in leaves slice (which may be
// modified as part of the operation).
func (t *logTreeTX) removeSequencedLeaves(leaves []*trillian.LogLeaf) error {
	// Delete in order of the hash values in the leaves.
	sort.Sort(byLeafIdentityHash(leaves))

	left := len(leaves)
	pos := 0
	for left > 0 {
		bs := left
		if bs > deleteBatchSize {
			bs = deleteBatchSize
		}
		tmpl, err := t.ls.getDeleteUnsequencedStmt(bs)
		if err != nil {
			glog.Warningf("Failed to get delete statement for sequenced work: %s", err)
			return err
		}
		stx := t.tx.Stmt(tmpl)
		var args []interface{}
		for l := pos; l < pos+bs; l++ {
			args = append(args, interface{}(leaves[l].LeafIdentityHash))
		}
		args = append(args, interface{}(t.treeID))
		result, err := stx.Exec(args...)

		if err != nil {
			// Error is handled by checkResultOkAndRowCountIs() below
			glog.Warningf("Failed to delete sequenced work: %s", err)
		}

		err = checkResultOkAndRowCountIs(result, err, int64(bs))

		if err != nil {
			return err
		}
		left -= bs
		pos += bs
	}

	return nil
}

// removeSequencedLeaves removes the passed in leaves slice (which may be
// modified as part of the operation).
func (t *logTreeTX) removeSequencedLeaves2(leaves []dequeuedLeaf) error {
	// Delete in order of the hash values in the leaves.
	// sort.Sort(byLeafIdentityHash(leaves))

	tmpl, err := t.ls.getDeleteOneUnsequencedStmt()
	if err != nil {
		glog.Warningf("Failed to get delete statement for sequenced work: %s", err)
		return err
	}

	stx := t.tx.Stmt(tmpl)
	for _, dql := range leaves {
		result, err := stx.Exec(t.treeID, dql.bucket, dql.queueTimestampNanos, dql.merkleLeafHash)
		err = checkResultOkAndRowCountIs(result, err, int64(1))

		if err != nil {
			return err
		}
	}

	return nil
}

func (t *logTreeTX) getLeavesByHashInternal(leafHashes [][]byte, tmpl *sql.Stmt, desc string) ([]*trillian.LogLeaf, error) {
	stx := t.tx.Stmt(tmpl)
	var args []interface{}
	for _, hash := range leafHashes {
		args = append(args, interface{}([]byte(hash)))
	}
	args = append(args, interface{}(t.treeID))
	rows, err := stx.Query(args...)
	if err != nil {
		glog.Warningf("Query() %s hash = %v", desc, err)
		return nil, err
	}

	// The tree could include duplicates so we don't know how many results will be returned
	var ret []*trillian.LogLeaf

	defer rows.Close()
	for rows.Next() {
		leaf := &trillian.LogLeaf{}
		var leafProtoData []byte
		var leafProto storagepb.LeafDataProto

		if err := rows.Scan(&leaf.MerkleLeafHash, &leaf.LeafIdentityHash, &leafProtoData, &leaf.LeafIndex); err != nil {
			glog.Warningf("LogID: %d Scan() %s = %s", t.treeID, desc, err)
			return nil, err
		}

		// Unpack the leaf data and extra data proto
		if err := proto.Unmarshal(leafProtoData, &leafProto); err != nil {
			return nil, err
		}
		leaf.LeafValue = leafProto.LeafValue
		leaf.ExtraData = leafProto.ExtraData

		if got, want := len(leaf.MerkleLeafHash), t.hashSizeBytes; got != want {
			return nil, fmt.Errorf("LogID: %d Scanned leaf %s does not have hash length %d, got %d", t.treeID, desc, want, got)
		}
		ret = append(ret, leaf)
	}

	return ret, nil
}

// GetActiveLogIDs returns a list of the IDs of all configured logs
func (t *logTreeTX) GetActiveLogIDs() ([]int64, error) {
	return getActiveLogIDs(t.tx)
}

func (t *logTreeTX) logLatency(label string, start time.Time) {
	t.logLatencyBetween(label, start, t.ls.timeSource.Now())
}

func (t *logTreeTX) logLatencyBetween(label string, start,end time.Time) {
	if logLatency {
		d := end.Sub(start).Seconds()
		glog.Infof("%s Latency: %.2f sec", label, d)
	}
}

func (t *logTreeTX) logLatencyQps(label string, d time.Duration, q int) {
	if logLatency {
		qps := float64(q) / d.Seconds()
		glog.Infof("%s Latency: %.2f sec for %d items (%.2f qps)", label, d.Seconds(), q, qps)
	}
}

// GetActiveLogIDsWithPendingWork returns a list of the IDs of all configured logs
// that have queued unsequenced leaves that need to be integrated
func (t *logTreeTX) GetActiveLogIDsWithPendingWork() ([]int64, error) {
	return getActiveLogIDsWithPendingWork(t.tx)
}

type byLeafIdentityHash []*trillian.LogLeaf

func (l byLeafIdentityHash) Len() int {
	return len(l)
}
func (l byLeafIdentityHash) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}
func (l byLeafIdentityHash) Less(i, j int) bool {
	return bytes.Compare(l[i].LeafIdentityHash, l[j].LeafIdentityHash) == -1
}

// genDequeueBuckets returns a list of buckets from which work should be currently taken.
// Using a ring buffer like approach, if enabled, this tries to separate the table key space
// regions that are being written by queueing and sequencing at a particular time. This can be
// effective for storage types that split data into ranges. It's usefulness for a generic RDBMS
// needs to be evaluated.
func genDequeueBuckets(now int64, config *storagepb.LogStorageConfig, merkleBucket int) []int32 {
	if config == nil || !config.EnableBuckets {
		return []int32{0} // everything always uses bucket zero
	}

	// If there's only one merkle bucket we can just use a single constant value for this
	// part of the bucket id instead of expanding all of them. We then only bucket by time.
	bucketHigh := int32((((now + config.NumUnseqBuckets/2) % config.NumUnseqBuckets) << 8))
	if config.NumMerkleBuckets <= 1 {
		return []int32{bucketHigh}
	}

	n := int(numByteValues / config.NumMerkleBuckets)
	ret := make([]int32, 0, n)
	for i := merkleBucket; i < merkleBucket+n; i++ {
		ret = append(ret, bucketHigh|int32(i%numByteValues))
	}
	return ret
}

// getQueueBucket gets the bucket currently used for queuing new work. If bucketing is enabled
// it should always return a value not in the set of buckets returned by genDequeueBuckets
// at the same point in time. The mlh0 parameter should be the first byte of the leaf
// MerkleTreeHash.
func getQueueBucket(now int64, config *storagepb.LogStorageConfig, mlh0 byte) int32 {
	if config == nil || !config.EnableBuckets {
		return 0 // everything always uses bucket zero
	}
	// As above if there's one merkle bucket we ignore the second level merkle bucket value and
	// just bucket by time.
	if config.NumMerkleBuckets <= 1 {
		mlh0 = 0
	}
	return int32((now % config.NumUnseqBuckets) << 8) | int32(mlh0)
}
