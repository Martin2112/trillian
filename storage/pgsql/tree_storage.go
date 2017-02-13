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

package pgsql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"flag"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/cache"
	"github.com/google/trillian/storage/storagepb"
	"github.com/lib/pq"
	"strconv"
)

// These statements are fixed
const (
	insertSubtreeMultiSQL = `INSERT INTO Subtree(TreeId, SubtreeId, Nodes, SubtreeRevision) ` + placeholderSQL
	insertTreeHeadSQL     = `INSERT INTO TreeHead(TreeId,TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature)
		 VALUES($1,$2,$3,$4,$5,$6)`
	selectTreeRevisionAtSizeOrLargerSQL = "SELECT TreeRevision,TreeSize FROM TreeHead WHERE TreeId=$1 AND TreeSize>=$2 ORDER BY TreeRevision LIMIT 1"
	selectActiveLogsSQL                 = "SELECT TreeId, KeyId from Trees where TreeType='LOG'"
	selectActiveLogsWithUnsequencedSQL  = "SELECT DISTINCT t.TreeId, t.KeyId from Trees t INNER JOIN Unsequenced u ON t.TreeId=u.TreeId WHERE TreeType='LOG'"
	selectSubtreeSQL                    = `
 SELECT x.SubtreeId, x.MaxRevision, Subtree.Nodes
 FROM (
 	SELECT n.SubtreeId, max(n.SubtreeRevision) AS MaxRevision
	FROM Subtree n
	WHERE n.SubtreeId IN (` + placeholderSQL + `) AND
	 n.TreeId = $1 AND n.SubtreeRevision <= $2
	GROUP BY n.SubtreeId
 ) AS x
 INNER JOIN Subtree 
 ON Subtree.SubtreeId = x.SubtreeId 
 AND Subtree.SubtreeRevision = x.MaxRevision 
 AND Subtree.TreeId = $3`
	placeholderSQL = "<placeholder>"
)

// TODO(Martin2112): Shouldn't have flags in low level code. Remove them when we've finished
// experimenting with storage options
var cockroachRetryFlag = flag.Bool("cockroach_retry", false, "If true we'll attempt to roll back / retry when we see this type of error from the server")
var cockroachClientRetryFlag = flag.Bool("cockroach_client_retry", false, "If true we'll enable client side retry custom logic for CockroachDB")
var cockroachSnapshotIsoFlag = flag.Bool("cockroach_snapshot_isolation", false, "If true we'll request SNAPSHOT isolation level on all transactions")

// pgSQLTreeStorage is shared between the mySQLLog- and (forthcoming) mySQLMap-
// Storage implementations, and contains functionality which is common to both,
type pgSQLTreeStorage struct {
	db *sql.DB

	// Must hold the mutex before manipulating the statement map. Sharing a lock because
	// it only needs to be held while the statements are built, not while they execute and
	// this will be a short time. These maps are from the number of placeholder
	// in the query to the statement that should be used.
	statementMutex sync.Mutex
	statements     map[string]map[int]*sql.Stmt
	// If true then the server version should support use of the ON CONFLICT clause for
	// INSERT statements
	useOnConflict bool
}

// OpenDB opens a database connection for all postgres-based storage implementations.
func OpenDB(dbURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		// Don't log uri as it could contain credentials
		glog.Warningf("Could not open postgres database, check config: %s", err)
		return nil, err
	}
	return db, nil
}

func newTreeStorage(db *sql.DB) *pgSQLTreeStorage {
	// Try to find the version and enable suitable options. If this fails we'll just use
	// the default options and continue silently.
	atLeast95 := false
	var version string
	if err := db.QueryRow("SHOW server_version").Scan(&version); err == nil {
		v := strings.SplitN(version, ".", 3)
		major, err := strconv.ParseInt(v[0], 10, 32)
		minor, err2 := strconv.ParseInt(v[1], 10, 32)

		if err == nil && err2 == nil {
			if major > 9 || (major == 9 && minor >= 5) {
				atLeast95 = true
				glog.V(1).Info("9.5+ server - ON CONFLICT enabled")
			}
		}
	}

	return &pgSQLTreeStorage{
		db:            db,
		statements:    make(map[string]map[int]*sql.Stmt),
		useOnConflict: atLeast95,
	}
}

// expandValuesSQL creates an expanded VALUES clause for multiple inserts. A special
// case because the params in pgsql are positional and we can't just duplicate the
// second (....) clause n times
func expandValuesPlaceholderSQL(sql string, cols, num int) string {
	if num <= 0 {
		panic(fmt.Errorf("Trying to expand SQL placeholder with <= 0 parameters: %s", sql))
	}

	parameters := ""
	colNum := 1
	for p := 0; p < num; p++ {
		if p == 0 {
			// Only the first one needs VALUES
			parameters += "VALUES"
		} else {
			// Otherwise, we're continuing a list
			parameters += ","
		}
		parameters += "("
		// Expand the inner list for the correct number of columns
		for c := 0; c < cols; c++ {
			if c != 0 {
				parameters += ","
			}
			parameters += fmt.Sprintf("$%d", colNum)
			colNum++
		}
		parameters += ")"
	}

	return strings.Replace(sql, placeholderSQL, parameters, 1)
}

// expandPlaceholderSQL expands an sql statement by adding a specified number of
// placeholder slots. At most one placeholder will be expanded.
func expandPlaceholderSQL(sql string, first, num int) string {
	if num <= 0 {
		panic(fmt.Errorf("Trying to expand SQL placeholder with <= 0 parameters: %s", sql))
	}

	parameters := fmt.Sprintf("$%d", first)
	p := first + 1
	for i := 0; i < num-1; i++ {
		parameters += fmt.Sprintf(",$%d", p+i)
	}

	return strings.Replace(sql, placeholderSQL, parameters, 1)
}

// Node IDs are stored using proto serialization
func decodeNodeID(nodeIDBytes []byte) (*storage.NodeID, error) {
	var nodeIDProto storagepb.NodeIDProto

	if err := proto.Unmarshal(nodeIDBytes, &nodeIDProto); err != nil {
		glog.Warningf("Failed to decode nodeid: %s", err)
		return nil, err
	}

	return storage.NewNodeIDFromProto(nodeIDProto), nil
}

func encodeNodeID(n storage.NodeID) ([]byte, error) {
	nodeIDProto := n.AsProto()
	marshalledBytes, err := proto.Marshal(nodeIDProto)

	if err != nil {
		glog.Warningf("Failed to encode nodeid: %s", err)
		return nil, err
	}

	return marshalledBytes, nil
}

// getStmt creates and caches sql.Stmt structs based on the passed in statement
// and number of bound arguments.
// TODO(al,martin): consider pulling this all out as a separate unit for reuse
// elsewhere.
func (m *pgSQLTreeStorage) getStmt(statement string, first, num int) (*sql.Stmt, error) {
	m.statementMutex.Lock()
	defer m.statementMutex.Unlock()

	if m.statements[statement] != nil {
		if m.statements[statement][num] != nil {
			// TODO(al,martin): we'll possibly need to expire Stmts from the cache,
			// e.g. when DB connections break etc.
			return m.statements[statement][num], nil
		}
	} else {
		m.statements[statement] = make(map[int]*sql.Stmt)
	}

	//return nil, fmt.Errorf(expandPlaceholderSQL(statement, first, num))

	s, err := m.db.Prepare(expandPlaceholderSQL(statement, first, num))

	if err != nil {
		glog.Warningf("Failed to prepare statement %d: %s", num, err)
		return nil, err
	}

	m.statements[statement][num] = s

	return s, nil
}

func (m *pgSQLTreeStorage) getSubtreeStmt(num int) (*sql.Stmt, error) {
	return m.getStmt(selectSubtreeSQL, 4, num)
}

func (m *pgSQLTreeStorage) setSubtreeStmt(num int) (*sql.Stmt, error) {
	tmpl := expandValuesPlaceholderSQL(insertSubtreeMultiSQL, 4, num)
	// Should not be any more placeholder expansion but we're not allowed to pass zero
	return m.getStmt(tmpl, 1, 1)
}

func (m *pgSQLTreeStorage) beginTreeTx(ctx context.Context, treeID int64, hashSizeBytes int, strataDepths []int, populate storage.PopulateSubtreeFunc, prepare storage.PrepareSubtreeWriteFunc) (treeTX, error) {
	// TODO(alcutter): use BeginTX(ctx) when we move to Go 1.8
	t, err := m.db.Begin()
	if err != nil {
		glog.Warningf("Could not start tree TX: %s", err)
		return treeTX{}, err
	}

	// If enabled request SNAPSHOT isolation
	if *cockroachSnapshotIsoFlag {
		if _, err := t.Exec("SET TRANSACTION ISOLATION LEVEL SNAPSHOT"); err != nil {
			return treeTX{}, err
		}
	}

	// If configured, enable the client side retry option for CockroachDB
	if *cockroachClientRetryFlag {
		if _, err := t.Exec("SAVEPOINT cockroach_restart"); err != nil {
			return treeTX{}, err
		}
	}

	return treeTX{
		tx:            t,
		ts:            m,
		treeID:        treeID,
		hashSizeBytes: hashSizeBytes,
		subtreeCache:  cache.NewSubtreeCache(strataDepths, populate, prepare),
		writeRevision: -1,
	}, nil
}

type treeTX struct {
	closed        bool
	tx            *sql.Tx
	ts            *pgSQLTreeStorage
	treeID        int64
	hashSizeBytes int
	subtreeCache  cache.SubtreeCache
	writeRevision int64
}

func (t *treeTX) getSubtree(treeRevision int64, nodeID storage.NodeID) (*storagepb.SubtreeProto, error) {
	s, err := t.getSubtrees(treeRevision, []storage.NodeID{nodeID})
	if err != nil {
		return nil, err
	}
	switch len(s) {
	case 0:
		return nil, nil
	case 1:
		return s[0], nil
	default:
		return nil, fmt.Errorf("got %d subtrees, but expected 1", len(s))
	}
}

func (t *treeTX) getSubtrees(treeRevision int64, nodeIDs []storage.NodeID) ([]*storagepb.SubtreeProto, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}

	tmpl, err := t.ts.getSubtreeStmt(len(nodeIDs))
	if err != nil {
		return nil, err
	}
	stx := t.tx.Stmt(tmpl)
	defer stx.Close()

	args := make([]interface{}, 0, len(nodeIDs)+3)

	// Append fixed params first
	args = append(args, interface{}(t.treeID))
	args = append(args, interface{}(treeRevision))
	args = append(args, interface{}(t.treeID))

	// populate args with nodeIDs
	for _, nodeID := range nodeIDs {
		if nodeID.PrefixLenBits%8 != 0 {
			return nil, fmt.Errorf("invalid subtree ID - not multiple of 8: %d", nodeID.PrefixLenBits)
		}

		nodeIDBytes := nodeID.Path[:nodeID.PrefixLenBits/8]

		args = append(args, interface{}(nodeIDBytes))
	}

	rows, err := stx.Query(args...)
	if err != nil {
		glog.Warningf("Failed to get merkle subtrees: %s", err)
		return nil, err
	}
	defer rows.Close()

	if rows.Err() != nil {
		// Nothing from the DB
		glog.Warningf("Nothing from DB: %s", rows.Err())
		return nil, rows.Err()
	}

	ret := make([]*storagepb.SubtreeProto, 0, len(nodeIDs))

	for rows.Next() {

		var subtreeIDBytes []byte
		var subtreeRev int64
		var nodesRaw []byte
		if err := rows.Scan(&subtreeIDBytes, &subtreeRev, &nodesRaw); err != nil {
			glog.Warningf("Failed to scan merkle subtree: %s", err)
			return nil, err
		}
		var subtree storagepb.SubtreeProto
		if err := proto.Unmarshal(nodesRaw, &subtree); err != nil {
			glog.Warningf("Failed to unmarshal SubtreeProto: %s", err)
			return nil, err
		}
		if subtree.Prefix == nil {
			subtree.Prefix = []byte{}
		}
		ret = append(ret, &subtree)
	}

	// The InternalNodes cache is possibly nil here, but the SubtreeCache (which called
	// this method) will re-populate it.
	return ret, nil
}

func (t *treeTX) storeSubtrees(subtrees []*storagepb.SubtreeProto) error {
	if len(subtrees) == 0 {
		glog.Warning("attempted to store 0 subtrees...")
		return nil
	}

	// TODO(al): probably need to be able to batch this in the case where we have
	// a really large number of subtrees to store.
	args := make([]interface{}, 0, len(subtrees))

	for _, s := range subtrees {
		s := s
		if s.Prefix == nil {
			panic(fmt.Errorf("nil prefix on %v", s))
		}
		subtreeBytes, err := proto.Marshal(s)
		if err != nil {
			return err
		}
		args = append(args, t.treeID)
		args = append(args, s.Prefix)
		args = append(args, subtreeBytes)
		args = append(args, t.writeRevision)
	}

	tmpl, err := t.ts.setSubtreeStmt(len(subtrees))
	if err != nil {
		return err
	}
	stx := t.tx.Stmt(tmpl)
	defer stx.Close()

	r, err := stx.Exec(args...)
	if err != nil {
		glog.Warningf("Failed to set merkle subtrees: %s", err)
		return err
	}
	_, _ = r.RowsAffected()
	return nil
}

func checkResultOkAndRowCountIs(res sql.Result, err error, count int64) error {
	// The Exec() might have just failed
	if err != nil {
		return err
	}

	// Otherwise we have to look at the result of the operation
	rowsAffected, rowsError := res.RowsAffected()

	if rowsError != nil {
		return rowsError
	}

	if rowsAffected != count {
		return fmt.Errorf("Expected %d row(s) to be affected but saw: %d", count,
			rowsAffected)
	}

	return nil
}

// GetTreeRevisionAtSize returns the max node version for a tree at a particular size.
// It is an error to request tree sizes larger than the currently published tree size.
// For an inexact tree size this implementation always returns the next largest revision if an
// exact one does not exist but it isn't required to do so.
func (t *treeTX) GetTreeRevisionIncludingSize(treeSize int64) (int64, int64, error) {
	// Negative size is not sensible and a zero sized tree has no nodes so no revisions
	if treeSize <= 0 {
		return 0, 0, fmt.Errorf("invalid tree size: %d", treeSize)
	}

	var treeRevision, actualTreeSize int64
	err := t.tx.QueryRow(selectTreeRevisionAtSizeOrLargerSQL, t.treeID, treeSize).Scan(&treeRevision, &actualTreeSize)

	return treeRevision, actualTreeSize, err
}

// getSubtreesAtRev returns a GetSubtreesFunc which reads at the passed in rev.
func (t *treeTX) getSubtreesAtRev(rev int64) cache.GetSubtreesFunc {
	return func(ids []storage.NodeID) ([]*storagepb.SubtreeProto, error) {
		return t.getSubtrees(rev, ids)
	}
}

// GetMerkleNodes returns the requests nodes at (or below) the passed in treeRevision.
func (t *treeTX) GetMerkleNodes(treeRevision int64, nodeIDs []storage.NodeID) ([]storage.Node, error) {
	return t.subtreeCache.GetNodes(nodeIDs, t.getSubtreesAtRev(treeRevision))
}

func (t *treeTX) SetMerkleNodes(nodes []storage.Node) error {
	for _, n := range nodes {
		err := t.subtreeCache.SetNodeHash(n.NodeID, n.Hash,
			func(nID storage.NodeID) (*storagepb.SubtreeProto, error) {
				return t.getSubtree(t.writeRevision, nID)
			})
		if err != nil {
			return err
		}
	}
	return nil
}

// Portions of this logic adapted from the tx.go file in the CockroachDB repo. Apache 2.0
// licensed.
func (t *treeTX) cockroachCommit() error {
	var err error

	// Whatever happens we must commit or rollback the tx.
	defer func() {
		if err == nil {
			// Ignore commit errors. The tx has already been committed by RELEASE.
			_ = t.tx.Commit()
		} else {
			// We always need to execute a Rollback() so sql.DB releases the connection.
			_ = t.tx.Rollback()
		}
	}()

	if err == nil {
		// RELEASE acts like COMMIT in CockroachDB. We use it since it gives us an
		// opportunity to react to retryable errors, whereas tx.Commit() doesn't.
		if _, err = t.tx.Exec("RELEASE SAVEPOINT cockroach_restart"); err == nil {
			return nil
		}
	}
	// We got an error; let's see if it's a retryable one and, if so, restart. We look
	// for the PG errcode SerializationFailureError:40001.
	pqErr, ok := err.(*pq.Error)
	if retryable := ok && pqErr.Code == "40001"; !retryable {
		// The TX is in an ambiguous state. "Maybe committed" is not a good result for a
		// database to return. We'll rollback and retry the same writes later.
		return err
	}
	// Try to roll things back to the savepoint. If it succeeds we still return the original
	// error because we want the caller to see it and retry
	if _, err2 := t.tx.Exec("ROLLBACK TO SAVEPOINT cockroach_restart"); err2 != nil {
		return err2
	}

	return err
}

func (t *treeTX) Commit() error {
	if t.writeRevision > -1 {
		err := t.subtreeCache.Flush(func(st []*storagepb.SubtreeProto) error {
			return t.storeSubtrees(st)
		})

		if err != nil {
			glog.Warningf("TX cache flush error: %v", err)
		}
	}
	t.closed = true

	// If configured, handle CockroachDB specific errors via client retry feature
	if *cockroachClientRetryFlag {
		return t.cockroachCommit()
	}

	if err := t.tx.Commit(); err != nil {
		glog.Warningf("TX commit error: %s", err)

		pqErr, ok := err.(*pq.Error)
		// If this is a retryable error from CockroachDB ensure we rollback everything.
		// The caller will have to manage retrying.
		if retryable := ok && pqErr.Code == "40001" && *cockroachRetryFlag; retryable {
			if err := t.tx.Rollback(); err != nil {
				glog.Warningf("TX commit failure rollback: %v", err)
			}
		}

		return err
	}
	return nil
}

func (t *treeTX) Rollback() error {
	t.closed = true
	if err := t.tx.Rollback(); err != nil {
		glog.Warningf("TX rollback error: %s", err)
		return err
	}
	return nil
}

func (t *treeTX) IsOpen() bool {
	return !t.closed
}

func checkDatabaseAccessible(ctx context.Context, db *sql.DB) error {
	_ = ctx

	stmt, err := db.Prepare("SELECT TreeId FROM Trees LIMIT 1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec()
	return err
}
