// Copyright 2017 Google Inc. All Rights Reserved.
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

	"github.com/golang/glog"
	"github.com/google/trillian/storage/sql/coresql/wrapper"
	"github.com/lib/pq"
)

// These are all tree related queries
const (
	insertSubtreeMultiSQL = `INSERT INTO Subtree(TreeId, SubtreeId, Nodes, SubtreeRevision) ` + placeholderSQL
	selectSubtreeSQL      = `
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

	selectTreeRevisionAtSizeOrLargerSQL = "SELECT TreeRevision,TreeSize FROM TreeHead WHERE TreeId=$1 AND TreeSize>=$2 ORDER BY TreeRevision LIMIT 1"

	insertTreeHeadSQL = `INSERT INTO TreeHead(TreeId,TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature)
		 VALUES($1,$2,$3,$4,$5,$6)`
	selectActiveLogsSQL                = "SELECT TreeId from Trees where TreeType='LOG'"
	selectActiveLogsWithUnsequencedSQL = "SELECT DISTINCT t.TreeId from Trees t INNER JOIN Unsequenced u WHERE TreeType='LOG' AND t.TreeId=u.TreeId"
	selectTreeRowSQL                   = "SELECT 1 FROM Trees WHERE TreeId = $1"
)

// These are all log related queries
const (
	selectLeavesByIndexSQL = `
			SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafValue,s.SequenceNumber,l.ExtraData
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.SequenceNumber IN (` + placeholderSQL + `) AND l.TreeId = $1 AND s.TreeId = l.TreeId`
	selectLeavesByMerkleHashSQL = `
	SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafValue,s.SequenceNumber,l.ExtraData
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.MerkleLeafHash IN (` + placeholderSQL + `) AND l.TreeId = $1 AND s.TreeId = l.TreeId`
	// Same as above except with leaves ordered by sequence so we only incur this cost when necessary
	orderBySequenceNumberSQL                     = " ORDER BY s.SequenceNumber"
	selectLeavesByMerkleHashOrderedBySequenceSQL = selectLeavesByMerkleHashSQL + orderBySequenceNumberSQL
	// TODO(drysdale): rework the code so the dummy hash isn't needed (e.g. this assumes hash size is 32)
	dummyMerkleLeafHash = "00000000000000000000000000000000"
	// This statement returns a dummy Merkle leaf hash value (which must be
	// of the right size) so that its signature matches that of the other
	// leaf-selection statements.
	selectLeavesByLeafIdentityHashSQL = `SELECT '` + dummyMerkleLeafHash + `',l.LeafIdentityHash,l.LeafValue,-1,l.ExtraData
			FROM LeafData l
			WHERE l.LeafIdentityHash IN (` + placeholderSQL + `) AND l.TreeId = $1`
	selectQueuedLeavesSQL = `SELECT LeafIdentityHash,MerkleLeafHash,MessageId,QueueTimestampNanos
			FROM Unsequenced
			WHERE TreeID=$1
			AND QueueTimestampNanos<=$2
			ORDER BY QueueTimestampNanos,LeafIdentityHash ASC LIMIT $3`
	deleteUnsequencedSQL         = "DELETE FROM Unsequenced WHERE TreeId=$1 AND MessageId=$2 AND QueueTimestampNanos=$3 AND LeafIdentityHash=$4"
	selectLatestSignedLogRootSQL = `SELECT TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature
			FROM TreeHead WHERE TreeId=$1
			ORDER BY TreeHeadTimestamp DESC LIMIT 1`
	insertUnsequencedEntrySQL = `INSERT INTO Unsequenced(TreeId,LeafIdentityHash,MerkleLeafHash,MessageId,QueueTimestampNanos)
			VALUES($1,$2,$3,$4,$5)`
	insertUnsequencedLeafSQL = `INSERT INTO LeafData(TreeId,LeafIdentityHash,LeafValue,ExtraData)
			VALUES($1,$2,$3,$4)`
	insertSequencedLeafSQL = `INSERT INTO SequencedLeafData(TreeId,LeafIdentityHash,MerkleLeafHash,SequenceNumber)
			VALUES($1,$2,$3,$4)`
	selectSequencedLeafCountSQL = "SELECT COUNT(*) FROM SequencedLeafData WHERE TreeId=$1"
)

// These are all map related queries
const (
	insertMapHeadSQL = `INSERT INTO MapHead(TreeId, MapHeadTimestamp, RootHash, MapRevision, RootSignature, MapperData)
	VALUES($1,$2,$3,$4,$5,$6)`
	selectLatestSignedMapRootSQL = `SELECT MapHeadTimestamp, RootHash, MapRevision, RootSignature, MapperData
		 FROM MapHead WHERE TreeId=$1
		 ORDER BY MapHeadTimestamp DESC LIMIT 1`
	insertMapLeafSQL = `INSERT INTO MapLeaf(TreeId, KeyHash, MapRevision, LeafValue) VALUES ($1,$2,$3,$4)`
	selectMapLeafSQL = `
 SELECT t1.KeyHash, t1.MapRevision, t1.LeafValue
 FROM MapLeaf t1
 INNER JOIN
 (
	SELECT TreeId, KeyHash, MAX(MapRevision) as maxrev
	FROM MapLeaf t0
	WHERE t0.KeyHash IN (` + placeholderSQL + `) AND
	      t0.TreeId = $1 AND t0.MapRevision <= $2
	GROUP BY t0.TreeId, t0.KeyHash
 ) t2
 ON t1.TreeId=t2.TreeId
 AND t1.KeyHash=t2.KeyHash
 AND t1.MapRevision=t2.maxrev`
)

// These are all admin related queries
const (
	selectTreeIDsSQL  = "SELECT TreeId FROM Trees"
	selectAllTreesSQL = `
		SELECT
			TreeId,
			TreeState,
			TreeType,
			HashStrategy,
			HashAlgorithm,
			SignatureAlgorithm,
			DisplayName,
			Description,
			CreateTimeMillis,
			UpdateTimeMillis,
			PrivateKey
		FROM Trees`
	selectTreeByIDSQL = selectAllTreesSQL + " WHERE TreeId = $1"
	insertTreeSQL     = `
		INSERT INTO Trees(
			TreeId,
			TreeState,
			TreeType,
			HashStrategy,
			HashAlgorithm,
			SignatureAlgorithm,
			DisplayName,
			Description,
			CreateTimeMillis,
			UpdateTimeMillis,
			PrivateKey)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	insertTreeControlSQL = `
		INSERT INTO TreeControl(
			TreeId,
			SigningEnabled,
			SequencingEnabled,
			SequenceIntervalSeconds)
		VALUES($1,$2,$3,$4)`
	updateTreeSQL = `
		UPDATE Trees
		SET TreeState=$1, DisplayName=$2, Description=$3, UpdateTimeMillis=$4
		WHERE TreeId=$5`
)

// Error code returned by lib/pq driver when inserting a duplicate row
const errCodeDuplicate = "23505"

type pgSQLWrapper struct {
	// Statements managed by this provider are specific to this database.
	db *sql.DB
	// Must hold the mutex before manipulating the statement map. Sharing a lock because
	// it only needs to be held while the statements are built, not while they execute and
	// this will be a short time. These maps are from the number of placeholder '?'
	// in the query to the statement that should be used.
	statementMutex sync.Mutex
	statements     map[string]map[int]*sql.Stmt
}

// NewWrapper creates and returns a DBWrapper appropriate for use with MySQL.
func NewWrapper(db *sql.DB) wrapper.DBWrapper {
	return &pgSQLWrapper{
		db:         db,
		statements: make(map[string]map[int]*sql.Stmt),
	}
}

func (m *pgSQLWrapper) DB() *sql.DB {
	return m.db
}

func (m *pgSQLWrapper) GetSubtreeStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectSubtreeSQL, 4, num)
	})
}

func (m *pgSQLWrapper) SetSubtreeStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		tmpl := expandValuesPlaceholderSQL(insertSubtreeMultiSQL, 4, num)
		// Should not be any more placeholder expansion but we're not allowed to pass zero
		return m.getStmt(tmpl, 1, 1)
	})
}

func (m *pgSQLWrapper) GetTreeRevisionIncludingSizeStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectTreeRevisionAtSizeOrLargerSQL)
}

func (m *pgSQLWrapper) InsertTreeHeadStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertTreeHeadSQL)
}

func (m *pgSQLWrapper) GetActiveLogsStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectActiveLogsSQL)
}

func (m *pgSQLWrapper) GetActiveLogsWithWorkStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectActiveLogsWithUnsequencedSQL)
}

func (m *pgSQLWrapper) GetLeavesByIndexStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByIndexSQL, 2, num)
	})
}

func (m *pgSQLWrapper) GetLeavesByLeafIdentityHashStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByLeafIdentityHashSQL, 2, num)
	})
}

func (m *pgSQLWrapper) DeleteUnsequencedStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(deleteUnsequencedSQL)
}

func (m *pgSQLWrapper) GetLeavesByMerkleHashStmt(tx *sql.Tx, num int, orderBySequence bool) (*sql.Stmt, error) {
	if orderBySequence {
		return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
			return m.getStmt(selectLeavesByMerkleHashOrderedBySequenceSQL, 2, num)
		})
	}

	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByMerkleHashSQL, 2, num)
	})
}

func (m *pgSQLWrapper) GetLatestSignedLogRootStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectLatestSignedLogRootSQL)
}

func (m *pgSQLWrapper) GetQueuedLeavesStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectQueuedLeavesSQL)
}

func (m *pgSQLWrapper) InsertUnsequencedEntryStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertUnsequencedEntrySQL)
}

func (m *pgSQLWrapper) InsertUnsequencedLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertUnsequencedLeafSQL)
}

func (m *pgSQLWrapper) InsertSequencedLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertSequencedLeafSQL)
}

func (m *pgSQLWrapper) GetSequencedLeafCountStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectSequencedLeafCountSQL)
}

func (m *pgSQLWrapper) GetMapLeafStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return wrapper.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectMapLeafSQL, 3, num)
	})
}

func (m *pgSQLWrapper) InsertMapHeadStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertMapHeadSQL)
}

func (m *pgSQLWrapper) GetLatestMapRootStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectLatestSignedMapRootSQL)
}

func (m *pgSQLWrapper) InsertMapLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertMapLeafSQL)
}

func (m *pgSQLWrapper) GetAllTreesStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectAllTreesSQL)
}

func (m *pgSQLWrapper) GetTreeStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectTreeByIDSQL)
}

func (m *pgSQLWrapper) GetTreeIDsStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectTreeIDsSQL)
}

func (m *pgSQLWrapper) InsertTreeStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertTreeSQL)
}

func (m *pgSQLWrapper) InsertTreeControlStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertTreeControlSQL)
}

func (m *pgSQLWrapper) UpdateTreeStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(updateTreeSQL)
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

// getStmt creates and caches sql.Stmt structs based on the passed in statement
// and number of bound arguments.
func (m *pgSQLWrapper) getStmt(statement string, first, num int) (*sql.Stmt, error) {
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

	s, err := m.db.Prepare(expandPlaceholderSQL(statement, first, num))
	if err != nil {
		glog.Warningf("Failed to prepare statement %d: %s", num, err)
		return nil, err
	}

	glog.Warningf("SQL: %s", s)

	m.statements[statement][num] = s

	return s, nil
}
func (m *pgSQLWrapper) IsDuplicateErr(err error) bool {
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == errCodeDuplicate {
			return true
		}
	}

	return false
}

func (m *pgSQLWrapper) OnOpenDB() error {
	return nil
}

func (m *pgSQLWrapper) TreeRowExists(treeID int64) error {
	var num int
	if err := m.db.QueryRow(selectTreeRowSQL, treeID).Scan(&num); err != nil {
		return fmt.Errorf("failed to get tree row for treeID %v: %v", treeID, err)
	}
	return nil
}

func (m *pgSQLWrapper) CheckDatabaseAccessible(ctx context.Context) error {
	_ = ctx
	stmt, err := m.DB().Prepare("SELECT TreeId FROM Trees LIMIT 1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec()
	return err
}

func (m *pgSQLWrapper) VariableArgsFirst() bool {
	// We want the variable arguments last as we have positional placeholders. This means we
	// want to keep the fixed parameters as $1, $2 etc. as they otherwise can't be written as
	// literal strings - they'd change depending on the number of variable args.
	return false
}