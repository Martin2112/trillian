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

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
	"github.com/google/trillian/storage/coresql"
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
	 n.TreeId = ? AND n.SubtreeRevision <= ?
	GROUP BY n.SubtreeId
 ) AS x
 INNER JOIN Subtree
 ON Subtree.SubtreeId = x.SubtreeId
 AND Subtree.SubtreeRevision = x.MaxRevision
 AND Subtree.TreeId = ?`
	placeholderSQL = "<placeholder>"

	selectTreeRevisionAtSizeOrLargerSQL = "SELECT TreeRevision,TreeSize FROM TreeHead WHERE TreeId=? AND TreeSize>=? ORDER BY TreeRevision LIMIT 1"

	insertTreeHeadSQL = `INSERT INTO TreeHead(TreeId,TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature)
		 VALUES(?,?,?,?,?,?)`
	selectActiveLogsSQL                = "SELECT TreeId from Trees where TreeType='LOG'"
	selectActiveLogsWithUnsequencedSQL = "SELECT DISTINCT t.TreeId from Trees t INNER JOIN Unsequenced u WHERE TreeType='LOG' AND t.TreeId=u.TreeId"
	selectTreeRowSQL = "SELECT 1 FROM Trees WHERE TreeId = ?"
)

// These are all log related queries
const (
	selectLeavesByIndexSQL = `
	    SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafValue,s.SequenceNumber,l.ExtraData
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.SequenceNumber IN (` + placeholderSQL + `) AND l.TreeId = ? AND s.TreeId = l.TreeId`
	selectLeavesByMerkleHashSQL = `
			SELECT s.MerkleLeafHash,l.LeafIdentityHash,l.LeafValue,s.SequenceNumber,l.ExtraData
			FROM LeafData l,SequencedLeafData s
			WHERE l.LeafIdentityHash = s.LeafIdentityHash
			AND s.MerkleLeafHash IN (` + placeholderSQL + `) AND l.TreeId = ? AND s.TreeId = l.TreeId`
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
			WHERE l.LeafIdentityHash IN (` + placeholderSQL + `) AND l.TreeId = ?`
	selectQueuedLeavesSQL = `SELECT LeafIdentityHash,MerkleLeafHash
			FROM Unsequenced
			WHERE TreeID=?
			AND QueueTimestampNanos<=?
			ORDER BY QueueTimestampNanos,LeafIdentityHash ASC LIMIT ?`
	deleteUnsequencedSQL = "DELETE FROM Unsequenced WHERE LeafIdentityHash IN (<placeholder>) AND TreeId = ?"
	selectLatestSignedLogRootSQL = `SELECT TreeHeadTimestamp,TreeSize,RootHash,TreeRevision,RootSignature
			FROM TreeHead WHERE TreeId=?
			ORDER BY TreeHeadTimestamp DESC LIMIT 1`
	insertUnsequencedEntrySQL = `INSERT INTO Unsequenced(TreeId,LeafIdentityHash,MerkleLeafHash,MessageId,QueueTimestampNanos)
			VALUES(?,?,?,?,?)`
	insertUnsequencedLeafSQL = `INSERT INTO LeafData(TreeId,LeafIdentityHash,LeafValue,ExtraData)
			VALUES(?,?,?,?)`
	insertSequencedLeafSQL = `INSERT INTO SequencedLeafData(TreeId,LeafIdentityHash,MerkleLeafHash,SequenceNumber)
			VALUES(?,?,?,?)`
	selectSequencedLeafCountSQL  = "SELECT COUNT(*) FROM SequencedLeafData WHERE TreeId=?"
)

// These are all map related queries
const (
	insertMapHeadSQL = `INSERT INTO MapHead(TreeId, MapHeadTimestamp, RootHash, MapRevision, RootSignature, MapperData)
	VALUES(?, ?, ?, ?, ?, ?)`
	selectLatestSignedMapRootSQL = `SELECT MapHeadTimestamp, RootHash, MapRevision, RootSignature, MapperData
		 FROM MapHead WHERE TreeId=?
		 ORDER BY MapHeadTimestamp DESC LIMIT 1`
	insertMapLeafSQL = `INSERT INTO MapLeaf(TreeId, KeyHash, MapRevision, LeafValue) VALUES (?, ?, ?, ?)`
	selectMapLeafSQL = `
 SELECT t1.KeyHash, t1.MapRevision, t1.LeafValue
 FROM MapLeaf t1
 INNER JOIN
 (
	SELECT TreeId, KeyHash, MAX(MapRevision) as maxrev
	FROM MapLeaf t0
	WHERE t0.KeyHash IN (` + placeholderSQL + `) AND
	      t0.TreeId = ? AND t0.MapRevision <= ?
	GROUP BY t0.TreeId, t0.KeyHash
 ) t2
 ON t1.TreeId=t2.TreeId
 AND t1.KeyHash=t2.KeyHash
 AND t1.MapRevision=t2.maxrev`
)

// Error code returned by MySQL driver when inserting a duplicate row
const errNumDuplicate = 1062

type mySQLStatementProvider struct {
	// Statements managed by this provider are specific to this database.
	db *sql.DB
	// Must hold the mutex before manipulating the statement map. Sharing a lock because
	// it only needs to be held while the statements are built, not while they execute and
	// this will be a short time. These maps are from the number of placeholder '?'
	// in the query to the statement that should be used.
	statementMutex sync.Mutex
	statements     map[string]map[int]*sql.Stmt
}

// NewStatementProvider creates and returns a StatementPprovider appropriate for use with
// MySQL.
func NewStatementProvider(db *sql.DB) coresql.StatementProvider {
	return &mySQLStatementProvider{
		db:         db,
		statements: make(map[string]map[int]*sql.Stmt),
	}
}

func (m *mySQLStatementProvider) GetSubtreeStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectSubtreeSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) SetSubtreeStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(insertSubtreeMultiSQL, num, "VALUES(?, ?, ?, ?)", "(?, ?, ?, ?)")
	})
}

func (m *mySQLStatementProvider) GetTreeRevisionIncludingSizeStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectTreeRevisionAtSizeOrLargerSQL)
}

func (m *mySQLStatementProvider) InsertTreeHeadStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertTreeHeadSQL)
}

func (m *mySQLStatementProvider) GetActiveLogsStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectActiveLogsSQL)
}

func (m *mySQLStatementProvider) GetActiveLogsWithWorkStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectActiveLogsWithUnsequencedSQL)
}

func (m *mySQLStatementProvider) GetLeavesByIndexStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByIndexSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) GetLeavesByLeafIdentityHashStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByLeafIdentityHashSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) DeleteUnsequencedStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(deleteUnsequencedSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) GetLeavesByMerkleHashStmt(tx *sql.Tx, num int, orderBySequence bool) (*sql.Stmt, error) {
	if orderBySequence {
		return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
			return m.getStmt(selectLeavesByMerkleHashOrderedBySequenceSQL, num, "?", "?")
		})
	}

	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectLeavesByMerkleHashSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) GetLatestSignedLogRootStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectLatestSignedLogRootSQL)
}

func (m *mySQLStatementProvider) GetQueuedLeavesStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectQueuedLeavesSQL)
}

func (m *mySQLStatementProvider) InsertUnsequencedEntryStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertUnsequencedEntrySQL)
}

func (m *mySQLStatementProvider) InsertUnsequencedLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertUnsequencedLeafSQL)
}

func (m *mySQLStatementProvider) InsertSequencedLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertSequencedLeafSQL)
}

func (m *mySQLStatementProvider) GetSequencedLeafCountStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectSequencedLeafCountSQL)
}

func (m *mySQLStatementProvider) GetMapLeafStmt(tx *sql.Tx, num int) (*sql.Stmt, error) {
	return coresql.PrepInTx(tx, func() (stmt *sql.Stmt, err error) {
		return m.getStmt(selectMapLeafSQL, num, "?", "?")
	})
}

func (m *mySQLStatementProvider) InsertMapHeadStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertMapHeadSQL)
}

func (m *mySQLStatementProvider) GetLatestMapRootStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(selectLatestSignedMapRootSQL)
}

func (m *mySQLStatementProvider) InsertMapLeafStmt(tx *sql.Tx) (*sql.Stmt, error) {
	return tx.Prepare(insertMapLeafSQL)
}

// expandPlaceholderSQL expands an sql statement by adding a specified number of '?'
// placeholder slots. At most one placeholder will be expanded.
func expandPlaceholderSQL(sql string, num int, first, rest string) string {
	if num <= 0 {
		panic(fmt.Errorf("Trying to expand SQL placeholder with <= 0 parameters: %s", sql))
	}

	parameters := first + strings.Repeat(","+rest, num-1)

	return strings.Replace(sql, placeholderSQL, parameters, 1)
}

// getStmt creates and caches sql.Stmt structs based on the passed in statement
// and number of bound arguments.
func (m *mySQLStatementProvider) getStmt(statement string, num int, first, rest string) (*sql.Stmt, error) {
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

	s, err := m.db.Prepare(expandPlaceholderSQL(statement, num, first, rest))

	if err != nil {
		glog.Warningf("Failed to prepare statement %d: %s", num, err)
		return nil, err
	}

	m.statements[statement][num] = s

	return s, nil
}

func (m *mySQLStatementProvider) IsDuplicateErr(err error) bool {
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == errNumDuplicate {
			return true
		}
	}

	return false
}

func (m *mySQLStatementProvider) OnOpenDB(db *sql.DB) error {
	if _, err := db.Exec("SET sql_mode = 'STRICT_ALL_TABLES'"); err != nil {
		glog.Warningf("Failed to set strict mode on mysql db: %s", err)
		return err
	}

	return nil
}

func (m *mySQLStatementProvider) TreeRowExists(db *sql.DB, treeID int64) error {
	var num int
	if err := m.db.QueryRow(selectTreeRowSQL, treeID).Scan(&num); err != nil {
		return fmt.Errorf("failed to get tree row for treeID %v: %v", treeID, err)
	}
	return nil
}

func (m *mySQLStatementProvider) CheckDatabaseAccessible(ctx context.Context, db *sql.DB) error {
	_ = ctx
	stmt, err := db.Prepare("SELECT TreeId FROM Trees LIMIT 1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec()
	return err
}
