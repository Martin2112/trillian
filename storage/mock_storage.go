// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/google/trillian/storage (interfaces: AdminStorage,AdminTX,LogStorage,LogTreeTX,MapStorage,MapTreeTX,ReadOnlyAdminTX,ReadOnlyLogTX,ReadOnlyLogTreeTX,ReadOnlyMapTreeTX)

package storage

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	trillian "github.com/google/trillian"
	time "time"
)

// Mock of AdminStorage interface
type MockAdminStorage struct {
	ctrl     *gomock.Controller
	recorder *_MockAdminStorageRecorder
}

// Recorder for MockAdminStorage (not exported)
type _MockAdminStorageRecorder struct {
	mock *MockAdminStorage
}

func NewMockAdminStorage(ctrl *gomock.Controller) *MockAdminStorage {
	mock := &MockAdminStorage{ctrl: ctrl}
	mock.recorder = &_MockAdminStorageRecorder{mock}
	return mock
}

func (_m *MockAdminStorage) EXPECT() *_MockAdminStorageRecorder {
	return _m.recorder
}

func (_m *MockAdminStorage) Begin(_param0 context.Context) (AdminTX, error) {
	ret := _m.ctrl.Call(_m, "Begin", _param0)
	ret0, _ := ret[0].(AdminTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminStorageRecorder) Begin(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Begin", arg0)
}

func (_m *MockAdminStorage) Snapshot(_param0 context.Context) (ReadOnlyAdminTX, error) {
	ret := _m.ctrl.Call(_m, "Snapshot", _param0)
	ret0, _ := ret[0].(ReadOnlyAdminTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminStorageRecorder) Snapshot(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Snapshot", arg0)
}

// Mock of AdminTX interface
type MockAdminTX struct {
	ctrl     *gomock.Controller
	recorder *_MockAdminTXRecorder
}

// Recorder for MockAdminTX (not exported)
type _MockAdminTXRecorder struct {
	mock *MockAdminTX
}

func NewMockAdminTX(ctrl *gomock.Controller) *MockAdminTX {
	mock := &MockAdminTX{ctrl: ctrl}
	mock.recorder = &_MockAdminTXRecorder{mock}
	return mock
}

func (_m *MockAdminTX) EXPECT() *_MockAdminTXRecorder {
	return _m.recorder
}

func (_m *MockAdminTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockAdminTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockAdminTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockAdminTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockAdminTX) CreateTree(_param0 context.Context, _param1 *trillian.Tree) (*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "CreateTree", _param0, _param1)
	ret0, _ := ret[0].(*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminTXRecorder) CreateTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CreateTree", arg0, arg1)
}

func (_m *MockAdminTX) GetTree(_param0 context.Context, _param1 int64) (*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "GetTree", _param0, _param1)
	ret0, _ := ret[0].(*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminTXRecorder) GetTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetTree", arg0, arg1)
}

func (_m *MockAdminTX) IsClosed() bool {
	ret := _m.ctrl.Call(_m, "IsClosed")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockAdminTXRecorder) IsClosed() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsClosed")
}

func (_m *MockAdminTX) ListTreeIDs(_param0 context.Context) ([]int64, error) {
	ret := _m.ctrl.Call(_m, "ListTreeIDs", _param0)
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminTXRecorder) ListTreeIDs(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListTreeIDs", arg0)
}

func (_m *MockAdminTX) ListTrees(_param0 context.Context) ([]*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "ListTrees", _param0)
	ret0, _ := ret[0].([]*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminTXRecorder) ListTrees(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListTrees", arg0)
}

func (_m *MockAdminTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockAdminTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

func (_m *MockAdminTX) UpdateTree(_param0 context.Context, _param1 int64, _param2 func(*trillian.Tree)) (*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "UpdateTree", _param0, _param1, _param2)
	ret0, _ := ret[0].(*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAdminTXRecorder) UpdateTree(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UpdateTree", arg0, arg1, arg2)
}

// Mock of LogStorage interface
type MockLogStorage struct {
	ctrl     *gomock.Controller
	recorder *_MockLogStorageRecorder
}

// Recorder for MockLogStorage (not exported)
type _MockLogStorageRecorder struct {
	mock *MockLogStorage
}

func NewMockLogStorage(ctrl *gomock.Controller) *MockLogStorage {
	mock := &MockLogStorage{ctrl: ctrl}
	mock.recorder = &_MockLogStorageRecorder{mock}
	return mock
}

func (_m *MockLogStorage) EXPECT() *_MockLogStorageRecorder {
	return _m.recorder
}

func (_m *MockLogStorage) BeginForTree(_param0 context.Context, _param1 int64) (LogTreeTX, error) {
	ret := _m.ctrl.Call(_m, "BeginForTree", _param0, _param1)
	ret0, _ := ret[0].(LogTreeTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogStorageRecorder) BeginForTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "BeginForTree", arg0, arg1)
}

func (_m *MockLogStorage) CheckDatabaseAccessible(_param0 context.Context) error {
	ret := _m.ctrl.Call(_m, "CheckDatabaseAccessible", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogStorageRecorder) CheckDatabaseAccessible(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CheckDatabaseAccessible", arg0)
}

func (_m *MockLogStorage) Snapshot(_param0 context.Context) (ReadOnlyLogTX, error) {
	ret := _m.ctrl.Call(_m, "Snapshot", _param0)
	ret0, _ := ret[0].(ReadOnlyLogTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogStorageRecorder) Snapshot(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Snapshot", arg0)
}

func (_m *MockLogStorage) SnapshotForTree(_param0 context.Context, _param1 int64) (ReadOnlyLogTreeTX, error) {
	ret := _m.ctrl.Call(_m, "SnapshotForTree", _param0, _param1)
	ret0, _ := ret[0].(ReadOnlyLogTreeTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogStorageRecorder) SnapshotForTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SnapshotForTree", arg0, arg1)
}

// Mock of LogTreeTX interface
type MockLogTreeTX struct {
	ctrl     *gomock.Controller
	recorder *_MockLogTreeTXRecorder
}

// Recorder for MockLogTreeTX (not exported)
type _MockLogTreeTXRecorder struct {
	mock *MockLogTreeTX
}

func NewMockLogTreeTX(ctrl *gomock.Controller) *MockLogTreeTX {
	mock := &MockLogTreeTX{ctrl: ctrl}
	mock.recorder = &_MockLogTreeTXRecorder{mock}
	return mock
}

func (_m *MockLogTreeTX) EXPECT() *_MockLogTreeTXRecorder {
	return _m.recorder
}

func (_m *MockLogTreeTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockLogTreeTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockLogTreeTX) DequeueLeaves(_param0 int, _param1 time.Time) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "DequeueLeaves", _param0, _param1)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) DequeueLeaves(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "DequeueLeaves", arg0, arg1)
}

func (_m *MockLogTreeTX) GetActiveLogIDs() ([]int64, error) {
	ret := _m.ctrl.Call(_m, "GetActiveLogIDs")
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetActiveLogIDs() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetActiveLogIDs")
}

func (_m *MockLogTreeTX) GetActiveLogIDsWithPendingWork() ([]int64, error) {
	ret := _m.ctrl.Call(_m, "GetActiveLogIDsWithPendingWork")
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetActiveLogIDsWithPendingWork() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetActiveLogIDsWithPendingWork")
}

func (_m *MockLogTreeTX) GetLeafDataByIdentityHash(_param0 [][]byte) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeafDataByIdentityHash", _param0)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetLeafDataByIdentityHash(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeafDataByIdentityHash", arg0)
}

func (_m *MockLogTreeTX) GetLeavesByHash(_param0 [][]byte, _param1 bool) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeavesByHash", _param0, _param1)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetLeavesByHash(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeavesByHash", arg0, arg1)
}

func (_m *MockLogTreeTX) GetLeavesByIndex(_param0 []int64) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeavesByIndex", _param0)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetLeavesByIndex(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeavesByIndex", arg0)
}

func (_m *MockLogTreeTX) GetMerkleNodes(_param0 int64, _param1 []NodeID) ([]Node, error) {
	ret := _m.ctrl.Call(_m, "GetMerkleNodes", _param0, _param1)
	ret0, _ := ret[0].([]Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetMerkleNodes(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetMerkleNodes", arg0, arg1)
}

func (_m *MockLogTreeTX) GetSequencedLeafCount() (int64, error) {
	ret := _m.ctrl.Call(_m, "GetSequencedLeafCount")
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) GetSequencedLeafCount() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetSequencedLeafCount")
}

func (_m *MockLogTreeTX) IsOpen() bool {
	ret := _m.ctrl.Call(_m, "IsOpen")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) IsOpen() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsOpen")
}

func (_m *MockLogTreeTX) LatestSignedLogRoot() (trillian.SignedLogRoot, error) {
	ret := _m.ctrl.Call(_m, "LatestSignedLogRoot")
	ret0, _ := ret[0].(trillian.SignedLogRoot)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) LatestSignedLogRoot() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LatestSignedLogRoot")
}

func (_m *MockLogTreeTX) QueueLeaves(_param0 []*trillian.LogLeaf, _param1 time.Time) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "QueueLeaves", _param0, _param1)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockLogTreeTXRecorder) QueueLeaves(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "QueueLeaves", arg0, arg1)
}

func (_m *MockLogTreeTX) ReadRevision() int64 {
	ret := _m.ctrl.Call(_m, "ReadRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) ReadRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ReadRevision")
}

func (_m *MockLogTreeTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

func (_m *MockLogTreeTX) SetMerkleNodes(_param0 []Node) error {
	ret := _m.ctrl.Call(_m, "SetMerkleNodes", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) SetMerkleNodes(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetMerkleNodes", arg0)
}

func (_m *MockLogTreeTX) StoreSignedLogRoot(_param0 trillian.SignedLogRoot) error {
	ret := _m.ctrl.Call(_m, "StoreSignedLogRoot", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) StoreSignedLogRoot(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StoreSignedLogRoot", arg0)
}

func (_m *MockLogTreeTX) UpdateSequencedLeaves(_param0 []*trillian.LogLeaf) error {
	ret := _m.ctrl.Call(_m, "UpdateSequencedLeaves", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) UpdateSequencedLeaves(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UpdateSequencedLeaves", arg0)
}

func (_m *MockLogTreeTX) WriteRevision() int64 {
	ret := _m.ctrl.Call(_m, "WriteRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockLogTreeTXRecorder) WriteRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "WriteRevision")
}

// Mock of MapStorage interface
type MockMapStorage struct {
	ctrl     *gomock.Controller
	recorder *_MockMapStorageRecorder
}

// Recorder for MockMapStorage (not exported)
type _MockMapStorageRecorder struct {
	mock *MockMapStorage
}

func NewMockMapStorage(ctrl *gomock.Controller) *MockMapStorage {
	mock := &MockMapStorage{ctrl: ctrl}
	mock.recorder = &_MockMapStorageRecorder{mock}
	return mock
}

func (_m *MockMapStorage) EXPECT() *_MockMapStorageRecorder {
	return _m.recorder
}

func (_m *MockMapStorage) BeginForTree(_param0 context.Context, _param1 int64) (MapTreeTX, error) {
	ret := _m.ctrl.Call(_m, "BeginForTree", _param0, _param1)
	ret0, _ := ret[0].(MapTreeTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapStorageRecorder) BeginForTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "BeginForTree", arg0, arg1)
}

func (_m *MockMapStorage) CheckDatabaseAccessible(_param0 context.Context) error {
	ret := _m.ctrl.Call(_m, "CheckDatabaseAccessible", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapStorageRecorder) CheckDatabaseAccessible(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CheckDatabaseAccessible", arg0)
}

func (_m *MockMapStorage) Snapshot(_param0 context.Context) (ReadOnlyMapTX, error) {
	ret := _m.ctrl.Call(_m, "Snapshot", _param0)
	ret0, _ := ret[0].(ReadOnlyMapTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapStorageRecorder) Snapshot(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Snapshot", arg0)
}

func (_m *MockMapStorage) SnapshotForTree(_param0 context.Context, _param1 int64) (ReadOnlyMapTreeTX, error) {
	ret := _m.ctrl.Call(_m, "SnapshotForTree", _param0, _param1)
	ret0, _ := ret[0].(ReadOnlyMapTreeTX)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapStorageRecorder) SnapshotForTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SnapshotForTree", arg0, arg1)
}

// Mock of MapTreeTX interface
type MockMapTreeTX struct {
	ctrl     *gomock.Controller
	recorder *_MockMapTreeTXRecorder
}

// Recorder for MockMapTreeTX (not exported)
type _MockMapTreeTXRecorder struct {
	mock *MockMapTreeTX
}

func NewMockMapTreeTX(ctrl *gomock.Controller) *MockMapTreeTX {
	mock := &MockMapTreeTX{ctrl: ctrl}
	mock.recorder = &_MockMapTreeTXRecorder{mock}
	return mock
}

func (_m *MockMapTreeTX) EXPECT() *_MockMapTreeTXRecorder {
	return _m.recorder
}

func (_m *MockMapTreeTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockMapTreeTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockMapTreeTX) Get(_param0 int64, _param1 [][]byte) ([]trillian.MapLeaf, error) {
	ret := _m.ctrl.Call(_m, "Get", _param0, _param1)
	ret0, _ := ret[0].([]trillian.MapLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapTreeTXRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Get", arg0, arg1)
}

func (_m *MockMapTreeTX) GetMerkleNodes(_param0 int64, _param1 []NodeID) ([]Node, error) {
	ret := _m.ctrl.Call(_m, "GetMerkleNodes", _param0, _param1)
	ret0, _ := ret[0].([]Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapTreeTXRecorder) GetMerkleNodes(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetMerkleNodes", arg0, arg1)
}

func (_m *MockMapTreeTX) IsOpen() bool {
	ret := _m.ctrl.Call(_m, "IsOpen")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) IsOpen() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsOpen")
}

func (_m *MockMapTreeTX) LatestSignedMapRoot() (trillian.SignedMapRoot, error) {
	ret := _m.ctrl.Call(_m, "LatestSignedMapRoot")
	ret0, _ := ret[0].(trillian.SignedMapRoot)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockMapTreeTXRecorder) LatestSignedMapRoot() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LatestSignedMapRoot")
}

func (_m *MockMapTreeTX) ReadRevision() int64 {
	ret := _m.ctrl.Call(_m, "ReadRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) ReadRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ReadRevision")
}

func (_m *MockMapTreeTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

func (_m *MockMapTreeTX) Set(_param0 []byte, _param1 trillian.MapLeaf) error {
	ret := _m.ctrl.Call(_m, "Set", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) Set(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Set", arg0, arg1)
}

func (_m *MockMapTreeTX) SetMerkleNodes(_param0 []Node) error {
	ret := _m.ctrl.Call(_m, "SetMerkleNodes", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) SetMerkleNodes(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetMerkleNodes", arg0)
}

func (_m *MockMapTreeTX) StoreSignedMapRoot(_param0 trillian.SignedMapRoot) error {
	ret := _m.ctrl.Call(_m, "StoreSignedMapRoot", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) StoreSignedMapRoot(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StoreSignedMapRoot", arg0)
}

func (_m *MockMapTreeTX) WriteRevision() int64 {
	ret := _m.ctrl.Call(_m, "WriteRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockMapTreeTXRecorder) WriteRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "WriteRevision")
}

// Mock of ReadOnlyAdminTX interface
type MockReadOnlyAdminTX struct {
	ctrl     *gomock.Controller
	recorder *_MockReadOnlyAdminTXRecorder
}

// Recorder for MockReadOnlyAdminTX (not exported)
type _MockReadOnlyAdminTXRecorder struct {
	mock *MockReadOnlyAdminTX
}

func NewMockReadOnlyAdminTX(ctrl *gomock.Controller) *MockReadOnlyAdminTX {
	mock := &MockReadOnlyAdminTX{ctrl: ctrl}
	mock.recorder = &_MockReadOnlyAdminTXRecorder{mock}
	return mock
}

func (_m *MockReadOnlyAdminTX) EXPECT() *_MockReadOnlyAdminTXRecorder {
	return _m.recorder
}

func (_m *MockReadOnlyAdminTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyAdminTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockReadOnlyAdminTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyAdminTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockReadOnlyAdminTX) GetTree(_param0 context.Context, _param1 int64) (*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "GetTree", _param0, _param1)
	ret0, _ := ret[0].(*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyAdminTXRecorder) GetTree(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetTree", arg0, arg1)
}

func (_m *MockReadOnlyAdminTX) IsClosed() bool {
	ret := _m.ctrl.Call(_m, "IsClosed")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockReadOnlyAdminTXRecorder) IsClosed() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsClosed")
}

func (_m *MockReadOnlyAdminTX) ListTreeIDs(_param0 context.Context) ([]int64, error) {
	ret := _m.ctrl.Call(_m, "ListTreeIDs", _param0)
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyAdminTXRecorder) ListTreeIDs(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListTreeIDs", arg0)
}

func (_m *MockReadOnlyAdminTX) ListTrees(_param0 context.Context) ([]*trillian.Tree, error) {
	ret := _m.ctrl.Call(_m, "ListTrees", _param0)
	ret0, _ := ret[0].([]*trillian.Tree)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyAdminTXRecorder) ListTrees(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListTrees", arg0)
}

func (_m *MockReadOnlyAdminTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyAdminTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

// Mock of ReadOnlyLogTX interface
type MockReadOnlyLogTX struct {
	ctrl     *gomock.Controller
	recorder *_MockReadOnlyLogTXRecorder
}

// Recorder for MockReadOnlyLogTX (not exported)
type _MockReadOnlyLogTXRecorder struct {
	mock *MockReadOnlyLogTX
}

func NewMockReadOnlyLogTX(ctrl *gomock.Controller) *MockReadOnlyLogTX {
	mock := &MockReadOnlyLogTX{ctrl: ctrl}
	mock.recorder = &_MockReadOnlyLogTXRecorder{mock}
	return mock
}

func (_m *MockReadOnlyLogTX) EXPECT() *_MockReadOnlyLogTXRecorder {
	return _m.recorder
}

func (_m *MockReadOnlyLogTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockReadOnlyLogTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockReadOnlyLogTX) GetActiveLogIDs() ([]int64, error) {
	ret := _m.ctrl.Call(_m, "GetActiveLogIDs")
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTXRecorder) GetActiveLogIDs() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetActiveLogIDs")
}

func (_m *MockReadOnlyLogTX) GetActiveLogIDsWithPendingWork() ([]int64, error) {
	ret := _m.ctrl.Call(_m, "GetActiveLogIDsWithPendingWork")
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTXRecorder) GetActiveLogIDsWithPendingWork() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetActiveLogIDsWithPendingWork")
}

func (_m *MockReadOnlyLogTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

// Mock of ReadOnlyLogTreeTX interface
type MockReadOnlyLogTreeTX struct {
	ctrl     *gomock.Controller
	recorder *_MockReadOnlyLogTreeTXRecorder
}

// Recorder for MockReadOnlyLogTreeTX (not exported)
type _MockReadOnlyLogTreeTXRecorder struct {
	mock *MockReadOnlyLogTreeTX
}

func NewMockReadOnlyLogTreeTX(ctrl *gomock.Controller) *MockReadOnlyLogTreeTX {
	mock := &MockReadOnlyLogTreeTX{ctrl: ctrl}
	mock.recorder = &_MockReadOnlyLogTreeTXRecorder{mock}
	return mock
}

func (_m *MockReadOnlyLogTreeTX) EXPECT() *_MockReadOnlyLogTreeTXRecorder {
	return _m.recorder
}

func (_m *MockReadOnlyLogTreeTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockReadOnlyLogTreeTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockReadOnlyLogTreeTX) GetLeafDataByIdentityHash(_param0 [][]byte) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeafDataByIdentityHash", _param0)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) GetLeafDataByIdentityHash(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeafDataByIdentityHash", arg0)
}

func (_m *MockReadOnlyLogTreeTX) GetLeavesByHash(_param0 [][]byte, _param1 bool) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeavesByHash", _param0, _param1)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) GetLeavesByHash(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeavesByHash", arg0, arg1)
}

func (_m *MockReadOnlyLogTreeTX) GetLeavesByIndex(_param0 []int64) ([]*trillian.LogLeaf, error) {
	ret := _m.ctrl.Call(_m, "GetLeavesByIndex", _param0)
	ret0, _ := ret[0].([]*trillian.LogLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) GetLeavesByIndex(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetLeavesByIndex", arg0)
}

func (_m *MockReadOnlyLogTreeTX) GetMerkleNodes(_param0 int64, _param1 []NodeID) ([]Node, error) {
	ret := _m.ctrl.Call(_m, "GetMerkleNodes", _param0, _param1)
	ret0, _ := ret[0].([]Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) GetMerkleNodes(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetMerkleNodes", arg0, arg1)
}

func (_m *MockReadOnlyLogTreeTX) GetSequencedLeafCount() (int64, error) {
	ret := _m.ctrl.Call(_m, "GetSequencedLeafCount")
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) GetSequencedLeafCount() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetSequencedLeafCount")
}

func (_m *MockReadOnlyLogTreeTX) IsOpen() bool {
	ret := _m.ctrl.Call(_m, "IsOpen")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) IsOpen() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsOpen")
}

func (_m *MockReadOnlyLogTreeTX) LatestSignedLogRoot() (trillian.SignedLogRoot, error) {
	ret := _m.ctrl.Call(_m, "LatestSignedLogRoot")
	ret0, _ := ret[0].(trillian.SignedLogRoot)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) LatestSignedLogRoot() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LatestSignedLogRoot")
}

func (_m *MockReadOnlyLogTreeTX) ReadRevision() int64 {
	ret := _m.ctrl.Call(_m, "ReadRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) ReadRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ReadRevision")
}

func (_m *MockReadOnlyLogTreeTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyLogTreeTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}

// Mock of ReadOnlyMapTreeTX interface
type MockReadOnlyMapTreeTX struct {
	ctrl     *gomock.Controller
	recorder *_MockReadOnlyMapTreeTXRecorder
}

// Recorder for MockReadOnlyMapTreeTX (not exported)
type _MockReadOnlyMapTreeTXRecorder struct {
	mock *MockReadOnlyMapTreeTX
}

func NewMockReadOnlyMapTreeTX(ctrl *gomock.Controller) *MockReadOnlyMapTreeTX {
	mock := &MockReadOnlyMapTreeTX{ctrl: ctrl}
	mock.recorder = &_MockReadOnlyMapTreeTXRecorder{mock}
	return mock
}

func (_m *MockReadOnlyMapTreeTX) EXPECT() *_MockReadOnlyMapTreeTXRecorder {
	return _m.recorder
}

func (_m *MockReadOnlyMapTreeTX) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockReadOnlyMapTreeTX) Commit() error {
	ret := _m.ctrl.Call(_m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) Commit() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Commit")
}

func (_m *MockReadOnlyMapTreeTX) Get(_param0 int64, _param1 [][]byte) ([]trillian.MapLeaf, error) {
	ret := _m.ctrl.Call(_m, "Get", _param0, _param1)
	ret0, _ := ret[0].([]trillian.MapLeaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Get", arg0, arg1)
}

func (_m *MockReadOnlyMapTreeTX) GetMerkleNodes(_param0 int64, _param1 []NodeID) ([]Node, error) {
	ret := _m.ctrl.Call(_m, "GetMerkleNodes", _param0, _param1)
	ret0, _ := ret[0].([]Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) GetMerkleNodes(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetMerkleNodes", arg0, arg1)
}

func (_m *MockReadOnlyMapTreeTX) IsOpen() bool {
	ret := _m.ctrl.Call(_m, "IsOpen")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) IsOpen() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsOpen")
}

func (_m *MockReadOnlyMapTreeTX) LatestSignedMapRoot() (trillian.SignedMapRoot, error) {
	ret := _m.ctrl.Call(_m, "LatestSignedMapRoot")
	ret0, _ := ret[0].(trillian.SignedMapRoot)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) LatestSignedMapRoot() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LatestSignedMapRoot")
}

func (_m *MockReadOnlyMapTreeTX) ReadRevision() int64 {
	ret := _m.ctrl.Call(_m, "ReadRevision")
	ret0, _ := ret[0].(int64)
	return ret0
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) ReadRevision() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ReadRevision")
}

func (_m *MockReadOnlyMapTreeTX) Rollback() error {
	ret := _m.ctrl.Call(_m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockReadOnlyMapTreeTXRecorder) Rollback() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Rollback")
}
