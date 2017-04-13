-- Postgres version of the tree schema

-- ---------------------------------------------
-- Tree stuff here
-- ---------------------------------------------

-- Tree parameters should not be changed after creation. Doing so can
-- render the data in the tree unusable or inconsistent.
CREATE TABLE IF NOT EXISTS Trees(
  TreeId                BIGINT NOT NULL,
  TreeState             VARCHAR CHECK (TreeState = 'ACTIVE' OR TreeState = 'FROZEN' OR TreeState = 'SOFT_DELETED' OR TreeState = 'HARD_DELETED') NOT NULL,
  TreeType              VARCHAR CHECK (TreeType = 'LOG' OR TreeType = 'MAP')  NOT NULL,
  HashStrategy          VARCHAR CHECK (HashStrategy = 'RFC_6962') NOT NULL,
  HashAlgorithm         VARCHAR CHECK (HashAlgorithm = 'SHA256') NOT NULL,
  SignatureAlgorithm    VARCHAR CHECK (SignatureAlgorithm = 'ECDSA' OR SignatureAlgorithm = 'RSA') NOT NULL,
  DisplayName           VARCHAR,
  Description           VARCHAR,
  CreateTimeMillis      BIGINT NOT NULL,
  UpdateTimeMillis      BIGINT NOT NULL,
  PrivateKey            BYTEA NOT NULL,
  PRIMARY KEY(TreeId)
);

-- This table contains tree parameters that can be changed at runtime such as for
-- administrative purposes.
CREATE TABLE IF NOT EXISTS TreeControl(
  TreeId                  BIGINT NOT NULL,
  SigningEnabled          BOOLEAN,
  SequencingEnabled       BOOLEAN,
  SequenceIntervalSeconds INTEGER,
  SignIntervalSeconds     INTEGER,
  PRIMARY KEY(TreeId),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId)
);

CREATE TABLE IF NOT EXISTS Subtree(
  TreeId               BIGINT NOT NULL,
  SubtreeId            BYTEA CHECK (SubtreeId IS NOT NULL And length(SubtreeId) <= 255),
  Nodes                BYTEA CHECK (Nodes IS NOT NULL And length(Nodes) <= 32768),
  SubtreeRevision      BIGINT NOT NULL,  -- negated because DESC indexes aren't supported :/
  PRIMARY KEY(TreeId, SubtreeId, SubtreeRevision),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

-- The TreeRevisionIdx is used to enforce that there is only one STH at any
-- tree revision
CREATE TABLE IF NOT EXISTS TreeHead(
  TreeId               BIGINT NOT NULL,
  TreeHeadTimestamp    BIGINT,
  TreeSize             BIGINT,
  RootHash             BYTEA CHECK (RootHash IS NOT NULL And length(RootHash) <= 255),
  RootSignature        BYTEA CHECK (RootSignature IS NOT NULL And length(RootSignature) <= 255),
  TreeRevision         BIGINT,
  PRIMARY KEY(TreeId, TreeHeadTimestamp),
  UNIQUE (TreeId, TreeRevision),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);


-- ---------------------------------------------
-- Log specific stuff here
-- ---------------------------------------------

-- Creating index at same time as table allows some storage engines to better
-- optimize physical storage layout. Most engines allow multiple nulls in a
-- unique index but some may not.

-- A leaf that has not been sequenced has a row in this table. If duplicate leaves
-- are allowed they will all reference this row.
CREATE TABLE IF NOT EXISTS LeafData(
  TreeId               BIGINT NOT NULL,
  -- Note that this is a simple SHA256 hash of the raw data used to detect corruption in transit and
  -- for deduping. It is not the leaf hash output of the treehasher used by the log.
  LeafIdentityHash     BYTEA CHECK (LeafIdentityHash IS NOT NULL And length(LeafIdentityHash) <= 255),
  -- This is the data stored in the leaf for example in CT it contains a DER encoded
  -- X.509 certificate but is application dependent
  LeafValue            BYTEA CHECK (LeafValue IS NOT NULL),
  -- This is extra data that the application can associate with the leaf should it wish to.
  -- This data is not included in signing and hashing.
  ExtraData            BYTEA,
  PRIMARY KEY(TreeId, LeafIdentityHash),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

CREATE INDEX LeafHashIdx ON LeafData(LeafIdentityHash);

-- When a leaf is sequenced a row is added to this table. If logs allow duplicates then
-- multiple rows will exist with different sequence numbers. The signed timestamp
-- will be communicated via the unsequenced table as this might need to be unique, depending
-- on the log parameters and we can't insert into this table until we have the sequence number
-- which is not available at the time we queue the entry. We need both hashes because the
-- LeafData table is keyed by the raw data hash.
CREATE TABLE IF NOT EXISTS SequencedLeafData(
  TreeId               BIGINT NOT NULL,
  SequenceNumber       BIGINT NOT NULL CHECK(SequenceNumber >= 0),
  -- Note that this is a simple SHA256 hash of the raw data used to detect corruption in transit.
  -- It is not the leaf hash output of the treehasher used by the log.
  LeafIdentityHash     BYTEA CHECK (LeafIdentityHash IS NOT NULL And length(LeafIdentityHash) <= 255),
  -- This is a MerkleLeafHash as defined by the treehasher that the log uses. For example for
  -- CT this hash will include the leaf prefix byte as well as the leaf data.
  MerkleLeafHash       BYTEA CHECK (MerkleLeafHash IS NOT NULL And length(MerkleLeafHash) <= 255),
  PRIMARY KEY(TreeId, SequenceNumber),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE,
  FOREIGN KEY(TreeId, LeafIdentityHash) REFERENCES LeafData(TreeId, LeafIdentityHash)
);

CREATE TABLE IF NOT EXISTS Unsequenced(
  TreeId               BIGINT NOT NULL,
  -- Note that this is a simple SHA256 hash of the raw data used to detect corruption in transit.
  -- It is not the leaf hash output of the treehasher used by the log.
  LeafIdentityHash     BYTEA CHECK (LeafIdentityHash IS NOT NULL And length(LeafIdentityHash) <= 255),
  -- This is a MerkleLeafHash as defined by the treehasher that the log uses. For example for
  -- CT this hash will include the leaf prefix byte as well as the leaf data.
  MerkleLeafHash       BYTEA CHECK (MerkleLeafHash IS NOT NULL And length(MerkleLeafHash) <= 255),
  -- SHA256("queueId"|TreeId|leafValueHash)
  -- We want this to be unique per entry per log, but queryable by FEs so that
  -- we can try to stomp dupe submissions.
  MessageId            BYTEA CHECK (MessageId IS NOT NULL And length(MessageId) <= 32),
  QueueTimestampNanos  BIGINT NOT NULL,
  PRIMARY KEY (TreeId, MessageId, QueueTimestampNanos, LeafIdentityHash)
);

-- ---------------------------------------------
-- Map specific stuff here
-- ---------------------------------------------

CREATE TABLE IF NOT EXISTS MapLeaf(
  TreeId                BIGINT NOT NULL,
  KeyHash               BYTEA CHECK (KeyHash IS NOT NULL And length(KeyHash) <= 255),
  -- MapRevision is stored negated to invert ordering in the primary key index
  -- st. more recent revisions come first.
  MapRevision           BIGINT NOT NULL,
  LeafValue             BYTEA CHECK (LeafValue IS NOT NULL),
  PRIMARY KEY(TreeId, KeyHash, MapRevision),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS MapHead(
  TreeId               BIGINT NOT NULL,
  MapHeadTimestamp     BIGINT,
  RootHash             BYTEA CHECK (RootHash IS NOT NULL And length(RootHash) <= 255),
  MapRevision          BIGINT,
  RootSignature        BYTEA CHECK (RootSignature IS NOT NULL And length(RootSignature) <= 255),
  MapperData           BYTEA,
  PRIMARY KEY(TreeId, MapHeadTimestamp),
  UNIQUE (TreeId, MapRevision),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);
