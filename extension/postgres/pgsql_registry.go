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

package postgres

import (
	"database/sql"
	"flag"

	_ "github.com/lib/pq"

	"github.com/google/trillian/extension"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/pgsql"
	"github.com/google/trillian/crypto"
)

var (
	// postgresURIFlag is the postgres db connection string.
	postgresURIFlag = flag.String("postgres_uri", "postgres://test:zaphod@localhost/test",
		"default uri to use with postgres storage")
	// an HSM interface in this way. Deferring these issues for later.
	privateKeyFile     = flag.String("private_key_file", "", "File containing a PEM encoded private key")
	privateKeyPassword = flag.String("private_key_password", "", "Password for server private key")
)
// pgsql implementation of extension.Registry.
type pgsqlRegistry struct {
	db *sql.DB
	km crypto.PrivateKeyManager
}

func (r *pgsqlRegistry) GetLogStorage() (storage.LogStorage, error) {
	return pgsql.NewLogStorage(r.db)
}

func (r *pgsqlRegistry) GetMapStorage() (storage.MapStorage, error) {
	return pgsql.NewMapStorage(r.db)
}

func (r *pgsqlRegistry) GetKeyManager(treeID int64) (crypto.PrivateKeyManager, error) {
	return r.km, nil
}

// NewPostgresExtensionRegistry returns the postgres extension.Registry implementation, which is
// backed by a postgres database and configured via flags.
// The returned registry is wraped in a cached registry.
func NewPostgresExtensionRegistry() (extension.Registry, error) {
	db, err := pgsql.OpenDB(*postgresURIFlag)
	if err != nil {
		return nil, err
	}
	km, err := crypto.NewFromPrivatePEMFile(*privateKeyFile, *privateKeyPassword)
	if err != nil {
		return nil, err
	}
	return &pgsqlRegistry{
		db: db,
		km: km,
	}, nil
}
