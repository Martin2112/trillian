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
)

// pgSQLURIFlag is the postgres db connection string.
var postgresURIFlag = flag.String("pgsql_uri", "postgres://test:zaphod@localhost/test",
	"uri to use with postgres storage")

// pgsql implementation of extension.Registry.
type pgsqlRegistry struct {
	db *sql.DB
}

func (r *pgsqlRegistry) GetLogStorage() (storage.LogStorage, error) {
	return pgsql.NewLogStorage(r.db)
}

func (r *pgsqlRegistry) GetMapStorage() (storage.MapStorage, error) {
	return pgsql.NewMapStorage(r.db)
}

// NewDefaultExtensionRegistry returns the default extension.Registry implementation, which is
// backed by a MySQL database and configured via flags.
// The returned registry is wraped in a cached registry.
func NewPostgresExtensionRegistry() (extension.Registry, error) {
	db, err := pgsql.OpenDB(*postgresURIFlag)
	if err != nil {
		return nil, err
	}
	return &pgsqlRegistry{
		db: db,
	}, nil
}
