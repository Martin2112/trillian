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

package main

import (
	"context"
	"flag"
	"fmt"

	_ "net/http/pprof"

	_ "github.com/go-sql-driver/mysql" // Load MySQL driver

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/server"
	"github.com/google/trillian/server/interceptor"
	"github.com/google/trillian/storage/sql/coresql"
	"github.com/google/trillian/storage/sql/coresql/db"
	"github.com/google/trillian/util"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

var (
	dbDriver            = flag.String("db_driver", "mysql", "Name of database driver to use (must be known to us)")
	dbURI               = flag.String("db_uri", "test:zaphod@tcp(127.0.0.1:3306)/test", "Connection URI for database")
	serverPortFlag      = flag.Int("port", 8090, "Port to serve log RPC requests on")
	httpPortFlag        = flag.Int("http_port", 8091, "Port to serve HTTP metrics and REST requests on (negative means disabled)")
	dumpMetricsInterval = flag.Duration("dump_metrics_interval", 0, "If greater than 0, how often to dump metrics to the logs.")
)

func main() {
	flag.Parse()

	// First make sure we can access the database, quit if not
	wrap, err := db.OpenDB(*dbDriver, *dbURI)
	if err != nil {
		glog.Exitf("Failed to open database: %v", err)
	}
	// No defer: database ownership is delegated to server.Main

	registry := extension.Registry{
		AdminStorage:  coresql.NewAdminStorage(wrap),
		SignerFactory: keys.PEMSignerFactory{},
		LogStorage:    coresql.NewLogStorage(wrap),
	}

	ts := util.SystemTimeSource{}
	stats := monitoring.NewRPCStatsInterceptor(ts, "ct", "example")
	stats.Publish()
	ti := interceptor.TreeInterceptor{Admin: registry.AdminStorage}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.WrapErrors(interceptor.Combine(stats.Interceptor(), ti.UnaryInterceptor))))
	// No defer: server ownership is delegated to server.Main

	httpEndpoint := ""
	if *httpPortFlag >= 0 {
		httpEndpoint = fmt.Sprintf("localhost:%v", *httpPortFlag)
	}

	m := server.Main{
		RPCEndpoint:  fmt.Sprintf("localhost:%v", *serverPortFlag),
		HTTPEndpoint: httpEndpoint,
		DB:           wrap.DB(),
		Registry:     registry,
		Server:       s,
		RegisterHandlerFn: func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
			return nil
		},
		RegisterServerFn: func(s *grpc.Server, registry extension.Registry) error {
			logServer := server.NewTrillianLogRPCServer(registry, ts)
			if err := logServer.IsHealthy(); err != nil {
				return err
			}
			trillian.RegisterTrillianLogServer(s, logServer)
			return err
		},
		DumpMetricsInterval: *dumpMetricsInterval,
	}

	ctx := context.Background()
	if err := m.Run(ctx); err != nil {
		glog.Exitf("Server exited with error: %v", err)
	}
}
