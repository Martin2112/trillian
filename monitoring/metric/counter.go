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

package metric

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/golang/glog"
)

// A Counter is a metric that can only increase.
type Counter interface {
	Add(n int64)
}
// A Gauge is a metric that represents a current value that can increase and decrease
type Gauge interface {
	Set(n int64)
}

type counter struct {
	mu              sync.Mutex
	name            string
	value           int64
	lastDumped      time.Time
	lastDumpedValue int64
}

type safeMetrics struct {
	mu sync.Mutex
	cm map[string]*counter
	gm map[string]*counter
}

var (
	metrics = safeMetrics{
		cm: make(map[string]*counter),
		gm: make(map[string]*counter),
	}
)

func (m *counter) Add(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value += n
}

func (m *counter) Set(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value = n
}

// NewCounter defines a cumulative metric. The name should be unique
// within a binary.
func NewCounter(name string) Counter {
	c := counter{name: name, lastDumped: time.Now()}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.isDup(c.name) {
		glog.Fatal("duplicate metric name registered: ", c.name)
	}
	metrics.cm[c.name] = &c
	return &c
}

// NewGauge defines a cumulative metric. The name should be unique
// within a binary.
func NewGauge(name string) Gauge {
	c := counter{name: name, lastDumped: time.Now()}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.isDup(c.name) {
		glog.Fatal("duplicate metric name registered: ", c.name)
	}
	metrics.cm[c.name] = &c
	return &c
}

func dump() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	glog.Info("dumping metrics:")
	keys := make([]string, 0, len(metrics.cm))
	for k := range metrics.cm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		m := metrics.cm[key]
		m.mu.Lock()
		current := m.value
		delta := current - m.lastDumpedValue
		now := time.Now()
		duration := now.Sub(m.lastDumped)
		m.lastDumped = now
		m.lastDumpedValue = current
		m.mu.Unlock()

		qps := float64(delta) / duration.Seconds()
		glog.Infof("%v: %v (%.1f qps)", key, current, qps)
	}
}

// DumpToLog arranges for all metrics to be logged at a regular
// interval. This is not practical for production monitoring, but can
// be useful during development.
func DumpToLog(ctx context.Context, d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			dump()
		case <-ctx.Done():
			return
		}
	}
}

// isDup tests if a named metric already exists. Must hold the mutex before calling
// this.
func (m *safeMetrics) isDup(name string) bool {
	if dup := metrics.cm[name]; dup != nil {
		return true
	}
	if dup := metrics.gm[name]; dup != nil {
		return true
	}

	return false
}