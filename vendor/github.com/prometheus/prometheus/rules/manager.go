// Copyright 2013 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/notifier"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/strutil"
)

// QueryFunc processes PromQL queries.
type QueryFunc func(ctx context.Context, q string, t time.Time) (promql.Vector, error)

// EngineQueryFunc returns a new query function that executes instant queries against
// the given engine.
// It converts scalar into vector results.
func EngineQueryFunc(engine *promql.Engine, q storage.Queryable) QueryFunc {
	return func(ctx context.Context, qs string, t time.Time) (promql.Vector, error) {
		q, err := engine.NewInstantQuery(ctx, q, nil, qs, t)
		if err != nil {
			return nil, err
		}
		res := q.Exec(ctx)
		if res.Err != nil {
			return nil, res.Err
		}
		switch v := res.Value.(type) {
		case promql.Vector:
			return v, nil
		case promql.Scalar:
			return promql.Vector{promql.Sample{
				T:      v.T,
				F:      v.V,
				Metric: labels.Labels{},
			}}, nil
		default:
			return nil, errors.New("rule result is not a vector or scalar")
		}
	}
}

// DefaultEvalIterationFunc is the default implementation of
// GroupEvalIterationFunc that is periodically invoked to evaluate the rules
// in a group at a given point in time and updates Group state and metrics
// accordingly. Custom GroupEvalIterationFunc implementations are recommended
// to invoke this function as well, to ensure correct Group state and metrics
// are maintained.
func DefaultEvalIterationFunc(ctx context.Context, g *Group, evalTimestamp time.Time) {
	g.metrics.IterationsScheduled.WithLabelValues(GroupKey(g.file, g.name)).Inc()

	start := time.Now()
	g.Eval(ctx, evalTimestamp)
	timeSinceStart := time.Since(start)

	g.metrics.IterationDuration.Observe(timeSinceStart.Seconds())
	g.setEvaluationTime(timeSinceStart)
	g.setLastEvaluation(start)
	g.setLastEvalTimestamp(evalTimestamp)
}

// The Manager manages recording and alerting rules.
type Manager struct {
	opts     *ManagerOptions
	groups   map[string]*Group
	mtx      sync.RWMutex
	block    chan struct{}
	done     chan struct{}
	restored bool

	logger log.Logger
}

// NotifyFunc sends notifications about a set of alerts generated by the given expression.
type NotifyFunc func(ctx context.Context, expr string, alerts ...*Alert)

type ContextWrapFunc func(ctx context.Context, g *Group) context.Context

// ManagerOptions bundles options for the Manager.
type ManagerOptions struct {
	ExternalURL *url.URL
	QueryFunc   QueryFunc
	NotifyFunc  NotifyFunc
	Context     context.Context
	// GroupEvaluationContextFunc will be called to wrap Context based on the group being evaluated.
	// Will be skipped if nil.
	GroupEvaluationContextFunc ContextWrapFunc
	Appendable                 storage.Appendable
	Queryable                  storage.Queryable
	Logger                     log.Logger
	Registerer                 prometheus.Registerer
	OutageTolerance            time.Duration
	ForGracePeriod             time.Duration
	ResendDelay                time.Duration
	GroupLoader                GroupLoader
	DefaultEvaluationDelay     func() time.Duration

	// AlwaysRestoreAlertState forces all new or changed groups in calls to Update to restore.
	// Useful when you know you will be adding alerting rules after the manager has already started.
	AlwaysRestoreAlertState bool

	Metrics *Metrics
}

// NewManager returns an implementation of Manager, ready to be started
// by calling the Run method.
func NewManager(o *ManagerOptions) *Manager {
	if o.Metrics == nil {
		o.Metrics = NewGroupMetrics(o.Registerer)
	}

	if o.GroupLoader == nil {
		o.GroupLoader = FileLoader{}
	}

	m := &Manager{
		groups: map[string]*Group{},
		opts:   o,
		block:  make(chan struct{}),
		done:   make(chan struct{}),
		logger: o.Logger,
	}

	return m
}

// Run starts processing of the rule manager. It is blocking.
func (m *Manager) Run() {
	level.Info(m.logger).Log("msg", "Starting rule manager...")
	m.start()
	<-m.done
}

func (m *Manager) start() {
	close(m.block)
}

// Stop the rule manager's rule evaluation cycles.
func (m *Manager) Stop() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	level.Info(m.logger).Log("msg", "Stopping rule manager...")

	for _, eg := range m.groups {
		eg.stop()
	}

	// Shut down the groups waiting multiple evaluation intervals to write
	// staleness markers.
	close(m.done)

	level.Info(m.logger).Log("msg", "Rule manager stopped")
}

// Update the rule manager's state as the config requires. If
// loading the new rules failed the old rule set is restored.
func (m *Manager) Update(interval time.Duration, files []string, externalLabels labels.Labels, externalURL string, groupEvalIterationFunc GroupEvalIterationFunc) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	groups, errs := m.LoadGroups(interval, externalLabels, externalURL, groupEvalIterationFunc, files...)

	if errs != nil {
		for _, e := range errs {
			level.Error(m.logger).Log("msg", "loading groups failed", "err", e)
		}
		return errors.New("error loading rules, previous rule set restored")
	}
	m.restored = true

	var wg sync.WaitGroup
	for _, newg := range groups {
		// If there is an old group with the same identifier,
		// check if new group equals with the old group, if yes then skip it.
		// If not equals, stop it and wait for it to finish the current iteration.
		// Then copy it into the new group.
		gn := GroupKey(newg.file, newg.name)
		oldg, ok := m.groups[gn]
		delete(m.groups, gn)

		if ok && oldg.Equals(newg) {
			groups[gn] = oldg
			continue
		}

		wg.Add(1)
		go func(newg *Group) {
			if ok {
				oldg.stop()
				newg.CopyState(oldg)
			}
			wg.Done()

			ctx := m.opts.Context
			if m.opts.GroupEvaluationContextFunc != nil {
				ctx = m.opts.GroupEvaluationContextFunc(ctx, newg)
			}
			// Wait with starting evaluation until the rule manager
			// is told to run. This is necessary to avoid running
			// queries against a bootstrapping storage.
			<-m.block
			newg.run(ctx)
		}(newg)
	}

	// Stop remaining old groups.
	wg.Add(len(m.groups))
	for n, oldg := range m.groups {
		go func(n string, g *Group) {
			g.markStale = true
			g.stop()
			if m := g.metrics; m != nil {
				m.IterationsMissed.DeleteLabelValues(n)
				m.IterationsScheduled.DeleteLabelValues(n)
				m.EvalTotal.DeleteLabelValues(n)
				m.EvalFailures.DeleteLabelValues(n)
				m.GroupInterval.DeleteLabelValues(n)
				m.GroupLastEvalTime.DeleteLabelValues(n)
				m.GroupLastDuration.DeleteLabelValues(n)
				m.GroupRules.DeleteLabelValues(n)
				m.GroupSamples.DeleteLabelValues((n))
			}
			wg.Done()
		}(n, oldg)
	}

	wg.Wait()
	m.groups = groups

	return nil
}

// GroupLoader is responsible for loading rule groups from arbitrary sources and parsing them.
type GroupLoader interface {
	Load(identifier string) (*rulefmt.RuleGroups, []error)
	Parse(query string) (parser.Expr, error)
}

// FileLoader is the default GroupLoader implementation. It defers to rulefmt.ParseFile
// and parser.ParseExpr
type FileLoader struct{}

func (FileLoader) Load(identifier string) (*rulefmt.RuleGroups, []error) {
	return rulefmt.ParseFile(identifier)
}

func (FileLoader) Parse(query string) (parser.Expr, error) { return parser.ParseExpr(query) }

// LoadGroups reads groups from a list of files.
func (m *Manager) LoadGroups(
	interval time.Duration, externalLabels labels.Labels, externalURL string, groupEvalIterationFunc GroupEvalIterationFunc, filenames ...string,
) (map[string]*Group, []error) {
	groups := make(map[string]*Group)

	shouldRestore := !m.restored || m.opts.AlwaysRestoreAlertState

	for _, fn := range filenames {
		rgs, errs := m.opts.GroupLoader.Load(fn)
		if errs != nil {
			return nil, errs
		}

		for _, rg := range rgs.Groups {
			itv := interval
			if rg.Interval != 0 {
				itv = time.Duration(rg.Interval)
			}

			rules := make([]Rule, 0, len(rg.Rules))
			for _, r := range rg.Rules {
				expr, err := m.opts.GroupLoader.Parse(r.Expr.Value)
				if err != nil {
					return nil, []error{fmt.Errorf("%s: %w", fn, err)}
				}

				if r.Alert.Value != "" {
					rules = append(rules, NewAlertingRule(
						r.Alert.Value,
						expr,
						time.Duration(r.For),
						time.Duration(r.KeepFiringFor),
						labels.FromMap(r.Labels),
						labels.FromMap(r.Annotations),
						externalLabels,
						externalURL,
						!shouldRestore,
						log.With(m.logger, "alert", r.Alert),
					))
					continue
				}
				rules = append(rules, NewRecordingRule(
					r.Record.Value,
					expr,
					labels.FromMap(r.Labels),
				))
			}

			groups[GroupKey(fn, rg.Name)] = NewGroup(GroupOptions{
				Name:                          rg.Name,
				File:                          fn,
				Interval:                      itv,
				Limit:                         rg.Limit,
				Rules:                         rules,
				SourceTenants:                 rg.SourceTenants,
				ShouldRestore:                 shouldRestore,
				Opts:                          m.opts,
				EvaluationDelay:               (*time.Duration)(rg.EvaluationDelay),
				done:                          m.done,
				EvalIterationFunc:             groupEvalIterationFunc,
				AlignEvaluationTimeOnInterval: rg.AlignEvaluationTimeOnInterval,
			})
		}
	}

	return groups, nil
}

// RuleGroups returns the list of manager's rule groups.
func (m *Manager) RuleGroups() []*Group {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	rgs := make([]*Group, 0, len(m.groups))
	for _, g := range m.groups {
		rgs = append(rgs, g)
	}

	slices.SortFunc(rgs, func(a, b *Group) int {
		fileCompare := strings.Compare(a.file, b.file)

		// If its 0, then the file names are the same.
		// Lets look at the group names in that case.
		if fileCompare != 0 {
			return fileCompare
		}
		return strings.Compare(a.name, b.name)
	})

	return rgs
}

// Rules returns the list of the manager's rules.
func (m *Manager) Rules() []Rule {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var rules []Rule
	for _, g := range m.groups {
		rules = append(rules, g.rules...)
	}

	return rules
}

// AlertingRules returns the list of the manager's alerting rules.
func (m *Manager) AlertingRules() []*AlertingRule {
	alerts := []*AlertingRule{}
	for _, rule := range m.Rules() {
		if alertingRule, ok := rule.(*AlertingRule); ok {
			alerts = append(alerts, alertingRule)
		}
	}

	return alerts
}

type Sender interface {
	Send(alerts ...*notifier.Alert)
}

// SendAlerts implements the rules.NotifyFunc for a Notifier.
func SendAlerts(s Sender, externalURL string) NotifyFunc {
	return func(ctx context.Context, expr string, alerts ...*Alert) {
		var res []*notifier.Alert

		for _, alert := range alerts {
			a := &notifier.Alert{
				StartsAt:     alert.FiredAt,
				Labels:       alert.Labels,
				Annotations:  alert.Annotations,
				GeneratorURL: externalURL + strutil.TableLinkForExpression(expr),
			}
			if !alert.ResolvedAt.IsZero() {
				a.EndsAt = alert.ResolvedAt
			} else {
				a.EndsAt = alert.ValidUntil
			}
			res = append(res, a)
		}

		if len(alerts) > 0 {
			s.Send(res...)
		}
	}
}
