package storegateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/grafana/regexp"
	"github.com/guptarohit/asciigraph"
	"github.com/oklog/ulid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/stretchr/testify/assert"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
	"go.uber.org/atomic"

	"github.com/grafana/mimir/pkg/storage/tsdb"
	"github.com/grafana/mimir/pkg/storage/tsdb/block"
	"github.com/grafana/mimir/pkg/storegateway/indexcache"
	"github.com/grafana/mimir/pkg/storegateway/indexheader"
	"github.com/grafana/mimir/pkg/util/pool"
	"github.com/grafana/mimir/tools/query-step-alignment-analysis/query_stat"
)

const (
	bucketLocation             = "/users/dimitar/proba/postings-shortcut/thanos-bucket"
	indexHeaderLocation        = "/users/dimitar/proba/postings-shortcut/local"
	queriesDump                = "/users/dimitar/proba/postings-shortcut/ops-21-mar-2023-query-dump.json"
	resultsLocation            = "/users/dimitar/proba/postings-shortcut/results.txt"
	tenantID                   = "10428"
	queryProcessingConcurrency = 10
)

var (
	blockULID = ulid.MustParse("01GW1P25XTPFDB3FYJWWC4JVV3")

	queryPathPrefix  = `/prometheus/api/v1/query`
	labelValuesRegex = regexp.MustCompile(`/prometheus/api/v1/label/(?P<lname>\w+)/values`)
	labelNamesPath   = `/prometheus/api/v1/labels`
	seriesPath       = `/prometheus/api/v1/series`
	remoteReadPath   = `/prometheus/api/v1/read`
	metadataPath     = `/prometheus/api/v1/metadata`
)

type stats struct {
	fetchedRegularPostings, fetchedShortcutPostings *atomic.Uint64
	fetchedRegularSeries, fetchedShortcutSeries     *atomic.Uint64
}

func newStats() stats {
	return stats{atomic.NewUint64(0), atomic.NewUint64(0), atomic.NewUint64(0), atomic.NewUint64(0)}
}

func (s stats) String() string {
	return fmt.Sprintf("\t%d\t%d\t%d\t%d", s.fetchedRegularPostings.Load(), s.fetchedRegularSeries.Load(), s.fetchedShortcutPostings.Load(), s.fetchedShortcutSeries.Load())
}

func RunPostingsSimulator() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listenForSignals(ctx, cancel)

	go func() {
		// expose pprof
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	logger := log.NewLogfmtLogger(os.Stdout)
	reg := prometheus.NewRegistry()

	block := setupBlock(ctx, logger, reg)
	defer block.Close()

	indexReader := block.indexReader()
	defer indexReader.Close()

	queriesFile, err := os.OpenFile(queriesDump, os.O_RDONLY, 0)
	noErr(err)
	defer queriesFile.Close()

	resultsFile, err := os.OpenFile(resultsLocation, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0660)
	noErr(err)
	defer resultsFile.Close()

	wg := &sync.WaitGroup{}
	defer wg.Wait()
	queriesChan := make(chan query_stat.QueryStat)
	defer close(queriesChan)
	resultSink := &resultConsumer{out: io.MultiWriter(resultsFile, os.Stdout)}
	defer resultSink.print()

	wg.Add(1)
	go processQueries(wg, queriesChan, indexReader, resultSink)

	queryDecoder := json.NewDecoder(queriesFile)

	q := &query_stat.QueryStat{}
	for {
		*q = query_stat.QueryStat{}
		if ctx.Err() != nil {
			break
		}
		err = queryDecoder.Decode(q)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			//fmt.Println("invalid query at offset ", queryDecoder.InputOffset())
			continue
		}

		queriesChan <- *q
	}
}

func processQueries(done *sync.WaitGroup, queries <-chan query_stat.QueryStat, indexr *bucketIndexReader, resultsDest *resultConsumer) {
	var (
		i                int
		currentMinute    int64
		statistics       = newStats()
		wg               = &sync.WaitGroup{}
		fannedOutQueries = make(chan query_stat.QueryStat)
		ctx, cancel      = context.WithCancel(context.Background())
	)
	defer done.Done()
	defer cancel()

	for q := range queries {
		if q.Timestamp.UnixNano()/int64(time.Minute) != currentMinute {
			close(fannedOutQueries)
			wg.Wait()
			resultsDest.record(q, statistics)

			wg.Add(queryProcessingConcurrency)
			statistics = newStats()
			fannedOutQueries = make(chan query_stat.QueryStat)
			for i := 0; i < queryProcessingConcurrency; i++ {
				go processQueriesSingle(ctx, wg, fannedOutQueries, indexr, statistics)
			}
			currentMinute = q.Timestamp.UnixNano() / int64(time.Minute)
		}

		fannedOutQueries <- q
		i++
	}
}

func processQueriesSingle(ctx context.Context, wg *sync.WaitGroup, fannedOutQueries <-chan query_stat.QueryStat, indexr *bucketIndexReader, statistics stats) {
	defer wg.Done()
	for q := range fannedOutQueries {
		timeWouldSkipStoreGateways := func(t time.Time) bool {
			return !t.IsZero() && t.After(q.Timestamp.Add(-12*time.Hour))
		}

		if timeWouldSkipStoreGateways(q.InstantQueryTime) {
			continue // this was an instant query which would have only touched ingesters, skip
		}

		if timeWouldSkipStoreGateways(q.Start) && timeWouldSkipStoreGateways(q.End) {
			continue // this was a range query that doesn't
		}

		vectorSelectors := extractVectorSelectors(q)
		for _, selector := range vectorSelectors {
			postingsStats, postingsWithShortcutStats := postings(ctx, selector.LabelMatchers, indexr)
			//printMatchers(selector.LabelMatchers)
			statistics.fetchedRegularPostings.Add(uint64(postingsStats.postingsTouchedSizeSum))
			statistics.fetchedShortcutPostings.Add(uint64(postingsWithShortcutStats.postingsTouchedSizeSum))
			statistics.fetchedRegularSeries.Add(uint64(postingsStats.seriesTouchedSizeSum))
			statistics.fetchedShortcutSeries.Add(uint64(postingsWithShortcutStats.seriesTouchedSizeSum))
		}
	}
}

func printMatchers(matchers []*labels.Matcher) {
	asStr := make([]string, len(matchers))
	for i, m := range matchers {
		asStr[i] = m.String()
	}
	sort.Strings(asStr)
	fmt.Println(strings.Join(asStr, " "))
}

type resultConsumer struct {
	out      io.Writer
	allStats []stats
}

func (c *resultConsumer) record(q query_stat.QueryStat, s stats) {
	if len(c.allStats) == 0 {
		fmt.Fprintf(c.out, "T\tfetched postings regular\tfetched series regular\tfetched postings shortcut\tfetched series shortcut\n")
	}
	fmt.Fprintln(c.out, q.Timestamp.UTC().Format(time.DateTime), s)
	c.allStats = append(c.allStats, s)
}

func (c *resultConsumer) print() {
	var curves [4][]float64 // two fields in each stat
	for _, s := range c.allStats {
		curves[0] = append(curves[0], float64(s.fetchedRegularPostings.Load()))
		curves[1] = append(curves[1], float64(s.fetchedShortcutPostings.Load()))
	}
	_, err := io.WriteString(c.out, asciigraph.PlotMany(curves[:], asciigraph.SeriesColors(asciigraph.Blue, asciigraph.DarkOrange), asciigraph.Width(465), asciigraph.Height(60), asciigraph.Caption("fetched postings")))
	noErr(err)

	curves = [4][]float64{} // two fields in each stat
	for _, s := range c.allStats {
		curves[0] = append(curves[0], float64(s.fetchedRegularSeries.Load()))
		curves[1] = append(curves[1], float64(s.fetchedShortcutSeries.Load()))
	}

	_, err = io.WriteString(c.out, asciigraph.PlotMany(curves[:], asciigraph.SeriesColors(asciigraph.Blue, asciigraph.DarkOrange), asciigraph.Width(465), asciigraph.Height(60), asciigraph.Caption("fetched series")))
	noErr(err)
}

func listenForSignals(ctx context.Context, cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	select {
	case <-ctx.Done():
		return
	case <-c:
		cancel()
	}
}

func postings(ctx context.Context, matchers []*labels.Matcher, indexr *bucketIndexReader) (stats, statsWithShortcut *queryStats) {
	doPostings := func(resolvePostings func(context.Context, []*labels.Matcher, *safeQueryStats) ([]storage.SeriesRef, []*labels.Matcher, error)) (*queryStats, []seriesChunkRefs) {
		s := newSafeQueryStats()
		p, remainingMatchers, err := resolvePostings(ctx, matchers, s)
		noErr(err)

		// Assume that all series that were fetched will be touched
		loadedRegularSeries, err := indexr.preloadSeries(ctx, p, s)
		noErr(err)

		var (
			symbolyzedLbls []symbolizedLabel
			chks           []chunks.Meta
			series         = make([]seriesChunkRefs, 0, len(loadedRegularSeries.series))
		)

	nextSeries:
		for _, seriesID := range p {
			_, err = loadedRegularSeries.unsafeLoadSeries(seriesID, &symbolyzedLbls, &chks, true, s.unsafeStats)
			noErr(err)
			lbls, err := indexr.LookupLabelsSymbols(symbolyzedLbls)
			noErr(err)

			for _, m := range remainingMatchers {
				if !m.Matches(lbls.Get(m.Name)) {
					continue nextSeries
				}
			}

			series = append(series, seriesChunkRefs{lset: lbls})
		}

		return s.export(), series
	}

	regularStats, selectedRegularSeries := doPostings(func(ctx context.Context, matchers []*labels.Matcher, s *safeQueryStats) ([]storage.SeriesRef, []*labels.Matcher, error) {
		series, err := indexr.expandedPostings(ctx, matchers, s)
		return series, nil, err
	})
	shortcutStats, selectedShortcutSeries := doPostings(indexr.expandedPostingsShortcut)

	assert.Equal(panicer{}, selectedRegularSeries, selectedShortcutSeries)

	return regularStats, shortcutStats
}

type panicer struct{}

func (panicer) Errorf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

func extractVectorSelectors(q query_stat.QueryStat) []*parser.VectorSelector {
	switch labelValsSubMatch := labelValuesRegex.FindStringSubmatch(q.RequestPath); {
	case q.RequestPath == metadataPath:
		return nil
	case q.RequestPath == remoteReadPath:
		return nil // this isn't exposed in the query logs, hopefully they aren't too many requests
	case len(labelValsSubMatch) > 0:
		return nil // TODO dimitarvdimitrov implement this too to predict what we can do if we also optimize label values calls
	case strings.HasPrefix(q.RequestPath, queryPathPrefix):
		return extractVectorSelectorsStr(q.Query)
	case q.RequestPath == labelNamesPath || q.RequestPath == seriesPath:
		if q.Match == "" {
			return nil
		}
		return extractVectorSelectorsStr(q.Match)
	default:
		panic("cannot classify path " + q.RequestPath + fmt.Sprintf(" %#v", q))
	}
}

func extractVectorSelectorsStr(q string) []*parser.VectorSelector {
	expr, err := parser.ParseExpr(q)
	if err != nil {
		return nil // some queries will be invalid, so we skip them
	}
	var selectors []*parser.VectorSelector
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if n, ok := node.(*parser.VectorSelector); ok {
			selectors = append(selectors, n)
		}
		return nil
	})

	return selectors
}

func setupBlock(ctx context.Context, logger log.Logger, reg *prometheus.Registry) *bucketBlock {
	completeBucket, err := filesystem.NewBucket(bucketLocation)
	noErr(err)

	userBucket := objstore.NewPrefixedBucket(completeBucket, tenantID)
	indexHeaderReader, err := indexheader.NewStreamBinaryReader(
		ctx,
		logger,
		userBucket,
		indexHeaderLocation,
		blockULID,
		tsdb.DefaultPostingOffsetInMemorySampling,
		indexheader.NewStreamBinaryReaderMetrics(reg),
		indexheader.Config{MaxIdleFileHandles: 1},
	)
	noErr(err)
	metaFetcher, err := block.NewMetaFetcher(logger, 1, objstore.WithNoopInstr(userBucket), indexHeaderLocation, reg, nil)
	noErr(err)
	blockMetas, errs, err := metaFetcher.Fetch(ctx)
	noErr(err)
	for _, err = range errs {
		noErr(err)
	}

	indexCache, err := indexcache.NewInMemoryIndexCacheWithConfig(logger, reg, indexcache.InMemoryIndexCacheConfig{
		MaxSize:     1024 * 1024 * 1024,
		MaxItemSize: 125 * 1024 * 1024,
	})
	noErr(err)
	block, err := newBucketBlock(
		ctx,
		tenantID,
		logger,
		NewBucketStoreMetrics(reg),
		blockMetas[blockULID],
		userBucket,
		indexHeaderLocation+"/"+blockULID.String(),
		indexCache,
		pool.NoopBytes{},
		indexHeaderReader,
		newGapBasedPartitioners(tsdb.DefaultPartitionerMaxGapSize, reg),
	)
	noErr(err)
	return block
}

func noErr(err error) {
	if err != nil {
		panic(err)
	}
}