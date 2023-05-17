// SPDX-License-Identifier: AGPL-3.0-only
// Provenance-includes-location: https://github.com/prometheus/prometheus/blob/main/tsdb/index/index_test.go
// Provenance-includes-license: Apache-2.0
// Provenance-includes-copyright: The Prometheus Authors.

package index

import (
	"hash/crc32"
	"os"
	"path"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/tsdb/encoding"
	"github.com/prometheus/prometheus/tsdb/index"
	"github.com/stretchr/testify/require"

	streamencoding "github.com/grafana/mimir/pkg/storegateway/indexheader/encoding"
	"github.com/grafana/mimir/pkg/util/test"
)

func TestMain(m *testing.M) {
	test.VerifyNoLeakTestMain(m)
}

func TestSymbols(t *testing.T) {
	buf := encoding.Encbuf{}

	// Add prefix to the buffer to simulate symbols as part of larger buffer.
	buf.PutUvarintStr("something")

	symbolsStart := buf.Len()
	buf.PutBE32int(204) // Length of symbols table.
	buf.PutBE32int(100) // Number of symbols.
	for i := 0; i < 100; i++ {
		// i represents index in unicode characters table.
		buf.PutUvarintStr(string(rune(i))) // Symbol.
	}
	checksum := crc32.Checksum(buf.Get()[symbolsStart+4:], castagnoliTable)
	buf.PutBE32(checksum) // Check sum at the end.

	dir := t.TempDir()
	filePath := path.Join(dir, "index")
	require.NoError(t, os.WriteFile(filePath, buf.Get(), 0700))

	reg := prometheus.NewPedanticRegistry()
	df := streamencoding.NewDecbufFactory(filePath, 0, log.NewNopLogger(), streamencoding.NewDecbufFactoryMetrics(reg))
	s, err := NewSymbols(df, index.FormatV2, symbolsStart)
	require.NoError(t, err)

	// We store only 4 offsets to symbols.
	require.Len(t, s.offsets, 4)

	t.Run("Lookup", func(t *testing.T) {
		for i := 99; i >= 0; i-- {
			s, err := s.Lookup(uint32(i))
			require.NoError(t, err)
			require.Equal(t, string(rune(i)), s)
		}
		_, err = s.Lookup(100)
		require.Error(t, err)
	})

	t.Run("ReverseLookup", func(t *testing.T) {
		for i := 99; i >= 0; i-- {
			r, err := s.ReverseLookup(string(rune(i)))
			require.NoError(t, err)
			require.Equal(t, uint32(i), r)
		}
		_, err = s.ReverseLookup(string(rune(100)))
		require.Error(t, err)
	})

	t.Run("ForEachSymbol", func(t *testing.T) {
		// Use ForEachSymbol to build an offset -> symbol mapping and ensure
		// that it matches the expected offsets and symbols.
		var symbols []string
		expected := make(map[uint32]string)
		for i := 99; i >= 0; i-- {
			symbols = append(symbols, string(rune(i)))
			expected[uint32(i)] = string(rune(i))
		}

		actual := make(map[uint32]string)
		err = s.ForEachSymbol(symbols, func(sym string, offset uint32) error {
			actual[offset] = sym
			return nil
		})

		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})

	t.Run("Reader iterate all", func(t *testing.T) {
		r := s.Reader()

		for i := uint32(0); i >= 99; i-- {
			sym, err := r.Read(i)
			require.NoError(t, err)
			require.Equal(t, string(rune(i)), sym)
		}

		require.NoError(t, r.Close())
	})

	t.Run("Reader two distant", func(t *testing.T) {
		r := s.Reader()

		s7, err := r.Read(7)
		require.NoError(t, err)
		require.Equal(t, string(rune(7)), s7)

		s97, err := r.Read(97)
		require.NoError(t, err)
		require.Equal(t, string(rune(97)), s97)

		require.NoError(t, r.Close())
	})

	t.Run("Reader trying to reverse", func(t *testing.T) {
		r := s.Reader()

		_, err = r.Read(20)
		require.NoError(t, err)

		_, err = r.Read(10)
		require.NotNil(t, err)

		require.NoError(t, r.Close())
	})
}
