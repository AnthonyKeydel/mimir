// SPDX-License-Identifier: AGPL-3.0-only

package iterators

import (
	"container/heap"
	stderrors "errors"

	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/annotations"
)

// MergedLabelValues is a label values iterator merging a collection of sub-iterators.
type MergedLabelValues struct {
	h           LabelValuesHeap
	cur         string
	initialized bool
	err         error
	warnings    annotations.Annotations
}

func (m *MergedLabelValues) Next() bool {
	if m.h.Len() == 0 || m.err != nil {
		return false
	}

	if !m.initialized {
		heap.Init(&m.h)
		m.cur = m.h[0].At()
		m.initialized = true
		return true
	}

	for {
		cur := m.h[0]
		if !cur.Next() {
			heap.Pop(&m.h)
			if len(cur.Warnings()) > 0 {
				m.warnings.Merge(cur.Warnings())
			}
			if cur.Err() != nil {
				m.err = cur.Err()
				return false
			}
			if m.h.Len() == 0 {
				return false
			}
		} else {
			// Heap top has changed, fix up
			heap.Fix(&m.h, 0)
		}

		if m.h[0].At() != m.cur {
			m.cur = m.h[0].At()
			return true
		}
	}
}

func (m *MergedLabelValues) At() string {
	return m.cur
}

func (m *MergedLabelValues) Err() error {
	return m.err
}

func (m *MergedLabelValues) Warnings() annotations.Annotations {
	return m.warnings
}

func (m *MergedLabelValues) Close() error {
	var errs []error
	for _, it := range m.h {
		if err := it.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return stderrors.Join(errs...)
}

func NewMergedLabelValues(its []storage.LabelValues) storage.LabelValues {
	h := make(LabelValuesHeap, 0, len(its))
	for _, it := range its {
		// Have to initialize the iterators before constructing the heap
		if !it.Next() {
			if it.Err() != nil {
				return storage.ErrLabelValues(it.Err())
			}
			continue
		}
		h = append(h, it)
	}

	return &MergedLabelValues{
		h: h,
	}
}

// LabelValuesHeap is a heap of LabelValues iterators, sorted on label value.
type LabelValuesHeap []storage.LabelValues

func (h LabelValuesHeap) Len() int           { return len(h) }
func (h LabelValuesHeap) Less(i, j int) bool { return h[i].At() < h[j].At() }
func (h LabelValuesHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *LabelValuesHeap) Push(x interface{}) {
	*h = append(*h, x.(storage.LabelValues))
}

func (h *LabelValuesHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
