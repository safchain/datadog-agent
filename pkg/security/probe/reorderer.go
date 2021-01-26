// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"context"
	"time"

	"github.com/DataDog/ebpf/manager"
)

type reOrdererNodePool struct {
	head *reOrdererNode
}

func (p *reOrdererNodePool) alloc() *reOrdererNode {
	node := p.head
	if node != nil && node.timestamp == 0 {
		p.head = node.nextFree
		node.data = nil
		return node
	}

	return &reOrdererNode{}
}

func (p *reOrdererNodePool) free(node *reOrdererNode) {
	node.timestamp = 0

	if p.head == nil {
		p.head = node
	} else {
		node.nextFree = p.head
		p.head = node
	}
}

type reOrdererNode struct {
	cpu        uint64
	timestamp  uint64
	data       []byte
	nextFree   *reOrdererNode
	generation uint64
}

type reOrdererHeap struct {
	heap []*reOrdererNode
	pool *reOrdererNodePool
}

func (h *reOrdererHeap) len() uint64 {
	return uint64(len(h.heap))
}

func (h *reOrdererHeap) swap(i, j int) {
	h.heap[i], h.heap[j] = h.heap[j], h.heap[i]
}

func (h *reOrdererHeap) less(i, j int) bool {
	return h.heap[i].timestamp < h.heap[j].timestamp
}

func (h *reOrdererHeap) up(node *reOrdererNode, i int, metric *ReOrdererMetric) {
	for {
		parent := (i - 1) / 2
		if parent == i || !h.less(i, parent) {
			return
		}
		h.swap(parent, i)
		i = parent

		metric.TotalDepth++
	}
}

func (h *reOrdererHeap) down(i int, n int, metric *ReOrdererMetric) {
	for {
		left := 2*i + 1
		if left >= n || left < 0 {
			return
		}
		v := left
		if right := left + 1; right < n && h.less(right, left) {
			v = right
		}
		if !h.less(v, i) {
			return
		}
		h.swap(i, v)
		i = v

		metric.TotalDepth++
	}
}

func (h *reOrdererHeap) enqueue(cpu uint64, data []byte, tm uint64, generation uint64, metric *ReOrdererMetric) {
	node := h.pool.alloc()
	node.timestamp = tm
	node.data = data
	node.cpu = cpu
	node.generation = generation

	metric.TotalOp++

	h.heap = append(h.heap, node)
	h.up(node, len(h.heap)-1, metric)
}

func (h *reOrdererHeap) dequeue(handler func(cpu uint64, data []byte), generation uint64, metric *ReOrdererMetric) {
	for {
		n := len(h.heap)
		if n == 0 {
			return
		}

		node := h.heap[0]
		if node.generation > generation {
			return
		}

		i := n - 1
		h.swap(0, i)
		h.down(0, i, metric)

		h.heap[i] = nil
		h.heap = h.heap[0:i]

		metric.TotalOp++
		handler(node.cpu, node.data)
	}
}

// ReOrdererOpts options to pass when creating a new instance of ReOrderer
type ReOrdererOpts struct {
	QueueSize  uint64        // size of the chan where the perf data are pushed
	Rate       time.Duration // delay between two time based iterations
	Retention  uint64        // bucket to keep before dequeueing
	MetricRate time.Duration // delay between two metric samples
}

func (r *ReOrdererMetric) zero() {
	// keep size of avoid overflow between queue/dequeue
	r.TotalDepth = 0
	r.TotalOp = 0
}

// ReOrdererMetric holds reordering metrics
type ReOrdererMetric struct {
	TotalOp    uint64
	TotalDepth uint64
	QueueSize  uint64
}

// ReOrderer defines an event re-orderer
type ReOrderer struct {
	queue       chan []byte
	handler     func(cpu uint64, data []byte)
	heap        *reOrdererHeap
	extractInfo func(data []byte) (uint64, uint64, error) // cpu, timestamp
	opts        ReOrdererOpts
	metric      ReOrdererMetric
	Metrics     chan ReOrdererMetric
	generation  uint64
}

// Start event handler loop
func (r *ReOrderer) Start(ctx context.Context) {
	flushTicker := time.NewTicker(r.opts.Rate)
	defer flushTicker.Stop()

	metricTicker := time.NewTicker(r.opts.MetricRate)
	defer metricTicker.Stop()

	var lastTm, tm, cpu uint64
	var err error

	for {
		select {
		case data := <-r.queue:
			if len(data) > 0 {
				if cpu, tm, err = r.extractInfo(data); err != nil {
					continue
				}
			} else {
				tm = lastTm
			}

			if tm == 0 {
				continue
			}
			lastTm = tm

			r.heap.enqueue(cpu, data, tm, r.generation, &r.metric)
			r.heap.dequeue(r.handler, r.generation-r.opts.Retention, &r.metric)

		case <-flushTicker.C:
			r.generation++
		case <-metricTicker.C:
			r.metric.QueueSize = r.heap.len()

			select {
			case r.Metrics <- r.metric:
			}

			r.metric.zero()
		case <-ctx.Done():
			return
		}
	}
}

// HandleEvent handle event form perf ring
func (r *ReOrderer) HandleEvent(CPU int, data []byte, perfMap *manager.PerfMap, manager *manager.Manager) {
	r.queue <- data
}

// NewReOrderer returns a new ReOrderer
func NewReOrderer(handler func(cpu uint64, data []byte), extractInfo func(data []byte) (uint64, uint64, error), opts ReOrdererOpts) *ReOrderer {
	return &ReOrderer{
		queue:   make(chan []byte, opts.QueueSize),
		handler: handler,
		heap: &reOrdererHeap{
			pool: &reOrdererNodePool{},
		},
		extractInfo: extractInfo,
		opts:        opts,
		Metrics:     make(chan ReOrdererMetric, 100000),
		generation:  1,
	}
}
