// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/rand"
)

func TestOrder(t *testing.T) {
	heap := &reOrdererHeap{
		pool: &reOrdererNodePool{},
	}
	metric := ReOrdererMetric{}

	for i := 0; i != 200; i++ {
		n := rand.Int()%254 + 1
		heap.enqueue(0, []byte{byte(n)}, uint64(n), 1, &metric)
	}

	var count int
	var last byte
	heap.dequeue(func(cpu uint64, data []byte) {
		count++
		if last > 0 {
			assert.GreaterOrEqual(t, data[0], last)
		}
		last = data[0]
	}, 1, &metric)

	assert.Equal(t, 200, count)
}

func TestOrderRetention(t *testing.T) {
	heap := &reOrdererHeap{
		pool: &reOrdererNodePool{},
	}
	metric := ReOrdererMetric{}

	for i := 0; i != 90; i++ {
		heap.enqueue(0, []byte{byte(i)}, uint64(i), uint64(i/30+1), &metric)
	}

	var count int
	heap.dequeue(func(cpu uint64, data []byte) { count++ }, 1, &metric)
	assert.Equal(t, 30, count)
	heap.dequeue(func(cpu uint64, data []byte) { count++ }, 2, &metric)
	assert.Equal(t, 60, count)
	heap.dequeue(func(cpu uint64, data []byte) { count++ }, 3, &metric)
	assert.Equal(t, 90, count)
}
