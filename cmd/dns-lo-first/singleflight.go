package main

import (
	"context"
	"sync"
)

type singleflight struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	done chan struct{}
	val  any
	err  error
}

func newSingleflight() *singleflight {
	return &singleflight{m: make(map[string]*call)}
}

func (g *singleflight) Do(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, error) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.done:
			return c.val, c.err
		}
	}
	c := &call{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn(ctx)
	close(c.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.val, c.err
}
