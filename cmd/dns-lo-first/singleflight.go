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
		// If ctx and c.done become ready in the same scheduling tick, a single select
		// picks randomly; prefer the shared result so waiters do not return deadline
		// errors after the leader already succeeded.
		select {
		case <-c.done:
			return c.val, c.err
		case <-ctx.Done():
			select {
			case <-c.done:
				return c.val, c.err
			default:
				return nil, ctx.Err()
			}
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
