package upstream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestUsableServersUsesAvailableBeforeFrozen(t *testing.T) {
	c := New(time.Second)
	c.cooldowns["a"] = time.Now().Add(time.Minute)

	got := c.usableServers([]string{"a", "b"})
	if len(got) != 1 || got[0] != "b" {
		t.Fatalf("got %#v, want only b", got)
	}
}

func TestUsableServersThawsEarliestWhenAllFrozen(t *testing.T) {
	c := New(time.Second)
	now := time.Now()
	c.cooldowns["a"] = now.Add(2 * time.Minute)
	c.cooldowns["b"] = now.Add(time.Minute)

	got := c.usableServers([]string{"a", "b"})
	if len(got) != 1 || got[0] != "b" {
		t.Fatalf("got %#v, want earliest frozen b", got)
	}
	if _, ok := c.cooldowns["b"]; ok {
		t.Fatal("expected b to be thawed")
	}
}

func TestIsTimeout(t *testing.T) {
	if !isTimeout(context.DeadlineExceeded) {
		t.Fatal("context deadline should be timeout")
	}
	if isTimeout(errors.New("plain error")) {
		t.Fatal("plain error should not be timeout")
	}
	if !isTimeout(timeoutErr{}) {
		t.Fatal("net timeout should be timeout")
	}
}

func TestSortByScoreOrdersLowerLatencyFirst(t *testing.T) {
	c := New(time.Second)
	c.recordLatency("slow", 200*time.Millisecond)
	c.recordLatency("fast", 20*time.Millisecond)

	got := c.sortByScore([]string{"slow", "unknown", "fast"})
	if len(got) != 3 {
		t.Fatalf("got %#v", got)
	}
	if got[0] != "fast" {
		t.Fatalf("got first %q, want fast; all=%#v", got[0], got)
	}
	if got[2] != "unknown" {
		t.Fatalf("got last %q, want unknown; all=%#v", got[2], got)
	}
}

func TestRecordLatencySmoothsRecentLatency(t *testing.T) {
	c := New(time.Second)
	c.recordLatency("a", 100*time.Millisecond)
	c.recordLatency("a", 200*time.Millisecond)

	if got := c.latency["a"]; got != 130*time.Millisecond {
		t.Fatalf("got latency %s, want 130ms", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

var _ net.Error = timeoutErr{}
