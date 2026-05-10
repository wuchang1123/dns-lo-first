package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type reputationStore struct {
	mu      sync.Mutex
	enabled bool
	path    string
	delta   int
	min     int
	max     int

	scores map[string]int
	log    *logger
}

type reputationDisk struct {
	Scores map[string]int `json:"scores"`
}

func newReputationStore(path string, enabled bool, delta, min, max int, log *logger) (*reputationStore, error) {
	s := &reputationStore{
		enabled: enabled,
		path:    path,
		delta:   delta,
		min:     min,
		max:     max,
		scores:  make(map[string]int),
		log:     log,
	}
	if enabled {
		if err := s.load(); err != nil {
			return nil, err
		}
		// Create the persistence file eagerly so "enabled" always materializes a file
		// even before the first adjustment happens.
		s.save()
	}
	log.Infof("reputation cache loaded enabled=%t entries=%d path=%s", enabled, len(s.scores), path)
	return s, nil
}

func (s *reputationStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var d reputationDisk
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	if d.Scores == nil {
		return nil
	}
	for k, v := range d.Scores {
		s.scores[k] = clampInt(v, s.min, s.max)
	}
	return nil
}

func (s *reputationStore) score(addr string) int {
	if s == nil || !s.enabled {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scores[addr]
}

func (s *reputationStore) adjust(addr string, good bool) {
	if s == nil || !s.enabled || addr == "" {
		return
	}
	s.mu.Lock()
	cur := s.scores[addr]
	if good {
		cur += s.delta
	} else {
		cur -= s.delta
	}
	s.scores[addr] = clampInt(cur, s.min, s.max)
	s.mu.Unlock()
	s.save()
}

func (s *reputationStore) snapshot() reputationDisk {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.scores))
	for k, v := range s.scores {
		out[k] = v
	}
	return reputationDisk{Scores: out}
}

func (s *reputationStore) save() {
	if s == nil || !s.enabled {
		return
	}
	writeJSON(s.path, s.snapshot(), s.log)
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}
