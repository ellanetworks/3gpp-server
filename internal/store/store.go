package store

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
)

type Store struct {
	mu       sync.RWMutex
	gnbs     map[string]*GnBContext
	nextID   atomic.Int64
}

func New() *Store {
	return &Store{
		gnbs: make(map[string]*GnBContext),
	}
}

func (s *Store) CreateGnB(mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []SliceConfig) *GnBContext {
	id := strconv.FormatInt(s.nextID.Add(1), 10)
	gnb := NewGnBContext(id, mcc, mnc, tac, gnbID, name, sst, sd, slices)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnbs[id] = gnb

	return gnb
}

func (s *Store) GetGnB(id string) (*GnBContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gnb, ok := s.gnbs[id]
	if !ok {
		return nil, fmt.Errorf("gnb %s not found", id)
	}

	return gnb, nil
}

func (s *Store) DeleteGnB(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.gnbs[id]; !ok {
		return fmt.Errorf("gnb %s not found", id)
	}

	delete(s.gnbs, id)
	return nil
}

func (s *Store) ListGnBs() []*GnBContext {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gnbs := make([]*GnBContext, 0, len(s.gnbs))
	for _, gnb := range s.gnbs {
		gnbs = append(gnbs, gnb)
	}

	return gnbs
}
