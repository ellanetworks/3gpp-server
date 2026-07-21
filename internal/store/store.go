// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
)

type Store struct {
	mu     sync.RWMutex
	gnbs   map[string]*GNBContext
	enbs   map[string]*ENBContext
	nextID atomic.Int64
}

func New() *Store {
	return &Store{
		gnbs: make(map[string]*GNBContext),
		enbs: make(map[string]*ENBContext),
	}
}

func (s *Store) CreateGNB(mcc, mnc, tac, gnbID string, gnbIDBitLength int, name string, sst int32, sd string, slices []SliceConfig) *GNBContext {
	id := strconv.FormatInt(s.nextID.Add(1), 10)
	gnb := NewGNBContext(id, mcc, mnc, tac, gnbID, gnbIDBitLength, name, sst, sd, slices)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnbs[id] = gnb

	return gnb
}

func (s *Store) GetGNB(id string) (*GNBContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gnb, ok := s.gnbs[id]
	if !ok {
		return nil, fmt.Errorf("gnb %s not found", id)
	}

	return gnb, nil
}

func (s *Store) DeleteGNB(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.gnbs[id]; !ok {
		return fmt.Errorf("gnb %s not found", id)
	}

	delete(s.gnbs, id)
	return nil
}

func (s *Store) CreateENB(mcc, mnc, tac, enbID string, enbIDBitLength int, name string) *ENBContext {
	id := strconv.FormatInt(s.nextID.Add(1), 10)
	enb := NewENBContext(id, mcc, mnc, tac, enbID, enbIDBitLength, name)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.enbs[id] = enb

	return enb
}

func (s *Store) GetENB(id string) (*ENBContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enb, ok := s.enbs[id]
	if !ok {
		return nil, fmt.Errorf("enb %s not found", id)
	}

	return enb, nil
}

func (s *Store) DeleteENB(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.enbs[id]; !ok {
		return fmt.Errorf("enb %s not found", id)
	}

	delete(s.enbs, id)

	return nil
}
