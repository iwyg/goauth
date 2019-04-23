package token

import (
	"errors"
	"sync"
)

type Store interface {
	Read() (Token, error)
	Write(Token) error
	Clear()
}

func NewStore() *defaultStore {
	return new(defaultStore)
}

type defaultStore struct {
	mu    sync.Mutex
	token Token
}

func (s *defaultStore) Read() (Token, error) {
	if s.token == nil {
		return nil, errors.New("no token to read")
	}

	return s.token, nil
}

func (s *defaultStore) Write(t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = t
	return nil
}

func (s *defaultStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = nil
}
