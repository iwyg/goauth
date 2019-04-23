package token

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	httpUtil "github.com/iwyg/goauth/http"
	"net/http"
)

const TokenStoreKey = "tokenStore"

func initTokenStore(r *http.Request) (Store, *http.Request) {
	var ok = true
	s := r.Context().Value(TokenStoreKey)
	store, ok := s.(Store)
	if !ok {
		store = NewStore()
		ctx := context.WithValue(r.Context(), TokenStoreKey, store)
		r = r.WithContext(ctx)
	}
	return store, r
}

func TokenStoreFromRequest(r *http.Request) (Store, error) {
	s := r.Context().Value(TokenStoreKey)
	store, ok := s.(Store)
	if !ok {
		return nil, errors.New("Store not initialized")
	}

	return store, nil
}

func NewTokenStoreProviderMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, newReq := initTokenStore(r)
			next.ServeHTTP(w, newReq)
		})
	}
}

type StoreProvider interface {
	Provide(*http.Request) (Store, error)
}

type RequestContextStoreProvider struct {
}

func (gc *RequestContextStoreProvider) Provide(r *http.Request) (Store, error) {
	return TokenStoreFromRequest(r)
}

func NewAnonTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, serr := TokenStoreFromRequest(r)

		if serr != nil {
			panic(serr)
		}

		if _, err := store.Read(); err != nil {
			store.Write(NewAnonymousToken())
		}
	}
}

func NewAnonTokenHandlerMiddleware() mux.MiddlewareFunc {
	return httpUtil.MuxMiddleware(NewAnonTokenHandler())
}
