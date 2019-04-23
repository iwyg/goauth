package security

import (
	"github.com/iwyg/goauth/token"
	"net/http"
	"sync"
)

var ctxMap map[*http.Request]Context

type Context interface {
	Token() token.Token
}

type contextImpl struct {
	mu      sync.Mutex
	Request *http.Request
	Store   token.Store
}

func (ctx *contextImpl) Token() token.Token {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	tok, err := ctx.Store.Read()
	if err != nil {
		return nil
	}

	return tok
}

func GetContext(r *http.Request) Context {
	ctx, ok := ctxMap[r]
	store, err := token.TokenStoreFromRequest(r)
	if err != nil {
		panic(err)
	}

	if !ok {
		ctx = &contextImpl{
			Store:   store,
			Request: r,
		}

		ctxMap[r] = ctx
		return ctx
	}

	return ctx
}
