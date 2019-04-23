package firewall

import (
	"github.com/iwyg/goauth/identity"
	"github.com/iwyg/goauth/token"
	"net/http"
)

type Listener func(r *http.Request) (http.Handler, error)

type ContextListener struct {
	id             ProviderKey
	store          token.Store
	identityFinder identity.Provider
}

func (c *ContextListener) readFromStore() {
}

func (c *ContextListener) refreshIdentity(t interface{}) (token.Token, error) {
	switch t.(type) {
	case token.IdentityToken:
		tok := t.(token.IdentityToken)
		identity, err := c.identityFinder.Refresh(tok.Identity())

		if err != nil {
			return nil, err
		}

		return tok.WithIdentity(identity), err
	}

	return t.(token.Token), nil
}

func (c *ContextListener) Handle(r *http.Request) (http.Handler, error) {
	t, readErr := c.store.Read()
	if readErr != nil {
		// do stuff
	}

	tok, err := c.refreshIdentity(t)

	if err == nil {
		c.store.Write(tok)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}), nil
}

type AnonListener struct {
	store token.Store
}

func (a *AnonListener) Handle(r *http.Request) (http.Handler, error) {

	tok, err := a.store.Read()

	if err != nil {
		tok = token.NewAnonymousToken()
		a.store.Write(tok)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}), nil
}
