package authentication

import (
	"github.com/iwyg/goauth/token"
	"log"
	"net/http"
)

type authenticationHandler struct {
	authenticator RequestAuthenticator
}

func (a *authenticationHandler) needsAuthentication(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "need authentication", http.StatusUnauthorized)
}

func (a *authenticationHandler) checkAuthToken(tok interface{}) bool {
	switch tok.(type) {
	case token.PostAuthToken:
		return true
	default:
		return false
	}
}

func (a *authenticationHandler) postAuthToken(t token.IdentityToken) token.PostAuthToken {
	return token.NewAuthenticatedToken(t.Identity())
}

func (a *authenticationHandler) doAuthenticate(r *http.Request) error {
	ts, err := token.TokenStoreFromRequest(r)

	if err != nil {
		return err
	}

	tok, err := a.authenticator.Authenticate(r)

	if err != nil {
		return err
	}

	ts.Clear()
	return ts.Write(tok)
}

func NewAuthenticationHandlerMiddleware(
	authenticator RequestAuthenticator,
) func(http.Handler) http.Handler {
	a := &authenticationHandler{
		authenticator: authenticator,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a.doAuthenticate(r)
			next.ServeHTTP(w, r)
		})
	}
}

func NewLogoutHandler(path string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			store, err := token.TokenStoreFromRequest(r)
			if err != nil {
				return
			}

			tok, err := store.Read()

			log.Printf("logout at  %s <-> %s\n", path, r.URL.Path)
			if path == r.URL.Path && err == nil && tok.IsFullyAuthenticated() {
				log.Printf("logout\n")
				store.Clear()
			}

			next.ServeHTTP(w, r)
		})
	}
}

//NewRedirectLoggedIn handle redirects of logged in users from the login url
func NewRedirectLoggedIn(path string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				next.ServeHTTP(w, r)
				return
			}
			if !func(w http.ResponseWriter, r *http.Request) bool {
				s, err := token.TokenStoreFromRequest(r)
				if err != nil {
					return false
				}

				tok, err := s.Read()

				if err != nil {
					return false
				}

				if !tok.IsFullyAuthenticated() {
					return false
				}

				return true
			}(w, r) {
				next.ServeHTTP(w, r)
				return
			}

			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		})
	}
}

func NewLoginRedirectHandler(path string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			store, err := token.TokenStoreFromRequest(r)
			if err != nil {
				return
			}
			tok, err := store.Read()
			if err != nil || !tok.IsFullyAuthenticated() {
				log.Printf("token %#v\n", tok)
				http.Redirect(w, r, path, http.StatusTemporaryRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
