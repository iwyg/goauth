package authentication

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/iwyg/goauth/identity"
	"github.com/iwyg/goauth/security"
	"github.com/iwyg/goauth/token"
)

type authResult struct {
	Token token.PostAuthToken
	Err   error
}

type credentialFields struct {
	credential string
	password   []byte
}

// Authenticator is a type that can extract credential information from a http request,
// check credentials against an identity and generate an authenticated token
type Authenticator interface {
	Supports(r *http.Request) bool
	Credentials(r *http.Request) (interface{}, error)
	CheckCredentials(credentials interface{}, identity identity.Identity) error
	Identity(context.Context, identity.Provider, interface{}) (identity.Identity, error)
	NewAuthenticatedToken(identity identity.Identity) (token.PostAuthToken, error)
}

// DefaultLoginAuthenticator can extract credential information from request parameters (username / password)
type DefaultLoginAuthenticator struct {
	PasswordChecker security.PasswordChecker
	CredentialField string
	PasswordField   string
}

func (a *DefaultLoginAuthenticator) Supports(r *http.Request) bool {
	return strings.ToLower(r.Method) == "post" &&
		r.FormValue(a.PasswordField) != "" &&
		r.FormValue(a.CredentialField) != ""
}

func (a *DefaultLoginAuthenticator) Credentials(r *http.Request) (interface{}, error) {
	if !a.Supports(r) {
		return nil, errors.New("request is not supported")
	}

	return &credentialFields{
		credential: r.FormValue(a.CredentialField),
		password:   []byte(r.FormValue(a.PasswordField)),
	}, nil
}

func (a *DefaultLoginAuthenticator) CheckCredentials(
	credentials interface{},
	identity identity.Identity,
) error {
	switch credentials.(type) {
	case *credentialFields:
		break
	default:
		return errors.New("unsupported credentials")
	}

	cred := credentials.(*credentialFields)

	p := identity.Password()
	pass, ok := p.(string)

	if !ok {
		return errors.New("unsupported password type")
	}

	if err := a.PasswordChecker.CheckPass(
		cred.password,
		[]byte(pass),
	); err != nil {
		return err
	}

	return nil
}

func (a *DefaultLoginAuthenticator) Identity(ctx context.Context, identities identity.Provider, credential interface{}) (identity.Identity, error) {
	c, ok := credential.(*credentialFields)
	if !ok {
		return nil, errors.New("credentials not supported")
	}
	return identities.Provide(c.credential)
}

func (a *DefaultLoginAuthenticator) NewAuthenticatedToken(
	identity identity.Identity,
) (token.PostAuthToken, error) {
	return token.NewAuthenticatedToken(identity), nil
}

type AuthenticatorManager struct {
	Authenticators    []Authenticator
	IdentityProviders []*identity.IdentityProviderMap
}

func (a *AuthenticatorManager) Run(r *http.Request) error {
	return nil
}

type AuthenticatorProvider interface {
	Authenticate(context.Context, token.Token) (token.PostAuthToken, error)
}

type GuardRequestAuthenticator struct {
	idProvider     identity.Provider
	idChecker      identity.IdentityChecker
	storeProvider  token.StoreProvider
	authenticators []Authenticator
}

func (g *GuardRequestAuthenticator) aggregateAuthenticators(ctx context.Context, authenticators ...Authenticator) <-chan Authenticator {
	out := make(chan Authenticator, len(authenticators))
	go func() {
		defer close(out)
		for _, a := range authenticators {
			select {
			case out <- a:
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	return out
}

func (g *GuardRequestAuthenticator) supportedAuthenticators(r *http.Request) []Authenticator {
	var out []Authenticator
	for _, auth := range g.authenticators {
		if !auth.Supports(r) {
			continue
		}

		out = append(out, auth)
	}

	return out
}

func (g *GuardRequestAuthenticator) doAuthenticateRequest(ctx context.Context, r *http.Request, at Authenticator) *authResult {
	var c interface{}
	var id identity.Identity
	var err error

	c, err = at.Credentials(r)
	if err != nil {
		return &authResult{Err: err}
	}

	id, err = at.Identity(ctx, g.idProvider, c)

	if err != nil {
		return &authResult{Err: err}
	}

	if err = g.idChecker.CheckPreAuth(id); err != nil {
		return &authResult{Err: err}
	}

	if err = at.CheckCredentials(c, id); err != nil {
		return &authResult{Err: err}
	}

	if err = g.idChecker.CheckPostAuth(id); err != nil {
		return &authResult{Err: err}
	}

	if err != nil {
		return &authResult{Err: err}
	}

	return &authResult{Token: token.NewAuthenticatedToken(id)}

}

func (g *GuardRequestAuthenticator) authenticateRequest(ctx context.Context, r *http.Request) (token.PostAuthToken, error) {
	sa := g.supportedAuthenticators(r)

	if len(sa) == 0 {
		return nil, errors.New("no supported authenticators")
	}

	ch := make(chan *authResult)

	var wg sync.WaitGroup

	for at := range g.aggregateAuthenticators(ctx, sa...) {
		wg.Add(1)
		go func(auth Authenticator) {
			defer wg.Done()
			select {
			case ch <- g.doAuthenticateRequest(ctx, r, auth):
			case <-ctx.Done():
				return

			}
		}(at)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for ret := range ch {
		if ret.Token != nil {
			return ret.Token, nil
		}
	}

	return nil, errors.New("authentication failed")
}

func (g *GuardRequestAuthenticator) verifyToken(ctx context.Context, t token.PostAuthToken) (token.PostAuthToken, error) {
	return t, nil
}

func (g *GuardRequestAuthenticator) Authenticate(r *http.Request) (token.PostAuthToken, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts, err := g.storeProvider.Provide(r)

	if err != nil {
		return nil, err
	}

	foundToken, _ := ts.Read()
	switch foundToken.(type) {
	case token.PostAuthToken:
		return g.verifyToken(ctx, foundToken.(token.PostAuthToken))
	default:
		return g.authenticateRequest(ctx, r)
	}
}

type RequestAuthenticator interface {
	Authenticate(r *http.Request) (token.PostAuthToken, error)
}

func NewGuardRequestAuthenticator(storeProvider token.StoreProvider, auths []Authenticator, idProvider identity.Provider,
	idChecker identity.IdentityChecker) *GuardRequestAuthenticator {

	return &GuardRequestAuthenticator{
		idProvider:     idProvider,
		idChecker:      idChecker,
		storeProvider:  storeProvider,
		authenticators: auths,
	}
}
