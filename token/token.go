package token

import (
	"encoding/gob"
	"github.com/iwyg/goauth/identity"
	"github.com/iwyg/goauth/role"
	"net/http"
)

var initialized = false

type Signer interface {
	Sign(SignedToken) ([]byte, error)
}

type SignatureVerifier interface {
	Verify(SignedToken) error
}

type Token interface {
	IsFullyAuthenticated() bool
	Roles() []role.Role
}

type IdentityToken interface {
	Token
	Identity() identity.Identity
	WithIdentity(identity.Identity) IdentityToken
}

type SignedToken interface {
	IdentityToken
	Sign(Signer, *http.Request) error
	Signature() ([]byte, error)
}

type RememberMe interface {
	IdentityToken
	ForHowLong() int
}

type PostAuthToken interface {
	SignedToken
	Refresh()
}

type PreAuthToken struct {
	AnonToken
	Credentials interface{}
}

type AnonToken struct {
}

func (a *AnonToken) Roles() []role.Role {
	return []role.Role{role.RLAnon}
}

func (a *AnonToken) IsFullyAuthenticated() bool {
	return false
}

type AuthenticatedToken struct {
	TokenIdentity identity.Identity `json:"identity"`
	TokenRoles    []role.Role       `json:"roles"`
}

func (t *AuthenticatedToken) Roles() []role.Role {
	return t.TokenRoles
}

func (t *AuthenticatedToken) IsFullyAuthenticated() bool {
	return true
}

func (t *AuthenticatedToken) Identity() identity.Identity {
	return t.TokenIdentity
}

func (t *AuthenticatedToken) Refresh() {
	t.TokenIdentity.Refresh()
}

func (t *AuthenticatedToken) Secret() {
	t.TokenIdentity.Refresh()
}

func (t *AuthenticatedToken) WithIdentity(id identity.Identity) IdentityToken {
	return NewAuthenticatedToken(id)
}

func (t *AuthenticatedToken) Sign(s Signer, r *http.Request) error {
	return nil
}

func (t *AuthenticatedToken) Signature() ([]byte, error) {
	return []byte(""), nil
}

//func NewPreAuthenticatedToken(key firewall.ProviderKey) *AnonToken {
//	tok := &AnonToken{key: key}
//	return tok
//}

func NewAnonymousToken() *AnonToken {
	tok := &AnonToken{}
	return tok
}

func NewAuthenticatedToken(identity identity.Identity) *AuthenticatedToken {
	tok := &AuthenticatedToken{
		TokenIdentity: identity,
		TokenRoles:    identity.Roles(),
	}

	return tok
}

func Init() {
	if initialized {
		return
	}

	gob.Register(&AnonToken{})
	gob.Register(&AuthenticatedToken{})
	initialized = true
}
