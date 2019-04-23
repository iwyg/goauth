package firewall

import (
	"errors"

	"github.com/iwyg/goauth/token"
)

type AuthorisationRequired interface {
	error
	Token() token.Token
}

type authorisationRequired struct {
	err error
	token token.Token
}

func (a *authorisationRequired) Token() token.Token {
	return a.token
}

func (a *authorisationRequired) Error() string {
	return a.err.Error()
}
func NewAuthorisationRequired(t token.Token) AuthorisationRequired {
	err := errors.New("authorization required")
	return &authorisationRequired{token: t, err: err}
}
