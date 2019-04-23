package authentication

import (
	"github.com/pkg/errors"
	"github.com/iwyg/goauth/token"
)

type NotAuthenticated interface {
	error
	Token() token.Token
}

type notAuthenticatedErr struct {
	Err error
	Tok token.Token
}

func (er *notAuthenticatedErr) Error() string {
	return er.Err.Error()
}

func (er *notAuthenticatedErr) Token() token.Token {
	return er.Tok
}

func NewNotAuthenticatedError(msg string, tok token.Token) *notAuthenticatedErr {
	return &notAuthenticatedErr{
		Err: errors.New(msg),
		Tok: tok,
	}
}
