package session

import (
	"errors"
	"github.com/gorilla/sessions"
	"net/http"
)

type Session interface {
	SetValue(interface{}, interface{})
	GetValue(interface{}) interface{}
	RemoveValue(interface{})
	IsNew() bool
	Expire()
	ID() string
}

type Provider interface {
	Provide(*http.Request, string) (Session, error)
	New(*http.Request, string) (Session, error)
	Save(http.ResponseWriter, *http.Request, Session) error
}

type GorillaSessionProvider struct {
	Store sessions.Store
}

func (sp *GorillaSessionProvider) Provide(r *http.Request, name string) (Session, error) {
	gs, err := sp.Store.Get(r, name)
	return &GorillaSession{Session: gs}, err
}

func (sp *GorillaSessionProvider) New(r *http.Request, name string) (Session, error) {
	gs, err := sp.Store.New(r, name)
	return &GorillaSession{Session: gs}, err
}

func (sp *GorillaSessionProvider) Save(w http.ResponseWriter, r *http.Request, session Session) error {
	var sess interface{} = session

	switch sess.(type) {
	case *GorillaSession:
		break
	default:
		return errors.New("incompatible session")
	}

	gs := sess.(*GorillaSession)
	return gs.Session.Save(r, w)
}

type GorillaSession struct {
	Session *sessions.Session
}

func (gs *GorillaSession) SetValue(key interface{}, val interface{}) {
	gs.Session.Values[key] = val
}

func (gs *GorillaSession) GetValue(key interface{}) interface{} {
	if val, found := gs.Session.Values[key]; found {
		return val
	}

	return nil
}

func (gs *GorillaSession) RemoveValue(key interface{}) {
	delete(gs.Session.Values, key)
}

func (gs *GorillaSession) Expire() {
	gs.Session.Options.MaxAge = -1
}

func (gs *GorillaSession) IsNew() bool {
	return gs.Session.IsNew
}

func (gs *GorillaSession) ID() string {
	return gs.Session.ID
}
