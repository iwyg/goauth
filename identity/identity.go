package identity

import (
	"encoding/gob"
	"github.com/iwyg/goauth/role"
)

var registeredIdentities = make(map[Identity]bool)

func Register(ids ...Identity) {
	for _, id := range ids {
		if registered, ok := registeredIdentities[id]; ok && registered {
			continue
		}

		gob.Register(id)
		registeredIdentities[id] = true
	}
}

type Identity interface {
	ID() interface{}
	Credential() interface{}
	Password() interface{}
	Roles() []role.Role
	IsBanned() bool
	IsActive() bool
	Refresh()
}

type InMemoryIdentity struct {
	UserId         interface{} `json:"id"`
	UserCredential interface{} `json:"credential"`
	UserPass       interface{} `json:"password"`
	UserRoles      []role.Role `json:"roles"`
}

func (i *InMemoryIdentity) ID() interface{} {
	return i.UserId
}

func (i *InMemoryIdentity) Credential() interface{} {
	return i.UserCredential
}

func (i *InMemoryIdentity) Password() interface{} {
	return i.UserPass
}

func (i *InMemoryIdentity) Roles() []role.Role {
	return i.UserRoles
}

func (i *InMemoryIdentity) IsBanned() bool {
	return false
}

func (i *InMemoryIdentity) IsActive() bool {
	return true
}

func (i *InMemoryIdentity) Refresh() {
	i.UserPass = ""
}
