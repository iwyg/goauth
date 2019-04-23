package identity

import (
	"encoding/json"
	"fmt"
	"github.com/iwyg/goauth/role"
	"io/ioutil"
	"os"
	"reflect"
)

type Provider interface {
	Provide(id interface{}) (Identity, error)
	Refresh(identity Identity) (Identity, error)
	Supports(identity Identity) bool
}

type inMemoryIdentityJSONMap struct {
	Users map[string]*inMemoryIdentityJSON `json:"users"`
}

type inMemoryIdentityJSON struct {
	ID       interface{} `json:"UserId"`
	Password interface{} `json:"UserPass"`
	Roles    []role.Role `json:"UserRoles"`
}

func loadInMemoryIdentitiesFromConfig(config InMemoryProviderConfig) (map[interface{}]Identity, error) {
	jsonFile, err := os.Open(config.UsersJSON)
	if err != nil {
		return nil, err
	}

	defer jsonFile.Close()
	byteVal, err := ioutil.ReadAll(jsonFile)

	if err != nil {
		return nil, err
	}

	users := inMemoryIdentityJSONMap{}
	json.Unmarshal(byteVal, &users)

	usersMap := make(map[interface{}]Identity)

	for c, u := range users.Users {
		usersMap[c] = &InMemoryIdentity{
			UserId:         u.ID,
			UserCredential: c,
			UserPass:       u.Password,
			UserRoles:      u.Roles,
		}
	}

	return usersMap, nil
}

func NewInMemoryProvider(config InMemoryProviderConfig) *InMemoryProvider {
	reload := func() (map[interface{}]Identity, error) {
		return loadInMemoryIdentitiesFromConfig(config)
	}

	usersMap, err := reload()

	if err != nil {
		panic(err)
	}

	return &InMemoryProvider{users: usersMap, refresh: reload}
}

type InMemoryProvider struct {
	users   map[interface{}]Identity
	refresh func() (map[interface{}]Identity, error)
}

type InMemoryProviderConfig struct {
	UsersJSON string
}

type UserNotFound struct {
	credential interface{}
}

func (e *UserNotFound) Error() string {
	return fmt.Sprintf("User \"%v\" not found", e.credential)
}

func (p *InMemoryProvider) Provide(credential interface{}) (Identity, error) {
	if identity, ok := p.users[credential]; ok {
		return identity, nil
	}

	return nil, &UserNotFound{credential: credential}
}

func (p *InMemoryProvider) Refresh(identity Identity) (Identity, error) {
	return identity, nil
}

func (p *InMemoryProvider) Supports(identity Identity) bool {
	return reflect.TypeOf(identity) == reflect.TypeOf(&InMemoryIdentity{})
}

type IdentityProviderMap struct {
	Providers map[string][]Provider
}
