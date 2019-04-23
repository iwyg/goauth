package firewall

import (
	http2 "github.com/iwyg/goauth/http"
	"net/http"
)

type Map interface {
	Listeners(r *http.Request) []Listener
}

type DefaultFirewallMap struct {
	handlers map[http2.RequestMatcher][]Listener
}

func (f *DefaultFirewallMap) Add(matcher http2.RequestMatcher, handlers ...Listener) {
	f.handlers[matcher] = handlers
}

func (f *DefaultFirewallMap) Listeners(r *http.Request) []Listener {
	for matcher, listeners := range f.handlers {
		if matcher.Matches(r) {
			return listeners
		}
	}

	return make([]Listener, 0)
}

func NewFirewallMap() *DefaultFirewallMap {
	handlers := make(map[http2.RequestMatcher][]Listener)
	m := &DefaultFirewallMap{handlers: handlers}

	return m
}
