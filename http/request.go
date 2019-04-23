package http

import (
	"net"
	"net/http"
	"regexp"
	"strings"
)

type RequestMatcher interface {
	Matches(r *http.Request) bool
}

type RequestMatcherConfig struct {
	Path    string   `json:"path"`
	Host    string   `json:"host"`
	Methods []string `json:"methods"`
	IPRange []string `json:"ipRange"`
	Schemes []string `json:"schemes"`
}

func NewRequestMatcher(config RequestMatcherConfig) RequestMatcher {

	pathExp, err := regexp.Compile("/" + config.Path + "/")
	if err != nil {
		panic(err)
	}

	hostExp, err := regexp.Compile("/" + config.Host + "/")
	if err != nil {
		panic(err)
	}

	r := &DefaultRequestMatcher{
		path:    hostExp,
		host:    pathExp,
		methods: config.Methods,
		schemes: config.Schemes,
		ips:     config.IPRange,
	}

	return r
}

type DefaultRequestMatcher struct {
	path    *regexp.Regexp
	host    *regexp.Regexp
	methods []string
	ips     []string
	schemes []string
}

func (m *DefaultRequestMatcher) Matches(r *http.Request) bool {
	return m.MatchesPath(r) &&
		m.MatchesHost(r) &&
		m.MatchesMethod(r) &&
		m.MatchesScheme(r) &&
		m.MatchesIpRange(r)
}

func (m *DefaultRequestMatcher) MatchesPath(r *http.Request) bool {
	return m.path.Match([]byte(r.RequestURI))
}

func (m *DefaultRequestMatcher) MatchesMethod(r *http.Request) bool {
	if len(m.methods) == 0 {
		return true
	}

	for _, m := range m.methods {
		if m == strings.ToLower(r.Method) {
			return true
		}
	}

	return false
}

func (m *DefaultRequestMatcher) MatchesHost(r *http.Request) bool {
	return m.host.Match([]byte(r.Host))
}

func (m *DefaultRequestMatcher) MatchesScheme(r *http.Request) bool {
	if len(m.schemes) == 0 {
		return true
	}

	for _, m := range m.schemes {
		if m == r.URL.Scheme {
			return true
		}
	}

	return false
}

func (m *DefaultRequestMatcher) MatchesIpRange(r *http.Request) bool {
	if len(m.ips) == 0 {
		return true
	}

	_, subnet, _ := net.ParseCIDR(r.RemoteAddr)
	for _, clientIP := range m.ips {
		ip := net.ParseIP(clientIP)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}
