package http

import (
	"github.com/gorilla/mux"
	"net/http"
)

type Handler func(http.ResponseWriter, *http.Request) (int, error)

func ExitError(w http.ResponseWriter, errF func() Error, f func()) func() {
	return func() {
		if err := errF(); err != nil {
			http.Error(w, err.Error(), err.StatusCode())
			return
		}
		f()
	}
}

type Error interface {
	error
	StatusCode() int
}

type StatusError struct {
	Code int
	Err  error
}

func (e *StatusError) StatusCode() int {
	return e.Code
}

func (e *StatusError) Error() string {
	return e.Err.Error()
}

func Muxify(in func(http.Handler) http.Handler) mux.MiddlewareFunc {
	return in
}

func MuxMiddleware(handlerFunc http.HandlerFunc) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerFunc(w, r)
			next.ServeHTTP(w, r)
		})
	}
}
