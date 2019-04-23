package firewall

import (
	"log"
	"net/http"
)

type statWriter struct {
	Status int
	http.ResponseWriter
}

func (w *statWriter) WriteHeader(status int) {
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statWriter) Write(b []byte) (int, error) {
	if w.Status == 0 {
		w.Status = http.StatusOK
	}

	return w.ResponseWriter.Write(b)
}



func NewMiddleware() func (http.Handler) http.Handler {
	return func(next http.Handler)  http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			next.ServeHTTP(w, r)
		})
	}
}

func NewMoveOnMiddleware() func (http.Handler) http.Handler {
	return func(next http.Handler)  http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := &statWriter{ResponseWriter: w}
			log.Printf("wait for it…\n")
			defer func () {
				if ww.Status == http.StatusUnauthorized {
					log.Printf("you shall not pass\n")
				}
			}()
			next.ServeHTTP(ww, r)
			log.Printf("Status %#v\n", ww.Status)
		})
	}
}
