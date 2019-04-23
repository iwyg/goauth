package session

import (
	"github.com/pkg/errors"
	httpUtil "github.com/iwyg/goauth/http"
	"github.com/iwyg/goauth/token"
	"log"
	"net/http"
)

type Config struct {
	Name     string
	TokenKey string
}

func NewSessionReaderHandler(conf Config, sp Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var exitErr httpUtil.Error
			defer httpUtil.ExitError(w, func() httpUtil.Error { return exitErr }, func() {
				next.ServeHTTP(w, r)
			})()

			session, err := sp.Provide(r, conf.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			log.Printf("%#v\n", session)

			tokens, storeErr := token.TokenStoreFromRequest(r)

			if storeErr != nil {
				log.Printf("could not read store from context %s\n", storeErr.Error())
				return
			}

			tok := session.GetValue(conf.TokenKey)
			session.RemoveValue(conf.TokenKey)

			if tok == nil {
				return
			}

			token, ok := tok.(token.Token)
			if !ok {
				log.Fatal("could not convert token from previous session\n")
			}

			log.Printf("successfully read token from session %#v\n", tok)

			tokens.Write(token)
		})

	}
}

func GetAuthenticatedToken(tok interface{}) (*token.AuthenticatedToken, error) {
	t, ok := tok.(*token.AuthenticatedToken)
	if !ok {
		return nil, errors.New("cannot convert to token")
	}

	return t, nil
}

//NewSessionWriterHandler initialize the token storage
func NewSessionWriterHandler(conf Config, sp Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var exitErr httpUtil.Error
			defer httpUtil.ExitError(w, func() httpUtil.Error { return exitErr }, func() {
				next.ServeHTTP(w, r)
			})()

			session, err := sp.Provide(r, conf.Name)
			session.RemoveValue(conf.TokenKey)
			tokens, storeErr := token.TokenStoreFromRequest(r)

			if storeErr != nil {
				log.Printf("could not read store from context %s\n", storeErr.Error())
				return
			}

			tok, err := tokens.Read()
			if err != nil {
				log.Printf("could not read from sp %s\n", err.Error())
				return
			}

			// won't write the token to the session if not authenticated
			if !tok.IsFullyAuthenticated() {
				session, _ = sp.New(r, conf.Name)
				sp.Save(w, r, session)
				log.Printf("found unauthenticated token %#v\n", tok)
				return
			}

			saveToken, err := GetAuthenticatedToken(tok)
			if err != nil {
				return
			}

			log.Printf("write token to session %#v\n", tok)
			session.SetValue(conf.TokenKey, saveToken)

			return
		})
	}
}

func NewSessionStartHandler(conf Config, sp Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sp.Provide(r, conf.Name)
			if err != nil || session.IsNew() {
				var err2 error
				session, err2 = sp.New(r, conf.Name)
				log.Println("start new session")
				if err2 != nil {
					log.Print(err2)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func NewSessionSaveHandler(conf Config, sp Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				session, _ := sp.Provide(r, conf.Name)
				if err := sp.Save(w, r, session); err != nil {
					log.Fatal(err)
				}
				next.ServeHTTP(w, r)
			})
	}
}

func NewSessionReaderMiddleWare(conf Config, store Provider) func(http.Handler) http.Handler {
	return NewSessionReaderHandler(conf, store)
}

func NewSessionWriterMiddleWare(conf Config, store Provider) func(http.Handler) http.Handler {
	return NewSessionWriterHandler(conf, store)
}

func NewSessionSaveHandlerMiddleware(conf Config, store Provider) func(http.Handler) http.Handler {
	return NewSessionSaveHandler(conf, store)
}

func NewSessionStartHandlerMiddleware(conf Config, store Provider) func(http.Handler) http.Handler {
	return NewSessionStartHandler(conf, store)
}
