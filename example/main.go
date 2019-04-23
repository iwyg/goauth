package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/iwyg/goauth/authentication"
	"github.com/iwyg/goauth/identity"
	"github.com/iwyg/goauth/role"
	"github.com/iwyg/goauth/security"
	"github.com/iwyg/goauth/session"
	"github.com/iwyg/goauth/token"
	"github.com/pkg/errors"
)

var indexTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
	</head>
  <body>
    <h1>hello {{ . }} </h1>
<ul>
<li><a href="/secure/area">secure area</a></li>
<li><a href="/login">login -></a></li>
</ul>
	</body>
</html> `))

var secureTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
	</head>
  <body>
    <h1>hello {{ . }} </h1>
<ul>
<li><a href="/logout">-> logout</a></li>
</ul>
	</body>
</html> `))
var loginTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
	</head>
  <body>
    <h1>please login </h1>
	  <form method="POST">
		<label>
      email
		  <input type="email" name="email"/>
	  </label>
		<label>
      password
		  <input type="password" name="password"/>
	  </label>
    <input type="submit" value="login"/>
	  </form>
	</body>
</html> `))

type delayedAuthenticator struct {
	authentication.Authenticator
	delay time.Duration
}

func (a *delayedAuthenticator) Identity(ctx context.Context, identities identity.Provider, credential interface{}) (identity.Identity, error) {
	an, b := func() (identity.Identity, error) {
		time.Sleep(a.delay)
		return a.Authenticator.Identity(ctx, identities, credential)
	}()

	select {
	case <-ctx.Done():
		log.Printf("lookup canceled\n")
		return nil, errors.New("sorry")
	default:
	}

	return an, b
}

func (a *delayedAuthenticator) CheckCredentials(credentials interface{}, identity identity.Identity) error {
	time.Sleep(a.delay)
	return a.Authenticator.CheckCredentials(credentials, identity)
}

type idProvider struct {
	users map[string]identity.Identity
}

func (i *idProvider) Provide(id interface{}) (identity.Identity, error) {
	log.Printf("credentials, %#v\n", id)
	cred, ok := id.(string)
	if !ok {
		return nil, errors.New("invalid credential")
	}

	if user, found := i.users[cred]; found {
		return user, nil
	}

	return nil, errors.New("user not found")
}

func (i *idProvider) Refresh(id identity.Identity) (identity.Identity, error) {
	return i.Provide(id.Credential())
}

func (i *idProvider) Supports(id identity.Identity) bool {
	return true
}

var sessStore *session.GorillaSessionProvider

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v\n", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func init() {
	defer log.Printf("done")
	log.Printf("running initialization...")

	cs := sessions.NewCookieStore([]byte("my-secret-key"))
	cs.Options = &sessions.Options{
		Domain:   "",
		Path:     "/",
		MaxAge:   3600 * 24,
		HttpOnly: true,
	}
	sessStore = &session.GorillaSessionProvider{
		Store: cs,
	}

	identity.Register(
		&identity.InMemoryIdentity{},
	)
	token.Init()
}

func mergeM(middlewares ...[]mux.MiddlewareFunc) []mux.MiddlewareFunc {
	var out []mux.MiddlewareFunc

	for _, mw := range middlewares {
		out = append(out, mw...)
	}

	return out
}

func main() {

	router := mux.NewRouter()
	router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		indexTemplate.Execute(w, "world")
	}))
	router.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginTemplate.Execute(w, nil)
	}))

	router.Handle("/logout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}))

	sessCfg := session.Config{
		Name:     "app",
		TokenKey: "__security",
	}

	users := make(map[string]identity.Identity)

	users["admin@example.org"] = &identity.InMemoryIdentity{
		UserId:   "c3efd24c-0978-4fd7-a228-f5a8355de755",
		UserPass: "$2a$10$v3zh/Lw4YhOQC02n4SO1d.Z7si4C/mKnWK8H/1AWsP6o4qTetMwwe", // password
		UserRoles: []role.Role{
			role.RLAdmin,
		},
	}

	users["user@example.com"] = &identity.InMemoryIdentity{
		UserId:   "c3efd24c-0978-4fd7-a228-f5a8355de756",
		UserPass: "$2a$10$v3zh/Lw4YhOQC02n4SO1d.Z7si4C/mKnWK8H/1AWsP6o4qTetMwwe", // password
		UserRoles: []role.Role{
			role.RLUser,
		},
	}

	idProvider := &idProvider{
		users: users,
	}

	checker := security.NewBCryptPasswordChecker()

	authHandler := authentication.NewAuthenticationHandlerMiddleware(
		authentication.NewGuardRequestAuthenticator(
			&token.RequestContextStoreProvider{},
			[]authentication.Authenticator{
				&delayedAuthenticator{
					Authenticator: &authentication.DefaultLoginAuthenticator{
						PasswordChecker: checker,
						PasswordField:   "password",
						CredentialField: "email",
					},
					delay: time.Second * 2,
				},
				&authentication.DefaultLoginAuthenticator{
					PasswordChecker: checker,
					PasswordField:   "password",
					CredentialField: "email",
				},
				&authentication.DefaultLoginAuthenticator{
					PasswordChecker: checker,
					PasswordField:   "password",
					CredentialField: "email",
				},
			},
			idProvider,
			identity.NewBaseIdentityChecker(),
		),
	)

	router.Use(
		//recoverHandler,
		token.NewTokenStoreProviderMiddleware(),
		session.NewSessionStartHandlerMiddleware(sessCfg, sessStore),
		session.NewSessionReaderMiddleWare(sessCfg, sessStore),
	)

	sec := router.PathPrefix("/secure").Subrouter()
	sec.Handle("/{path:.*}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureTemplate.Execute(w, "cruel world. You are safe now")
	}))

	router.Use(
		authHandler,
		authentication.NewLogoutHandler("/logout"),
		session.NewSessionWriterMiddleWare(sessCfg, sessStore),
		session.NewSessionSaveHandlerMiddleware(sessCfg, sessStore),
		authentication.NewRedirectLoggedIn("/login"),
	)

	sec.Use(
		authentication.NewLoginRedirectHandler("/login"),
	)

	out := handlers.CombinedLoggingHandler(os.Stdout, router)

	log.Printf("start listening on 127.0.0.0:8005\n")
	log.Fatal(http.ListenAndServe("localhost:8005", out))
}
