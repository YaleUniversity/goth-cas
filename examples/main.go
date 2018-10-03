package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	cas "github.com/YaleUniversity/goth-cas"
	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

func main() {
	goth.UseProviders(cas.New("http://localhost:3001/auth/cas/callback"))

	p := pat.New()
	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(res, user)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		log.Println("inside logout route")
		gothic.Logout(res, req)
		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})

	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		// try to get the user without re-authenticating
		if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
			t, _ := template.New("foo").Parse(userTemplate)
			t.Execute(res, gothUser)
		} else {
			gothic.BeginAuthHandler(res, req)
		}
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		log.Println("inside home route")
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, nil)
	})
	log.Fatal(http.ListenAndServe(":3001", p))
}

var indexTemplate = `<p><a href="/auth/cas">Log in with CAS</a></p>`
var userTemplate = `
<p><a href="/logout/{{.Provider}}">logout</a></p>
<p>UserID: {{.UserID}}</p>
`
