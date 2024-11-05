package controllers

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"time"
)

func GenerateCsrf() string {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func ValidateCsrf(val string, r *http.Request) bool {
	cookie, err := r.Cookie("csrf-token")
	if err != nil {
		return false
	}
	return cookie.Value == val
}

type LoginProps struct {
	CsrfToken    string
	ErrorMessage string
}

func HandleGETLogin(t *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		csrf := GenerateCsrf()
		expiration := time.Now().Add(365 * 24 * time.Hour)
		csrfCookie := http.Cookie{Name: "csrf-token", Value: csrf, Expires: expiration, SameSite: 1, HttpOnly: true}
		http.SetCookie(w, &csrfCookie)
		t.ExecuteTemplate(w, "login", &LoginProps{CsrfToken: csrf, ErrorMessage: ""})
	}
}

func HandlePOSTLogin(t *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			return
		}
		if !ValidateCsrf(r.Form.Get("csrf-token"), r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		t.ExecuteTemplate(w, "login", &LoginProps{ErrorMessage: "Username or password incorrect", CsrfToken: r.Form.Get("csrf-token")})
	}
}
