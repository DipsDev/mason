package controllers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/pages"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Session struct {
	id     string
	user   *common.User
	expiry time.Time
	// add more as project grows
}

func (s *Session) Expired() bool {
	return time.Now().After(s.expiry)
}

var sessions = map[string]*Session{}

func createSession(user *common.User) *Session {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	id := hex.EncodeToString(bytes)

	sess := &Session{
		expiry: time.Now().Add(12 * time.Minute),
		id:     id,
		user:   user,
	}
	sessions[id] = sess
	return sess

}

func generateCsrf() string {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func validateCsrf(val string, r *http.Request) bool {
	cookie, err := r.Cookie("csrf-token")
	if err != nil {
		return false
	}
	return cookie.Value == val
}

func createCookie(name string, value string) *http.Cookie {
	expiration := time.Now().Add(12 * 24 * time.Hour)
	ck := http.Cookie{Name: name, Value: value, Expires: expiration} // add samesite, secure and httpOnly in prod
	return &ck
}

type LoginProps struct {
	CsrfToken    string
	ErrorMessage string
}

func ShowLogin(w http.ResponseWriter, r *http.Request) {
	csrf := generateCsrf()
	http.SetCookie(w, createCookie("csrf-token", csrf))
	pages.Login(csrf, "").Render(r.Context(), w)

}

func CreateLogin(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		return
	}
	if r.Form.Get("csrf-token") == "" || !validateCsrf(r.Form.Get("csrf-token"), r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	email := r.Form.Get("email")
	password := r.Form.Get("password")
	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stmtOut, err := common.DB.Prepare("SELECT password, id, email, username FROM users WHERE email = ? OR username = ?")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var passwordSQL, idSQL, emailSQL, usernameSQL string
	err = stmtOut.QueryRow(email, email).Scan(&passwordSQL, &idSQL, &emailSQL, &usernameSQL)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		pages.Login(r.Form.Get("csrf-token"), "Incorrect username or password").Render(r.Context(), w)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordSQL), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		pages.Login(r.Form.Get("csrf-token"), "Incorrect username or password").Render(r.Context(), w)
		return
	}

	// create a session cookie
	sess := createSession(&common.User{Id: idSQL, Email: email, Username: usernameSQL})
	cookie := createCookie("MASONSESSION", sess.id)
	http.SetCookie(w, cookie)

	// Redirect user to dashboard
	http.Redirect(w, r, "/panel", http.StatusFound)

}

func HandleLogout(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("MASONSESSION")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessToken := c.Value
	delete(sessions, sessToken)

	http.SetCookie(w, &http.Cookie{
		Name:    "MASONSESSION",
		Value:   "",
		Expires: time.Now(),
	})

	http.Redirect(w, r, "/", http.StatusFound)

}
