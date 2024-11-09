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
	expiration := time.Now().Add(common.SessionTimout)
	ck := http.Cookie{Name: name, Value: value, Expires: expiration, SameSite: http.SameSiteLaxMode, Path: "/", HttpOnly: true} // add secure in prod
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

	stmtOut, err := common.DB.Prepare("SELECT password, id, email, username, role FROM users WHERE email = ? OR username = ?")
	defer stmtOut.Close()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var passwordSQL []byte
	var sqlUser common.User
	err = stmtOut.QueryRow(email, email).Scan(&passwordSQL, &sqlUser.Id, &sqlUser.Email, &sqlUser.Username, &sqlUser.Role)
	if err != nil {
		pages.Login(r.Form.Get("csrf-token"), "Incorrect username or password").Render(r.Context(), w)
		return
	}

	err = bcrypt.CompareHashAndPassword(passwordSQL, []byte(password))
	if err != nil {
		pages.Login(r.Form.Get("csrf-token"), "Incorrect username or password").Render(r.Context(), w)
		return
	}

	// create a session cookie
	sess := common.SessionStore.CreateSession(&sqlUser)
	cookie := createCookie(common.SessionName, sess.Id)
	http.SetCookie(w, cookie)

	// Redirect user to dashboard
	http.Redirect(w, r, "/panel", http.StatusFound)

}

func HandleLogout(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie(common.SessionName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessToken := c.Value
	common.SessionStore.DeleteSession(sessToken)

	http.SetCookie(w, &http.Cookie{
		Name:    common.SessionName,
		Value:   "",
		Expires: time.Now(),
	})

	http.Redirect(w, r, "/", http.StatusFound)

}
