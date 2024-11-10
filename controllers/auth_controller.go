package controllers

import (
	"crypto/rand"
	"database/sql"
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

type loginViewModel struct {
	errorMessage string
	statusCode   int
}

func ShowLogin(w http.ResponseWriter, r *http.Request) {
	csrf := generateCsrf()
	http.SetCookie(w, createCookie("csrf-token", csrf))
	pages.Login(csrf, "").Render(r.Context(), w)

}

func CreateLogin(w http.ResponseWriter, r *http.Request) {
	result := createLogin(w, r)
	if result.statusCode == http.StatusOK {
		http.Redirect(w, r, "/panel", http.StatusFound)
		return
	}
	pages.Login(r.FormValue("csrf-token"), result.errorMessage).Render(r.Context(), w)
}

func createLogin(w http.ResponseWriter, r *http.Request) loginViewModel {

	err := r.ParseForm()
	if err != nil {
		return loginViewModel{errorMessage: "An unexpected error occurred.", statusCode: http.StatusInternalServerError}

	}
	if r.Form.Get("csrf-token") == "" || !validateCsrf(r.Form.Get("csrf-token"), r) {
		return loginViewModel{errorMessage: "Invalid csrf.", statusCode: http.StatusBadRequest}
	}
	email := r.Form.Get("email")
	password := r.Form.Get("password")
	if email == "" || password == "" {
		return loginViewModel{errorMessage: "The password or username used are incorrect.", statusCode: http.StatusBadRequest}
	}

	var passwordSQL []byte
	var sqlUser common.User
	rows := common.DB.QueryRow("SELECT users.password, users.id, users.email, users.username, users.role from users where email = ? or username = ?",
		email, email)

	if err := rows.Scan(&passwordSQL, &sqlUser.Id, &sqlUser.Email, &sqlUser.Username, &sqlUser.Role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return loginViewModel{errorMessage: "The password or username used are incorrect.", statusCode: http.StatusUnauthorized}
		}
		return loginViewModel{errorMessage: "An unexpected error occurred.", statusCode: http.StatusInternalServerError}
	}

	err = bcrypt.CompareHashAndPassword(passwordSQL, []byte(password))
	if err != nil {
		return loginViewModel{errorMessage: "The password or username used are incorrect.", statusCode: http.StatusUnauthorized}
	}

	// create a session cookie
	sess := common.SessionStore.CreateSession(&sqlUser)
	cookie := createCookie(common.SessionName, sess.Id)
	http.SetCookie(w, cookie)

	// Redirect user to dashboard
	return loginViewModel{errorMessage: "", statusCode: http.StatusOK}

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
