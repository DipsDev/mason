package controllers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func csrf(req *http.Request) {
	const csrfTok = "THIS_IS_A_TEST"
	req.AddCookie(&http.Cookie{
		Name:  "csrf-token",
		Value: csrfTok,
	})
}

func form() url.Values {
	f := url.Values{}
	f.Add("csrf-token", "THIS_IS_A_TEST")
	return f
}

func TestLogin_Should_Fail_When_Empty_Credentials(t *testing.T) {
	loginForm := form()
	loginForm.Add("username", "")
	loginForm.Add("password", "")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	csrf(req)
	CreateLogin(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Login should return a 400 status code, got %s", resp.Status)
	}
}
