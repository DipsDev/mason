package controllers

import (
	"github.com/DipsDev/mason/common"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	common.InitDatabase("root:root@/mason")
	m.Run()
	common.CloseDatabase()
}

func csrf(req *http.Request) {
	const csrfTok = "THIS_IS_A_TEST"
	req.AddCookie(&http.Cookie{
		Name:  "csrf-token",
		Value: csrfTok,
	})
}

func form(email string, password string) url.Values {
	f := url.Values{}
	f.Add("csrf-token", "THIS_IS_A_TEST")
	f.Add("email", email)
	f.Add("password", password)
	return f
}

func TestLogin_Should_Fail_When_Empty_Credentials(t *testing.T) {
	loginForm := form("", "")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	csrf(req)
	result := createLogin(w, req)
	if result.statusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, result.statusCode)
	}

}

func TestLogin_Should_Fail_When_Csrf_Invalid(t *testing.T) {
	loginForm := form("test", "test")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	result := createLogin(w, req)
	if result.statusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, result.statusCode)
	}
}

func TestLogin_Should_Fail_When_Credentials_Are_Invalid(t *testing.T) {
	loginForm := form("test", "test")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	csrf(req)
	result := createLogin(w, req)
	if result.statusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d. %s", http.StatusUnauthorized, result.statusCode, result.errorMessage)
	}
}
