package common

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/net/context"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	Id       string
	UserId   string
	Email    string
	Username string
	Expiry   time.Time
	// add more as project grows
}

type SessionProvider struct {
	sessions map[string]*Session
	lock     sync.RWMutex
}

func (s *Session) Expired() bool {
	return time.Now().After(s.Expiry)
}

var SessionStore = &SessionProvider{sessions: make(map[string]*Session)}
var SessionName = "__MASONSESSION"

func generateId() string {
	b := make([]byte, 33)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (sp *SessionProvider) CreateSession(user *User) *Session {
	id := generateId()

	sess := &Session{
		Expiry:   time.Now().Add(12 * time.Minute),
		Id:       id,
		Username: user.Username,
		Email:    user.Email,
		UserId:   user.Id,
	}

	sp.lock.Lock()
	sp.sessions[id] = sess
	sp.lock.Unlock()

	return sess

}

func (sp *SessionProvider) DeleteSession(token string) {
	sp.lock.Lock()
	delete(sp.sessions, token)
	sp.lock.Unlock()
}

// GetSession returns the found session in the http request, or nil of doesn't exist
func (sp *SessionProvider) GetSession(r *http.Request) *Session {
	cookie, err := r.Cookie(SessionName)
	if err != nil {
		return nil
	}

	sp.lock.RLock()
	sess := sp.sessions[cookie.Value]
	sp.lock.RUnlock()
	return sess
}

type contextKey string

var contextClass = contextKey("session")

// WithSession is a middleware for getting user's session regardless if he is authenticated or not.
// it allows usage of GetSession inside the required templates.
func WithSession(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextClass, SessionStore.GetSession(r))
		next(w, r.WithContext(ctx))
	})
}

// WithAuth is a middleware for getting user's session only if they are logged in.
// it redirects to login if the user isn't logged in.
// it allows usage of GetSession inside the required templates.
func WithAuth(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionStore.GetSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), contextClass, sess)
		next(w, r.WithContext(ctx))
	})
}

// GetSession fetches the session data from a given context.
// it should be paired with WithAuth or WithSession if used.
// it returns the current user session, and whether the user is authenticated or not.
func GetSession(ctx context.Context) (*Session, bool) {
	if sess, ok := ctx.Value(contextClass).(*Session); ok {
		return sess, true
	}
	return nil, false
}
