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
	Id        string
	CsrfToken string
	UserId    string
	Email     string
	Username  string
	Role      userRole
	Expiry    time.Time
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

const SessionName = "MAID"

const SessionTimout = 7 * time.Minute

func generateId() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (sp *SessionProvider) CreateSession(user *User) *Session {
	id := generateId()

	sess := &Session{
		Expiry:    time.Now().Add(SessionTimout),
		CsrfToken: generateId(),
		Id:        id,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		UserId:    user.Id,
	}

	sp.lock.Lock()
	sp.sessions[id] = sess
	sp.lock.Unlock()

	return sess
}

func (sp *SessionProvider) CopySession(sess *Session) *Session {
	newId := generateId()

	newSess := &Session{
		Expiry:    time.Now().Add(SessionTimout),
		CsrfToken: sess.CsrfToken,
		Id:        newId,
		Username:  sess.Username,
		Email:     sess.Email,
		Role:      sess.Role,
		UserId:    sess.UserId,
	}

	sp.lock.Lock()
	sp.sessions[newId] = newSess
	sp.lock.Unlock()
	return newSess
}

func (sp *SessionProvider) DeleteSession(token string) {
	sp.lock.Lock()
	delete(sp.sessions, token)
	sp.lock.Unlock()
}

// GetServerSession returns the session stored in the server, returns nil if not found.
func (sp *SessionProvider) GetServerSession(r *http.Request) *Session {
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
		ctx := context.WithValue(r.Context(), contextClass, SessionStore.GetServerSession(r))
		next(w, r.WithContext(ctx))
	})
}

// WithAuth is a middleware for getting user's session only if they are logged in.
// it redirects to login if the user isn't logged in.
// it allows usage of GetSession inside the required templates.
func WithAuth(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionStore.GetServerSession(r)

		// If not session, then redirect to login
		if sess == nil || sess.Expired() {
			if r.Header.Get("HX-Request") != "" {
				w.Header().Set("HX-Redirect", "/login")
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Refresh session
		newSess := SessionStore.CopySession(sess)

		ck := &http.Cookie{Name: SessionName, Value: newSess.Id, Path: "/", Expires: newSess.Expiry, SameSite: http.SameSiteLaxMode, HttpOnly: true}
		http.SetCookie(w, ck)

		// Delete old session
		SessionStore.DeleteSession(sess.Id)

		ctx := context.WithValue(r.Context(), contextClass, newSess)
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

// GetSessionUser fetches the user from the session data context.
// it returns the data in the database, at oppose to GetSession, that returns the data stored in the session - which is not reliable.
// it returns nil if the user is not logged in.
func GetSessionUser(ctx context.Context) *User {
	sess, ok := GetSession(ctx)
	if !ok {
		return nil
	}
	stmtOut, err := DB.Prepare("SELECT id, username, email, role FROM users WHERE id = ?")
	if err != nil {
		return nil
	}
	defer stmtOut.Close()

	var user User

	err = stmtOut.QueryRow(sess.UserId).Scan(&user.Id, &user.Username, &user.Email, &user.Role)
	if err != nil {
		return nil
	}
	return &user

}
