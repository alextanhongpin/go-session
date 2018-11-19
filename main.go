package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"
)

// TODO: Add encryption, and auto-refresh.
// Recommended by OWASP.
const cookieName = "id"

func main() {
	manager := NewManager(ManagerOptions{
		TTLSeconds: int64((1 * time.Hour).Seconds()),
		Storage:    NewInMemorySessionStorage(),
	})

	sess, err := manager.Init(w, r)
	if err != nil {
		log.Fatal(err)
	}
	sess.Set("name", "john")
	sess.Set("age", 10)
	if err := manager.Save(sess); err != nil {
		log.Fatal(err)
	}
	if err := manager.Clear(w, r); err != nil {
		log.Fatal(err)
	}
}

type Storage interface {
	Get(id string) (*Session, error)
	Put(id string, sess *Session) error
	Delete(id string) error
}

/*
type Session interface {
	IsValid() bool

	Set(key string, value interface{})
	Get(key string) interface{}

	Clear(storage Storage) error
	Write(storage Storage) error
	Read(storage Storage) error
}
*/

type Session struct {
	id        string
	createdAt time.Time
	expiresIn time.Duration
	values    map[string]interface{}
}

func NewSession(id string, expiresIn time.Duration) *Session {
	return &Session{
		id:        id,
		createdAt: time.Now(),
		expiresIn: expiresIn,
		values:    make(map[string]interface{}),
	}
}

func (s *Session) IsValid() bool {
	return time.Since(s.createdAt) < s.expiresIn
}

func (s *Session) Set(key string, value interface{}) {
	s.values[key] = value
}

func (s *Session) Get(key string) interface{} {
	value, _ := s.values[key]
	return value
}

func (s *Session) Clear(storage Storage) error {
	return storage.Delete(s.id)
}

func (s *Session) Write(storage Storage) error {
	return storage.Put(s.id, s)
}

func (s *Session) Read(storage Storage) error {
	sess, err := storage.Get(s.id)
	if err != nil {
		return err
	}
	*s = *sess
	return nil
}

// Use Login
// Read the cookie to check the session.
// Session exist, still valid -> Error, cannot have duplicate session.
// Session exist, but expired -> Refresh the session.
// Session does not exist -> Create a new session, and store it. Set the cookie and return.

type Manager interface {
	Init(w http.ResponseWriter, r *http.Request) (*Session, error)
	Clear(w http.ResponseWriter, r *http.Request) error
	Save(sess *Session) error
	// Can use redis expire key for this.
	// GC() error
}

// cookie.setMaxAge( 0 ) will delete the cookie right away.
// cookie.setMaxAge( -1 ) will preserve the cookie for a while and delete the cookie when the browser exits.

type ManagerOptions struct {
	TTLSeconds time.Duration
	Storage    Storage
}

type Manager struct {
	mu      sync.RWMutex
	options ManagerOptions
}

func NewManager(opts ManagerOptions) *Manager {
	return &Manager{opts}
}

func (m *Manager) sessionID(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (m *Manager) NewSession() (*Session, error) {
	sid, err := m.sessionID(32)
	if err != nil {
		return nil, err
	}
	session := NewSession(sid, m.options.TTLSeconds)
	err := session.Write(m.options.Storage)
	return session, err
}

// TODO: Encrypt value.
func (m *Manager) SetCookie(w http.ResponseWriter, sid string) {
	expiration := time.Now().Add(time.Duration(m.options.TTLSeconds) * time.Second)
	cookie := http.Cookie{
		Name:     cookieName,
		Path:     "/",
		Value:    sid,
		HttpOnly: true,
		Expires:  expiration,
		Secure:   true,
		MaxAge:   m.options.TTLSeconds,
	}
	http.SetCookie(w, &cookie)
}

func (m *Manager) clearSession(id string) error {
	session := &Session{ID: id}
	return session.Clear(m.options.Storage)
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     cookieName,
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		Expires:  time.Now().Add(-100 * time.Hour),
		Secure:   true,
		MaxAge:   -1,
	}
	http.SetCookie(w, &cookie)
}

func (m *Manager) Clear(w http.ResponseWriter, id string) error {
	m.clearCookie(w)
	return m.clearSession(is)
}

func (m *Manager) Init(w http.ResponseWriter, r *http.Request) (*Session, error) {
	// Get the cookie.
	id, err := m.read(r)
	if err != nil {
		// No cookie found, create new session.
		session, err := m.NewSession()
		if err != nil {
			return nil, err
		}
		// Store the session to the cookie.
		m.SetCookie(w, session.id)
		return session, nil
	}
	session := &Session{id: id}
	if err := session.Read(m.storage); err != nil {
		return nil, err
	}
	if !session.IsValid() {
		return nil, errors.New("session expired")
	}
	// 5% chance of renewing the session.
	return session, nil
}

func (m *Manager) read(r *http.Request) (string, error) {
	c, err := r.Cookie(cookieName)
	// http.ErrNoCookie
	if err != nil {
		return "", err
	}
	if c.Value == "" {
		return nil, errors.New("session_id is required")
	}
	return c.Value, nil
}

func (m *Manager) Clear(w http.ResponseWriter, r *http.Request) error {
	// Get the cookie containing the session id.
	id, err := m.read(r)
	if err != nil {
		return err
	}
	return m.clear(w, id)
}

func (m *Manager) Save(session *Session) error {
	return session.Write(m.options.Storage)
}
