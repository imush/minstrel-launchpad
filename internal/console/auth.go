package console

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"
)

const (
	iterations   = 600_000
	sessionTTL   = 7 * 24 * time.Hour
	setupTTL     = time.Hour
	minPassword  = 8
	cookieName   = "launchpad_console"
	maxSessions  = 64
	setupCodeLen = 16
)

var (
	errBadPassword = errors.New("wrong password")
	errShort       = errors.New("use at least 8 characters")
	errBadSetup    = errors.New("the setup link is wrong, used or expired")
)

// Access guards the console: one password, set through a setup link that
// only someone who can read the launchpad's log or run its command line
// gets. The password protects the console only; the app's connections use
// their own device tokens.
type Access struct {
	path string

	mu       sync.Mutex
	stored   passwordFile
	sessions map[string]time.Time // hash → expiry
	setup    map[string]time.Time // setup code hash → expiry
}

type passwordFile struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

// OpenAccess loads the console password from path, if one is set.
func OpenAccess(path string) (*Access, error) {
	a := &Access{path: path, sessions: map[string]time.Time{}, setup: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	return a, json.Unmarshal(data, &a.stored)
}

// HasPassword reports whether a console password has been set.
func (a *Access) HasPassword() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stored.Hash != ""
}

// SetupCode makes a one-time code that lets its holder set the password,
// for the first visit or when it's forgotten.
func (a *Access) SetupCode() string {
	code := hex.EncodeToString(random(setupCodeLen))
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for h, exp := range a.setup {
		if now.After(exp) {
			delete(a.setup, h)
		}
	}
	a.setup[hashOf(code)] = now.Add(setupTTL)
	return code
}

// Setup sets a new password with a setup code, ends all sessions, and
// returns a session for the caller.
func (a *Access) Setup(code, password string) (string, error) {
	if len(password) < minPassword {
		return "", errShort
	}
	h := hashOf(code)
	a.mu.Lock()
	exp, ok := a.setup[h]
	delete(a.setup, h)
	a.mu.Unlock()
	if !ok || time.Now().After(exp) {
		return "", errBadSetup
	}
	salt := random(16)
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	stored := passwordFile{
		Salt:       base64.RawStdEncoding.EncodeToString(salt),
		Hash:       base64.RawStdEncoding.EncodeToString(key),
		Iterations: iterations,
	}
	data, _ := json.MarshalIndent(stored, "", "  ")
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return "", err
	}
	a.mu.Lock()
	a.stored = stored
	a.sessions = map[string]time.Time{}
	a.mu.Unlock()
	return a.newSession(), nil
}

// Login checks the password and returns a new session.
func (a *Access) Login(password string) (string, error) {
	a.mu.Lock()
	stored := a.stored
	a.mu.Unlock()
	if stored.Hash == "" {
		return "", errBadPassword
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(stored.Salt)
	want, err2 := base64.RawStdEncoding.DecodeString(stored.Hash)
	if err1 != nil || err2 != nil {
		return "", errors.New("console password file is damaged; set a new password")
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, stored.Iterations, len(want))
	if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		return "", errBadPassword
	}
	return a.newSession(), nil
}

func (a *Access) newSession() string {
	id := base64.RawURLEncoding.EncodeToString(random(32))
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for h, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, h)
		}
	}
	if len(a.sessions) >= maxSessions {
		for h := range a.sessions {
			delete(a.sessions, h)
			break
		}
	}
	a.sessions[hashOf(id)] = now.Add(sessionTTL)
	return id
}

// Valid reports whether session is a live session.
func (a *Access) Valid(session string) bool {
	if session == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[hashOf(session)]
	return ok && time.Now().Before(exp)
}

// Logout ends session.
func (a *Access) Logout(session string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, hashOf(session))
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
