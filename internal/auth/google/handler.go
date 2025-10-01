package google

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	appconfig "demo/internal/config"
)

const (
	defaultUserInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// Handler manages the Google OAuth 2.0 authorization flow.
type Handler struct {
	oauthConfig      *oauth2.Config
	userInfoEndpoint string
	stateCookie      appconfig.OAuthStateCookieConfig
}

// NewHandler constructs a Google OAuth handler using application configuration.
func NewHandler(cfg appconfig.GoogleOAuthConfig) (*Handler, error) {
	if !cfg.Enabled {
		return nil, errors.New("google oauth is disabled")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("google oauth client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("google oauth client secret is required")
	}
	redirectURL := strings.TrimSpace(cfg.RedirectURL)
	if redirectURL == "" {
		return nil, errors.New("google oauth redirect url is required")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       append([]string(nil), scopes...),
		Endpoint:     google.Endpoint,
	}

	handler := &Handler{
		oauthConfig:      oauthConfig,
		userInfoEndpoint: defaultUserInfoEndpoint,
		stateCookie:      cfg.StateCookie,
	}

	if handler.stateCookie.Name == "" {
		handler.stateCookie.Name = "oauth_state"
	}
	if handler.stateCookie.Path == "" {
		handler.stateCookie.Path = "/"
	}
	if handler.stateCookie.MaxAge <= 0 {
		handler.stateCookie.MaxAge = 600
	}

	return handler, nil
}

// Login initiates the OAuth authorization code flow by redirecting to Google.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		log.Printf("event=google_oauth_state_generation_failed error=%v", err)
		http.Error(w, "failed to initiate oauth flow", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, h.buildStateCookie(state))

	authURL := h.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback completes the OAuth authorization code flow and returns Google user information.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errType := r.URL.Query().Get("error"); errType != "" {
		description := r.URL.Query().Get("error_description")
		if description == "" {
			description = "authorization failed"
		}
		http.Error(w, fmt.Sprintf("google oauth error: %s", description), http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(h.stateCookie.Name)
	if err != nil {
		http.Error(w, "oauth state cookie not found", http.StatusBadRequest)
		return
	}

	if !constantTimeEqual(stateCookie.Value, state) {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}

	// Clear the state cookie after validation.
	http.SetCookie(w, h.clearStateCookie())

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := h.oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("event=google_oauth_exchange_failed error=%v", err)
		http.Error(w, "failed to exchange authorization code", http.StatusBadGateway)
		return
	}

	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Get(h.userInfoEndpoint)
	if err != nil {
		log.Printf("event=google_oauth_userinfo_request_failed error=%v", err)
		http.Error(w, "failed to retrieve user information", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("event=google_oauth_userinfo_http_error status=%d", resp.StatusCode)
		http.Error(w, "unexpected response from google userinfo endpoint", http.StatusBadGateway)
		return
	}

	var userInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("event=google_oauth_userinfo_decode_failed error=%v", err)
		http.Error(w, "failed to decode user information", http.StatusBadGateway)
		return
	}

	writeJSON(w, userInfo)
}

func (h *Handler) buildStateCookie(value string) *http.Cookie {
	maxAge := h.stateCookie.MaxAge
	expires := time.Now().Add(time.Duration(maxAge) * time.Second)

	return &http.Cookie{
		Name:     h.stateCookie.Name,
		Value:    value,
		Path:     h.stateCookie.Path,
		Domain:   h.stateCookie.Domain,
		Secure:   h.stateCookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}

func (h *Handler) clearStateCookie() *http.Cookie {
	return &http.Cookie{
		Name:     h.stateCookie.Name,
		Path:     h.stateCookie.Path,
		Domain:   h.stateCookie.Domain,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   h.stateCookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("event=google_oauth_response_write_failed error=%v", err)
	}
}
