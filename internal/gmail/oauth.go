package gmail

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmailv1 "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const gmailScope = gmailv1.MailGoogleComScope

var (
	oauthOnce     sync.Once
	oauthCfg      *oauth2.Config
	statesMu      sync.Mutex
	pendingStates = map[string]time.Time{}
)

func oauthConfig() *oauth2.Config {
	oauthOnce.Do(func() {
		redirectURL := os.Getenv("OAUTH_REDIRECT_URL")
		if redirectURL == "" {
			redirectURL = "http://localhost:8080/oauth/callback"
		}
		oauthCfg = &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  redirectURL,
			Scopes:       []string{gmailScope},
			Endpoint:     google.Endpoint,
		}
	})
	return oauthCfg
}

// StartOAuth returns the Google consent URL.
func StartOAuth() (string, error) {
	state := randomHex(16)
	statesMu.Lock()
	pendingStates[state] = time.Now()
	statesMu.Unlock()
	go func() {
		time.Sleep(10 * time.Minute)
		statesMu.Lock()
		delete(pendingStates, state)
		statesMu.Unlock()
	}()
	url := oauthConfig().AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

// CallbackHandler handles /oauth/callback.
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	statesMu.Lock()
	_, ok := pendingStates[state]
	if ok {
		delete(pendingStates, state)
	}
	statesMu.Unlock()

	if !ok {
		http.Error(w, "invalid or expired OAuth state", http.StatusBadRequest)
		return
	}

	cfg := oauthConfig()
	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	svc, err := gmailService(context.Background(), cfg, token)
	if err != nil {
		http.Error(w, "gmail service error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	profile, err := svc.Users.GetProfile("me").Do()
	if err != nil {
		http.Error(w, "get profile error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "marshal token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	encToken, err := crypto.Encrypt(string(tokenJSON))
	if err != nil {
		http.Error(w, "encrypt token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	acct := models.Account{
		Label:     profile.EmailAddress,
		Email:     profile.EmailAddress,
		TokenJSON: encToken,
	}
	if err := db.DB.Create(&acct).Error; err != nil {
		http.Error(w, "save account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, `<html><body><h2>Account added! You can close this tab.</h2></body></html>`)
}

// GmailServiceForAccount returns an authenticated Gmail API service for the given account.
func GmailServiceForAccount(ctx context.Context, acct *models.Account) (*gmailv1.Service, error) {
	cfg := oauthConfig()
	dec, err := crypto.Decrypt(acct.TokenJSON)
	if err != nil {
		return nil, fmt.Errorf("decrypt token: %w", err)
	}
	var token oauth2.Token
	if err := json.Unmarshal([]byte(dec), &token); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return gmailService(ctx, cfg, &token)
}

func gmailService(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*gmailv1.Service, error) {
	ts := cfg.TokenSource(ctx, token)
	return gmailv1.NewService(ctx, option.WithTokenSource(ts))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
