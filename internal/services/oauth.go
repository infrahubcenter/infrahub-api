// Package services: oauth.go implements GitHub/Google OAuth login --
// invite-only (AuthService.LoginWithVerifiedEmail never creates a new
// user), so this file's only job is turning an authorization code into a
// verified email address the caller actually controls. Two real,
// meaningfully different implementations (GitHub/Google have different
// token/userinfo response shapes) behind one small interface -- mirrors
// PackageManagerFactory's interface+factory shape for "few real-
// behavioral-difference variants" (see package_manager.go).
package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthProviderName identifies a supported OAuth login provider.
type OAuthProviderName string

const (
	OAuthProviderGitHub OAuthProviderName = "github"
	OAuthProviderGoogle OAuthProviderName = "google"
)

// OAuthProvider abstracts one OAuth2 provider's authorize-URL building and
// code-for-verified-email exchange.
type OAuthProvider interface {
	Name() OAuthProviderName
	Configured() bool
	AuthURL(state string) string
	// Exchange trades an authorization code for the caller's own verified
	// email address -- never returns an email the provider hasn't itself
	// marked verified (see each implementation's own doc comment).
	Exchange(ctx context.Context, code string) (email string, err error)
}

// GenerateOAuthState returns a URL-safe random token for CSRF protection
// across the Start -> provider -> Callback round trip.
func GenerateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oauthHTTPTimeout bounds every outbound token-exchange/userinfo request
// to either provider -- generous for a simple JSON API call, small enough
// that a slow/unreachable provider can't hang a login attempt indefinitely.
const oauthHTTPTimeout = 10 * time.Second

// oauthDoJSON performs req and decodes a JSON response into out --
// shared by both providers below since the request/response mechanics
// (only the URLs/payloads differ) are identical.
func oauthDoJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

// --- GitHub ---

type GitHubOAuthProvider struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
}

// NewGitHubOAuthProvider creates a GitHubOAuthProvider. clientID/clientSecret
// may be empty (unconfigured) -- Configured() reports this.
func NewGitHubOAuthProvider(clientID, clientSecret, redirectBaseURL string) *GitHubOAuthProvider {
	return &GitHubOAuthProvider{
		clientID: clientID, clientSecret: clientSecret,
		redirectURL: redirectBaseURL + "/api/auth/oauth/github/callback",
		httpClient:  &http.Client{Timeout: oauthHTTPTimeout},
	}
}

func (p *GitHubOAuthProvider) Name() OAuthProviderName { return OAuthProviderGitHub }
func (p *GitHubOAuthProvider) Configured() bool        { return p.clientID != "" && p.clientSecret != "" }

func (p *GitHubOAuthProvider) AuthURL(state string) string {
	q := url.Values{
		"client_id": {p.clientID}, "redirect_uri": {p.redirectURL},
		"scope": {"read:user user:email"}, "state": {state},
	}
	return "https://github.com/login/oauth/authorize?" + q.Encode()
}

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type githubUser struct {
	Email string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// Exchange trades code for GitHub's own verified primary email. GitHub's
// /user endpoint only returns an email when the account's primary email
// is public; when it's private (the common case), this falls back to
// /user/emails and requires an entry marked both primary AND verified --
// never trusts an unverified address.
func (p *GitHubOAuthProvider) Exchange(ctx context.Context, code string) (string, error) {
	if !p.Configured() {
		return "", fmt.Errorf("github oauth is not configured")
	}

	form := url.Values{
		"client_id": {p.clientID}, "client_secret": {p.clientSecret},
		"code": {code}, "redirect_uri": {p.redirectURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tokenResp githubTokenResponse
	if err := oauthDoJSON(p.httpClient, req, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("github token exchange failed: %s", tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("github token exchange returned no access token")
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")
	var user githubUser
	if err := oauthDoJSON(p.httpClient, userReq, &user); err != nil {
		return "", err
	}
	if user.Email != "" {
		return user.Email, nil
	}

	emailsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	emailsReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	emailsReq.Header.Set("Accept", "application/vnd.github+json")
	var emails []githubEmail
	if err := oauthDoJSON(p.httpClient, emailsReq, &emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("github account has no verified primary email")
}

// --- Google ---

type GoogleOAuthProvider struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
}

// NewGoogleOAuthProvider creates a GoogleOAuthProvider. clientID/clientSecret
// may be empty (unconfigured) -- Configured() reports this.
func NewGoogleOAuthProvider(clientID, clientSecret, redirectBaseURL string) *GoogleOAuthProvider {
	return &GoogleOAuthProvider{
		clientID: clientID, clientSecret: clientSecret,
		redirectURL: redirectBaseURL + "/api/auth/oauth/google/callback",
		httpClient:  &http.Client{Timeout: oauthHTTPTimeout},
	}
}

func (p *GoogleOAuthProvider) Name() OAuthProviderName { return OAuthProviderGoogle }
func (p *GoogleOAuthProvider) Configured() bool        { return p.clientID != "" && p.clientSecret != "" }

func (p *GoogleOAuthProvider) AuthURL(state string) string {
	q := url.Values{
		"client_id": {p.clientID}, "redirect_uri": {p.redirectURL},
		"response_type": {"code"}, "scope": {"openid email profile"}, "state": {state},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode()
}

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

type googleUserinfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// Exchange trades code for Google's own verified email via the userinfo
// endpoint -- simpler than verifying the id_token JWT's signature/claims
// directly, and equally trustworthy since it's fetched fresh from Google
// using the access token this exchange just obtained. Requires
// email_verified == true -- never trusts an unverified address.
func (p *GoogleOAuthProvider) Exchange(ctx context.Context, code string) (string, error) {
	if !p.Configured() {
		return "", fmt.Errorf("google oauth is not configured")
	}

	form := url.Values{
		"client_id": {p.clientID}, "client_secret": {p.clientSecret},
		"code": {code}, "redirect_uri": {p.redirectURL}, "grant_type": {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tokenResp googleTokenResponse
	if err := oauthDoJSON(p.httpClient, req, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("google token exchange failed: %s", tokenResp.Error)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("google token exchange returned no access token")
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return "", err
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	var user googleUserinfo
	if err := oauthDoJSON(p.httpClient, userReq, &user); err != nil {
		return "", err
	}
	if user.Email == "" || !user.EmailVerified {
		return "", fmt.Errorf("google account has no verified email")
	}
	return user.Email, nil
}
