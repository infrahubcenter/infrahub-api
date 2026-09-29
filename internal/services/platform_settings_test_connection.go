// Package services: platform_settings_test_connection.go implements the
// Owner-facing "Test Connection" probes for sign-in-method settings --
// mirrors the app's established Test Connection convention (classify the
// real outcome into the existing ConnectionTestStatus vocabulary already
// used for database connections, database_health.go; never a bespoke
// per-feature status enum).
//
// SMTP's test is a real, honest test: it sends one actual email. OAuth
// credentials cannot be tested that way -- a full "sign-in works" check
// needs a real browser consent redirect, which a backend-only probe can
// never do. What CAN be tested server-side, and is: whether the provider
// itself recognizes the Client ID/Secret pair at all, using each
// provider's own credential-check surface with a deliberately-invalid
// token/code -- the response distinguishes "bad credentials" from
// "credentials fine, the made-up token/code is (as expected) rejected."
// Callers must present this as "Credentials recognized," never "Login
// verified," so the UI doesn't overpromise what was actually checked.
package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// TestSMTP sends one real test email to recipientEmail using candidate's
// settings -- reuses sendSMTPMail (notification_provider.go), the exact
// same SMTP mechanics every other email this app sends already goes
// through, so a successful test is a genuine guarantee invites will work
// too, not a separate code path that could drift from the real one.
func TestSMTP(ctx context.Context, candidate SMTPUpdateInput, password, recipientEmail string) ConnectionTestStatus {
	settings := smtpSettings{
		host: candidate.Host, port: candidate.Port, username: candidate.Username,
		password: password, from: candidate.FromEmail, useTLS: candidate.UseTLS, timeout: smtpTestTimeout,
	}
	err := sendSMTPMail(ctx, settings, recipientEmail, "InfraHub test email",
		"This is a test email from InfraHub, confirming your SMTP settings are configured correctly. If you received this, invite emails will work.")
	return classifySMTPTestError(err)
}

func classifySMTPTestError(err error) ConnectionTestStatus {
	if err == nil {
		return ConnCONNECTED
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, "auth", "535", "534", "530", "authentication"):
		return ConnAUTHFAILED
	case containsAny(msg, "timeout", "timed out", "deadline exceeded"):
		return ConnTIMEOUT
	case containsAny(msg, "tls", "certificate", "x509"):
		return ConnTLSERROR
	case containsAny(msg, "connection refused", "no such host", "network is unreachable", "dial tcp"):
		return ConnREFUSED
	default:
		return ConnUNKNOWN
	}
}

// TestGitHubOAuthCredentials checks whether GitHub recognizes clientID/
// clientSecret as a real, matching OAuth App credential pair -- via
// GitHub's own "check a token" API (POST /applications/{client_id}/token,
// Basic-auth'd with client_id:client_secret), deliberately presenting a
// token that cannot possibly be real. GitHub validates the credentials
// BEFORE looking up the token: 401 means the credentials themselves are
// wrong; 404/422 means the credentials are fine and it's the made-up
// token (as expected) that wasn't found.
func TestGitHubOAuthCredentials(ctx context.Context, clientID, clientSecret string) ConnectionTestStatus {
	body := strings.NewReader(`{"access_token":"infrahub-credential-test-token"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.github.com/applications/"+url.PathEscape(clientID)+"/token", body)
	if err != nil {
		return ConnUNKNOWN
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: smtpTestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return classifyHTTPDialError(err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ConnAUTHFAILED
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return ConnCONNECTED
	default:
		return ConnUNKNOWN
	}
}

// TestGoogleOAuthCredentials checks whether Google recognizes clientID/
// clientSecret as a real, matching OAuth Client credential pair -- POSTs
// to Google's token endpoint with a deliberately-invalid authorization
// code. Google's error response distinguishes "invalid_client" (the
// credentials themselves are wrong) from "invalid_grant"/other (the
// credentials are fine, it's the made-up code that was, as expected,
// rejected).
func TestGoogleOAuthCredentials(ctx context.Context, clientID, clientSecret string) ConnectionTestStatus {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"infrahub-credential-test-code"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"https://infrahub.invalid/oauth-credential-test"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return ConnUNKNOWN
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: smtpTestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return classifyHTTPDialError(err)
	}
	defer resp.Body.Close()

	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)
	switch parsed.Error {
	case "invalid_client", "unauthorized_client":
		return ConnAUTHFAILED
	case "":
		return ConnUNKNOWN
	default:
		// invalid_grant, redirect_uri_mismatch, invalid_request, etc. --
		// every one of these means Google accepted the client_id/secret
		// pair and rejected something else about the deliberately-fake
		// request instead, exactly as expected.
		return ConnCONNECTED
	}
}

func classifyHTTPDialError(err error) ConnectionTestStatus {
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return ConnTIMEOUT
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, "tls", "certificate", "x509"):
		return ConnTLSERROR
	case containsAny(msg, "connection refused", "no such host", "network is unreachable"):
		return ConnREFUSED
	default:
		return ConnUNKNOWN
	}
}

