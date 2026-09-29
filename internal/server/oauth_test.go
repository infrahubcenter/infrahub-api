// This file exercises AuthService.LoginWithVerifiedEmail (the OAuth-login
// counterpart to Login) directly against the service, since actually
// exchanging an OAuth code requires real GitHub/Google credentials this
// dev environment doesn't have -- what's fully testable without those is
// the invite-only account-lookup logic itself: an existing active user
// gets a session, an unknown email is rejected, a disabled account is
// rejected. See services/oauth.go's own doc comment for the provider
// exchange half, which is not covered here.
package server_test

import (
	"context"
	"errors"
	"testing"

	"vmcontrolcenter/backend/internal/services"
)

func TestAuthService_LoginWithVerifiedEmail_ExistingActiveUser_IssuesSession(t *testing.T) {
	e := setup(t)
	memberEmail, _, memberID := e.createMember(t)

	session, err := e.auth.LoginWithVerifiedEmail(context.Background(), memberEmail)
	if err != nil {
		t.Fatalf("LoginWithVerifiedEmail = %v, want nil error", err)
	}
	if session.User.ID != memberID {
		t.Errorf("session.User.ID = %v, want %v", session.User.ID, memberID)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Error("expected a real access/refresh token pair")
	}
}

func TestAuthService_LoginWithVerifiedEmail_UnknownEmail_NoAccount(t *testing.T) {
	e := setup(t)

	_, err := e.auth.LoginWithVerifiedEmail(context.Background(), uniqueEmail(t, "no-such-user"))
	if !errors.Is(err, services.ErrNoAccountForEmail) {
		t.Fatalf("err = %v, want ErrNoAccountForEmail", err)
	}
}

func TestAuthService_LoginWithVerifiedEmail_DisabledAccount_Rejected(t *testing.T) {
	e := setup(t)
	memberEmail, _, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminUser, err := e.auth.Login(context.Background(), adminEmail, adminPassword)
	if err != nil {
		t.Fatalf("admin login fixture: %v", err)
	}

	isActive := false
	if _, _, err := e.auth.UpdateUserAccount(context.Background(), adminUser.User.ID, memberID, services.UpdateUserAccountInput{IsActive: &isActive}); err != nil {
		t.Fatalf("disable member fixture: %v", err)
	}

	_, err = e.auth.LoginWithVerifiedEmail(context.Background(), memberEmail)
	if !errors.Is(err, services.ErrAccountDisabled) {
		t.Fatalf("err = %v, want ErrAccountDisabled", err)
	}
}
