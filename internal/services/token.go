package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessTokenClaims are the only claims placed in the access token JWT.
// Deliberately minimal: identity, role, and a token ID for traceability --
// never passwords, credentials, or anything else sensitive.
type AccessTokenClaims struct {
	UserID uuid.UUID `json:"sub"`
	Role   string    `json:"role"`
	jwt.RegisteredClaims
}

// TokenService issues and verifies access tokens and generates refresh
// token values.
type TokenService struct {
	secret    []byte
	accessTTL time.Duration
}

// NewTokenService creates a TokenService. secret signs/verifies access
// tokens (HMAC-SHA256); accessTTL is how long an issued access token
// remains valid.
func NewTokenService(secret string, accessTTL time.Duration) *TokenService {
	return &TokenService{secret: []byte(secret), accessTTL: accessTTL}
}

// IssueAccessToken creates a signed, short-lived JWT for userID/role.
func (s *TokenService) IssueAccessToken(userID uuid.UUID, role string) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// WSTicketAudience marks a WebSocket ticket: a short-lived token a console
// served from another site (e.g. the hosted console on Vercel, whose login
// cookie never reaches this backend's own domain) passes as ?ws_ticket= to
// open a WebSocket directly to this API. RequireAuthentication accepts it
// only on WebSocket upgrades, and never accepts it as a normal login.
const WSTicketAudience = "ws-ticket"

// WSTicketTTL is how long a WebSocket ticket can be used to open a
// connection (an already-open connection is unaffected by it expiring).
const WSTicketTTL = 2 * time.Minute

// IssueWSTicket creates a WebSocket ticket for userID/role.
func (s *TokenService) IssueWSTicket(userID uuid.UUID, role string) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{WSTicketAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(WSTicketTTL)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign ws ticket: %w", err)
	}
	return signed, nil
}

// IsWSTicket reports whether claims belong to a WebSocket ticket.
func IsWSTicket(claims *AccessTokenClaims) bool {
	for _, a := range claims.Audience {
		if a == WSTicketAudience {
			return true
		}
	}
	return false
}

// ParseAccessToken validates signature and expiry and returns the claims.
func (s *TokenService) ParseAccessToken(tokenString string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}
	return claims, nil
}

// AccessTTL returns the configured access token lifetime.
func (s *TokenService) AccessTTL() time.Duration {
	return s.accessTTL
}

// GenerateRefreshToken creates a new high-entropy refresh token. It returns
// both the plaintext value (sent to the client, never persisted) and its
// SHA-256 hex hash (the only form written to refresh_tokens.token_hash).
func GenerateRefreshToken() (plain string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	return plain, HashRefreshToken(plain), nil
}

// HashRefreshToken hashes a refresh token value for lookup/storage. Refresh
// tokens are high-entropy random values (not user-chosen secrets), so a
// fast cryptographic hash is appropriate here -- unlike passwords, which
// use Argon2id.
func HashRefreshToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
