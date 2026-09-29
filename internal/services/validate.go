package services

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const maxNameLength = 200

// validateName trims whitespace and checks non-empty / max length. It
// returns the trimmed value so callers never need to trim twice.
func validateName(label, name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("%w: %s is required", ErrValidation, label)
	}
	if len(trimmed) > maxNameLength {
		return "", fmt.Errorf("%w: %s must be %d characters or fewer", ErrValidation, label, maxNameLength)
	}
	return trimmed, nil
}

// validateSSHPort checks the port is in the valid TCP port range.
func validateSSHPort(port int32) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: ssh_port must be between 1 and 65535", ErrValidation)
	}
	return nil
}

// validateAddress checks addr is a plausible IP address or hostname. It
// deliberately doesn't attempt DNS resolution or connectivity -- Step 4
// only registers configuration, it never connects to anything.
func validateAddress(addr string) (string, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "", fmt.Errorf("%w: address is required", ErrValidation)
	}
	if net.ParseIP(trimmed) != nil {
		return trimmed, nil
	}
	// Not an IP -- accept it as a hostname if it looks like one (no
	// whitespace, no path/scheme characters).
	if strings.ContainsAny(trimmed, " \t\n/\\?#") {
		return "", fmt.Errorf("%w: address must be a valid IP address or hostname", ErrValidation)
	}
	return trimmed, nil
}

// validateWebhookURL checks a notification-policy webhook URL is
// well-formed and rejects the one class of target that can never be a
// legitimate webhook destination: loopback and link-local addresses --
// which includes the cloud-metadata endpoint every major provider exposes
// at a link-local IP (AWS/GCP/Azure's 169.254.169.254, ECS's
// 169.254.170.2). Ordinary private network ranges (10.x, 172.16.x,
// 192.168.x) are deliberately left unblocked: unlike the metadata service,
// a self-hosted internal webhook relay is a legitimate target for this
// application, and blocking them would break real deployments (spec §9:
// "do not break legitimate infrastructure connections"). This only
// inspects literal IP hosts, not resolved DNS -- a hostname is trusted the
// same way a database host or S3 endpoint already is.
func validateWebhookURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: webhook_url is required", ErrValidation)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: webhook_url is not a valid URL", ErrValidation)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: webhook_url must use http or https", ErrValidation)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: webhook_url must include a host", ErrValidation)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: webhook_url may not target a loopback or link-local address", ErrValidation)
		}
	}
	return nil
}
