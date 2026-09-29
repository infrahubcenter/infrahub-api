// This file exercises the EMAIL/SLACK/TEAMS notification providers
// directly against real servers (a minimal hand-rolled SMTP server for
// EMAIL, real httptest.Servers for SLACK/TEAMS) -- proving each one
// actually speaks its real wire protocol rather than mocking the
// NotificationProvider interface, mirroring this project's established
// "fake server, not a mock" testing convention. Deliberately at the
// provider level, not through the full alert-evaluation pipeline (Alert
// creation/dedup/etc.), since that's already covered elsewhere and adds
// unrelated moving parts to what's being verified here.
package services

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTPServer speaks just enough SMTP (RFC 5321) -- EHLO, MAIL FROM,
// RCPT TO, DATA, QUIT -- to accept one message from a real net/smtp
// client and hand its raw text back to the test.
type fakeSMTPServer struct {
	addr     string
	received chan string
}

func startFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{addr: ln.Addr().String(), received: make(chan string, 1)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 fake.smtp.local ESMTP")

	var dataLines []string
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				s.received <- strings.Join(dataLines, "\n")
				write("250 OK: message accepted")
				continue
			}
			dataLines = append(dataLines, line)
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-fake.smtp.local")
			write("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			write("250 OK")
		case upper == "DATA":
			inData = true
			dataLines = nil
			write("354 Start mail input")
		case upper == "QUIT":
			write("221 Bye")
			return
		default:
			write("500 unrecognized command")
		}
	}
}

func TestEmailProvider_Send_DeliversOverRealSMTP(t *testing.T) {
	server := startFakeSMTPServer(t)
	host, portStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	p := NewEmailProvider(host, int32(port), "", "", "notifications@infrahub.local", false, 5*time.Second)
	payload := NotificationPayload{
		Severity: AlertSeverityCritical, Title: "VM CPU critical", Body: "CPU usage is 95%",
		ResourceName: "web-1", ResourceType: "VM", RecipientEmail: "admin@example.com",
	}
	if err := p.Send(context.Background(), payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case msg := <-server.received:
		if !strings.Contains(msg, "web-1") {
			t.Errorf("expected the message body to mention the resource name, got: %s", msg)
		}
		if !strings.Contains(msg, "Subject: [InfraHub][CRITICAL] VM CPU critical") {
			t.Errorf("expected a subject line reflecting severity/title, got: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake SMTP server never received the message")
	}
}

func TestEmailProvider_Validate_RequiresHostAndRecipient(t *testing.T) {
	unconfigured := NewEmailProvider("", 587, "", "", "from@x.com", false, time.Second)
	if err := unconfigured.Validate(NotificationPayload{RecipientEmail: "a@b.com"}); err == nil {
		t.Error("expected an error when SMTP host is unconfigured")
	}

	configured := NewEmailProvider("smtp.example.com", 587, "", "", "from@x.com", false, time.Second)
	if err := configured.Validate(NotificationPayload{}); err == nil {
		t.Error("expected an error when the payload has no recipient email")
	}
}

func TestSlackProvider_Send_PostsExpectedPayload(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewSlackProvider(5 * time.Second)
	payload := NotificationPayload{
		Severity: AlertSeverityWarning, Title: "Disk space low", Body: "Disk usage is 85%",
		ResourceName: "db-1", ResourceType: "DATABASE", SlackWebhookURL: server.URL,
	}
	if err := p.Send(context.Background(), payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if receivedBody["text"] == "" || !strings.Contains(receivedBody["text"], "Disk space low") {
		t.Errorf("expected the Slack message text to include the alert title, got: %v", receivedBody)
	}
}

func TestSlackProvider_Send_MissingURL_ReturnsClearError(t *testing.T) {
	p := NewSlackProvider(5 * time.Second)
	if err := p.Send(context.Background(), NotificationPayload{}); err == nil {
		t.Fatal("expected an error when no Slack webhook URL is configured")
	}
}

func TestTeamsProvider_Send_PostsMessageCard(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewTeamsProvider(5 * time.Second)
	payload := NotificationPayload{
		Severity: AlertSeverityCritical, Title: "Object storage unreachable", Body: "Connection refused",
		ResourceName: "backups", ResourceType: "OBJECT_STORAGE", TeamsWebhookURL: server.URL,
	}
	if err := p.Send(context.Background(), payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if receivedBody["@type"] != "MessageCard" {
		t.Errorf("expected a MessageCard payload, got: %v", receivedBody)
	}
	title, _ := receivedBody["title"].(string)
	if !strings.Contains(title, "Object storage unreachable") {
		t.Errorf("expected the card title to include the alert title, got: %v", receivedBody)
	}
}

func TestTeamsProvider_Send_MissingURL_ReturnsClearError(t *testing.T) {
	p := NewTeamsProvider(5 * time.Second)
	if err := p.Send(context.Background(), NotificationPayload{}); err == nil {
		t.Fatal("expected an error when no Teams webhook URL is configured")
	}
}
