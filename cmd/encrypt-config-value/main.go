// Command encrypt-config-value turns a plaintext secret into the
// ENC(base64...) form that belongs in development.ini.enc/production.ini.enc --
// the write-side counterpart to how internal/config/encrypted_env.go
// reads those files back. It never touches the ini files themselves:
// paste the printed line in yourself, next to the KEY it belongs to.
//
// Usage:
//
//	SECRET=<key> go run ./cmd/encrypt-config-value "the secret value"
//	SECRET=<key> go run ./cmd/encrypt-config-value   # reads one line from stdin instead
//
// The master key is never guessed or defaulted here (unlike the server's
// own local-development file fallback) -- this command has no
// development-vs-production context to decide whether that fallback
// would even be appropriate, so it always requires SECRET
// explicitly. Generate one with: go run ./cmd/gen-encryption-key
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"vmcontrolcenter/backend/internal/config"
)

func main() {
	key, err := config.SecretFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encrypt-config-value:", err)
		os.Exit(1)
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "encrypt-config-value: SECRET is not set (generate one with: go run ./cmd/gen-encryption-key)")
		os.Exit(1)
	}

	var plaintext string
	if len(os.Args) > 1 {
		plaintext = os.Args[1]
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "encrypt-config-value: no value given (pass it as an argument, or pipe one line to stdin)")
			os.Exit(1)
		}
		plaintext = strings.TrimSpace(scanner.Text())
	}
	if plaintext == "" {
		fmt.Fprintln(os.Stderr, "encrypt-config-value: value is empty")
		os.Exit(1)
	}

	encrypted, err := config.EncryptValue(key, plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encrypt-config-value:", err)
		os.Exit(1)
	}
	fmt.Println(encrypted)
}
