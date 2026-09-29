// Command gen-encryption-key prints a fresh base64-encoded 32-byte key
// suitable for SSH_CREDENTIAL_ENCRYPTION_KEY. It does not read or write
// anything else -- run it once per environment and store the output as a
// secret (never commit it).
package main

import (
	"fmt"
	"os"

	"vmcontrolcenter/backend/internal/services"
)

func main() {
	key, err := services.GenerateEncryptionKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-encryption-key:", err)
		os.Exit(1)
	}
	fmt.Println(key)
}
