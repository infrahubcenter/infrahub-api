// Command infrahub-config creates and reads the encrypted per-stage config
// files (<stage>.ini.enc) that internal/config loads -- see
// internal/config/encrypted_env.go.
//
// Each stage has a plain file you edit locally (never committed) and the
// encrypted file the API reads:
//
//	development.ini  --encrypt-->  development.ini.enc
//	development.ini  <--decrypt--  development.ini.enc
//
//	infrahub-config encrypt --stage development   # development.ini -> development.ini.enc
//	infrahub-config decrypt --stage development   # development.ini.enc -> development.ini
//	infrahub-config convert --stage development   # old per-value ENC(...) file -> whole-file
//
// --in/--out override the file names; "-" means stdin/stdout. decrypt
// won't overwrite an existing plain file unless --force is given.
// Wrapper for this repo: ./config.sh encrypt|decrypt [stage]
//
// The secret (master key) comes from SECRET or SECRET_FILE
// (generate one with gen-encryption-key). The stage is bound into the
// ciphertext: a file encrypted for staging only opens as staging.
//
// In the API image: docker run --rm -e SECRET -v "$PWD:/w" -w /w \
//
//	docker.io/infrahubcenter/infrahub-api:1.0.0 /app/infrahub-config encrypt --stage production
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"vmcontrolcenter/backend/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	stage := fs.String("stage", "", "development | staging | production")
	in := fs.String("in", "", "input file")
	out := fs.String("out", "", "output file")
	force := fs.Bool("force", false, "decrypt: overwrite an existing plain file")
	_ = fs.Parse(os.Args[2:])

	if !slices.Contains(config.Stages, *stage) {
		fail("--stage must be one of " + strings.Join(config.Stages, ", "))
	}
	key := masterKey()
	plainFile, encFile := *stage+".ini", *stage+".ini.enc"

	switch cmd {
	case "encrypt":
		*in, *out = or(*in, plainFile), or(*out, encFile)
		plain := read(*in)
		if config.IsEncryptedFile(plain) {
			fail(*in + " is already encrypted")
		}
		write(*out, encrypt(key, *stage, plain))
		if *out != "-" {
			fmt.Fprintf(os.Stderr, "wrote %s (stage %s)\n", *out, *stage)
		}
	case "decrypt":
		*in, *out = or(*in, encFile), or(*out, plainFile)
		plain, err := config.DecryptFile(key, *stage, read(*in))
		if err != nil {
			fail(err.Error())
		}
		if *out != "-" && !*force {
			if _, err := os.Stat(*out); err == nil {
				fail(*out + " already exists -- edit it, or pass --force to replace it")
			}
		}
		write(*out, plain)
		if *out != "-" {
			fmt.Fprintf(os.Stderr, "wrote %s -- edit it, then: infrahub-config encrypt --stage %s\n", *out, *stage)
		}
	case "convert":
		*in, *out = or(*in, encFile), or(*out, encFile)
		src := read(*in)
		if config.IsEncryptedFile(src) {
			fail(*in + " is already in the whole-file format")
		}
		plain, err := config.DecryptValues(key, src)
		if err != nil {
			fail(err.Error())
		}
		write(*out, encrypt(key, *stage, plain))
		fmt.Fprintf(os.Stderr, "converted %s -> %s (stage %s)\n", *in, *out, *stage)
	default:
		usage()
	}
}

func masterKey() string {
	key, err := config.SecretFromEnv()
	if err != nil {
		fail(err.Error())
	}
	if key == "" {
		fail("set SECRET or SECRET_FILE (generate a key with gen-encryption-key)")
	}
	return key
}

func encrypt(key, stage string, plain []byte) []byte {
	enc, err := config.EncryptFile(key, stage, plain)
	if err != nil {
		fail(err.Error())
	}
	return []byte(enc)
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func read(path string) []byte {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail(err.Error())
		}
		return b
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	return b
}

func write(path string, b []byte) {
	if path == "-" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil { // ciphertext only; readable by the API's own user
		fail(err.Error())
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: infrahub-config encrypt|decrypt|convert --stage development|staging|production [--in FILE] [--out FILE] [--force]")
	os.Exit(2)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "infrahub-config:", msg)
	os.Exit(1)
}
