# syntax=docker/dockerfile:1

# Production image for the Infra Hub Center Go backend. Local development
# does not use this file at all (see README.md's "Start the Go backend" --
# `go run ./cmd/server` against a docker-compose-only Postgres); this exists
# purely for deploying the built server, see docs/deployment.md.

# --- Build stage ---
# Cross-compiles on the build host for each --platform target (pure Go).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Cached separately from source so an unrelated code change doesn't force
# re-downloading every module.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: every database/SSH driver this project uses (pgx, go-sql-
# driver/mysql, mongo-driver, go-redis, golang.org/x/crypto/ssh) is pure Go,
# so a fully static binary is possible -- and preferable, since it removes
# any libc version coupling between the build and runtime base images.
# Every operator command is built (not just the server) so an operator can
# run migrations/seed/bootstrap/key-generation from the same image via
# `docker run --entrypoint /app/migrate <image> up` -- see docs/deployment.md.
ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64}
RUN go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate && \
    go build -trimpath -ldflags="-s -w" -o /out/seed ./cmd/seed && \
    go build -trimpath -ldflags="-s -w" -o /out/bootstrap-admin ./cmd/bootstrap-admin && \
    go build -trimpath -ldflags="-s -w" -o /out/gen-encryption-key ./cmd/gen-encryption-key && \
    go build -trimpath -ldflags="-s -w" -o /out/encrypt-config-value ./cmd/encrypt-config-value

# --- Runtime stage ---
FROM alpine:3.20 AS runtime

# ca-certificates: required for outbound TLS (S3-compatible object storage,
# TLS-enabled standalone database connections, HTTPS alert webhooks) --
# without it every such connection fails certificate verification.
RUN apk add --no-cache ca-certificates && \
    addgroup -S app && adduser -S -G app -H -D app

WORKDIR /app
COPY --from=build /out/server /out/migrate /out/seed /out/bootstrap-admin /out/gen-encryption-key /out/encrypt-config-value ./
# goose (cmd/migrate) reads migrations from disk at a relative "migrations"
# path, not an embedded filesystem -- see cmd/migrate/main.go -- so the
# directory has to travel with the binary.
COPY --from=build /src/migrations ./migrations
# Only the production template ships in the image (every secret VALUE in
# it is AES-256-GCM ciphertext, see internal/config/encrypted_env.go).
# Deployments either set DATABASE_URL, JWT_SECRET, ... as plain
# environment variables -- which always win over the file -- or point
# INFRAHUB_CONFIG_DIR at their own encrypted production.ini.enc and supply
# INFRAHUB_MASTER_KEY at container start.
COPY --from=build /src/production.ini.enc ./
# Runs migrations + seed (+ first admin) before the server -- see the
# script's own header for the switches.
COPY --chmod=0755 docker-entrypoint.sh ./

ENV APP_ENV=production
USER app
EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
