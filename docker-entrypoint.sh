#!/bin/sh
# Container entrypoint: prepares the database, then runs the API server.
#
#   INFRAHUB_AUTO_MIGRATE=true (default)  run migrations + seed on start
#   BOOTSTRAP_ADMIN_EMAIL/NAME/PASSWORD   create the first admin once
#                                          (skipped when one already exists)
#
# Any other command (e.g. "./migrate status", "./bootstrap-admin") runs
# as-is instead of the server.
set -e
cd /app

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

if [ "${INFRAHUB_AUTO_MIGRATE:-true}" = "true" ]; then
    # The database may still be starting (compose/Kubernetes start order),
    # so retry migrations for up to ~2 minutes before giving up.
    attempt=1
    until ./migrate up; do
        if [ "$attempt" -ge 24 ]; then
            echo "entrypoint: database not reachable after $attempt attempts, giving up" >&2
            exit 1
        fi
        echo "entrypoint: migrate failed (attempt $attempt), retrying in 5s..." >&2
        attempt=$((attempt + 1))
        sleep 5
    done
    ./seed

    if [ -n "$BOOTSTRAP_ADMIN_EMAIL" ] && [ -n "$BOOTSTRAP_ADMIN_PASSWORD" ]; then
        # Refuses (non-zero) once any admin exists -- expected on every
        # restart after the first, so it never fails the container.
        ./bootstrap-admin || echo "entrypoint: bootstrap-admin skipped (an admin already exists)"
    fi
fi

exec ./server
