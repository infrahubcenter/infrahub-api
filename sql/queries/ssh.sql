-- Trust-on-first-use host key store (one current key per resource). Trust
-- is only ever established by TrustHostKey (backend re-dials and records
-- whatever key is presented -- see docs/ssh-architecture.md); nothing else
-- writes to this table, so an existing row is always something an admin
-- explicitly trusted.

-- name: GetHostKeyByResource :one
SELECT * FROM ssh_host_keys WHERE resource_id = $1;

-- name: TrustHostKey :one
INSERT INTO ssh_host_keys (resource_id, host, port, algorithm, fingerprint, public_key)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (resource_id) DO UPDATE SET
    host = EXCLUDED.host,
    port = EXCLUDED.port,
    algorithm = EXCLUDED.algorithm,
    fingerprint = EXCLUDED.fingerprint,
    public_key = EXCLUDED.public_key,
    last_verified_at = now()
RETURNING *;

-- name: TouchHostKeyVerified :exec
UPDATE ssh_host_keys SET last_verified_at = now() WHERE resource_id = $1;

-- name: DeleteHostKey :exec
DELETE FROM ssh_host_keys WHERE resource_id = $1;
