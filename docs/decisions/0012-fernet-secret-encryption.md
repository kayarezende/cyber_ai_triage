# 0012: Fernet-based secret encryption

Date: 2026-04-15
Status: Accepted

## Context

Per-tenant secrets must be stored encrypted at rest:
- Splunk service account tokens (`tenants.splunk_token_encrypted`).
- Splunk HEC tokens (`tenants.splunk_hec_token_encrypted`).
- OpenRouter keys for future per-tenant key ownership.
- Future customer API tokens.

Options:
- Application-level encryption with a key in env (Fernet).
- Postgres `pgcrypto` column-level encryption.
- KMS (AWS KMS, HashiCorp Vault) with per-tenant data keys.

Founder priorities: "our app needs to be secure, do the secure option" + "this is MVP, don't over-engineer."

## Decision

**Fernet (from Python `cryptography` lib) with 32-byte key sourced from env var `TENANT_SECRET_KEY`.**

- `cryptography.fernet.Fernet` — AES-128-CBC + HMAC-SHA256, authenticated encryption.
- Key generated once, stored in `.env` (never committed). Documented in `.env.example`.
- Application encrypts on write, decrypts on read. DB stores opaque ciphertext.
- Rotation: manual + documented in `docs/operations.md`. 90-day hygienic rotation recommended.
- One key for all tenants in MVP. Per-tenant keys + KMS envelope encryption post-MVP.

## Alternatives considered

- **`pgcrypto` column-level encryption** — encryption key still has to live somewhere, and if it's in Postgres config, compromise of the DB = compromise of the encryption. Rejected.
- **AWS KMS / Vault from day 1** — industry gold standard but adds cloud/vault dependency before any paying customer. Rejected as over-engineering for MVP.
- **Raw AES without authentication (libsodium)** — Fernet's authenticated encryption catches tampering; raw AES doesn't. Rejected.
- **No encryption (rely on DB-level access controls)** — would fail any third-party security review. Rejected.

## Consequences

**Gain:**
- Tokens unreadable if DB dump leaks without env.
- Trivial to implement (~20 lines).
- Fernet rotation is a single key swap + re-encrypt script.
- Clear upgrade path: wrap Fernet with per-tenant data keys encrypted by KMS when needed.

**Accept:**
- If the env-file key leaks, all tenant secrets are compromised. Same risk profile as most SaaS MVPs.
- No per-tenant key isolation (one key for all). OK for MVP, must change before IRAP or high-sensitivity customers.
- Key rotation is manual — easy to forget. Calendar reminder + runbook required.

## Related

- ADR 0011 — auth model doesn't touch tenant secrets directly.
- `docs/operations.md` — rotation runbook (to be written wk 12).
