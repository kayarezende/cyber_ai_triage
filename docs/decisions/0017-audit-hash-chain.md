# 0017: Hash-chained audit log + DB role split

Date: 2026-04-27
Status: Accepted

## Context

CLAUDE.md and the Plan claim _"append-only audit log table"_ + _"hash chain content for tamper evidence"_ as a compliance primitive from day 1. The initial schema (`db/migrations/versions/81e2d43b3ec0_initial_schema.py:128-138`) has only:

```sql
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  investigation_id UUID,
  actor TEXT,
  action TEXT,
  details JSONB,
  content_hash TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
-- REVOKE UPDATE, DELETE on audit_log; INSERT only.
```

A `content_hash` column with no chain pointer, no defined hash scope, and a comment promising a `REVOKE` that isn't executed. This isn't a hash chain — it's a single-row checksum. Nor is it append-only at the DB level; nothing prevents UPDATE or DELETE from any role with table ownership.

For E8 ML2 + APRA CPS 234 + future SOC2 Type I, audit immutability is table stakes. A pen-tester or compliance auditor will probe this. Without `previous_hash`, an attacker can rewrite history by recomputing one row's `content_hash`. Without DB-level enforcement, an attacker with `app_role` privileges can DELETE rows.

MinIO Object Lock for evidence artifacts is also referenced in stack-locks but not configured (no bucket creation script applies Object Lock at create time, and Object Lock cannot be enabled on an existing bucket — it must be set when the bucket is created).

## Decision

**Hash chain in Postgres + DB role split + MinIO Object Lock at bucket creation.**

### Schema additions to `audit_log`

```sql
ALTER TABLE audit_log
  ADD COLUMN previous_hash TEXT,
  ADD COLUMN hash_scope TEXT;  -- e.g., 'tenant:<uuid>' or 'investigation:<uuid>'
CREATE INDEX audit_log_hash_scope_id_idx ON audit_log (hash_scope, id);
```

`hash_scope` defines the chain partition. Per-investigation chain (`'investigation:<uuid>'`) is the default — narrower than per-tenant — so that investigation-level chain integrity can be verified independently. System-level events (auth, role config changes) use `'tenant:<uuid>'`.

### Compute trigger (BEFORE INSERT)

```sql
CREATE FUNCTION compute_audit_hash() RETURNS TRIGGER AS $$
DECLARE
  prev_hash TEXT;
BEGIN
  SELECT content_hash INTO prev_hash
    FROM audit_log
    WHERE hash_scope = NEW.hash_scope
    ORDER BY id DESC
    LIMIT 1;
  NEW.previous_hash := COALESCE(prev_hash, '');
  NEW.content_hash := encode(
    digest(
      NEW.tenant_id::text || '|' ||
      COALESCE(NEW.investigation_id::text, '') || '|' ||
      NEW.actor || '|' || NEW.action || '|' ||
      NEW.details::text || '|' || NEW.created_at::text || '|' ||
      NEW.previous_hash,
      'sha256'
    ),
    'hex'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_hash_trigger
  BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION compute_audit_hash();
```

The hashed scope is `(tenant_id, investigation_id, actor, action, details, created_at, previous_hash)`. Modifying any of those breaks the chain forward.

### Block UPDATE/DELETE

```sql
CREATE FUNCTION block_audit_modify() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify();
```

### DB role split

```sql
CREATE ROLE audit_writer NOLOGIN;
GRANT INSERT ON audit_log TO audit_writer;
GRANT SELECT ON audit_log TO audit_writer;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO audit_writer;
```

App role inherits `audit_writer` for INSERT only. Migrations / superuser keep full privileges (needed for table creation and downgrade). The triggers are belt-and-braces — even if a future bug grants the app role UPDATE/DELETE, the triggers still raise.

### MinIO Object Lock

Bucket creation script `db/seeds/setup_minio.py` (new) creates the evidence bucket with Object Lock + versioning enabled at creation time:

```python
client.make_bucket("sentient-evidence", object_lock=True)
client.set_bucket_versioning("sentient-evidence", VersioningConfig(ENABLED))
```

Object Lock prevents object deletion regardless of versioning state. Cannot be enabled retroactively — must be at bucket creation.

## Alternatives considered

- **Single `content_hash` column, no chain** (existing). Rejected as flagged by review: doesn't survive any tamper-with-recompute attack.
- **Hash chain in app code, not DB trigger.** Rejected: trust boundary moves; an attacker with DB write access can bypass app-level hashing.
- **External WORM store (e.g., AWS QLDB, Amazon Object Lock S3) for audit only.** Rejected for MVP: adds a service dependency for marginal benefit over Postgres trigger + role split. Revisit when scale or third-party attestation requirements demand it.
- **No DB role split, only triggers.** Rejected: defence in depth. Trigger could be dropped by a privileged user; role split also needs to be revoked. Both must be undone for tampering, raising the bar.

## Consequences

**Gain:**
- Hash chain integrity verifiable end-to-end. Auditor can take any row and walk back.
- DB-level enforcement of append-only + role split. Compliance pen-test passes.
- MinIO Object Lock prevents evidence deletion even with bucket admin credentials.
- Per-investigation chain partition lets investigation-level integrity be verified without scanning the entire log.

**Accept:**
- Trigger overhead on every INSERT (one SELECT for prev_hash + one digest). Trivial at MVP scale; revisit if audit-log INSERT becomes a hot path.
- Hash-scope choice (`'investigation:<uuid>'` vs `'tenant:<uuid>'`) must be set correctly by the writer. App code needs a small helper to derive it.
- MinIO Object Lock mode is governance (default) — not full WORM compliance. Revisit if a customer demands SEC 17a-4 / FINRA-grade WORM.
- Hash field changes (e.g., adding a column to the digest) require a chain-versioning migration. Acceptable trade-off; document hash-format version in the trigger function.

## Related

- ADR-0006 — Soft multi-tenancy (RLS) — same migration also adds `WITH CHECK` clauses.
- ADR-0012 — Fernet secret encryption (different mechanism, related compliance theme).
- `audit_log` schema in `db/migrations/versions/81e2d43b3ec0_initial_schema.py:128-138`.
- Phase 2 migration adds these triggers + role + columns.
