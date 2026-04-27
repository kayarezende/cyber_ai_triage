# Splunk Setup — founder runbook

One-time setup on the Splunk box so Sentient Layer can pull notables, enrich
them, and write verdicts back. Founder-run; not executable by the MVP stack.

Referenced from [`tasks/todo.md`](../tasks/todo.md) (wk 0 + wk 1). The app
side reads Splunk creds from `.env` (`SPLUNK_*`) per
[`.env.example`](../.env.example).

---

## 1. Target versions

- Splunk Enterprise 9.x (tested against 9.2+).
- Splunk Enterprise Security 7.x (for the Incident Review / `notable_update`
  endpoint + ES CIM data models).

If the founder's box runs older ES, confirm `notable_update` REST endpoint
exists (introduced in ES 6.x) before proceeding to wk 8.

---

## 2. Indexes

Create three indexes on the Splunk box (CLI or **Settings → Indexes**):

```bash
./splunk add index main          -datatype event        # if not already present
./splunk add index botsv3        -datatype event
./splunk add index triage_verdicts -datatype event
```

| Index            | Purpose                                                              |
|------------------|----------------------------------------------------------------------|
| `main`           | Default landing index for enrichment queries during investigation.   |
| `botsv3`         | Splunk Boss of the SOC v3 dataset (eval corpus — see §6).            |
| `triage_verdicts`| HEC target — every finished investigation writes an OCSF event here. |

---

## 3. HEC token

Used by `siem_hec_post` (ADR 0008 dual writeback, wk 8).

1. **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Name: `sentient-triage-hec`
3. Source type: `_json` (we post OCSF JSON)
4. Allowed indexes: `triage_verdicts` (default `triage_verdicts`)
5. Enable Token → save the token value
6. Global settings: **Enable HEC**, port `8088`, HTTPS enabled (TLS managed by
   Splunk; the app sets `SPLUNK_VERIFY_TLS` to control verification).

Copy the token into `.env`:

```
SPLUNK_HEC_HOST=<splunk host>
SPLUNK_HEC_PORT=8088
SPLUNK_HEC_TOKEN=<paste here>
```

Ping:

```bash
curl -k "https://${SPLUNK_HEC_HOST}:${SPLUNK_HEC_PORT}/services/collector/health" \
     -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN}"
# → {"text":"HEC is healthy","code":17}
```

---

## 4. Service account + role

Used by `siem_query`, `siem_get_notable`, `siem_notable_update`. Auth via
Splunk management REST bearer token on port 8089.

### Role `sentient_triage_role`

- Capabilities:
  - `search` (ad-hoc SPL via `siem_query`)
  - `edit_notable_events` (for `notable_update` — wk 8)
  - `rest_properties_get`, `list_inputs` (introspection)
- Inherits from `user` (NOT `power` — least privilege).
- Allowed indexes: `main`, `botsv3`, `triage_verdicts`, plus any notable /
  app-specific indexes your deployment uses.
- Search filter: none (tenant isolation lives server-side in Sentient Layer,
  not Splunk — ADR 0006 soft-tenancy).

### User `sentient_triage`

- Roles: `sentient_triage_role` (+ `ess_analyst` if ES is installed — read
  access to notables).
- Create a **token** (Settings → Tokens → New Token) with no expiry for MVP
  (rotation runbook in `docs/operations.md`, wk 12).

Copy into `.env`:

```
SPLUNK_HOST=<splunk host>
SPLUNK_PORT=8089
SPLUNK_TOKEN=<paste here>
```

Smoke:

```bash
curl -k "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/server/info?output_mode=json" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}" | jq .generator
# → {"version": "9.x.x", "build": "..."}
```

---

## 5. Saved search + alert-action webhook

Wired in wk 4 (ingest path).

### 5.1 Saved search

Create the saved search that drives triage, e.g.:
```
index=notable | table *
```
Scheduled, throttled to dedupe by `event_id`.

### 5.2 Webhook URL

**Alert action → Webhook** pointing at:
```
http://api.triage.local/api/incidents/ingest
```
HTTPS wk 12; see TLS note at the bottom.

### 5.3 Webhook secret carrier

Stock Splunk Enterprise's webhook alert action does **not** support custom
headers (verified Splunk 10.x alerting manual). ADR-0021 supersedes the
ADR-0014 §header carrier — the secret travels in the request body.

In the saved-search alert action, add a webhook **parameter**:

| Field | Value |
|-------|-------|
| Name  | `secret` |
| Value | `${INGEST_WEBHOOK_SECRET}` (paste the value from `.env`) |

Splunk's webhook action then POSTs a JSON body of the form:

```json
{
  "sid": "scheduler__...",
  "search_name": "<your saved search name>",
  "result": { "...the search row..." },
  "results_link": "...",
  "secret": "<INGEST_WEBHOOK_SECRET>"
}
```

The API does `hmac.compare_digest(body.secret, INGEST_WEBHOOK_SECRET)` →
401 on mismatch.

> ⚠️ **Sensitive saved-search export.** The webhook parameter value is
> stored in the saved-search definition. Anyone with `admin_all_objects`
> (or who can read an exported `savedsearches.conf`) sees the secret in
> cleartext. Treat saved-search exports as sensitive — redact `secret`
> before sharing.

### 5.4 Smoke

Drop a test notable after wk 4 lands → an `incidents` row should appear in
Postgres within seconds.

---

## 6. Splunk BOTS v3 load (eval corpus)

Manual, founder-run. Do this **on the Splunk box** — the docker host is the
wrong machine (dataset is large).

1. Pull the dataset:
   ```bash
   git clone https://github.com/splunk/botsv3.git
   # or download botsv3_data_set.tgz directly from the repo's release assets
   ```
2. Confirm the `botsv3` index exists (§2).
3. Ingest (run as the Splunk OS user):
   ```bash
   ./splunk add oneshot /path/to/botsv3_data_set.tgz -index botsv3
   ```
   May take 30+ minutes depending on box size. Tail `$SPLUNK_HOME/var/log/splunk/splunkd.log`.
4. (If ES is installed) Enable CIM data model acceleration for the models the
   dataset populates: **Settings → Data Models → CIM_* → Acceleration**.
5. **Verify the load actually worked** — `earliest=0` is rejected on Splunk
   10.0.2 (returns `Invalid earliest_time`). Use the BOTS time window
   directly:
   ```
   index=botsv3 earliest=2018-08-01T00:00:00 latest=2018-09-30T00:00:00
     | stats count
   ```
   Expect ~millions of events. **If count is 0 the load did not succeed** —
   re-run §6.3 and check `splunkd.log` for ingestion errors. (Wk 2 caught
   exactly this: the wk-1 todo was ticked from documentation alone, not
   from a verifying query, and BOTS data was missing on the founder's box.)
6. **Time picker note:** BOTS v3 is 2018-era data. Eval runs must pin the
   time range to **2018-08-01 → 2018-09-01** (see repo README for the exact
   scenario window). The eval harness (wk 10) sets this automatically.

Once loaded — and verified by query — tick the BOTS v3 box.

---

## 7. `notable_update` REST verification

Quick sanity check that the service account can write back (dual-writeback
wk 8). Requires a notable ID — grab one from the ES Incident Review page.

```bash
curl -k -X POST \
  "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/notable_update" \
  -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
  -d "ruleUIDs=<notable_id>" \
  -d "comment=sentient-layer connectivity test" \
  -d "status=0"
# → {"success":true,...}
```

If you get `403`, the role is missing `edit_notable_events`. If you get
`404`, the ES `notable_update` endpoint isn't installed on this box.

---

## 8. Network reachability from the docker host

Run these from the machine that runs `docker compose up`:

```bash
# Management REST (search, notable_update)
curl -k -I "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/server/info"

# HEC (writeback)
curl -k -I "https://${SPLUNK_HEC_HOST}:${SPLUNK_HEC_PORT}/services/collector/health"
```

Both must respond (HTTP 200 or 401 depending on auth). If they hang or
refuse, fix firewall / VPN before anything else — the orchestrator will time
out waiting on these.

---

## 9. TLS note (deferred to wk 12)

- `SPLUNK_VERIFY_TLS=true` in `.env` — set `false` only if the Splunk box
  serves a self-signed cert and the docker host doesn't trust its CA. Prefer
  trusting the CA over disabling verification.
- The app-side edge (Traefik) is **HTTP-only in MVP** (`docker-compose.yml`).
  `app.triage.local` / `api.triage.local` speak HTTP until wk 12 hardening
  adds a self-signed CA + cert trust on the docker host.
- The Splunk webhook must target `http://api.triage.local/...` until the
  above lands.
