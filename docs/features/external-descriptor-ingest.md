# External Descriptor Ingest — Composable wairz

Wairz is designed to be a **composable analysis component** that other
tools push artifacts into — not the only path through which firmware
enters the platform. External tools (Velociraptor collection artifacts,
dissect.target plugins, chipsec on-host probes, custom JTAG harness
scripts, in-house extraction pipelines) push **structured descriptors**
that wairz uses to drive walkers + finding emission.

The first ingestor surface is bare-metal MCU/DSP chip hints (Rule #52
Phase 1+2, 2026-05-19). Future surfaces ride the same protocol shape.

---

## Architecture

```
External tool (Velociraptor, dissect, custom)
        │
        │   HTTP POST + X-API-Key + JSON body
        ▼
   wairz API (FastAPI)
        │   rate-limited @ TIER_A_LIGHT_ACK
        │   validated against closed-grammar Pydantic schema
        │   idempotency check (firmware, ingestor, hash)
        ▼
   bare_metal_descriptors  ← append-only with supersedes_id chain
        │
        │   walker reads MOST-RECENT NON-SUPERSEDED descriptor
        │   ordered by (precedence_rank DESC, received_at DESC)
        ▼
   bare_metal_walker  →  Finding rows (CWE-tagged)
```

**Provenance arbitration** (Scout CC §SC11): when multiple descriptors
compete, walker picks the highest-precedence non-superseded row:

  `operator > attested_external > unauthenticated_external > auto_detection`

So an operator's hand-entered descriptor ALWAYS outranks an
external-ingestor push, even when the external push arrives later. Scout
GG §SC5 stop-the-line bug was that the walker initially ordered by
timestamp only — a LATER unauthenticated_external push could outrank an
EARLIER operator decision. Fixed at commit `0fb58ca` (Phase 2.0).

---

## Endpoint: `POST /api/v1/projects/{p}/firmware/{f}/bare-metal-hint`

### Auth

`X-API-Key: <project_key>` — Phase 1 single shared key per project →
ingestor receives `descriptor_source: unauthenticated_external`. Phase 3
adds per-ingestor scoped keys + `attested_external` precedence (Scout EE
§5.4).

### Rate limit

`TIER_A_LIGHT_ACK` = 30 requests/hour/IP per Rule #51. Sub-second ACK;
the walker auto-trigger fires detached. Operators iterating against
their own firmware can burst beyond 30 by using multiple API keys or by
deferring re-pushes (most chip-hint workflows are 1 push per firmware).

### Request

```http
POST /api/v1/projects/6645e769-6bf2-4228-af54-304b0dc40b4e/firmware/78ad638b-f99b-4cb0-ac28-e36e05846007/bare-metal-hint HTTP/1.1
X-API-Key: <key>
Content-Type: application/json

{
  "chip_family_hint": "ti/tms320f28066",
  "domain_hint": "c28x_core",
  "ingestor_id": "velociraptor-fleet-a",
  "evidence": {
    "collected_at": "2026-05-19T15:00:00Z",
    "collector_host": "plc-fleet-01.example",
    "jtag_idcode": "0x008F0001",
    "csm_status_register": "0x0070"
  }
}
```

### Required fields

| Field | Type | Notes |
|---|---|---|
| `chip_family_hint` | `"vendor/family"` | Must be in the catalog. Use `list_chip_families` MCP to enumerate. |

### Optional fields

| Field | Default | Notes |
|---|---|---|
| `domain_hint` | First declared on family | Required for composite SoCs (NXP S32G, TI Sitara AM62x) — pick the correct domain. |
| `ingestor_id` | `"http-default"` | Pick a stable string per ingestor; (firmware, ingestor, hash) is the idempotency key. |
| `evidence` | `{}` | Free-form provenance — operator-visible at the descriptor row. |

### Responses

**201 Created** — new descriptor persisted:

```http
HTTP/1.1 201 Created
X-Descriptor-Id: 6a14ce27-ca75-434b-9196-60d47d2e4731
Content-Type: application/json

{
  "descriptor_id": "6a14ce27-ca75-434b-9196-60d47d2e4731",
  "firmware_id": "78ad638b-f99b-4cb0-ac28-e36e05846007",
  "chip_family_hint": "ti/tms320f28066",
  "domain_hint": "c28x_core",
  "descriptor_source": "unauthenticated_external",
  "ingestor_id": "velociraptor-fleet-a",
  "descriptor_hash": "c6db65abcd29887635c946c0c4db65db",
  "received_at": "2026-05-19T15:00:00+00:00",
  "status": "created"
}
```

**200 OK** — idempotent replay (same `(firmware, ingestor, hash)` triple already exists):

```json
{
  "descriptor_id": "6a14ce27-...",
  "status": "idempotent_replay",
  "...": "same body as 201"
}
```

The DB-level partial unique index `ux_bare_metal_descriptors_idempotency`
backs this (Scout GG §SC3 durability — Idempotency-Key HTTP cache is
fast-path; the DB unique index is the authoritative gate).

**409 Conflict** — same ingestor previously pushed a DIFFERENT hash:

```json
{
  "detail": {
    "error": "ingestor 'velociraptor-fleet-a' previously pushed a different descriptor for this firmware",
    "prior_descriptor_id": "6a14ce27-...",
    "prior_descriptor_hash": "c6db65abcd29887635c946c0c4db65db",
    "hint": "explicit supersedes_id required to update — Phase 2.5 feature; use a unique ingestor_id per ingestor in the meantime"
  }
}
```

**422 Unprocessable Entity** — `chip_family_hint` not in catalog:

```json
{
  "detail": {
    "error": "chip_family_hint 'invented/chip' not in catalog",
    "known_families": ["nxp/spc58", "ti/tms320f28066"],
    "hint": "drop a YAML at data/chip_families/<vendor>/<family>.yaml — operators may extend the catalog without a rebuild"
  }
}
```

**404 Not Found** — project or firmware doesn't exist (or firmware not in project).

**429 Too Many Requests** — rate limit hit. Body carries Rule #51 structured shape:

```json
{
  "error": "Rate limit exceeded",
  "tier": "TIER_A_LIGHT_ACK",
  "retry_after_seconds": 120,
  "hint": "this endpoint is limited to 30 requests/hour per IP"
}
```

---

## Velociraptor integration example

A Velociraptor collection artifact runs JTAG extraction, computes the
chip ID, then pushes the result via `Net.Curl()`:

```vql
LET wairz_key = environ(VAR="WAIRZ_API_KEY")
LET wairz_url = "https://wairz.example/api/v1/projects/" + project_id +
                "/firmware/" + firmware_id + "/bare-metal-hint"

SELECT * FROM Net.Curl(
  url=wairz_url,
  method='POST',
  headers={
    "X-API-Key": wairz_key,
    "Content-Type": "application/json"
  },
  body=serialize(item={
    "chip_family_hint": chip_family,    -- from JTAG IDCODE → catalog lookup
    "domain_hint": domain,
    "ingestor_id": "velociraptor-" + client_id,
    "evidence": {
      "client_id": client_id,
      "collected_at": now(),
      "jtag_idcode": jtag_idcode,
      "csm_status": csm_status_word
    }
  })
)
```

The ingestor_id binds to the Velociraptor client — concurrent fleet
pushes against different firmwares are independent; the same client
re-pushing the same firmware is idempotent.

---

## Roadmap

| Phase | Feature |
|---|---|
| 2 (shipped 2026-05-19) | HTTP endpoint, idempotency, 409 conflict, descriptor table |
| 2.5 | `supersedes_id` explicit update path (PUT with prior_descriptor_id) |
| 3 | Per-ingestor scoped API keys + `attested_external` precedence (Scout EE §5.4) |
| 3 | HMAC-signed descriptors (sigstore deferred to Phase 4) |
| 3 | Webhook back-channel for walker completion (replaces polling) |
| 4 | Cross-surface generic `POST /external-descriptors` with `descriptor_kind` field (Rule-of-Two unlock — when 2nd surface arrives) |

---

## Pointers

- HTTP endpoint: `backend/app/routers/bare_metal.py`
- Descriptor model: `backend/app/models/bare_metal_descriptor.py`
- Pydantic body schema: `backend/app/routers/bare_metal.py::BareMetalHintRequest`
- Walker descriptor resolution: `backend/app/services/bare_metal_walker.py::_most_recent_descriptor`
- Precedence map: `backend/app/services/bare_metal_walker.py::_SOURCE_PRECEDENCE`
- MCP analog (operator-side): `backend/app/ai/tools/bare_metal.py::submit_bare_metal_descriptor`
- Rule: `CLAUDE.md` Rule #52 (schema-driven discipline), Rule #33 (idempotency contract), Rule #51 (rate-limit tier), Rule #46 (META-CANARY discipline for the no-decrypt + precedence gates)
- Chip-family extension docs: [`extending-firmware-patterns.md`](extending-firmware-patterns.md#surface-6--chip_familiesyaml-rule-52--bare-metal-mcudsp-audit)
