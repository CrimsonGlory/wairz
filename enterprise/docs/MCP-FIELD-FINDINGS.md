# MCP Field Findings — first real cloud agent session (2026-06-12)

Triaged notes from the **first end-to-end agent run** against the cloud Wairz MCP
(`wairz.digitalandrew.io/mcp`), reverse-engineering a router firmware
(`/sbin/httpd` `pingTest` command-injection question). Captured here so they
don't get lost; status reflects what was fixed during that session vs. what's
still open.

Two buckets:

- **Cloud transport / UX** — specific to the enterprise (Streamable HTTP +
  CloudFront) deploy. Tracked as **`enterprise/PLAN.md` Phase 6**; summarized
  below for completeness.
- **Core tool bugs** — reproduce on a **local** install too (not cloud-specific).
  These are the focus of this doc; they belong against `main` / the product.

---

## Already fixed in this session (won't recur)

| Symptom the agent saw | Real cause | Status |
|---|---|---|
| Origin fully unreachable mid-session; every call (even `get_project_info`) returns CloudFront HTML | The MCP sidecar's event loop hung on a synchronous boto3 Batch call with **no `batch` VPC endpoint** (no route) → `/healthz` timed out → ECS reaped the task. Plus operator redeploys during debugging. | **Fixed** — `batch` VPC endpoint added; tolerant health check; task resized. |
| `batch:TagResource` `AccessDenied` that "persisted ~1 min" | IAM propagation lag after the grant. | **Fixed** — grant is permanent; one-off lag only. |
| Ghidra jobs never completed | 6-bug Batch-dispatch chain (endpoint, ListJobs API, IAM revision-pinning, TagResource, system-vs-venv python, stale "running" row). | **Fixed** — see PLAN.md §4 batch commits; validated `start_binary_analysis → SUCCEEDED`. |

---

## Open — cloud transport / UX (→ PLAN.md Phase 6)

1. **CloudFront returns HTML error pages for `/mcp`**, so the client gets
   `Unexpected content type: text/html` instead of a typed/retryable error. The
   single highest-leverage fix.
2. **Heavy sync RE tools (`decompile_function`/`list_functions`) 504 at the 60s
   edge** on cold cache; should return a job handle like `start_binary_analysis`.
   `check_binary_analysis_status` itself 504'd during cold start (it should be
   lightweight — it does a synchronous boto3 `describe_jobs` + sha recompute).
3. **`/mcp` reconnect clears the active project** — re-bind server-side.

Details + proposed fixes: `enterprise/PLAN.md` Phase 6.

---

## Second cloud agent session (2026-06-14) — re-test of the same pingTest workflow

Re-ran the exact `/sbin/httpd` `pingTest` command-injection workflow against the
live cloud stack (project `sdcard`, ARM httpd linking `libsml.so`) to confirm the
2026-06-12 fixes and look for new issues. **All previously-fixed field bugs
behaved correctly** (PLT-stub hint instant on cold cache → named `libsml.so`;
`resolve_import` resolved + decompiled the real impl, surfacing the
`system("ping -c 1 %s")` injection; `disassemble` on a stub returns the hint not
empty; by-address accepted; `hexdump_data` works; `search_strings` `query` alias
works). Two new findings:

### NEW (fixed this session) — one-shot decompile worker re-dispatched to Batch
`decompile_function` by-address on a cold cache (`httpd` `handle_request`
@0x000263d0) went `queued → starting → FAILED`:

```
AccessDeniedException: role wairz-test-batch-job not authorized to perform
batch:SubmitJob on resource arn:aws:batch:...:job-definition/   (empty name)
```

Root cause: `app.workers.run_function_decompile` runs ON the Batch Ghidra box but
called the dispatching `run_ghidra_subprocess`, which in cloud mode re-routes to
the reuse worker via `batch:SubmitJob` — so the worker tried to submit *another*
Batch job (recursive dispatch) and its job role rightly can't. The sibling
analysis worker already runs Ghidra in-process, which is why
`start_binary_analysis` SUCCEEDED but `start_function_decompile` failed.

**Fixed** (`7fdc84b`) — worker now calls `_run_ghidra_local` (same in-process
executor the reuse + analysis workers use). Redeployed (ghidra image
`7fdc84b3170b`, job-def rev 23); re-ran the failing call live: job **SUCCEEDED**,
worker log shows `Reusing project … DecompileFunction.java (-process, no
re-analysis)` (no SubmitJob), and `decompile_function 0x000263d0` now returns the
full `handle_request` pseudo-C from cache. Regression test
`test_function_decompile_worker.py` pins the in-process executor.

### Cloud #1 is worse than "cosmetic" — it breaks MCP reconnection across a backend roll
Confirmed mechanism with a hard repro: an unknown/stale `Mcp-Session-Id` returns
**`HTTP 200` + `content-type: text/html`** (the SPA `index.html`), because the
distribution-wide `custom_error_response` (403 **and** 404 → `/index.html`)
rewrites the ALB/MCP origin's `404 session-not-found`. The Streamable-HTTP client
can't distinguish "session expired → re-initialize" from a hard error, so after
any backend task replacement (every redeploy, every ECS roll) a connected client
wedges on `Unexpected content type: text/html` until fully restarted. This was
the actual cause of the connection failures in both sessions.
**Recommended fix:** decouple SPA deep-link routing from the global error rewrite
so `/mcp*` (and `/api/*`) 404s pass through untouched. Cleanest is a CloudFront
viewer-request Function that rewrites only extension-less, non-`/mcp`, non-`/api`
paths to `/index.html`, then drop the distribution-wide `custom_error_response`.
Minimal-risk alternative: drop only the `404→index.html` rewrite and keep
`403→index.html` (S3+OAC returns 403 for missing keys, so SPA routing survives;
MCP returns 404 for unknown sessions, which would then reach the client).

**✅ Fixed (`c2c5355`)** with the recommended approach: an
`aws_cloudfront_function` (viewer-request) attached to the S3 default behavior
rewrites only extension-less deep links to `/index.html`; `/api/*` and `/mcp*`
keep their own behaviors and pass 404s through honestly, and the
distribution-wide `custom_error_response` is dropped. Stale `Mcp-Session-Id`
now re-initializes cleanly across a backend roll.

### Minor (cosmetic) — background-decompiled output carries Ghidra log prefixes
Functions decompiled via the one-shot/background worker come back with per-line
`INFO  DecompileFunction.java> …` prefixes interleaved in the pseudo-C, whereas
the synchronous/reuse-worker path is clean. Readable but noisier; the background
path should strip the headless log prefix the same way the sync path does.

**✅ Fixed (`c2c5355`)** — `_parse_decompile_output` now strips the per-line
level+script prefix and the trailing `(GhidraScript)` marker, cleaning both the
sync and background paths; regression test in `test_ghidra_decompile_parse.py`.

---

## Fix status (updated 2026-06-22)

| Item | Status |
|---|---|
| Cloud (2026-06-14) one-shot decompile worker re-dispatched to Batch (SubmitJob denial) | ✅ **fixed** (`7fdc84b`) — worker runs Ghidra in-process via `_run_ghidra_local`; live-validated job SUCCEEDED + cached result |
| Cloud #1 CloudFront HTML masks 404 → breaks MCP reconnection after backend roll | ✅ **fixed** (`c2c5355`) — SPA routing moved to an `aws_cloudfront_function` on the S3 behavior only; `/api/*` and `/mcp*` keep their own behaviors and return honest 404s, so a stale `Mcp-Session-Id` re-initializes cleanly instead of wedging on `text/html` |
| Cloud background-decompile output carries Ghidra `INFO …>` log prefixes | ✅ **fixed** (`c2c5355`) — `_parse_decompile_output` strips the per-line level+script prefix and the trailing `(GhidraScript)` marker (sync + background paths); regression test added |
| Core #1 PLT/import-stub blindness | ✅ **fixed** (`3f44b89`) — detect thunk/import → route to resolve_import; live-validated (0.9s vs 600s hang) |
| Core #2 resolve_import false negative | ✅ **fixed** (`3f44b89`) — whole-rootfs lib search + precise "why" diagnostics; live-validated (found pingTest in libsml.so) |
| Core #3 no decompile/disassemble by address | ✅ **fixed** (`a110bed`) — decompile_function accepts `0x…` (now incl. getFunctionContaining), documented |
| Core #4 hexdump_data unimplemented | ✅ **fixed** (`a110bed`) — implemented as a real tool |
| Core #5 search_strings param naming | ✅ **fixed** (`a110bed`) — accepts `query` alias |
| Core #6 warm_analysis_worker not coupled to readiness | ⏳ open (low) |
| Cloud #2 sync tools 504 on cold cache | ✅ **fixed** (`3f44b89`) — async "analyzing — poll" handle |
| Cloud #2c decompile_function 504s on cache-miss (uncached/by-address) | ✅ **fixed** (`5c9b72a`) — cache hit served direct, else routed to async decompile worker; live-validated (0.8s handle vs 60s timeout) |
| Cloud #2b status-poll / dispatch blocks event loop | ✅ **mitigated** (`a110bed`) — boto3 wrapped in `asyncio.to_thread` |
| Cloud #1 CloudFront HTML error pages | ✅ **resolved** (`c2c5355`) — API/MCP paths no longer get the SPA index.html rewrite; residual is only CloudFront's genuine edge page when the origin is actually down (expected) |
| Cloud #3 persist active project across reconnect | ⏳ open — needs token-identity plumbing through the transport |

The per-item detail below is retained for the open items + as a record.

---

## Open — core tool bugs (reproduce locally; against `main`/product)

### 1. PLT/import-stub blindness in `decompile_function` / `disassemble_function` — HIGH
- **Repro:** `pingTest` in `/sbin/httpd` is a **PLT import thunk** (real impl is
  in `libsml.so`). `decompile_function pingTest` **hung the full 600 s timeout —
  twice**; `disassemble_function pingTest` returned **empty** (no error).
- **Impact:** two ~10-minute dead-ends before the analyst manually found the real
  implementation. Worst single time-sink of the session.
- **Fix:** detect that the target is a thunk/PLT stub and **short-circuit** with a
  pointer to `resolve_import` (and the resolved library), rather than feeding a
  stub to the decompiler. `disassemble_function` should **error**, not return
  empty, on a non-decodable/stub target.

### 2. `resolve_import` false negative — HIGH
- **Repro:** reported `pingTest` "not found in any linked library" while listing
  `libsml.so` among those searched — but `pingTest` **is** exported by
  `libsml.so`. Appears to require the target library to be **pre-analyzed** and
  **fails closed** without saying so.
- **Fix:** distinguish **"not exported anywhere"** from **"library not yet
  analyzed"**; ideally trigger/queue analysis of the candidate lib, or at least
  return an actionable "analyze `libsml.so` first" message instead of a flat
  not-found.

### 3. No decompile/disassemble **by address** — MEDIUM
- When a symbol resolves to a stub (or is stripped), there's no fallback to point
  the decompiler/disassembler at a raw address. `disassemble_function` takes only
  a function name.
- **Fix:** accept an `address` argument on `disassemble_function` /
  `decompile_function` (or add `disassemble_at`/`decompile_at`).

### 4. `hexdump_data` advertised but unimplemented — LOW
- Listed in the deferred tool set; calling it returns **`No such tool
  available`**. Stale registration or missing handler — implement or de-list.

### 5. `search_strings` param naming inconsistency — LOW
- Requires `pattern`, but the analyst (reasonably) passed `query` and got
  `'pattern' is a required property`. Other string tools
  (`search_binary_content`, `find_string_refs`) use different conventions.
- **Fix:** align the parameter name across the string-search tools (or accept an
  alias) for a consistent surface.

### 6. `warm_analysis_worker` doesn't guarantee warmth — LOW
- Returned "starting ~1–3 min", but the **very next** `decompile_function` still
  timed out at 600 s. The warm signal isn't coupled to the decompiler's actual
  readiness.
- **Fix:** make `warm_analysis_worker` block until (or report) genuine readiness,
  or have the decompile path consume the warmed worker.

---

## Highest-leverage, across both buckets
1. ✅ Typed/retryable errors instead of CloudFront HTML (cloud #1) — fixed (`c2c5355`).
2. ✅ PLT/import-stub detection → route to `resolve_import`; make `resolve_import`
   work without manual pre-analysis (core #1 + #2) — fixed (`3f44b89`).
3. ⏳ Persist active project across reconnect (cloud #3) — **still open**; needs
   token-identity plumbing through the transport.
4. ✅ Job handle for sync RE tools on cold cache (cloud #2) — fixed (`3f44b89` / `5c9b72a`).

**Remaining open:** cloud #3 (persist project across reconnect) and core #6
(`warm_analysis_worker` readiness coupling) — both low-priority UX polish.
