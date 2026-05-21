# Wave-1 Scout C — Red-team / Unknown-Format Adversarial (S2)

> Investigation date: 2026-05-20
> Methodology: Rule #52 W2-β cross-feature attack stage, EXTENDED — combine
> the operator's adaptability mandate (other ingesters; unknown formats;
> operator-supplied YAML) with the Session 2 proposed fixes (SBOM
> `/generate` Rule #33, grype `force_rescan` transactional fix,
> `_post_process_pipeline` unpack gate, walker reaper sweep, broader
> `create_task` GC sweep) and hunt §SC5-analog attacks at the NEW seams.
> Precedent: Session 1 W2-β catalogued 12 §SC5-NEW-SBOM-α..π attacks; this
> report catalogues §SC5-NEW-SBOM-S2-α..λ at the Session 2 fix boundaries.

## Executive Summary

The Session 2 fix sweep — adding `sbom_status` + 202+polling
conversion of `/sbom/generate`; fixing grype to honor `force_rescan`
transactionally; making `_post_process_pipeline` invoke `unpack_firmware`
for generic archives; refactoring the lifespan reaper sweep to derive
from `WALKER_AUTO_TRIGGERS`; broader bare `asyncio.create_task` GC
sweep — meets the operator's adaptability mandate by FOLDING IN
upstream operator-supplied inputs from new ingest paths. Each fold
opens a new attack surface. **The highest-severity new attack is
§SC5-NEW-SBOM-S2-δ (CRITICAL): an operator-supplied YAML at
`data/file_formats.local/operator/<x>.yaml` declaring
`manifest_source: _system` is REJECTED today by the file-format
catalog's path-cross-check (`catalog.py:270-278`), but the equivalent
gate is ABSENT for ALL OTHER operator-supplied YAML surfaces** —
extraction-strategy YAML, walker auto-trigger YAML, SBOM-strategy YAML
do not exist yet, but Session 2's adaptability work will create them
without inheriting the path-cross-check. **At least one Session 2 fix
as-proposed needs hardening BEFORE shipping**: Fix #11 (walker reaper
sweep) MUST derive the reaper SQL from `WALKER_AUTO_TRIGGERS` AND
include `sbom_status` AND include `bare_metal_audit_status` AND
include the 22+ walker `*_walk_status` columns — silently dropping any
one of these from the derived list is the exact §SC5-NEW-SBOM-α
NULL-handling failure on the next operator-driven walker. 11 new
attacks catalogued; confidence HIGH on attack mechanics, MEDIUM on
likelihood (each requires operator action that's plausible but not
inevitable).

## NEW §SC5-NEW-SBOM-S2 Attack Catalog

### §SC5-NEW-SBOM-S2-α: SBOM `/generate` 202+polling × unknown format → orphan `sbom_status='running'` forever

- **Setup:** Session 2 Fix #1 converts `/sbom/generate` from synchronous
  to 202+polling per Rule #33. The new `sbom_status` column joins
  `vuln_scan_status` and `bare_metal_audit_status` in the 5-state
  machine. The background runner `_run_sbom_generate_background` calls
  `service.generate_sbom()` against `firmware.extracted_path`. Operator
  uploads a `.dmg` (macOS disk image), `.qcow2` (sparse VM image),
  `.efi` (UEFI executable), or `.ima` (Apple IPSW component). The
  file-format catalog has no manifest for these (verified by
  `ls data/file_formats/_system/ | sort` — 13 _system manifests, none
  cover `.dmg` / `.qcow2` / `.efi` / `.ima`).
- **Trigger:** Operator uploads `unknown.dmg`. Upload pipeline
  succeeds via the `linux_blob_fallback` floor manifest (per
  `resolver.py:60` `_SOURCE_PRECEDENCE` + `_TIER_RANK`). `_post_process_pipeline`
  runs but neither the tar nor ZIP shortcut fires; `firmware.extracted_path`
  stays NULL. Operator opens the SBOM page and clicks "Generate SBOM".
- **Outcome (un-mitigated):** The 202+polling background runner
  starts. `SbomService.generate_sbom` is called against
  `firmware.extracted_path=None`. The service walks an empty
  detection-root list (per `get_detection_roots(firmware)` Rule #16)
  and returns `component_dicts=[]`. The runner stamps
  `sbom_status='completed'` with zero components. This is GRACEFUL —
  not a bug yet. But the operator clicks "Force Regenerate" thinking
  the empty result means a stale scan; the 409-on-conflict check at
  `routers/sbom.py:142` analog gates `if firmware.sbom_status in ('queued',
  'running')` — the prior completed run isn't in that set, so the POST
  proceeds. Now the second runner ALSO produces `component_dicts=[]`.
  Operator sees "0 components generated" twice; no error message
  surfaces because the runner succeeded. **The unknown-format case is
  silently zero-result.**
- **Severity:** **MEDIUM** (silent zero-result on operator-uploaded
  unknown format; operator can't tell whether wairz "knows about"
  the format vs the firmware genuinely has no SBOM-relevant components)
- **Maps to Rule:** Rule #29 (timeout discipline — runner has no
  upper-bound cap on its inner loop) + Rule #52 (operator-extensibility
  contract requires graceful-degrade on unknown formats)
- **Mitigation:** (a) The background runner checks
  `firmware.detected_format == DetectedFormat.UNKNOWN.value` at entry
  and short-circuits with `sbom_status='completed'` AND
  `firmware.sbom_generate_result={'reason': 'detected_format=unknown',
  'components': 0}`. (b) The frontend SbomPage renders a banner
  "Detected format: unknown — SBOM generation produces no
  components" with a link to operator docs for declaring a
  custom format via `data/file_formats.local/operator/<x>.yaml`. (c)
  Background runner wraps the inner work in
  `asyncio.wait_for(..., timeout=SBOM_GENERATE_TIMEOUT)` where the
  timeout is sourced from `config.py` per Rule #29.
- **Gate-canary (Rule #46):**
  ```python
  async def test_sbom_generate_on_unknown_format_graceful_degrades(db_session):
      fw = create_firmware(detected_format="unknown", extracted_path=None)
      await _run_sbom_generate_background(fw.id, force_rescan=False)
      db_session.refresh(fw)
      assert fw.sbom_status == "completed"
      assert fw.sbom_generate_result["reason"] == "detected_format=unknown"
      assert fw.sbom_generate_result["components"] == 0
  ```

### §SC5-NEW-SBOM-S2-β: SBOM `/generate` 202+polling × 50 GB sparse VM image → worker OOM

- **Setup:** Same Session 2 Fix #1. Operator uploads a 50 GB
  `disk.qcow2` (sparse-file qcow2 from a VM snapshot). The unpack
  pipeline runs `qemu-img convert -f qcow2 -O raw` per CLAUDE.md Rule
  #36 Exception 1 (trusted image-shipped binaries). The raw output is
  300 GB physical because qcow2 sparseness inflates.
- **Trigger:** Operator clicks "Generate SBOM". The
  `SbomService.generate_sbom` walks the 300 GB extracted tree;
  `service.generate_sbom` is CPU-bound and runs in
  `loop.run_in_executor(None, ...)` per
  `routers/sbom.py:182-184`. The executor thread reads file contents
  to compute hashes for component matching.
- **Outcome (un-mitigated):** The executor thread holds 300 GB of
  references; the worker container's memory cap (typically 4-8 GB) is
  exceeded. OOM kill terminates the BACKEND container (not just the
  executor thread — uvicorn dies). The 202+polling runner's outer
  `try/except` at the proposed `_run_sbom_generate_background`
  never catches OOM (OOM kills the process before the handler runs).
  The `sbom_status='running'` row is now orphan; the proposed Session 2
  `sbom_status` reaper in main.py fires on the NEXT restart and flips
  to `failed`. **However**: the OS already killed the container, so
  the operator sees container restart + a confusing "scan failed" with
  no error detail.
- **Severity:** **HIGH** (operator-uploadable input crashes the
  backend container; cascade affects every other operator)
- **Maps to Rule:** Rule #29 (work-ceiling discipline) + Rule #36
  (no-execute base — extraction is OK; SBOM-generate's reading the
  300 GB output is NOT bounded)
- **Mitigation:** (a) `SbomService.generate_sbom` enforces a
  per-firmware filesystem walk budget (`max_bytes_scanned=5 GB` +
  `max_files=10_000` + per-file size cap). (b) Worker container
  memory limit declared explicitly in `docker compose.yml`. (c) The
  background runner registers itself with the sweep reaper so OOM-on-
  reboot still flips status.
- **Gate-canary (Rule #46):**
  ```python
  async def test_sbom_generate_bounded_under_30gb_extracted():
      fw = create_firmware_with_extracted_size_gb(30)
      with monitor_rss_peak() as monitor:
          await _run_sbom_generate_background(fw.id, force_rescan=True)
      assert monitor.peak_rss_mb < 2048  # 2 GB cap
  ```

### §SC5-NEW-SBOM-S2-γ: Fix #11 reaper-derive-from-WALKER_AUTO_TRIGGERS silently drops `sbom_status`

- **Setup:** Session 2 Fix #11 refactors `main.py` lifespan reaper
  block to derive the reaper SQL from
  `walker_registry.WALKER_AUTO_TRIGGERS` (a list of safe-runner
  callables). The refactor walks the list and emits one `UPDATE
  firmware SET <op>_walk_status='failed' WHERE <op>_walk_status IN
  ('queued','running')` per safe-runner. The intuition is "every
  walker gets a reaper". But `sbom_status`, `vuln_scan_status`,
  `bare_metal_audit_status`, `upload_stage`, `cve_match_status`,
  `device_dump_status`, `authenticode_chain_status`,
  `registry_hive_walk_status`, `dotnet_decompile_status`, etc. are
  202+polling state machines, NOT walker safe-runners.
- **Trigger:** A future Session 3+ adds Fix #11 and the refactor
  drops the existing five inlined reapers (device-dump, cve-match,
  vuln-scan, upload_stage, bare_metal_audit) in favor of "the new
  unified one". On the NEXT backend restart after a scan crash, only
  `*_walk_status` columns get reaped — `sbom_status` /
  `vuln_scan_status` rows remain `running` forever.
- **Outcome (un-mitigated):** Operator's stuck vuln-scan row from a
  pre-restart crash now permanently 409s every new scan attempt. The
  current Rule #51 §SC5-NEW-SBOM-α defense regresses silently.
- **Severity:** **HIGH** (regression of a Session 1 shipped Fix #5)
- **Maps to Rule:** Rule #47 (consumer-hook enumeration when changing
  a state-machine column source-of-truth) + Rule #51 (Rule #33 conversion
  invariant sweep across reapers)
- **Mitigation:** Fix #11's refactor splits the reaper list into TWO
  axes: `WALKER_STATUS_COLUMNS` derived from `WALKER_AUTO_TRIGGERS`
  AND `STATE_MACHINE_COLUMNS = ['sbom_status', 'vuln_scan_status',
  'bare_metal_audit_status', 'upload_stage', 'cve_match_status',
  'device_dump_status', 'authenticode_chain_status',
  'registry_hive_walk_status', 'dotnet_decompile_status', ...]`. The
  reaper SQL is emitted from BOTH lists. The function `assert_reaper_lists_disjoint_and_complete()`
  is a Rule #46 META-CANARY at startup that verifies every
  `*_status` / `*_stage` Mapped column on Firmware appears in
  EXACTLY ONE of the two lists.
- **Gate-canary (Rule #46):**
  ```python
  def test_reaper_lists_cover_every_state_column():
      from app.models.firmware import Firmware
      cols = {c.name for c in Firmware.__table__.columns
              if c.name.endswith(("_status", "_stage", "_walk_status"))}
      from app.main import WALKER_STATUS_COLUMNS, STATE_MACHINE_COLUMNS
      assert cols == set(WALKER_STATUS_COLUMNS) | set(STATE_MACHINE_COLUMNS)
      assert not (set(WALKER_STATUS_COLUMNS) & set(STATE_MACHINE_COLUMNS))
  ```

### §SC5-NEW-SBOM-S2-δ: Operator-supplied YAML × authority laundering (CRITICAL)

- **Setup:** The operator's mandate is "we won't be the only ones
  ingesting files into the tool". The Rule #52 first instance
  (file-format catalog) ALREADY enforces path-cross-check at
  `catalog.py:270-278`: a YAML at
  `data/file_formats.local/operator/aggressive.yaml` declaring
  `manifest_source: _system` is REJECTED at load with the message
  `path cross-check: file at aggressive.yaml (tier 'operator')
  declares manifest_source='_system'`. **But**: the Session 2
  adaptability fixes will create NEW operator-supplied YAML surfaces
  for extraction strategies (the ADAPTIVE_BACKLOG
  `prior-2026-05-18:RvwC-CC-2` proposes a `extraction_strategy`
  Literal — but its YAML enforcement is not designed yet) and may add
  walker-config YAML, SBOM-strategy YAML, etc.
- **Trigger:** An operator at a customer site drops
  `data/extraction_strategies/operator/aggressive.yaml` (NEW directory
  Session 2 creates) declaring:
  ```yaml
  strategy_source: _system
  apply_to: ".*\\.(zip|tar)"
  extraction_handler: shell_exec
  command: "tar xf {file} && cat /etc/shadow >> {extract_dir}/.x"
  ```
- **Outcome (un-mitigated):** If the new schema doesn't mirror the
  file-format catalog's path-cross-check, the manifest loads. If the
  Pydantic model doesn't use `extra: "forbid"` (per
  `feedback_wave2_cross_feature_methodology.md` memory entry), an
  unknown `command` field silently passes. If the closed-grammar
  doesn't enumerate the handlers via `Literal["builtin_tar",
  "builtin_zip", "builtin_unblob"]`, an arbitrary `shell_exec` value
  is accepted. Even if the handler isn't actually invoked (because no
  code path looks it up), the YAML now SITS in the data tree
  pretending to be a `_system` authority — the next operator-supplied
  walker that DOES consume `strategy_source: _system` to elevate
  privileges will accept it. This is the §SC5 authority-laundering
  shape verbatim.
- **Severity:** **CRITICAL** (authority laundering enables RCE if any
  downstream consumer trusts `_system` to mean "trusted built-in")
- **Maps to Rule:** Rule #36 (no-execute discipline — YAML must NOT
  carry `script`/`command`/`template`/`predicate` strings) + Rule #45
  (parse-only for security-sensitive surfaces) + Rule #52 (closed-grammar
  discipline for operator-extensible YAML)
- **Mitigation:** EVERY NEW operator-supplied YAML schema added in
  Session 2 (extraction-strategy, walker-config, SBOM-strategy, etc.)
  ships with: (a) Pydantic `model_config = ConfigDict(extra="forbid")`;
  (b) every extensible field is `Literal[<closed-vocabulary>]`; (c)
  path-cross-check mirroring `_expected_source_for_path` at
  `catalog.py:92-118`; (d) Rule #46 META-CANARY canary
  `test_<surface>_forbidden_keys_rejected` synthesizing the four
  forbidden tokens `regex|script|template|predicate|lua|expression|command`
  via in-memory YAML; (e) authority-laundering canary
  `test_<surface>_path_cross_check_rejects_operator_claiming_system`.
- **Gate-canary (Rule #46):**
  ```python
  def test_operator_yaml_cannot_claim_system_authority():
      from app.services.extraction_strategy_catalog import ExtractionStrategyCatalog
      cat = ExtractionStrategyCatalog(
          system_root=tmp_system, local_root=tmp_local,
      )
      (tmp_local / "operator" / "x.yaml").write_text(
          "strategy_source: _system\napply_to: '.*'\nhandler: builtin_tar\n"
      )
      with pytest.warns(UserWarning, match="path cross-check"):
          snap = cat.get_snapshot()
      assert "x" not in snap.by_id  # rejected at load
  ```

### §SC5-NEW-SBOM-S2-ε: Polyglot ZIP×qcow2 × `_post_process_pipeline` strategy ambiguity

- **Setup:** Session 2 Fix #9 makes `_post_process_pipeline` invoke
  `unpack_firmware()` for generic archives (Scout A's Session 1
  primary suspect, only partially addressed by Fix #3's walker
  un-gating). The pipeline at `firmware_service.py:544-822` today has
  tar shortcut (line 588-660) THEN zip shortcut (line 663-759); Fix
  #9 adds a fallback `unpack_firmware` invocation when neither
  shortcut applies. An attacker crafts a polyglot:
  `.zip` containing both `META-INF/com/google/android/` (Android OTA
  marker per the `_is_android_firmware_zip` helper at line 675) AND
  `payload.bin` whose first 4 bytes are `QFI\xfb` (qcow2 magic).
- **Trigger:** Operator uploads `polyglot.zip`. The pipeline sees
  `is_zip=True`, calls `_is_android_firmware_zip(storage_path)` —
  returns True (META-INF dir present). The `is_rootfs` branch is
  skipped because `is_android` shortcuts it (per
  `firmware_service.py:679-680`). The Android-shortcut at line 685
  preserves the ZIP intact for Android-specific tooling.
- **Outcome (un-mitigated):** Android tooling later reads `payload.bin`
  thinking it's an Android boot image; some Android downstream parser
  hits the qcow2 magic and either crashes (best case) or misinterprets
  qcow2 metadata as Android-specific structures (worst case). With
  Fix #9 in place, the fallback `unpack_firmware()` also fires AFTER
  the Android shortcut (currently `extracted_via_shortcut` would be
  True so fallback skipped) — but if the fallback is added with the
  WRONG precondition (e.g. "if no fs_root yet" instead of "if not
  extracted_via_shortcut"), it ALSO fires and unblob recursively
  extracts the qcow2, producing dual extracted trees with conflicting
  detection-root sets.
- **Severity:** **HIGH** (silent dual-strategy ambiguity that depends
  on Fix #9's precondition choice)
- **Maps to Rule:** Rule #19 (evidence-first — probe with `xxd`
  before deciding precondition) + Rule #47 (consumer-hook enumeration
  when extending `_post_process_pipeline`'s strategy decision tree)
- **Mitigation:** Fix #9's fallback precondition is EXACTLY `if not
  extracted_via_shortcut and not is_android and not is_rootfs`. The
  closed-grammar `extraction_strategy: Literal["shortcut_tar",
  "shortcut_rootfs_zip", "shortcut_android_zip",
  "shortcut_generic_zip", "unblob", "unrecognized"]` is set ONCE per
  pipeline run, and the polyglot case is logged as a WARN to operator
  ("polyglot detected; chose <strategy> per highest-precedence
  marker"). The strategy column is persisted on Firmware for operator
  inspection.
- **Gate-canary (Rule #46):**
  ```python
  async def test_polyglot_android_qcow2_picks_android_strategy():
      fw = create_firmware_with_polyglot(android=True, qcow2_magic=True)
      await _post_process_pipeline(db, fw, update_stage=True)
      assert fw.extraction_strategy == "shortcut_android_zip"
      # fallback unblob did NOT fire — fs_root stays android-specific
  ```

### §SC5-NEW-SBOM-S2-ζ: Nested archive bomb × Fix #9 unblob fallback

- **Setup:** Fix #9 adds `unpack_firmware()` invocation for generic
  archives that don't match any shortcut. `unpack_firmware` calls
  `run_unblob_extraction` at `unpack_common.py:943` with
  `timeout=1200` (20 minutes). Operator (malicious or naive) uploads
  a 200 KB tarball that, on unblob-recursive extraction, expands to
  100,000+ small files at depth 50 (a controlled zip-bomb variant).
- **Trigger:** Pipeline reaches the fallback `unpack_firmware`. unblob
  starts recursive extraction; depth-traversal explodes file count.
- **Outcome (un-mitigated):** unblob does NOT have a built-in file-count
  cap (verified by `unblob --help` flag review per Rule #6). The
  worker container's inode count exceeds the filesystem's available
  inodes; subsequent file creates fail with `ENOSPC`. The detection
  pipeline's downstream walkers (each opens its own session +
  scandirs the tree) start failing with ENOSPC; symptoms cascade
  across UNRELATED firmware on the same worker. The shared-worker
  pool inode exhaustion is a denial-of-service for the cluster.
- **Severity:** **HIGH** (DoS surface; depth-based archive bombs are
  a known attack class)
- **Maps to Rule:** Rule #6 (CLI flag verification) + Rule #36
  (no-execute discipline is fine here; unblob runs as data parser —
  but no-execute didn't bound recursion depth or file count)
- **Mitigation:** (a) Fix #9 wraps `run_unblob_extraction` with a
  pre-flight `du -s` check + post-flight `find . | wc -l` cap, both
  bounded; (b) `unpack_common.py:961` adds
  `--depth 10 --max-extraction-bytes <N>` flags to the unblob
  invocation if unblob supports them (Rule #6 grep first); (c)
  worker container's filesystem mount has a quota; (d) the unblob
  output dir is a dedicated tmpfs with `size=20G` per container so
  exhaustion is contained.
- **Gate-canary (Rule #46):**
  ```python
  async def test_archive_bomb_bounded_by_unblob_depth():
      bomb = create_recursive_zip_bomb(depth=100, total_bytes_decompressed=100_000_000_000)
      result = await run_unblob_extraction(bomb, "/tmp/out", timeout=60)
      # unblob should reject OR cap; final file count < 50_000
      assert sum(1 for _ in Path("/tmp/out").rglob("*")) < 50_000
  ```

### §SC5-NEW-SBOM-S2-η: Concurrent operators × grype force_rescan transaction lock cascade

- **Setup:** Session 2 Fix #6 wraps grype's DELETE-then-INSERT
  (`grype_service.py:160-165`) in a single transaction per
  §SC5-NEW-SBOM-μ. Today the DELETE is UNCONDITIONAL at line 161 —
  grype always clears the firmware's vulnerabilities before
  inserting. Fix #6 makes the DELETE conditional on `force_rescan`
  AND wraps both DELETE+INSERT in the outer transaction.
- **Trigger:** Three operators trigger `force_rescan=True` on the
  same firmware simultaneously (Wave-2 §SC5-NEW-SBOM-γ analog — the
  SbomPage UI doesn't gate per-firmware; operators legitimately
  multi-tab triage). With Session 1's `TIER_A_LIGHT_ACK=30/hour`, each
  ack succeeds. Each background runner opens its own
  `async_session_factory()` session and races to acquire the
  per-firmware row-level lock on `firmware.vuln_scan_status='queued'`.
- **Outcome (un-mitigated):** Two of the three runners are stuck
  waiting for the row lock (PostgreSQL serial-update semantics). The
  third runner proceeds, DELETEs vulnerabilities, runs grype (~4
  minutes), INSERTs. The other two runners wait the full 4 minutes
  on the lock. After the first finishes, the second runs — DELETEs
  the rows the first just inserted, runs grype again, INSERTs again.
  The third does the same. **Total time: 12 minutes for 3 concurrent
  force_rescans of the same firmware** instead of 4 minutes if they
  coordinated. Each adds 30/hour budget consumption. Across a
  3-operator triage session, the 30/hour budget for that firmware
  evaporates in 90 minutes of triage thrash.
- **Severity:** **MEDIUM** (perf + rate-limit budget consumption;
  not a data-integrity issue because transactional DELETE+INSERT
  per Fix #6 makes each rescan atomic)
- **Maps to Rule:** Rule #33 .a (idempotency under concurrent
  triggers — the 409 already gates `queued`/`running`, but the
  three-operator race is exactly the case where 409 fires for
  operator-2 and operator-3 after operator-1's 202 has landed)
- **Mitigation:** (a) Verify the 409 fires correctly under concurrent
  POSTs — the row read at `routers/sbom.py:592` plus the write at
  line 598 must be in the same transaction with `SELECT ... FOR UPDATE`
  semantics or rely on a unique-constraint. (b) Frontend SbomPage
  pessimistically locally-disables the "Force Regenerate" button while
  any tab reports `vuln_scan_status='queued'`. (c) The `_BACKGROUND_TASKS`
  set at `routers/sbom.py:25` already prevents create_task GC; the
  Session 2 broader sweep should extend this to the 4 sites at
  `routers/hardware_firmware.py:654,750` + `routers/fuzzing.py:143`.
- **Gate-canary (Rule #46):**
  ```python
  async def test_concurrent_force_rescan_409s_correctly():
      fw = create_firmware_with_sbom_components()
      r1 = await client.post(f"/firmware/{fw.id}/vulnerabilities/scan?force_rescan=true")
      assert r1.status_code == 202
      r2 = await client.post(f"/firmware/{fw.id}/vulnerabilities/scan?force_rescan=true")
      assert r2.status_code == 409  # idempotency check fires
      r3 = await client.post(f"/firmware/{fw.id}/vulnerabilities/scan?force_rescan=true")
      assert r3.status_code == 409
  ```

### §SC5-NEW-SBOM-S2-θ: Fix #11 reaper × operator-supplied future walker

- **Setup:** Fix #11 derives the reaper list from
  `WALKER_AUTO_TRIGGERS`. Per the operator's adaptability mandate, a
  FUTURE Rule #52 walker will be operator-supplied (e.g.
  `data/walkers/operator/my_proprietary_decoder.yaml` declaring a
  walker plugin per the `register_matcher` precedent in
  `file_format_catalog/plugins/`). The operator's walker declares its
  status column as `my_proprietary_status` with values `(idle,
  queued, running, completed, failed, partial)` — note the
  `partial` state outside the Rule #33 .c canonical 5-state.
- **Trigger:** Operator's walker emits `partial` mid-run; backend
  restarts; Fix #11's reaper runs `UPDATE firmware SET
  my_proprietary_status='failed' WHERE my_proprietary_status IN
  ('queued', 'running')`. The `partial` row is NOT in that set; it
  stays at `partial`. The operator's NEXT scan attempt's 409 check
  reads `if my_proprietary_status in ('queued', 'running')` — also
  False. The new scan starts, races the orphaned partial state.
- **Outcome (un-mitigated):** Two concurrent partial scans on the
  same firmware; the operator's walker likely has no internal
  idempotency on `partial` state; results corrupt.
- **Severity:** **MEDIUM** (depends on operator's walker
  state-machine discipline; if they follow Rule #33 .c the issue
  is structurally prevented)
- **Maps to Rule:** Rule #33 .c (closed 5-state grammar is MANDATORY
  for any new state-machine column; `partial` is forbidden) + Rule #52
  (closed-grammar discipline at YAML load) + Rule #47 (consumer-hook
  enumeration — operator-supplied walkers MUST inherit the reaper
  shape)
- **Mitigation:** Operator-supplied walker registration at
  `walker_registry.py` analog REJECTS any walker whose declared
  status-column states aren't a strict subset of `{'idle', 'queued',
  'running', 'completed', 'failed'}`. The Pydantic model for
  walker-config YAML uses `WalkerStatus =
  Literal["idle","queued","running","completed","failed"]`. Fix #11's
  reaper-derivation walks the column metadata via SQLAlchemy `Mapped`
  reflection and asserts every status column declares the canonical
  CHECK constraint shape at startup.
- **Gate-canary (Rule #46):**
  ```python
  def test_operator_walker_yaml_rejects_partial_state():
      from app.services.walker_catalog import WalkerCatalog
      yaml_text = "walker_id: x\nstates: [idle, queued, running, partial]\n"
      with pytest.raises(ValidationError, match="partial"):
          WalkerManifest.model_validate(yaml.safe_load(yaml_text))
  ```

### §SC5-NEW-SBOM-S2-ι: Grype `force_rescan=True` × SBOM regeneration race

- **Setup:** Fix #6 (transactional grype DELETE+INSERT) + Fix #1
  (SBOM /generate 202+polling). Operator's workflow:
  `force_rescan=True` on /sbom/generate (which now clears
  `sbom_components` per existing line 169-174 and waits the polling
  loop) → operator clicks Vuln Scan force_rescan=True BEFORE the SBOM
  regen completes.
- **Trigger:** SBOM regen is in `sbom_status='running'`, mid-flush of
  the new component rows. Vuln scan's 409 check reads
  `if vuln_scan_status in ('queued', 'running')` — False (vuln_scan
  is idle). The 202 returns; the vuln-scan background runner
  immediately tries to read `sbom_components` and call
  `scan_with_grype` (`routers/sbom.py:493-497`). It sees a partial
  set of components (the SBOM regen has flushed some but not all);
  grype runs against an incomplete CDX; matches against the partial
  set; transactional DELETE removes prior vulnerabilities; INSERTs
  vulnerabilities matching the PARTIAL component set. The SBOM regen
  then completes, adding more components, but those components have
  no vulnerability rows.
- **Outcome (un-mitigated):** Inconsistent
  vulnerability/component pair; some components have no vulnerability
  rows even though they should match a CVE. Operator sees "10
  components, 3 vulnerabilities" when the truth is "15 components, 7
  vulnerabilities". Silent under-reporting.
- **Severity:** **HIGH** (silent under-reporting of vulnerabilities
  — security regression)
- **Maps to Rule:** Rule #33 .a (idempotency under cross-endpoint
  state interactions) + Rule #47 (consumer-hook enumeration —
  vuln-scan is a consumer of sbom_components)
- **Mitigation:** `routers/sbom.py:587` vuln-scan POST adds the
  precondition `if firmware.sbom_status in ('queued', 'running'):
  raise HTTPException(409, "SBOM generation in progress; wait for
  completion")`. Frontend SbomPage disables the Vuln Scan button while
  `sbom_status` is `queued`/`running`. The vuln-scan background runner
  re-reads `sbom_status` immediately before calling `scan_with_grype`
  and aborts with `vuln_scan_status='failed'` + error message if SBOM
  generation slid into running between the 202 ack and the runner's
  start.
- **Gate-canary (Rule #46):**
  ```python
  async def test_vuln_scan_409s_while_sbom_generate_running():
      fw = create_firmware(sbom_status="running")
      r = await client.post(f"/firmware/{fw.id}/vulnerabilities/scan")
      assert r.status_code == 409
      assert "SBOM generation in progress" in r.json()["detail"]
  ```

### §SC5-NEW-SBOM-S2-κ: Broader create_task GC sweep × misses `routers/fuzzing.py:143`

- **Setup:** Session 2 broader sweep extends the
  `_spawn_background_task` helper at `routers/sbom.py:28-37` to the 4
  other sites identified at session-1 close:
  `routers/hardware_firmware.py:654,750`, `routers/fuzzing.py:143`,
  and `routers/firmware.py:175,297`. If the sweep misses any one
  site, the GC-vanish symptom recurs at that site.
- **Trigger:** Sweep PR ships covering 3 of 4 sites; the 4th (e.g.
  `fuzzing.py:143`) is missed because the grep used was
  `grep -n "asyncio.create_task" backend/app/routers/*.py | grep -v
  "_spawn_background_task"` and the `fuzzing.py` line uses a
  documented comment immediately above. Operator runs a fuzzing
  campaign that triggers GC pressure mid-spawn.
- **Outcome (un-mitigated):** The fuzzing background spawn task is
  GC'd; the campaign row stays in `status='queued'` forever; same
  symptom Scout D's Session 1 primary symptom enumerated for vuln_scan.
- **Severity:** **MEDIUM** (regression of Fix #8 to a different
  router; cosmetic-impact-only since fuzzing-status reaper covers it)
- **Maps to Rule:** Rule #31 (width-canary discipline — re-run the
  grep with the broader pattern before trusting the count)
- **Mitigation:** Session 2 sweep's grep uses `grep -rn
  'asyncio\.create_task\|asyncio\.gather' backend/app/routers/` and
  verifies the count against `git grep
  '_spawn_background_task\|asyncio\.create_task'` to confirm
  each site is covered. A repo-wide ruff rule
  `no-bare-asyncio-create-task-in-routers` (custom plugin) blocks
  future regressions.
- **Gate-canary (Rule #46):**
  ```python
  def test_no_bare_asyncio_create_task_in_routers():
      import re
      for path in Path("backend/app/routers").rglob("*.py"):
          src = path.read_text()
          # All `asyncio.create_task` must be in `_spawn_background_task`
          # OR a documented comment above
          matches = list(re.finditer(r"asyncio\.create_task\(", src))
          for m in matches:
              # Find the line; check the 5 lines above for either
              # _spawn_background_task definition OR a # noqa rationale
              ctx = src[max(0, m.start()-200):m.start()]
              assert "_spawn_background_task" in ctx or "# noqa: BARE_CREATE_TASK" in ctx
  ```

### §SC5-NEW-SBOM-S2-λ: Polling cadence × dual sbom/vuln-scan polls × DB pool exhaustion (S2 escalation)

- **Setup:** Session 1 already addressed §SC5-NEW-SBOM-γ partially
  by bumping the DB pool to 15+25=40 and shipping the vuln-scan
  reaper. Session 2 Fix #1 adds `sbom_status` as a second 202+polling
  state. Now the SbomPage MIGHT poll BOTH `/sbom/generate/status` AND
  `/sbom/vulnerabilities/scan/status` every 2s.
- **Trigger:** 5 operators each open SbomPage in 2 tabs each = 10
  parallel polling sessions. Each session polls 2 endpoints × 1 req
  per 2s = 5 req/s sustained. Total: 50 req/s across the cluster,
  each acquiring a DB connection via `Depends(get_db)`.
- **Outcome (un-mitigated):** The pool 40 fills with polling
  connections. Other endpoints (firmware list, file tree) timeout.
- **Severity:** **HIGH** (multi-operator triage hits the pool ceiling)
- **Maps to Rule:** Rule #51 .iv (DB pool headroom) + Rule #29
  (polling cadence as a perf surface)
- **Mitigation:** (a) Frontend polling backoff (2s → 4s → 8s → 16s
  → 32s) per W2-β §SC5-NEW-SBOM-λ. (b) Frontend visibility-API
  gating: hidden tabs stop polling. (c) Composite-status endpoint
  `/firmware/{id}/status-composite` returns BOTH `sbom_status` AND
  `vuln_scan_status` in one query, halving the polling overhead. (d)
  DB pool bump to 20+30=50.
- **Gate-canary (Rule #46):** Identical to Session 1 W2-β §SC5-NEW-SBOM-λ.

## Unknown-Format Robustness

**Today:** Operator uploads `.dmg` / `.qcow2` / `.efi` / `.ima` /
`.bup` / custom-extension — the file-format catalog falls through to
`linux_blob_fallback` (the floor-tier sentinel at
`data/file_formats/_system/linux_blob_fallback.yaml`). The
`_post_process_pipeline` neither tar nor zip shortcut fires;
`firmware.extracted_path` stays NULL. Walkers run via Fix #3's
un-gated fan-out, but `get_detection_roots(firmware)` returns `[]`
(no extracted_path); each walker no-ops cleanly. SBOM /generate today
(synchronous) returns `cached=False, total=0`. **Operator perceives:
"my firmware uploaded but wairz did nothing".**

**Session 2 should ensure:** (a) Closed `DetectedFormat` Literal adds
explicit `unknown` member (per Rule #52); the schema-driven response
surface tells the operator EXACTLY what was detected (e.g.
`detected_format: 'unknown'` vs `detected_format: 'qcow2_sparse'`
where `qcow2_sparse` is a NEW closed-grammar entry that operators
can ship via `data/file_formats.local/operator/qcow2.yaml`). (b)
Graceful-degrade in SBOM /generate's 202+polling runner — if
`detected_format == 'unknown'`, runner stamps result and returns
without scanning. (c) Frontend banner on SbomPage when
`detected_format == 'unknown'` linking to operator-docs for
custom-format YAML authoring.

## Operator-Supplied YAML Attack Surface (Rule #52)

Three distinct authority-laundering analogs apply across new operator-
supplied YAML surfaces Session 2 may create:

1. **Extraction-strategy YAML** (ADAPTIVE_BACKLOG
   `prior-2026-05-18:RvwC-CC-2`): the proposal is closed-grammar
   `Literal["shortcut_clean", "shortcut_recursed", "unblob"]`. EXTEND
   this to include `manifest_source` field + path-cross-check per
   `_expected_source_for_path` analog. Pydantic
   `model_config = ConfigDict(extra="forbid")` MANDATORY.

2. **Walker-config YAML** (future Rule #52 walker shape — per Rule
   #44 the operator-supplied walker MUST emit a
   `lookup_<artefact>_across_firmwares` MCP tool). Schema enforces
   `WalkerStatus` Literal MUST equal the canonical 5-state. Plugin
   handler discovery via `register_matcher` analog — frozen
   post-startup per file-format catalog precedent (`catalog.py`
   `PLUGIN_REGISTRY` is module-level `freeze_plugin_registry`'d).
   Operator YAML CANNOT carry plugin Python code; only `plugin_ref`
   string keyed to the pre-frozen registry.

3. **SBOM-strategy YAML** (Session 2 Fix #1 may add — strategy
   pattern for SBOM generators across vendor families). Same shape;
   same gates.

**Cross-cutting required gates** (apply to ALL three NEW surfaces):
(a) Pydantic `extra: "forbid"` (b) every extensible field closed
Literal (c) `_expected_source_for_path` cross-check (d)
`PLUGIN_REGISTRY` is module-level + frozen post-startup (e) Rule #46
META-CANARY synthesizing forbidden-key in-memory YAML AND assertion
the gate fires. The `feedback_wave2_cross_feature_methodology.md`
memory entry's Rule #52 W2-β template applies verbatim: 5 Wave-1
single-axis scouts + 3 Wave-2 critique scouts (W2-α / W2-β / W2-γ)
for any new closed-grammar surface.

## Cross-Feature Cascade (W2-β analog)

If Session 2 ships Fix #1 + Fix #9 + Fix #11 + Fix #6 BUT skips the
hardening above, the worst-case multi-operator triage session is:

1. Operator A uploads `unknown.qcow2`. Fix #9's fallback runs
   `unpack_firmware`; unblob produces a 50 GB extraction; SBOM
   /generate (Fix #1) runs into §SC5-NEW-SBOM-S2-β (OOM kill).
2. Backend container crashes; on restart Fix #11's derived reaper
   (without §SC5-NEW-SBOM-S2-γ split) misses `sbom_status` — the row
   stays `running` forever.
3. Operator A retries; 409 forever.
4. Operator B opens a malicious YAML at
   `data/extraction_strategies/operator/x.yaml` claiming
   `strategy_source: _system` per §SC5-NEW-SBOM-S2-δ; no
   path-cross-check; the file loads. The handler isn't invoked, but
   the YAML accreted as "trusted _system authority" — a future
   Session 3+ walker that consumes `strategy_source` for elevation
   accepts it.
5. Operator C concurrently triggers `force_rescan=True` on a SBOM
   that's mid-regen per §SC5-NEW-SBOM-S2-ι; vulnerabilities are
   silently under-reported.
6. Operator D's tab polls trigger §SC5-NEW-SBOM-S2-λ; the pool fills;
   firmware list endpoint times out for Operator E.
7. **Operator perceives Session 2 made things strictly worse.** Files
   a critical bug. Fix sweep gets reverted.

## Pre-Cutover Robustness Checklist

| Session 2 Fix | Required Gate-Canaries Before Merge |
|---|---|
| **Fix #1** (SBOM /generate 202+polling) | §SC5-NEW-SBOM-S2-α (unknown-format graceful-degrade); §SC5-NEW-SBOM-S2-β (memory-bound); §SC5-NEW-SBOM-S2-ι (sbom-vuln race 409); §SC5-NEW-SBOM-S2-λ (polling backoff + composite endpoint) |
| **Fix #6** (grype force_rescan) | §SC5-NEW-SBOM-S2-η (concurrent 409 verification + frontend button gate); transactional rollback per Session 1 §SC5-NEW-SBOM-μ |
| **Fix #9** (`_post_process_pipeline` unblob fallback) | §SC5-NEW-SBOM-S2-ε (polyglot precedence); §SC5-NEW-SBOM-S2-ζ (archive-bomb bounded recursion) |
| **Fix #11** (walker reaper sweep) | §SC5-NEW-SBOM-S2-γ (reaper list completeness — split walker vs state-machine columns); §SC5-NEW-SBOM-S2-θ (operator-supplied walker state-set discipline) |
| **Broader create_task sweep** | §SC5-NEW-SBOM-S2-κ (width-canary grep + ruff plugin) |
| **NEW closed-grammar surfaces** (extraction-strategy YAML, walker-config YAML, SBOM-strategy YAML) | §SC5-NEW-SBOM-S2-δ (path-cross-check + extra:forbid + closed Literals + Rule #46 META-CANARY for every absence assertion) |

## Recommendations for W2-α + W2-γ

1. **W2-α convergence MUST resolve the Fix #11 reaper-derivation
   question explicitly.** Two camps: (a) walker-only reaper derived
   from `WALKER_AUTO_TRIGGERS`; (b) two-axis reaper covering walkers
   AND state-machine columns. Pick (b) per §SC5-NEW-SBOM-S2-γ;
   require the Rule #46 META-CANARY that asserts column-list
   completeness via SQLAlchemy reflection.

2. **W2-α MUST flag Fix #9's fallback precondition as a precision
   risk.** §SC5-NEW-SBOM-S2-ε shows the polyglot ambiguity. The
   precondition is exactly `if not extracted_via_shortcut and not
   is_android and not is_rootfs` — not `if fs_root is None`.

3. **W2-γ Rule #28 yardstick re-measure:** `routers/sbom.py` 1114
   LOC + `firmware_service.py` 937 LOC + `walker_registry.py` 201
   LOC + `grype_service.py` 264 LOC + `unpack_common.py` 1950 LOC.
   Fix #1 adds ~300 LOC (sbom_status migration + 202+polling +
   tests). Fix #9 adds ~140 LOC (fallback unblob + tests). Fix #11
   adds ~220 LOC (refactor + META-CANARY). Fix #6 adds ~90 LOC.
   Broader create_task sweep adds ~80 LOC. **Drift-adjusted total
   ~1,170 net LOC for Session 2** — within the W2-γ single-session
   envelope but close to the +20% drift line. W2-γ verdict should
   reaffirm SINGLE-SESSION-FEASIBLE with a §SC5-NEW-SBOM-S2 hardening
   bundle requirement.

4. **W2-α should converge on closed-grammar discipline for ALL NEW
   operator-supplied YAML surfaces.** §SC5-NEW-SBOM-S2-δ is the
   CRITICAL attack; every Session 2 fix that introduces a new YAML
   surface inherits the Rule #52 framework's 5 gates: `extra:forbid`,
   closed Literals, path-cross-check, frozen plugin registry, Rule #46
   META-CANARY trio. The file-format catalog's `catalog.py:270-278`
   is the precedent; copy verbatim.

5. **W2-α should explicitly require the `_spawn_background_task`
   helper to MOVE to `app/utils/background.py`** as a shared utility,
   not inline in `routers/sbom.py:28-37`. This is the cleanest way to
   prevent §SC5-NEW-SBOM-S2-κ regression — every router imports the
   shared helper; no per-router copies drift.

6. **For W2-β (this scout's natural successor in a future session):**
   Cross-feature the Session 2 Fix #9 unblob fallback against the
   Session 1 §SC5-NEW-SBOM-η walker fan-out semaphore. The semaphore
   bounds walker concurrency; does it bound unblob spawn concurrency?
   If a single operator uploads 5 unknown firmware in burst, do 5
   unblob processes fire concurrently and starve the worker
   container? The mitigation may need a SECOND semaphore in
   `_post_process_pipeline`.
