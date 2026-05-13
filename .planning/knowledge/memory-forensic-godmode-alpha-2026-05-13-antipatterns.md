# Anti-patterns: λ memory-forensic-godmode α (session 1)

> Extracted: 2026-05-13
> Postmortem: ``.planning/postmortems/postmortem-memory-forensic-godmode-alpha-session-1-2026-05-13.md``

## Failed Patterns

### 1. SQLAlchemy identity-map masking walker effect in a backfill script

- **What was done:** First version of
  ``backend/scripts/backfill_walker_results_2026_05_13.py`` re-SELECTed
  the firmware row after the walker chain ran in fresh sessions.
  The outer ``async_session_factory`` session's identity map returned
  the cached pre-walk firmware row; the re-SELECT reported
  "results 0 → 0" even though walkers had stamped 21 result columns.
- **Failure mode:** Silent under-count. The backfill reported success
  but operators couldn't tell whether walkers actually ran or were
  no-ops. Worse, the natural diagnostic — "compare results before
  vs after" — became misleading.
- **Evidence:** Smoke test ``--firmware-id 998c547e`` showed
  ``results 0 → 0`` while ``\d firmware`` showed all 21 result
  columns populated.
- **How to avoid:** When walkers commit to DIFFERENT sessions and
  the outer needs a refreshed view, ``db.expire(firmware)`` BEFORE
  the re-SELECT is mandatory. Plain re-SELECT returns the cached
  instance. This is the rare case where ``db.refresh`` IS load-bearing
  (Rule #32 lists this as the explicit exception). Prefer the
  explicit ``db.expire(<obj>)`` + re-SELECT shape over
  ``db.refresh`` because the intent is clearer in code review.

### 2. Tests dir not bundled in runtime image

- **What was done:** Tried to run ``docker compose exec backend pytest
  tests/test_tar_of_image_integration.py`` for local verification of
  the test fix; ``/app/tests`` didn't exist in the backend container.
- **Failure mode:** Local test verification blocked. Operators have
  to either (a) ``docker cp`` the test directory in, OR (b) install
  ``pytest`` + ``pytest-asyncio`` ad-hoc into the venv, OR (c)
  build the CI image variant.
- **Evidence:** ``docker compose exec -T backend ls /app/tests``
  returned ``Could not find the file /app/tests in container``.
- **How to avoid:** Either (a) make tests a bind-mount in
  docker-compose.yml so ``docker compose exec backend pytest`` works
  out-of-box, OR (b) document the docker-cp + pip-install workaround
  in CLAUDE.md so future agents don't waste a cycle figuring it out.
  Latter is cheaper.

### 3. Spec-claim vs DB-truth drift

- **What was done:** Session resume said "16 firmware rows have NULL
  extracted_path between 847eae9 and 5f3d195". DB query returned 0
  rows matching that exact criterion.
- **Failure mode:** If the script had been authored blind to the
  spec drift, it would have shipped a no-op (Rule #19 dormant-
  abstraction antipattern). The Rule #19 reflex (query DB before
  writing the SQL) caught it.
- **Evidence:** ``SELECT count(*) FROM firmware WHERE upload_stage =
  'ready' AND extracted_path IS NULL;`` returned 0; widening the
  criteria to ``extracted_path IS NOT NULL AND
  registry_hive_walk_result IS NULL`` surfaced the real 16-row
  scope.
- **How to avoid:** Apply Rule #19 evidence-first reflex to EVERY
  spec-derived count. The DB describes truth; specs describe intent
  at-write-time which may have aged. Rule #31 width-canary discipline
  (re-run with broader regex/SQL) catches the false-zero shape.

### 4. Worker image stale relative to backend image

- **What was done:** Tried to run the backfill script against the
  worker container (intended for the long-running pipeline). The
  worker's ``app.workers.walker_registry`` import failed:
  ``ModuleNotFoundError: No module named 'app.workers.walker_registry'``.
  Backend container had it; worker didn't. Resume notes said all
  three (backend / worker / migrator) were rebuilt — but worker
  evidently wasn't.
- **Failure mode:** Two images that should be identical per Rule #8
  diverged silently. Resume notes lied about "all rebuilt", or the
  rebuild was skipped, or one container picked up cached layers.
- **Evidence:** ``docker compose images backend worker migrator``
  shows three different image IDs (``ee0d3f1622b9``, ``faa0e7b98d3f``,
  ``d65f47dfde56``) — yet they SHOULD be the same per Rule #8.
- **How to avoid:** Rule #8 explicitly demands rebuilding backend +
  worker + migrator together. The drift seen this session is a
  Rule #8 violation surfaced during a maintenance task. The mitigation
  is to verify the image IDs match BEFORE trusting "all rebuilt"
  claims: ``docker compose images <a> <b> <c> | awk '{print $4}' |
  sort -u | wc -l`` must return 1.

### 5. Rule #47 consumer-hook miss on the walker-bridge fix

- **What was done:** Commit ``5f3d195`` (walker-bridge wire-in)
  changed ``firmware.extracted_path`` from "rootfs path" to "any
  extraction starting point". Tests that used the OLD invariant as
  a proxy were left orphaned.
- **Failure mode:** Backend Tests failed on the boundary commit
  ``44124db`` with a single assertion error in
  ``test_zip_of_fat_image_does_not_shortcut``. Caught by CI (the
  good case) but only on the boundary commit (Rule #41 — concurrency
  cancel-in-progress cancelled all intermediate runs).
- **Evidence:** ``44124db`` Backend Tests failure log:
  ``AssertionError: zip containing a raw FS image was falsely
  classified as rootfs / assert
  '/data/firmware/.../zip_contents' is None``.
- **How to avoid:** Rule #47 mitigation. When a state-machine /
  semantic refactor lands, grep ALL consumers of the old semantic
  and migrate the test assertions to discriminate on a TRUE-intent
  signal (in this case, ``unpack_log`` text marker). The
  walker-bridge author needed to grep ``firmware\.extracted_path
  is None`` across the test suite before merging.

### 6. Symbol bundles can't ship in this commit chain

- **What was done:** λ.α.C Dockerfile gate references
  ``backend/vol3-symbols/{windows,linux,mac}.zip`` for the build-time
  COPY + sha256sum -c verify, but those bundles aren't fetched
  yet (~885 MiB combined).
- **Failure mode:** ``docker compose build --build-arg INCLUDE_VOL3=1``
  with the gate enabled will fall into the "SHA256SUMS absent"
  graceful-degrade branch, log a warning, and ship an image WITHOUT
  any symbol bundles. λ.α.D vol3_runner builds will detect the empty
  symbols dir and fail with "no symbols available" — correct per
  Rule #37 truthful-degradation but UX-confusing without context.
- **Evidence:** ``ls backend/vol3-symbols/`` shows
  ``README.md, SHA256SUMS.url`` — no ``.zip``, no ``SHA256SUMS``.
- **How to avoid:** Ship ``scripts/refresh-vol3-symbols.sh`` and run
  it BEFORE the first INCLUDE_VOL3=1 build is expected to succeed
  end-to-end. This session shipped the gate scaffolding only;
  bundle fetch + commit is the next session's first task.

## Quality rule candidates (none promoted)

No high-confidence regex-expressible rules emerged from this session.
The patterns above are all SHAPE-discipline / mechanical-reflex
patterns that resist auto-enforcement.

The Rule #47 mechanical reflex ("grep all consumers of an
extracted_path-style proxy before merging the refactor") IS regex-
expressible against test files, but the proxy is too generic
(``\.extracted_path\s+is\s+None``) to fire only on legitimate
candidates without high false-positive rate. Left as a Rule #47
codification + manual-review item.

Anti-pattern #4 (worker image stale) could become a pre-commit
``docker compose images`` health-check that warns when the three
images have different IDs, but this is a HOOK not a quality rule.
Filed for separate consideration.
