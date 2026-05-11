"""LATTE-style LLM taint analysis MCP tools.

Two tools:

* ``scan_taint_analysis`` — fast, binary-wide pre-filter that returns a
  structured prompt asking the MCP client (Claude) to rank candidate
  vulnerable functions. Reuses the existing Ghidra analysis cache
  (``list_imports`` / ``xrefs`` / ``decompile_function``) to build the
  candidate list; composes a CoT prompt with per-candidate decompiled
  snippets and a JSON output schema.

* ``deep_dive_taint_analysis`` — per-function deep-dive that slices a
  2-hop neighbourhood around the target (xrefs both directions),
  identifies source / sink call sites against the YAML dictionaries, and
  composes a 4-stage CoT prompt matching the LATTE paper (sink-ID →
  source-ID → dataflow → CWE classification).

Both tools return **strings** (structured prompts). The MCP client — the
already-connected Claude — performs the reasoning. No Anthropic SDK
import, no API keys on the backend. See CLAUDE.md §Security rule 3 and
the intake `feature-latte-llm-taint-analysis.md` for the positioning
rationale.

Cache: composed prompts are stored in ``analysis_cache`` under
``taint_scan:<md5-12>`` / ``taint_deepdive:<md5-12>`` keyed on binary
sha256 + tool args, so re-scans are free. ``analysis_cache.operation``
is ``VARCHAR(512)`` — our keys are ~30 chars (CLAUDE.md rule 15).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services import ghidra_service
from app.services.ghidra_service import decompile_function

logger = logging.getLogger(__name__)

# Dictionary files live alongside this module so changes ship together.
_THIS_DIR = Path(__file__).resolve().parent
_SINKS_YAML = _THIS_DIR / "_taint_sinks.yaml"
_SOURCES_YAML = _THIS_DIR / "_taint_sources.yaml"

# Per-candidate decomp budget when composing the scan prompt. 50
# candidates × 1.5KB ≈ 75KB pre-truncate; after 30KB cap we retain
# roughly the top 20 by score — that's intentional, score ordering is
# the filter.
_SCAN_DECOMP_BYTES = 1500

# Per-hop decomp budget for the deep-dive prompt. Target is one function
# in depth + ~7 neighbours as context; decomp of the target itself gets
# the larger budget.
_DEEPDIVE_TARGET_DECOMP_BYTES = 8000
_DEEPDIVE_NEIGHBOUR_DECOMP_BYTES = 800

# Cap on ``max_candidates`` so we can't accidentally OOM / blow the
# 30KB truncation cap with a pathological request.
_MAX_CANDIDATES_CAP = 200

# Confidence levels — ordered low→high for comparison.
_CONFIDENCE_LEVELS = ("low", "medium", "high")


# ---------------------------------------------------------------------------
# YAML dictionary loaders
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_sinks_yaml() -> dict[str, Any]:
    """Load sink dictionary. Cached for process lifetime.

    Reloading requires process restart; the tool is a read-only consumer
    of the YAML.
    """
    with open(_SINKS_YAML, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    families = data.get("families") or {}
    if not isinstance(families, dict):
        raise ValueError(f"Malformed {_SINKS_YAML.name}: 'families' must be a dict")
    return data


@lru_cache(maxsize=1)
def _load_sources_yaml() -> dict[str, Any]:
    """Load source dictionary. Cached for process lifetime."""
    with open(_SOURCES_YAML, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    families = data.get("families") or {}
    if not isinstance(families, dict):
        raise ValueError(f"Malformed {_SOURCES_YAML.name}: 'families' must be a dict")
    return data


def _sink_name_set() -> set[str]:
    """Flat set of every sink symbol across all families."""
    out: set[str] = set()
    for fam in _load_sinks_yaml().get("families", {}).values():
        out.update(fam.get("sinks") or [])
    return out


def _source_name_set() -> set[str]:
    """Flat set of every source symbol across all families."""
    out: set[str] = set()
    for fam in _load_sources_yaml().get("families", {}).values():
        out.update(fam.get("sources") or [])
    return out


def _sink_to_cwe() -> dict[str, str]:
    """Map each sink name to its CWE family identifier (best-match)."""
    out: dict[str, str] = {}
    for fam_name, fam in _load_sinks_yaml().get("families", {}).items():
        cwe = fam.get("cwe", "CWE-unknown")
        for sink in fam.get("sinks") or []:
            # First-hit-wins if the same name appears in two families.
            out.setdefault(sink, cwe)
    return out


# ---------------------------------------------------------------------------
# Ranking / filtering
# ---------------------------------------------------------------------------


def _rank_candidates(
    xrefs: dict[str, dict[str, list[dict]]],
    imports: list[dict],
    sinks: set[str],
    sources: set[str],
) -> list[dict]:
    """Score every caller-of-a-sink and return ranked list.

    Scoring (intentionally coarse so the MCP client does the nuanced
    triage):

    * +2 per distinct dangerous sink the function calls directly.
    * +1 per distinct user-input source the function calls directly.
    * +1 if the function has ≥3 incoming callers (centrality proxy).
    * +1 if the function is named ``main`` or contains the substring
      ``handle`` / ``parse`` / ``cmd`` / ``request`` (common entry shapes).

    Returns list of ``{"function", "score", "sinks": [...],
    "sources": [...], "incoming_callers": int, "primary_cwe": str}``
    sorted by score descending.
    """
    imported_names = {imp.get("name") for imp in imports if imp.get("name")}
    imported_sinks = imported_names & sinks
    imported_sources = imported_names & sources

    if not imported_sinks:
        return []

    sink_cwe = _sink_to_cwe()
    candidates: dict[str, dict] = {}

    # Pass 1: for each function, inspect its outgoing xrefs and bucket
    # sinks + sources touched.
    for func_name, func_data in xrefs.items():
        touched_sinks: set[str] = set()
        touched_sources: set[str] = set()
        for ref in func_data.get("from", []) or []:
            to_func = ref.get("to_func") or ""
            if to_func in imported_sinks:
                touched_sinks.add(to_func)
            if to_func in imported_sources:
                touched_sources.add(to_func)
        if touched_sinks:
            candidates[func_name] = {
                "function": func_name,
                "sinks": sorted(touched_sinks),
                "sources": sorted(touched_sources),
                "incoming_callers": len(func_data.get("to", []) or []),
            }

    # Pass 2: score + assign primary CWE (first sink's CWE).
    ranked: list[dict] = []
    for name, data in candidates.items():
        score = (
            2 * len(data["sinks"])
            + len(data["sources"])
            + (1 if data["incoming_callers"] >= 3 else 0)
        )
        lname = name.lower()
        if name == "main" or any(
            tok in lname for tok in ("handle", "parse", "cmd", "request")
        ):
            score += 1
        primary_cwe = sink_cwe.get(data["sinks"][0], "CWE-unknown")
        ranked.append(
            {
                **data,
                "score": score,
                "primary_cwe": primary_cwe,
            }
        )

    ranked.sort(key=lambda c: (-c["score"], c["function"]))
    return ranked


def _apply_confidence_gate(
    ranked: list[dict], min_confidence: str
) -> list[dict]:
    """Filter candidates by confidence threshold.

    * ``low``: score ≥ 1 (anything that calls a sink).
    * ``medium``: ≥2 sinks OR (≥1 sink AND ≥1 source).
    * ``high``: ≥2 sinks AND ≥1 source.
    """
    if min_confidence not in _CONFIDENCE_LEVELS:
        min_confidence = "medium"

    out: list[dict] = []
    for c in ranked:
        ns = len(c["sinks"])
        nsrc = len(c["sources"])
        if min_confidence == "low" and c["score"] >= 1:
            out.append(c)
        elif min_confidence == "medium" and (ns >= 2 or (ns >= 1 and nsrc >= 1)):
            out.append(c)
        elif min_confidence == "high" and (ns >= 2 and nsrc >= 1):
            out.append(c)
    return out


# ---------------------------------------------------------------------------
# Prompt composition
# ---------------------------------------------------------------------------


def _truncate_decomp(body: str, max_bytes: int) -> str:
    """Middle-out truncate: keep first 60% and last 30%, inject marker."""
    if not body:
        return ""
    encoded = body.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return body
    head_bytes = int(max_bytes * 0.6)
    tail_bytes = int(max_bytes * 0.3)
    head = encoded[:head_bytes].decode("utf-8", errors="replace")
    tail = encoded[-tail_bytes:].decode("utf-8", errors="replace")
    # Align to line boundaries for readability.
    if "\n" in head:
        head = head.rsplit("\n", 1)[0]
    if "\n" in tail:
        tail = tail.split("\n", 1)[1]
    return f"{head}\n// ... [middle elided for brevity] ...\n{tail}"


def _compose_scan_prompt(
    binary_path: str,
    min_confidence: str,
    focus_cwe: list[str] | None,
    candidates: list[dict],
    decomps: dict[str, str],
    imports_count: int,
) -> str:
    """Render the scan-tool prompt. Returns a string under 30KB."""
    sinks_by_cwe = _load_sinks_yaml().get("families", {})
    focus_note = ""
    if focus_cwe:
        focus_note = (
            f"\nFocus on CWE families: {', '.join(focus_cwe)}. "
            f"Deprioritise other findings."
        )

    header = [
        "# LATTE-Style Binary Taint Analysis — Scan",
        "",
        f"Binary: `{binary_path}`",
        f"Imports inspected: {imports_count}",
        f"Confidence threshold: {min_confidence}",
        f"Candidate functions (pre-filtered): {len(candidates)}",
        focus_note,
        "",
        "## Sink inventory (by CWE family)",
        "",
    ]
    for fam_name, fam in sinks_by_cwe.items():
        header.append(
            f"- **{fam.get('cwe','?')}** ({fam_name}): "
            f"{', '.join(fam.get('sinks', [])[:8])}"
            + ("..." if len(fam.get("sinks", [])) > 8 else "")
        )
    header.append("")
    header.append("## Candidate functions (ranked by heuristic score)")
    header.append("")

    body: list[str] = []
    for idx, cand in enumerate(candidates, 1):
        func = cand["function"]
        decomp = decomps.get(func, "// (decompilation unavailable or failed)")
        body.append(f"### {idx}. `{func}` (score {cand['score']})")
        body.append(f"- Sinks called: {', '.join(cand['sinks']) or '(none)'}")
        body.append(f"- Sources visible: {', '.join(cand['sources']) or '(none)'}")
        body.append(f"- Incoming callers: {cand['incoming_callers']}")
        body.append(f"- Primary CWE guess: {cand['primary_cwe']}")
        body.append("")
        body.append("```c")
        body.append(_truncate_decomp(decomp, _SCAN_DECOMP_BYTES))
        body.append("```")
        body.append("")

    instructions = [
        "## Your task",
        "",
        "For EACH candidate above, perform LATTE-style taint analysis:",
        "",
        "1. **Source identification** — which parameter or call site brings "
        "untrusted input into this function? Quote the decompiled line(s) "
        "verbatim.",
        "2. **Sink identification** — which call site is the dangerous "
        "operation? Quote the exact line(s).",
        "3. **Dataflow** — trace whether the tainted value reaches the sink "
        "unsanitized. If an intermediate function sanitises (strlen-bound, "
        "escape, validator), say so explicitly.",
        "4. **Classification** — assign a CWE from the inventory above. If "
        "you can't connect source → sink, say `no-flow` and skip.",
        "",
        "### Output schema (REQUIRED — quote 3+ consecutive decompiled "
        "lines per step as evidence; do not hallucinate lines not in the "
        "decomp body)",
        "",
        "```json",
        "{",
        '  "findings": [',
        "    {",
        '      "function": "<name>",',
        '      "cwe": "CWE-NNN",',
        '      "confidence": "low|medium|high",',
        '      "source_evidence": "<3+ consecutive decomp lines>",',
        '      "sink_evidence": "<3+ consecutive decomp lines>",',
        '      "flow": "<1-2 sentence explanation>",',
        '      "exploitable": true',
        "    }",
        "  ]",
        "}",
        "```",
        "",
        "### Rules",
        "- Do NOT invent code that isn't in the decompilation above.",
        "- If a candidate has NO exploitable path, OMIT it from the findings "
        "array — don't emit no-flow entries.",
        "- If evidence is ambiguous, set `confidence: low`.",
    ]

    parts = header + body + instructions
    return "\n".join(parts)


def _compose_deepdive_prompt(
    binary_path: str,
    function_name: str,
    decomp: str,
    callers: list[dict],
    callees: list[dict],
    caller_classifications: dict[str, str],
    callee_classifications: dict[str, str],
    neighbour_decomps: dict[str, str],
    focus_cwe: list[str] | None,
) -> str:
    """Render the deep-dive 4-stage CoT prompt."""
    sinks_by_cwe = _load_sinks_yaml().get("families", {})
    focus_note = ""
    if focus_cwe:
        focus_note = (
            f"\nFocus on CWE families: {', '.join(focus_cwe)}."
        )

    lines: list[str] = [
        "# LATTE-Style Binary Taint Analysis — Deep Dive",
        "",
        f"Binary: `{binary_path}`",
        f"Target function: `{function_name}`",
        focus_note,
        "",
        "## Decompiled target",
        "",
        "```c",
        _truncate_decomp(decomp, _DEEPDIVE_TARGET_DECOMP_BYTES),
        "```",
        "",
        "## Immediate callers (up to 2 hops)",
        "",
    ]
    if callers:
        for c in callers:
            name = c.get("caller") or c.get("from_func") or "(unknown)"
            addr = c.get("address") or c.get("from") or "?"
            label = caller_classifications.get(name, "")
            tag = f" [{label}]" if label else ""
            lines.append(f"- `{name}` @ `{addr}`{tag}")
            neigh = neighbour_decomps.get(name)
            if neigh:
                lines.append("  ```c")
                lines.append(
                    _truncate_decomp(neigh, _DEEPDIVE_NEIGHBOUR_DECOMP_BYTES)
                )
                lines.append("  ```")
    else:
        lines.append("- (none — target may be an entry point)")

    lines.append("")
    lines.append("## Immediate callees (up to 2 hops)")
    lines.append("")
    if callees:
        for c in callees:
            name = c.get("to_func") or c.get("to") or "(unknown)"
            addr = c.get("to") or c.get("address") or "?"
            label = callee_classifications.get(name, "")
            tag = f" [{label}]" if label else ""
            lines.append(f"- `{name}` @ `{addr}`{tag}")
    else:
        lines.append("- (none)")
    lines.append("")

    # Sink inventory as a concise reference
    lines.append("## Sink inventory (by CWE family)")
    lines.append("")
    for fam_name, fam in sinks_by_cwe.items():
        lines.append(
            f"- **{fam.get('cwe','?')}** ({fam_name}): "
            f"{', '.join(fam.get('sinks', [])[:8])}"
        )
    lines.append("")

    lines.extend(
        [
            "## Your task — 4-stage chain of thought (LATTE-style)",
            "",
            "Complete each stage in order. QUOTE 3+ consecutive lines from "
            "the decompiled target for every claim.",
            "",
            "### Stage 1 — Sink identification",
            "Which call sites in the target act as taint sinks? For each, "
            "quote the exact lines. Which parameter is the taint-relevant "
            "argument?",
            "",
            "### Stage 2 — Source identification",
            "Which parameters or upstream calls introduce untrusted data? "
            "If callers marked [POTENTIAL SOURCE] above pass a value to the "
            "target, say so. Quote the relevant decompiled lines.",
            "",
            "### Stage 3 — Dataflow",
            "Trace each (source, sink) pair through the target's "
            "decompilation. Note any sanitisation (length check, escape "
            "function, validator). Cite consecutive lines.",
            "",
            "### Stage 4 — CWE classification & exploitability",
            "Assign CWE (CWE-78, CWE-120, CWE-134, CWE-190, CWE-787, etc.). "
            "Rate exploitability: `confirmed` | `probable` | `theoretical`.",
            "",
            "### Output schema (REQUIRED)",
            "",
            "```json",
            "{",
            f'  "function": "{function_name}",',
            '  "stages": {',
            '    "sink_id": [{"sink":"<name>","line_evidence":"<3+ lines>",'
            '"tainted_param":"<param>"}],',
            '    "source_id": [{"source":"<name>","line_evidence":"<3+ lines>"}],',
            '    "dataflow": [{"source":"<name>","sink":"<name>","steps":'
            '["<line1>","<line2>",...],"sanitised":false}],',
            '    "classification": {"cwe":"CWE-NNN","exploitability":'
            '"confirmed|probable|theoretical","confidence":"low|medium|high",'
            '"rationale":"<1-2 sentences>"}',
            "  }",
            "}",
            "```",
            "",
            "If any stage yields nothing (e.g. no sinks found), return an "
            "empty array for that stage — do NOT invent evidence.",
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _hash_args(*parts: Any) -> str:
    """Stable short hash for cache-key disambiguation."""
    joined = "|".join(str(p) for p in parts)
    return hashlib.md5(joined.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_scan_taint_analysis(
    input: dict, context: ToolContext
) -> str:
    """Build a LATTE-style scan prompt for a whole binary."""
    try:
        path = context.resolve_path(input["binary_path"])
    except (KeyError, ValueError) as exc:
        return f"Error: {exc}"
    except Exception as exc:  # sandbox rejections
        return f"Error: invalid binary_path ({exc})"

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: Binary not found: {input['binary_path']}"

    min_confidence = (input.get("min_confidence") or "medium").lower()
    if min_confidence not in _CONFIDENCE_LEVELS:
        return (
            f"Error: min_confidence must be one of {list(_CONFIDENCE_LEVELS)}; "
            f"got {min_confidence!r}"
        )

    max_candidates = int(input.get("max_candidates") or 50)
    if max_candidates <= 0 or max_candidates > _MAX_CANDIDATES_CAP:
        max_candidates = min(max(max_candidates, 1), _MAX_CANDIDATES_CAP)

    focus_cwe_raw = input.get("focus_cwe") or []
    focus_cwe = [c.strip() for c in focus_cwe_raw if isinstance(c, str)]

    try:
        binary_sha256 = await ghidra_service.ensure_analysis(
            path, context.firmware_id, context.db
        )
    except Exception as exc:
        return f"Error: Ghidra analysis unavailable for this binary ({exc})"

    # Cache key: (sha, args). Length well under VARCHAR(512) (rule 15).
    cache_key = (
        f"taint_scan:{_hash_args(min_confidence, max_candidates, ','.join(focus_cwe))}"
    )
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db
    )
    if cached and isinstance(cached, dict) and cached.get("prompt"):
        return str(cached["prompt"])

    # Gather imports + xrefs from ghidra_service.
    try:
        imports = await ghidra_service.get_imports(path, context.firmware_id, context.db)
    except Exception as exc:
        return f"Error: could not retrieve imports ({exc})"

    xrefs_entry = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, "xrefs", context.db
    )
    xrefs = (xrefs_entry or {}).get("xrefs", {})
    if not xrefs:
        return (
            "Error: no xref data for this binary. "
            "Run list_functions or list_imports first to populate the ghidra_service."
        )

    # Rank + gate.
    ranked = _rank_candidates(
        xrefs, imports, _sink_name_set(), _source_name_set()
    )
    gated = _apply_confidence_gate(ranked, min_confidence)

    if focus_cwe:
        gated = [c for c in gated if c.get("primary_cwe") in focus_cwe]

    if not gated:
        return (
            f"No candidate functions passed the `{min_confidence}` "
            f"confidence gate (scanned {len(ranked)} caller-of-sink "
            f"candidates). Try `min_confidence: low` for a wider net."
        )

    gated = gated[:max_candidates]

    # Pull decomps for each candidate (best-effort; non-fatal on miss).
    decomps: dict[str, str] = {}
    for cand in gated:
        fn = cand["function"]
        try:
            decomps[fn] = await decompile_function(
                binary_path=path,
                function_name=fn,
                firmware_id=context.firmware_id,
                db=context.db,
            )
        except Exception as exc:  # decomp can legitimately fail per-function
            logger.debug("decompile failed for %s: %s", fn, exc)
            decomps[fn] = ""

    prompt = _compose_scan_prompt(
        binary_path=input["binary_path"],
        min_confidence=min_confidence,
        focus_cwe=focus_cwe or None,
        candidates=gated,
        decomps=decomps,
        imports_count=len(imports),
    )

    # Cache the composed prompt. Uses flush() internally (rule 3).
    try:
        await ghidra_service.store_cached(
            context.firmware_id,
            path,
            binary_sha256,
            cache_key,
            {"prompt": prompt},
            context.db,
        )
    except Exception as exc:  # cache write failure shouldn't kill the call
        logger.warning("taint_scan cache write failed: %s", exc)

    return prompt


async def _handle_deep_dive_taint_analysis(
    input: dict, context: ToolContext
) -> str:
    """Build a LATTE 4-stage CoT prompt for a single function."""
    try:
        path = context.resolve_path(input["binary_path"])
    except (KeyError, ValueError) as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error: invalid binary_path ({exc})"

    function_name = input.get("function_name")
    if not function_name or not isinstance(function_name, str):
        return "Error: function_name is required."

    include_callers = int(input.get("include_callers") or 2)
    include_callees = int(input.get("include_callees") or 5)

    focus_cwe_raw = input.get("focus_cwe") or []
    focus_cwe = [c.strip() for c in focus_cwe_raw if isinstance(c, str)]

    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, path):
        return f"Error: Binary not found: {input['binary_path']}"

    try:
        binary_sha256 = await ghidra_service.ensure_analysis(
            path, context.firmware_id, context.db
        )
    except Exception as exc:
        return f"Error: Ghidra analysis unavailable ({exc})"

    cache_key = (
        f"taint_deepdive:"
        f"{_hash_args(function_name, include_callers, include_callees, ','.join(focus_cwe))}"
    )
    cached = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db
    )
    if cached and isinstance(cached, dict) and cached.get("prompt"):
        return str(cached["prompt"])

    # Decompile the target (fatal if this fails — the prompt is pointless
    # without the body).
    try:
        decomp = await decompile_function(
            binary_path=path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except FileNotFoundError:
        return f"Error: Binary not found at '{input['binary_path']}'."
    except TimeoutError as exc:
        return f"Error: decompilation timed out ({exc})"
    except RuntimeError as exc:
        return f"Error: {exc}"

    # Gather xrefs.
    xrefs_entry = await ghidra_service.get_cached(
        context.firmware_id, binary_sha256, "xrefs", context.db
    )
    xrefs = (xrefs_entry or {}).get("xrefs", {})
    func_xrefs = xrefs.get(function_name, {}) or {}

    # Callers: direct + one more hop.
    direct_callers = list(func_xrefs.get("to", []) or [])[:include_callers]
    callers: list[dict] = list(direct_callers)
    seen_callers = {
        (c.get("from_func") or c.get("caller")) for c in direct_callers
    }
    for c in direct_callers:
        parent = c.get("from_func") or c.get("caller")
        if not parent:
            continue
        grand = xrefs.get(parent, {}).get("to", []) or []
        for gp in grand[: max(1, include_callers)]:
            key = gp.get("from_func") or gp.get("caller")
            if key and key not in seen_callers:
                seen_callers.add(key)
                callers.append(gp)

    # Callees: direct + one more hop.
    direct_callees = list(func_xrefs.get("from", []) or [])[:include_callees]
    callees: list[dict] = list(direct_callees)
    seen_callees = {(c.get("to_func") or c.get("to")) for c in direct_callees}
    for c in direct_callees:
        child = c.get("to_func") or c.get("to")
        if not child:
            continue
        grand = xrefs.get(child, {}).get("from", []) or []
        for gc in grand[: max(1, include_callees)]:
            key = gc.get("to_func") or gc.get("to")
            if key and key not in seen_callees:
                seen_callees.add(key)
                callees.append(gc)

    # Classify neighbours against source / sink dictionaries.
    sinks = _sink_name_set()
    sources = _source_name_set()

    def _classify(name: str | None) -> str:
        if not name:
            return ""
        if name in sources:
            return "POTENTIAL SOURCE"
        if name in sinks:
            return "POTENTIAL SINK"
        return ""

    caller_class = {
        (c.get("from_func") or c.get("caller") or ""): _classify(
            c.get("from_func") or c.get("caller") or ""
        )
        for c in callers
    }
    callee_class = {
        (c.get("to_func") or c.get("to") or ""): _classify(
            c.get("to_func") or c.get("to") or ""
        )
        for c in callees
    }

    # Best-effort decomp of immediate callers that are THEMSELVES interesting
    # (i.e. classified as source — their internals may show how taint enters).
    neighbour_decomps: dict[str, str] = {}
    for name, label in caller_class.items():
        if label == "POTENTIAL SOURCE" and name:
            try:
                neighbour_decomps[name] = await decompile_function(
                    binary_path=path,
                    function_name=name,
                    firmware_id=context.firmware_id,
                    db=context.db,
                )
            except Exception as exc:
                logger.debug("neighbour decomp failed for %s: %s", name, exc)

    prompt = _compose_deepdive_prompt(
        binary_path=input["binary_path"],
        function_name=function_name,
        decomp=decomp,
        callers=callers,
        callees=callees,
        caller_classifications=caller_class,
        callee_classifications=callee_class,
        neighbour_decomps=neighbour_decomps,
        focus_cwe=focus_cwe or None,
    )

    try:
        await ghidra_service.store_cached(
            context.firmware_id,
            path,
            binary_sha256,
            cache_key,
            {"prompt": prompt},
            context.db,
        )
    except Exception as exc:
        logger.warning("taint_deepdive cache write failed: %s", exc)

    return prompt


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_taint_llm_tools(registry: ToolRegistry) -> None:
    """Register LATTE-style LLM taint analysis tools."""

    registry.register(
        name="scan_taint_analysis",
        description=(
            "LATTE-style binary-wide taint pre-filter. Walks the binary's "
            "import table for dangerous sinks (strcpy, system, sprintf, "
            "execve, etc.), finds functions that call them, ranks by sink "
            "count + source reachability + caller centrality, and returns "
            "a structured prompt asking the client LLM to triage each "
            "candidate and emit a JSON findings array. Reuses the Ghidra "
            "analysis cache — first call per binary triggers analysis "
            "(1-3 min); subsequent calls are instant. Complements the "
            "deterministic `trace_dataflow` tool: use trace_dataflow for "
            "fast heuristic paths, scan_taint_analysis for LLM-augmented "
            "recall."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "min_confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": (
                        "Pre-filter threshold. `low` keeps anything calling "
                        "a sink; `medium` (default) requires 2+ sinks OR 1 "
                        "sink + 1 source; `high` requires 2+ sinks AND 1+ "
                        "source."
                    ),
                },
                "max_candidates": {
                    "type": "integer",
                    "description": (
                        "Cap on candidate functions included in the prompt "
                        "(default 50, max 200). Candidates are sorted by "
                        "score descending."
                    ),
                },
                "focus_cwe": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional CWE whitelist (e.g. ['CWE-78','CWE-120']). "
                        "Candidates whose primary CWE guess is outside the "
                        "list are omitted."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_scan_taint_analysis,
    )

    registry.register(
        name="deep_dive_taint_analysis",
        description=(
            "LATTE-style per-function deep dive. Takes a single function, "
            "walks xrefs 2 hops in both directions, classifies neighbours "
            "against source/sink dictionaries, and returns a 4-stage "
            "chain-of-thought prompt (sink-ID → source-ID → dataflow → "
            "CWE classification) with quoted decompiled lines as evidence. "
            "Use after `scan_taint_analysis` picks a target, or on any "
            "function you suspect is vulnerable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to deep-dive (from list_functions).",
                },
                "include_callers": {
                    "type": "integer",
                    "description": "Max immediate callers to include (default 2).",
                },
                "include_callees": {
                    "type": "integer",
                    "description": "Max immediate callees to include (default 5).",
                },
                "focus_cwe": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional CWE whitelist to steer classification "
                        "(e.g. ['CWE-78'])."
                    ),
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_deep_dive_taint_analysis,
    )
