---
id: add-signal-kind
title: Add a new signal kind to a Rule #52 closed-grammar catalog
status: Rule-of-Three (promoted 2026-05-22 with ICS protocol catalog Session 2)
applies_to:
  - file_format catalog (P3.2.b TextFormatConstraint, P3.x SubstringInHeadConstraint)
  - ICS protocol catalog (IcsStringInBinaryConstraint, IcsFunctionCodeSetConstraint)
  - future closed-grammar surfaces (decoder family, vendor adapter, JTAG TAP, etc.)
companions:
  - Rule #25 single-slice exception #2 (cross-stack alignment commit)
  - Rule #46 paired META-CANARY (every closed-table gate)
  - Rule #48 5-part cross-stack alignment test shape
  - Rule #52 closed-grammar Rule-of-Three DURABLE BEYOND DEBATE
---

# Add a new signal kind to a Rule #52 closed-grammar catalog

When extending a Rule #52 closed-grammar YAML catalog (file_format,
ICS protocol, etc.) with a **new signal kind** — operator-extensible
detection primitive — apply this 4-element pattern. Rule-of-Three:
TextFormatConstraint (P3.2.b) + SubstringInHeadConstraint (P3.x) +
ICS Session 1's IcsStringInBinaryConstraint/IcsFunctionCodeSetConstraint.

## Context

The catalog's `DetectionSignal` discriminator is a closed Literal
(e.g. `IcsSignalKind = Literal["magic_bytes", "string_in_binary",
"function_code_set", "port_signature", "library_symbol"]`). Each
kind has a sub-model carrying its parameters (`needles_hex`,
`window_bytes`, etc.) and an evaluator function in the resolver's
closed dispatch table.

Adding a new kind requires changes across 4 surfaces (1-3 ship in
ONE Rule #25 single-slice commit; #4 in subsequent commits as new
manifests use the kind):

1. **Closed Literal** — add the new value to `<Surface>SignalKind`
2. **Sub-model** — `<Surface><KindName>Constraint` Pydantic class
3. **Evaluator** — function in the resolver's `SIGNAL_EVALUATORS`
   dispatch table
4. **YAML manifests** — operator-extensible files that reference
   the new kind

## Steps

### 1. Closed Literal (`backend/app/schemas/<surface>.py`)

```python
# Add to the existing closed Literal — keep it tight; over-broad
# values invite the catalog into "operator can declare arbitrary
# behavior via YAML" territory which Rule #52's hard rule forbids.
IcsSignalKind = Literal[
    "magic_bytes",
    "string_in_binary",
    "function_code_set",
    "port_signature",
    "library_symbol",
    "new_kind_here",  # ← new entry
]
```

### 2. Sub-model with `extra='forbid'` + symmetric-reject validator

```python
class IcsNewKindConstraint(BaseModel):
    """Constraint params for the new signal kind. Closed-grammar —
    NO regex / NO eval / NO open-string fields. Add fields with
    closed Literals or fixed types (int / bool / bytes-hex)."""
    model_config = ConfigDict(extra="forbid")

    # field defs — closed Literals where possible
    needles_hex: list[str]
    case_sensitive: bool = False
    combine: Literal["all", "any"] = "all"
    min_count: int = Field(ge=1, default=1)

    @model_validator(mode="after")
    def _check_combine_min_count(self):
        if self.combine == "all" and self.min_count != 1:
            raise ValueError("combine='all' requires min_count=1")
        return self


class IcsDetectionSignal(BaseModel):
    """Add the constraint as an optional field on the signal envelope."""
    kind: IcsSignalKind
    description: str
    new_kind_constraint: IcsNewKindConstraint | None = None

    @model_validator(mode="after")
    def _check_kind_fields(self):
        # REQUIRED-WHEN pair: kind=new_kind_here ⇒ new_kind_constraint
        # MUST be set
        if self.kind == "new_kind_here" and self.new_kind_constraint is None:
            raise ValueError(
                "kind='new_kind_here' requires new_kind_constraint to be set"
            )
        # SYMMETRIC-REJECT pair: new_kind_constraint set ⇒ kind MUST be
        # new_kind_here (prevents "I set the constraint but forgot to
        # set kind" silent skip)
        if self.new_kind_constraint is not None and self.kind != "new_kind_here":
            raise ValueError(
                "new_kind_constraint set but kind != 'new_kind_here'"
            )
        return self
```

### 3. Evaluator + dispatch entry (`backend/app/services/<surface>_catalog/resolver.py`)

```python
def _eval_new_kind(
    signal: IcsDetectionSignal,
    blob_head: bytes,
    path: str,
    size: int,
    context: IcsResolverContext | None,
) -> bool:
    """Evaluate the new signal kind against the binary head.

    NO hardcoded byte sequences — Rule #46 anti-hardcode AST canary
    enforces this. All needle/pattern values come from the
    constraint (which itself comes from YAML).
    """
    constraint = signal.new_kind_constraint
    if constraint is None:
        return False
    # decode needles via bytes.fromhex (closed-grammar — operator
    # supplies HEX, code never builds bytes from strings)
    needles = [bytes.fromhex(n) for n in constraint.needles_hex]
    # apply the constraint's closed semantics
    ...
    return matched


SIGNAL_EVALUATORS: dict[IcsSignalKind, _SignalEvaluator] = {
    "magic_bytes": _eval_magic_bytes,
    "string_in_binary": _eval_string_in_binary,
    "function_code_set": _eval_function_code_set,
    "port_signature": _eval_port_signature,
    "library_symbol": _eval_library_symbol,
    "new_kind_here": _eval_new_kind,   # ← new entry
}
```

### 4. Cost-class entry (resolver.py)

```python
_SIGNAL_COST_CLASS: dict[IcsSignalKind, int] = {
    "port_signature": 0,
    "magic_bytes": 1,
    "function_code_set": 2,
    "library_symbol": 2,
    "string_in_binary": 3,
    "new_kind_here": 2,  # ← pick cost based on I/O profile
}
```

## Required META-CANARIES (Rule #46)

Every closed table gets a paired exhaustive + synthesize-violation
canary in `tests/test_<surface>_resolver.py`:

```python
def test_signal_evaluators_exhaustive_against_literal():
    """SIGNAL_EVALUATORS MUST cover every IcsSignalKind value. Drift
    = silent skip on the missing kind."""
    from typing import get_args
    literal_values = set(get_args(IcsSignalKind))
    assert set(SIGNAL_EVALUATORS.keys()) == literal_values


def test_signal_evaluators_exhaustive_gate_actually_fires():
    """Rule #46 paired canary — synthesize a missing-kind dispatch
    table; confirm exhaustive-check would reject."""
    from typing import get_args
    literal_values = set(get_args(IcsSignalKind))
    # Remove one entry — synthesize the violation
    truncated = {k: v for k, v in SIGNAL_EVALUATORS.items() if k != "new_kind_here"}
    assert set(truncated.keys()) != literal_values, (
        "synthetic violation MUST differ from Literal set — paired "
        "canary proves exhaustive-check would fire on a missing entry"
    )


def test_signal_cost_class_exhaustive_against_literal():
    """Cost-class table covers every kind."""
    from typing import get_args
    assert set(_SIGNAL_COST_CLASS.keys()) == set(get_args(IcsSignalKind))


# Anti-hardcode AST canary — enforce evaluator can't hardcode bytes
def test_eval_new_kind_no_hardcoded_byte_literals():
    """The evaluator body MUST NOT contain bytes-literal patterns that
    look like hardcoded format-specific signatures — those belong in
    YAML (operator-extensible) not in code. AST-walk over the
    evaluator function asserts."""
    import ast
    import inspect
    src = inspect.getsource(_eval_new_kind)
    tree = ast.parse(src)
    bytes_literals = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, bytes)
        and len(n.value) >= 2  # 2+ bytes = suspicious signature
    ]
    assert not bytes_literals, (
        f"_eval_new_kind has hardcoded byte literals {bytes_literals!r} "
        f"— move them into the YAML constraint instead. Closed-grammar "
        f"contract: code carries logic, YAML carries data."
    )


def test_eval_new_kind_anti_hardcode_canary_fires():
    """Rule #46 paired canary — synthesize a hostile evaluator with a
    hardcoded `b"specific_format_magic"`; confirm AST-walk gate
    rejects it."""
    src = '''
def _eval_hostile(signal, blob_head, path, size, context):
    if b"libmodbus" in blob_head:  # hardcoded — should be in YAML
        return True
    return False
'''
    import ast
    tree = ast.parse(src)
    bytes_literals = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, bytes)
        and len(n.value) >= 2
    ]
    assert bytes_literals, (
        "synthetic hostile evaluator MUST be detected by AST-walk; "
        "without this canary the production gate's silent-pass risk "
        "is unbounded"
    )
```

## Gotchas

* **Sub-model + signal envelope must ship in the SAME commit.** Per
  Rule #25 single-slice exception #2 — the cross-stack pair (Literal +
  sub-model + envelope field + evaluator) shares strict alignment; the
  symmetric-reject validator returns ValidationError if any surface is
  partial.
* **Cost class is load-bearing.** Per the resolver's cost-sorted
  evaluation (Wave-1 S5 attack O — I/O cost amplification DoS), a
  high-cost kind placed in the wrong cost bucket can starve sibling
  kinds. New string-scanning kinds = cost 3; new fixed-offset byte
  kinds = cost 1.
* **YAML schema lock-step.** The `*.schema.json` (if shipped) must be
  regenerated when the Literal value list changes. Without it,
  yaml-language-server LSP autocomplete misses the new value.
* **Don't accept open-string fields in the sub-model.** Operators
  authoring YAML must NOT be able to declare regex strings, code
  snippets, or eval-able predicates. Every field is a closed Literal,
  fixed type, or bytes-hex literal. Pydantic `extra='forbid'`
  structurally rejects undeclared keys.

## Verify

* `pytest backend/tests/test_<surface>_resolver.py -k "exhaustive"`
  — every closed table covers every Literal value
* `pytest backend/tests/test_<surface>_resolver.py -k "anti_hardcode"`
  — evaluator body free of hardcoded byte signatures
* `pytest backend/tests/test_<surface>_schema.py -k "<new_kind_here>"`
  — sub-model + symmetric-reject + extra='forbid' enforce the
  closed-grammar contract
* End-to-end: ship a synthetic YAML manifest using the new kind +
  assert resolve_all returns a match

## References

* **Rule #52** (closed-grammar Rule-of-Three DURABLE BEYOND DEBATE)
  — the macro contract this recipe sits inside
* **Rule #25 single-slice exception #2** — Literal + sub-model +
  envelope + evaluator ship in ONE commit per Rule #48 5-part shape
* **Rule #46** — paired META-CANARY discipline for every closed
  table (exhaustive check + synthesize-violation canary)
* **`.mex/patterns/cross-stack-alignment-test.md`** — when the new
  kind crosses backend↔frontend, follow that recipe for the
  finding-source alignment surface
