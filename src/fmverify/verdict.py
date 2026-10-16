"""Verdicts: an outcome, the statement it supports, and every check behind it.

A verdict is never a bare pass. It says what was checked, what each check
found and why, what the verifier had to rely on, and what the verdict does
not establish.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import functools
import json
from typing import Any, Callable, Iterable

from . import __version__


class Status(str, enum.Enum):
    """The result of one check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NOT_CHECKED = "not_checked"
    INFO = "info"


class Outcome(str, enum.Enum):
    """The result of a whole verification."""

    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


EXIT_CODES = {Outcome.VALID: 0, Outcome.INVALID: 1, Outcome.INDETERMINATE: 2}
EXIT_USAGE = 64
EXIT_INTERNAL = 70  # a fault in the verifier itself: never a verdict


@dataclasses.dataclass
class Check:
    """One thing the verifier checked, with its reasons and reliance.

    ``required`` checks that come back ``not_checked`` make the verdict
    indeterminate; optional ones are reported but do not hold it back.
    """

    id: str
    status: Status
    summary: str
    reasons: list[str] = dataclasses.field(default_factory=list)
    relies_on: list[str] = dataclasses.field(default_factory=list)
    required: bool = True
    data: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Verdict:
    kind: str
    subject: str
    outcome: Outcome
    statement: str
    checks: list[Check]
    does_not_establish: list[str]
    checked_at: str
    tool: dict[str, str]

    @property
    def relies_on(self) -> list[str]:
        seen: list[str] = []
        for check in self.checks:
            for item in check.relies_on:
                if item not in seen:
                    seen.append(item)
        return seen

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.outcome]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "outcome": self.outcome.value,
            "statement": self.statement,
            "checks": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "summary": c.summary,
                    "reasons": list(c.reasons),
                    "relies_on": list(c.relies_on),
                    "required": c.required,
                    "data": c.data,
                }
                for c in self.checks
            ],
            "relies_on": self.relies_on,
            "does_not_establish": list(self.does_not_establish),
            "checked_at": self.checked_at,
            "tool": dict(self.tool),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False, ensure_ascii=False)

    def to_text(self) -> str:
        lines = [f"{self.outcome.value.upper()}: {self.statement}", f"Subject: {self.subject}", "", "Checks:"]
        for c in self.checks:
            optional = "" if c.required else " (optional)"
            lines.append(f"  [{c.status.value}] {c.id}{optional}: {c.summary}")
            for reason in c.reasons:
                lines.append(f"      - {reason}")
        relied = self.relies_on
        if relied:
            lines += ["", "Relied on:"] + [f"  - {r}" for r in relied]
        if self.does_not_establish:
            lines += ["", "Does not establish:"] + [f"  - {d}" for d in self.does_not_establish]
        lines += ["", f"{self.tool['name']} {self.tool['version']}, checked at {self.checked_at}"]
        return "\n".join(lines)


def decide(checks: Iterable[Check]) -> Outcome:
    """Any failure makes a verdict invalid; a required check left undone, or no
    passing check at all, makes it indeterminate."""
    checks = list(checks)
    if any(c.status is Status.FAIL for c in checks):
        return Outcome.INVALID
    if any(c.status is Status.NOT_CHECKED and c.required for c in checks):
        return Outcome.INDETERMINATE
    if not any(c.status is Status.PASS for c in checks):
        return Outcome.INDETERMINATE
    return Outcome.VALID


def now_utc() -> str:
    return utc(_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0))


def utc(t: _dt.datetime) -> str:
    """ISO 8601 in UTC with Z; fractional seconds only when there are any, in
    milliseconds when that is exact (a token's .419 stays .419, not .419000)."""
    t = t.astimezone(_dt.timezone.utc) if t.tzinfo else t
    s = t.replace(tzinfo=None, microsecond=0).isoformat()
    if t.microsecond:
        s += f".{t.microsecond // 1000:03d}" if t.microsecond % 1000 == 0 else f".{t.microsecond:06d}"
    return s + "Z"


def make_verdict(
    kind: str,
    subject: str,
    checks: list[Check],
    statements: dict[Outcome, str],
    does_not_establish: list[str],
    checked_at: str | None = None,
) -> Verdict:
    outcome = decide(checks)
    return Verdict(
        kind=kind,
        subject=subject,
        outcome=outcome,
        statement=statements[outcome],
        checks=checks,
        does_not_establish=does_not_establish,
        checked_at=checked_at or now_utc(),
        tool={"name": "fm-verify", "version": __version__},
    )


MAX_SAFE_INTEGER = 2**53 - 1


def whole_number(value: Any, what: str, least: int = 0) -> int:
    """A count or position as signed JSON gives it: a whole number from
    ``least`` to 2^53 - 1, never a string, a boolean or a fraction. A larger
    one is not what a JavaScript signer meant: JSON parsing there rounds it
    to another value, which the signature then covers."""
    if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{what} is {value!r}, not a whole number from {least} to 2^53 - 1")
    return value


def summarize(sub: Verdict, cid: str, what: str, others_valid: int) -> Check:
    """One proof's verdict as a row of a larger one (a token in an anchor, a
    proof in a certificate). A proof that holds with warnings is a warning row
    naming them, so the row says what the proof's own verdict says; one that
    could not be checked names what was not checked and what it noted.
    ``others_valid`` counts the other proofs that hold: while one does, a
    proof that could not be checked is not required."""
    data = {"verdict": sub.to_dict()}
    if sub.outcome is Outcome.VALID:
        warned = [f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.WARN]
        return Check(cid, Status.WARN if warned else Status.PASS, sub.statement, reasons=warned, relies_on=sub.relies_on, data=data)
    if sub.outcome is Outcome.INVALID:
        return Check(cid, Status.FAIL, f"{what} does not hold",
                     reasons=[f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.FAIL], data=data)
    noted = [f"{c.id}: {c.summary}" for c in sub.checks
             if (c.status is Status.NOT_CHECKED and c.required) or c.status in (Status.WARN, Status.INFO)]
    return Check(cid, Status.NOT_CHECKED, f"{what} could not be checked: {sub.statement}", reasons=noted,
                 required=others_valid == 0, data=data)


# What no anchor verdict establishes, whatever its outcome. Kept in one place
# so that every verdict says the same thing (standing ruling
# shows-the-work-never-proves-no-AI: the record never claims more than it shows).
ANCHOR_LIMITS = [
    "who wrote the content, or how it was written",
    "that the content is true, original, or free of AI assistance",
    "that the content did not exist earlier than the anchor (an anchor bounds existence from above only)",
]


MALFORMED = (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError)


def guarded(kind: str, check_id: str, what: str, limits: list[str] | None = None) -> Callable:
    """Wrap a verification so that input malformed in a way its structured
    checks do not anticipate gives an invalid verdict naming the error, not an
    exception. (Parsing errors of every format here are ValueErrors.)"""

    def wrap(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except MALFORMED as exc:
                check = Check(check_id, Status.FAIL, f"the {what} is malformed", reasons=[f"{type(exc).__name__}: {exc}"])
                return make_verdict(kind, kwargs.get("subject") or what, [check],
                                    {o: f"The {what} is malformed." for o in Outcome},
                                    ANCHOR_LIMITS if limits is None else limits, kwargs.get("checked_at"))
        return inner

    return wrap
