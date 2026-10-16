"""The tamper audit, briefly: every valid case's inputs changed a few ways.
A change still judged valid must show in the verdict or be explained from
the data (tools/tamper_audit.py). FM_TAMPER_ROUNDS raises the count; the
release check runs 200."""

import importlib.util
import os
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "tools" / "tamper_audit.py"


def test_no_change_is_accepted_unseen():
    spec = importlib.util.spec_from_file_location("tamper_audit", TOOL)
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    result = audit.audit(int(os.environ.get("FM_TAMPER_ROUNDS", "6")))
    assert result["totals"]["runs"] > 500
    assert not result["crashes"], result["crashes"][:3]
    assert not result["unexplained"], result["unexplained"]
