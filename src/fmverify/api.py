"""One entry point for pages and programs: a JSON request in, a verdict out.

``verify(request)`` reads nothing from disk and opens no connection. Every
input travels in the request, binary data as base64. It runs wherever
Python and the ``cryptography`` library run, including a browser under
Pyodide, so a hosted page can run the same code as the command line.

The request shape is documented in ``docs/API.md``. The answer is the
verdict as ``Verdict.to_dict()`` gives it, or ``{"api": ..., "error": ...}``
when the request itself is malformed.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from . import __version__, anchors, merkle, ots, pki, rfc3161
from .bitcoin import NETWORKS, HeaderChain, HeaderError, HeaderSet, HeaderSource
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, make_verdict

API = "fm-verify/0"


class RequestError(ValueError):
    pass


def _b64(value: Any, what: str) -> bytes:
    if not isinstance(value, str):
        raise RequestError(f"{what} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RequestError(f"{what} is not base64") from exc


def _hex(value: Any, what: str, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise RequestError(f"{what} must be a hex string")
    try:
        b = bytes.fromhex(value)
    except ValueError as exc:
        raise RequestError(f"{what} is not hex") from exc
    if length is not None and len(b) != length:
        raise RequestError(f"{what} is {len(b)} bytes, not {length}")
    return b


def _sources(req: dict) -> list[HeaderSource]:
    network = NETWORKS[req.get("network", "mainnet")]
    min_work = req.get("min_work_bits")
    out: list[HeaderSource] = []
    for i, h in enumerate(req.get("headers", [])):
        name = h.get("name") or f"headers[{i}]"
        try:
            if h.get("kind") == "chain":
                out.append(HeaderChain(_b64(h.get("data"), f"headers[{i}].data"), int(h.get("start", 0)), network, name=name,
                                       min_work_bits=min_work))
            elif h.get("kind") == "sparse":
                out.append(HeaderSet.parse(h.get("text", ""), network, name=name, min_work_bits=min_work))
            else:
                raise RequestError(f"headers[{i}].kind must be 'chain' or 'sparse'")
        except HeaderError as exc:
            raise RequestError(f"headers[{i}]: {exc}") from exc
    return out


def _certs(values: Any, what: str) -> list:
    out = []
    for i, pem in enumerate(values or []):
        if not isinstance(pem, str):
            raise RequestError(f"{what}[{i}] must be PEM text")
        try:
            out += pki.load_certificates(pem.encode("ascii"))
        except ValueError as exc:
            raise RequestError(f"{what}[{i}] is not a PEM certificate") from exc
    return out


def _subject(req: dict) -> tuple[bytes | None, bytes | None]:
    file_bytes = _b64(req["file"], "file") if "file" in req else None
    digest = _hex(req["digest"], "digest") if "digest" in req else None
    if file_bytes is not None and digest is not None:
        raise RequestError("give file or digest, not both")
    return file_bytes, digest


def _run(req: dict):
    if not isinstance(req, dict):
        raise RequestError("the request must be a JSON object")
    if req.get("api", API) != API:
        raise RequestError(f"api {req.get('api')!r}; this verifier answers {API}")
    if req.get("network", "mainnet") not in NETWORKS:
        raise RequestError(f"network must be one of {', '.join(sorted(NETWORKS))}")
    if "explorer" in req:
        raise RequestError("this entry point makes no network call: fetch headers yourself and pass them as sparse headers, naming where they came from")
    kind = req.get("kind")
    label = req.get("label")
    if kind == "ots":
        file_bytes, digest = _subject(req)
        return ots.verify(_b64(req.get("proof"), "proof"), _sources(req), file_bytes=file_bytes, digest=digest,
                          network=NETWORKS[req.get("network", "mainnet")], subject=label)
    if kind == "rfc3161":
        file_bytes, digest = _subject(req)
        return rfc3161.verify(_b64(req.get("token"), "token"), file_bytes=file_bytes, digest=digest,
                              digest_alg=req.get("digest_alg", "sha256"), roots=_certs(req.get("roots"), "roots"),
                              extra_certs=_certs(req.get("chain"), "chain"), subject=label)
    if kind == "merkle":
        proof = req.get("proof")
        if not isinstance(proof, dict):
            raise RequestError("proof must be an object")
        leaf = _b64(req["leaf"], "leaf") if "leaf" in req else _hex(proof.get("leaf", ""), "proof.leaf")
        root = _hex(req["root"], "root", 32) if "root" in req else None
        return merkle.verify_inclusion(leaf, proof, expected_root=root, subject=label)
    if kind == "anchors":
        batch_doc = req.get("batch")
        anchor_files = {name: _b64(v, f"anchor_files.{name}") for name, v in (req.get("anchor_files") or {}).items()}
        held = {path: _b64(v, f"files.{path}") for path, v in (req.get("files") or {}).items()}
        try:
            batch = anchors.batch_from_doc(batch_doc, anchor_files, name=label or "batch")
        except anchors.BatchError as exc:
            return make_verdict("anchor-batch", f"anchor batch {label or 'batch'}",
                                [Check("anchors.batch", Status.FAIL, "the batch could not be read", reasons=[str(exc)])],
                                {o: "The anchor batch could not be read." for o in Outcome}, ANCHOR_LIMITS)
        return anchors.verify_batch(batch, header_sources=_sources(req), network=NETWORKS[req.get("network", "mainnet")],
                                    roots=_certs(req.get("roots"), "roots"), extra_certs=_certs(req.get("chain"), "chain"),
                                    held=held)
    raise RequestError("kind must be one of ots, rfc3161, merkle, anchors")


def verify(request: dict) -> dict:
    """Answer one request. Never raises for a malformed request: the answer
    then carries ``error``."""
    try:
        return _run(request).to_dict()
    except (RequestError, KeyError, TypeError, AttributeError) as exc:
        return {"api": API, "error": str(exc) if isinstance(exc, RequestError) else f"malformed request: {exc!r}",
                "tool": {"name": "fm-verify", "version": __version__}}


def verify_json(text: str) -> str:
    """The same, JSON text in and out."""
    try:
        request = json.loads(text)
    except json.JSONDecodeError as exc:
        return json.dumps({"api": API, "error": f"the request is not JSON: {exc}"})
    return json.dumps(verify(request), ensure_ascii=False)
