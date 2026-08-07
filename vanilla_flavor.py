"""QRen Coder as a Vanilla Core flavor.

This is an adapter, not a rewrite. The QRCF encoder/decoder underneath is
untouched — this module only maps the Vanilla Core contract
(``run(capability, params)``) onto QRen's existing public API, and returns
plain JSON-serializable dicts so any host can consume the result.

Design notes:
  * QRen's convention is that ``output`` names the hybrid ``.qren.png``
    container, and ``xqmem`` additionally writes the standalone XQPE bytes
    beside it. The ``self-test`` capability round-trips through the
    ``.xqmem`` because that path needs no image library, keeping the flavor
    verifiable in a zero-dependency host — the same constraint Vanilla Core
    holds itself to.
  * Nothing here imports ``vanilla_core``. The flavor stays independently
    usable — Vanilla Core is one possible caller, not a dependency.
"""

from __future__ import annotations

import base64
from pathlib import Path

from qrcf_types import BlockType, CompressionTier, QRenError
from qrcf_encoder import QRenEncoder
from qrcf_decoder import QRenDecoder

CAPABILITIES = ("encode", "decode", "verify", "block-types", "self-test")


class FlavorError(Exception):
    """Raised for bad input to this adapter, kept distinct from QRenError."""


def _require(params: dict, key: str):
    if key not in params:
        raise FlavorError(f"capability requires --param {key}=<value>")
    return params[key]


def _encode(params: dict) -> dict:
    """params: data (required), name, block_type, compression, output, tags"""
    data = _require(params, "data")

    block_type = None
    if "block_type" in params:
        raw = str(params["block_type"]).upper()
        try:
            block_type = BlockType[raw]
        except KeyError:
            raise FlavorError(
                f"unknown block_type {raw!r}; expected one of "
                f"{[b.name for b in BlockType]}"
            )

    compression = None
    if "compression" in params:
        raw = str(params["compression"]).upper()
        matches = [t for t in CompressionTier if t.name == raw or t.name.endswith(f"_{raw}")]
        if not matches:
            raise FlavorError(
                f"unknown compression {raw!r}; expected one of "
                f"{[t.name for t in CompressionTier]}"
            )
        compression = matches[0]

    encoder = QRenEncoder()
    output = params.get("output")
    result = encoder.encode(
        data=data,
        name=params.get("name", "archive"),
        block_type=block_type,
        compression=compression,
        runic_tags=params.get("tags"),
        metadata=params.get("metadata"),
        output_path=output,
        output_xqmem=params.get("xqmem", True) and output is not None,
    )
    return result


def _decode(params: dict) -> dict:
    """params: path (required), verify (default True), raw (return base64)"""
    path = str(_require(params, "path"))
    if not Path(path).exists():
        raise FlavorError(f"no such file: {path}")

    decoder = QRenDecoder(verify_integrity=bool(params.get("verify", True)))
    result = decoder.decode(path)

    # The payload may be arbitrary bytes; make the return value JSON-safe.
    payload = result.get("data")
    if isinstance(payload, (bytes, bytearray)):
        try:
            result["data"] = payload.decode("utf-8")
            result["data_encoding"] = "utf-8"
        except UnicodeDecodeError:
            result["data"] = base64.b64encode(payload).decode("ascii")
            result["data_encoding"] = "base64"
    return result


def _verify(params: dict) -> dict:
    """Integrity check only — reports pass/fail instead of raising, so a
    caller can check many archives in a loop.

    QRen signals integrity problems two different ways: hard format errors
    raise QRenError, while section/Merkle mismatches come back in the decode
    result as ``valid=False`` plus ``validation_errors``. Both must be
    consulted — checking only for a raised exception silently passes
    corrupted archives.
    """
    path = str(_require(params, "path"))
    if not Path(path).exists():
        raise FlavorError(f"no such file: {path}")
    try:
        result = QRenDecoder(verify_integrity=True).decode(path)
    except QRenError as exc:
        return {"path": path, "ok": False, "error": str(exc), "error_type": type(exc).__name__}

    errors = list(result.get("validation_errors") or [])
    ok = bool(result.get("valid")) and not errors
    out = {"path": path, "ok": ok}
    if not ok:
        out["validation_errors"] = errors
    return out


def _block_types(params: dict) -> dict:
    return {
        "block_types": [
            {"name": b.name, "code": f"0x{b.value:02X}"} for b in BlockType
        ],
        "compression_tiers": [
            {"name": t.name, "code": f"0x{t.value:02X}"} for t in CompressionTier
        ],
    }


def _self_test(params: dict) -> dict:
    """Round-trip a payload through encode/decode in a temp dir and report.

    Lets a host confirm the flavor is actually functional in its environment
    without shelling out to the project's own test suite."""
    import tempfile

    sample = params.get("data", {"vanilla": "core", "qren": "coder", "n": 42})
    with tempfile.TemporaryDirectory() as tmp:
        # QRen's convention: output_path is the .qren.png container, and
        # output_xqmem writes the dependency-free .xqmem alongside it. We
        # round-trip through the .xqmem so the self-test needs no image layer.
        out = str(Path(tmp) / "selftest.qren.png")
        enc = QRenEncoder().encode(
            data=sample, name="selftest", output_path=out, output_xqmem=True
        )
        xqmem_path = enc["paths"]["xqmem"]
        dec = QRenDecoder(verify_integrity=True).decode(xqmem_path)
        payload = dec.get("data")
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "archive_id": enc["archive_id"],
            "block_type": enc["block_type"],
            "compression": enc["compression"],
            "size_original": enc["size_original"],
            "size_compressed": enc["size_compressed"],
            "compression_ratio": enc["compression_ratio"],
            "merkle_root": enc["merkle_root"],
            "valid": dec.get("valid"),
            "round_tripped": payload,
        }


_DISPATCH = {
    "encode": _encode,
    "decode": _decode,
    "verify": _verify,
    "block-types": _block_types,
    "self-test": _self_test,
}


def run(capability: str | None = None, params: dict | None = None) -> dict:
    """Vanilla Core entrypoint. See CAPABILITIES for what `capability` accepts."""
    params = params or {}
    capability = capability or "self-test"
    handler = _DISPATCH.get(capability)
    if handler is None:
        raise FlavorError(
            f"unknown capability {capability!r}; expected one of {list(_DISPATCH)}"
        )
    return handler(params)
