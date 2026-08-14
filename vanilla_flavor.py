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

Two layers, one adapter
-----------------------
``qren/qrcf/`` is the container format — QREN/XQPE magic, PNG+trailer, Merkle
integrity. ``qren/`` above it is the semantic layer — the block-type taxonomy,
the Crystal Slime lifecycle, the Runic tokens, and the Magic Circle I/O
boundary. They deliberately do not share bytes on the wire, and this adapter
does not pretend otherwise: it exposes both, it does not bridge them.

The first five capabilities are the container. The last four (``classify``,
``slime-phase``, ``tokens``, ``circle``) are the semantic layer. A capability
is declared here only once it has an adapter test, so the manifest never
promises more than the tests demonstrate.
"""

from __future__ import annotations

import base64
from pathlib import Path

from qren import block_types, classifier
from qren.crystal_slime import (
    CrystallizationTrigger, SlimeState, SlimeTracker, crystal_baby_fusion,
)
from qren.magic_circle import MagicCircle, OperationResult
from qren.qrcf.qrcf_types import BlockType, CompressionTier, QRenError
from qren.qrcf.qrcf_encoder import QRenEncoder
from qren.qrcf.qrcf_decoder import QRenDecoder
from qren.tokens import ALL_TOKENS

CAPABILITIES = (
    # container format
    "encode", "decode", "verify", "block-types", "self-test",
    # semantic layer
    "classify", "slime-phase", "tokens", "circle",
)


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


# ── semantic layer ────────────────────────────────────────────────────────
# The container capabilities above move bytes. These four expose what the
# bytes MEAN: which type a payload is, where a block sits in its lifecycle,
# what the pre-encoded tokens currently stand for, and the I/O boundary that
# routes a block to a context.


def _classify(params: dict) -> dict:
    """params: content (required), filename, metadata

    Deterministic and read-only by contract. ``echoed_content_hash`` is the
    classifier's own proof that it did not modify what it was given, and it
    is returned rather than checked-and-discarded so the caller can verify
    the same property across a process boundary.
    """
    content = _require(params, "content")
    if isinstance(content, str):
        content = content.encode("utf-8")
    if not isinstance(content, (bytes, bytearray)):
        raise FlavorError(
            f"content must be str or bytes, got {type(content).__name__}")

    metadata = params.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise FlavorError("metadata must be a dict when given")

    result = classifier.classify(
        content=bytes(content),
        filename=params.get("filename"),
        metadata=metadata,
    )
    return result.to_dict()


def _slime_phase(params: dict) -> dict:
    """params: identity (required), state, triggers, advance, fuse_with

    AMORPHOUS -> ICE -> CRYSTAL. Stateless across calls: the caller supplies
    the current state and the triggers observed since the last transition,
    and gets back where that lands. Persistence is the host's business, not
    the flavor's.

    ``fuse_with`` performs a Crystal Baby fusion instead: two ICE parents
    produce a new CRYSTAL with its own derived identity.
    """
    identity = str(_require(params, "identity"))

    def _state(raw, label):
        try:
            return SlimeState[str(raw).upper()]
        except KeyError:
            raise FlavorError(
                f"unknown {label} {raw!r}; expected one of "
                f"{[s.name for s in SlimeState]}")

    state = _state(params.get("state", "AMORPHOUS"), "state")

    if "fuse_with" in params:
        other = str(params["fuse_with"])
        other_state = _state(params.get("fuse_with_state", "ICE"), "fuse_with_state")
        try:
            child = crystal_baby_fusion(
                SlimeTracker(identity=identity, state=state),
                SlimeTracker(identity=other, state=other_state),
            )
        except ValueError as exc:
            # A refused fusion is a real answer, not an adapter fault.
            raise FlavorError(str(exc))
        return {
            "operation": "crystal-baby-fusion",
            "parents": [identity, other],
            "identity": child.identity,
            "state": child.state.name,
            "block_type": child.block_type.name,
            "block_code": child.block_type.hex_code,
        }

    tracker = SlimeTracker(identity=identity, state=state)
    recorded = []
    for raw in params.get("triggers") or []:
        try:
            trigger = CrystallizationTrigger(str(raw).lower())
        except ValueError:
            raise FlavorError(
                f"unknown trigger {raw!r}; expected one of "
                f"{[t.value for t in CrystallizationTrigger]}")
        tracker.record_trigger(trigger)
        recorded.append(trigger.value)

    can_advance = tracker.can_advance()
    advanced = tracker.advance() if params.get("advance", True) else False

    return {
        "identity": identity,
        "operation": "advance" if params.get("advance", True) else "inspect",
        "state_from": state.name,
        "state": tracker.state.name,
        "advanced": advanced,
        "can_advance": can_advance,
        "triggers_recorded": recorded,
        "block_type": tracker.block_type.name,
        "block_code": tracker.block_type.hex_code,
    }


def _tokens(params: dict) -> dict:
    """params: token (optional — one of the three symbols, or a name)

    Each token's ``state`` is computed from what is actually wired in this
    build rather than restated from the spec, so an EA that reports 'active'
    is a claim about the code, not about a document.
    """
    wanted = params.get("token")
    entries = list(ALL_TOKENS.values())
    if wanted is not None:
        key = str(wanted)
        entries = [t for t in entries
                   if key == t.token or key.upper() in (t.name.upper(),
                                                        t.token.strip("⟨⟩"))]
        if not entries:
            raise FlavorError(
                f"unknown token {wanted!r}; expected one of "
                f"{[t.token for t in ALL_TOKENS.values()]}")

    return {
        "tokens": [
            {
                "token": t.token,
                "name": t.name,
                "state": t.state(),
                "wire_code": f"0x{t.wire_code:02X}",
                "block_type": (block_types.get(t.wire_code).name
                               if block_types.get(t.wire_code) else None),
                "compression_ratio": t.compression_ratio,
                "nada_protected": t.nada_protected,
                "requires": list(t.requires),
                "derived_from": list(t.derived_from),
                "resolves_to": t.resolves_to,
                "full_concept": t.full_concept,
            }
            for t in entries
        ],
        "count": len(entries),
    }


def _circle(params: dict) -> dict:
    """params: input (required), mode ('3A' or '3B'), input_encoding

    Runs the Magic Circle boundary: InputParser -> BlockRouter -> operation
    -> OutputFormatter. No reasoning substrate is wired in — this adapter
    exposes the boundary, and a boundary with a model inside it is no longer
    testable as a boundary. An echo operation stands in, so what this
    capability demonstrates is mode detection and routing, which is exactly
    what it claims and nothing more.

    The echo passes the input block through rather than returning text alone,
    because Mode 2 is defined as block-in/block-out: an operation producing no
    block makes the mode unrepresentable rather than merely uninteresting.
    """
    value = _require(params, "input")
    encoding = params.get("input_encoding")
    if encoding == "base64":
        if not isinstance(value, str):
            raise FlavorError("input_encoding=base64 requires a string input")
        try:
            value = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise FlavorError(f"input is not valid base64: {exc}")

    mode = params.get("mode")
    if mode is not None:
        mode = str(mode).upper()
        if mode not in ("3A", "3B"):
            raise FlavorError(f"unknown mode {mode!r}; expected '3A' or '3B'")

    def echo(block, context):
        raw = block.metadata.get("raw_text")
        seen = raw if raw is not None else f"{len(block.payload)} payload bytes"
        return OperationResult(text=f"[{context}] received: {seen}", block=block)

    try:
        result = MagicCircle(operation=echo).invoke(value, force_mode3=mode)
    except (TypeError, ValueError) as exc:
        raise FlavorError(str(exc))

    info = result.input_block.block_type_info
    return {
        "io_mode": result.io_mode.value,
        "routed_context": result.routed_context,
        "input_block_type": info.name if info else None,
        "input_block_code": info.hex_code if info else
                            f"0x{result.input_block.block_type:02X}",
        "output": _jsonable(result.output),
    }


def _jsonable(value):
    """Mode 2 hands back raw wire bytes and Mode 3A a dict containing them.

    Returning them unchanged would make the result un-serializable for the
    one caller shape this contract exists to serve, so bytes become base64
    and say so — an encoding the caller can reverse, not a lossy repr.
    """
    if isinstance(value, (bytes, bytearray)):
        return {"encoding": "base64",
                "value": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    return value


_DISPATCH = {
    "encode": _encode,
    "decode": _decode,
    "verify": _verify,
    "block-types": _block_types,
    "self-test": _self_test,
    "classify": _classify,
    "slime-phase": _slime_phase,
    "tokens": _tokens,
    "circle": _circle,
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
