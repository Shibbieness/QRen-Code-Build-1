#!/usr/bin/env python3
"""
QRCF Phase 2 — test suite.

Covers `qrcf_types_phase2.py` and `qrcf_circle_rules.py`: ~83 KB and 28
top-level definitions that shipped, imported cleanly, and were reachable by
nothing and covered by nothing. They were referenced only in a docstring.

Writing this immediately found a defect that had been latent since the package
restructure: `is_crystal_valid` and `verify_ice_contract` both did
`from qrcf_types import EdgeType` — the absolute form — and raised
ModuleNotFoundError on every call. Nobody noticed, because calling them was
not something anything did.

That is the argument for this file. Code that is never run is not dormant, it
is unverified: it looks like a capability in an inventory and behaves like a
gap when reached for.

Run:  python -m qren.qrcf.test_phase2
"""

import os
import sys
import tempfile
import time
import traceback


# ═══════════════════════════════════════════════════════════════
# HARNESS — matches test_phase1.py so both read the same way
# ═══════════════════════════════════════════════════════════════

class TestResult:
    def __init__(self, name):
        self.name = name
        self.passed = False
        self.message = ""
        self.duration = 0.0


def run_test(name, func):
    r = TestResult(name)
    start = time.time()
    try:
        func(r)
        r.passed = True
    except AssertionError as e:
        r.message = str(e) or "assertion failed"
    except Exception as e:
        r.message = f"{type(e).__name__}: {e}"
        if os.environ.get("QREN_TEST_TRACE"):
            traceback.print_exc()
    r.duration = (time.time() - start) * 1000
    return r


from .qrcf_types import BlockType, EdgeType, NormalizationProfile  # noqa: E402
from .qrcf_types_phase2 import (  # noqa: E402
    BoneBlockHeader, BracketType, CacheLine, CrystalLatticeHeader,
    EvictionPolicy, NestedQRenHeader, RAMCacheBlock, VoidJumpHeader,
    VoidJumpType, is_crystal_valid, verify_ice_contract,
)
from .qrcf_circle_rules import (  # noqa: E402
    CircleRuleSet, QRECLevel, QRMatrixSpec, QRVersion, RuleChainResolver,
)


# ═══════════════════════════════════════════════════════════════
# HEADERS — pack/unpack round-trips
# ═══════════════════════════════════════════════════════════════

def test_void_jump_header(r):
    """VOID (0x0C) is the non-linear traversal primitive. Its three
    constructors must each survive a round-trip, and the fixed size must hold
    — a header whose packed length drifts from FIXED_SIZE corrupts every block
    after it in the section."""
    cases = [
        VoidJumpHeader.reset(),
        VoidJumpHeader.jump_to(depth=2, arc_id=7),
        VoidJumpHeader.jump_to(depth=0, arc_id=0, save_context=False),
        VoidJumpHeader.jump_back(),
    ]
    for h in cases:
        packed = h.pack()
        assert len(packed) == VoidJumpHeader.FIXED_SIZE, (
            f"{h.jump_type.name}: packed {len(packed)} bytes, "
            f"FIXED_SIZE says {VoidJumpHeader.FIXED_SIZE}")
        assert VoidJumpHeader.unpack(packed) == h, f"{h.jump_type.name} lost data"
    r.message = f"{len(cases)} jump forms round-tripped"


def test_void_jump_semantics(r):
    """RESET means 'current depth/arc', encoded as the sentinel values. If a
    sentinel were stored as a real coordinate the jump would land somewhere."""
    reset = VoidJumpHeader.reset()
    assert reset.jump_type == VoidJumpType.RESET
    assert reset.target_depth == 0xFF, "RESET lost its depth sentinel"
    assert reset.target_arc_id == 0xFFFF, "RESET lost its arc sentinel"

    jump = VoidJumpHeader.jump_to(depth=3, arc_id=11)
    assert jump.target_depth == 3 and jump.target_arc_id == 11
    assert VoidJumpHeader.unpack(jump.pack()).target_arc_id == 11


def test_bone_block_header(r):
    """BONE (0x0B) is a pinned structural scaffold carrying a variable-length
    technorganic profile, so unpack returns the consumed length as well —
    getting that wrong misaligns everything downstream."""
    for profile in (b"", b"scaffold", bytes(range(64))):
        h = BoneBlockHeader(pin_count=3, technorganic_profile=profile)
        packed = h.pack()
        back, consumed = BoneBlockHeader.unpack(packed)
        assert back == h, f"profile len {len(profile)}: round-trip differs"
        assert consumed == len(packed), (
            f"profile len {len(profile)}: reported {consumed} consumed, "
            f"packed {len(packed)}")
        assert back.profile_len == len(profile)   # property, not a method
    r.message = "empty, short and 64-byte profiles all round-tripped"


def test_bone_pinning(r):
    """A BONE with live REQUIRES edges at seal time is pinned; the flag is
    what stops it being collected."""
    pinned = BoneBlockHeader(pin_count=2)
    unpinned = BoneBlockHeader(pin_count=0)
    assert isinstance(pinned.is_pinned, bool)   # property
    assert isinstance(unpinned.is_pinned, bool)
    assert BoneBlockHeader.unpack(pinned.pack())[0].pin_count == 2


def test_crystal_lattice_header(r):
    """CRYSTAL (0x0D) is a repeating lattice; lattice_degree 0 means 'being
    formed', which must survive as 0 rather than becoming a real valence."""
    for degree in (0, 1, 4, 255):
        h = CrystalLatticeHeader(lattice_degree=degree)
        packed = h.pack()
        assert len(packed) == CrystalLatticeHeader.FIXED_SIZE
        back = CrystalLatticeHeader.unpack(packed)
        assert back == h, f"degree {degree} round-trip differs"
        assert back.lattice_degree == degree
    assert CrystalLatticeHeader(lattice_degree=0).lattice_degree == 0
    r.message = "degrees 0, 1, 4, 255 round-tripped"


def test_nested_qren_header(r):
    """NESTED (0x08) carries a whole inner QRenCode: depth, bracket, arc and
    the inner manifest hash. The hash is 32 bytes and must come back exactly —
    a truncated hash silently breaks inner-archive verification."""
    digest = bytes(range(32))
    h = NestedQRenHeader(depth=2, bracket_type=BracketType.SQUARE, arc_id=5,
                         inner_qrcf_len=4096, inner_manifest_hash=digest)
    packed = h.pack()
    assert len(packed) == NestedQRenHeader.FIXED_SIZE, (
        f"packed {len(packed)}, FIXED_SIZE {NestedQRenHeader.FIXED_SIZE}")
    back = NestedQRenHeader.unpack(packed)
    assert back == h
    assert back.inner_manifest_hash == digest, "inner manifest hash altered"
    assert back.inner_qrcf_len == 4096
    r.message = "depth, bracket, arc and 32-byte manifest hash preserved"


def test_every_header_declares_its_size_honestly(r):
    """FIXED_SIZE is used to advance through a section. If any header packs to
    a different length than it declares, every block after it is misread — the
    same class of failure as the unknown-block-type bug, arrived at from the
    other direction."""
    fixed = [
        (VoidJumpHeader, VoidJumpHeader.reset()),
        (CrystalLatticeHeader, CrystalLatticeHeader()),
        (NestedQRenHeader, NestedQRenHeader()),
    ]
    for cls, inst in fixed:
        assert len(inst.pack()) == cls.FIXED_SIZE, (
            f"{cls.__name__} packs {len(inst.pack())} but declares "
            f"{cls.FIXED_SIZE}")
    # BoneBlockHeader is variable-length by design: fixed part + profile.
    bone = BoneBlockHeader(technorganic_profile=b"xyz")
    assert len(bone.pack()) == BoneBlockHeader.FIXED_SIZE + 3, (
        "BoneBlockHeader's variable part is not FIXED_SIZE + profile length")
    r.message = "3 fixed headers exact, BONE variable part correct"


# ═══════════════════════════════════════════════════════════════
# VALIDATORS — the semantic contracts
# ═══════════════════════════════════════════════════════════════

def test_validators_are_callable_at_all(r):
    """REGRESSION. Both validators did `from qrcf_types import EdgeType` — the
    absolute form — and raised ModuleNotFoundError on every call, from the
    moment this package gained a package structure. Nothing imported the
    module, so nothing ever found out."""
    assert is_crystal_valid([]) in (True, False)
    assert verify_ice_contract("ab" * 32, []) in (True, False)


def test_ice_contract_rejects_outgoing_edges(r):
    """ICE is a frozen snapshot: zero outgoing dependency edges. A validator
    that returns True for everything is decorative, so this asserts both
    directions."""
    block = "ab" * 32
    assert verify_ice_contract(block, []) is True, "clean ICE was rejected"
    violating = [{"from": block, "edge_type": EdgeType.REQUIRES}]
    assert verify_ice_contract(block, violating) is False, (
        "ICE with an outgoing REQUIRES edge was accepted")
    other = [{"from": "cd" * 32, "edge_type": EdgeType.REQUIRES}]
    assert verify_ice_contract(block, other) is True, (
        "another block's edge was attributed to this one")


def test_crystal_validity_needs_a_bond(r):
    """A CRYSTAL is a lattice bonded by dependency edges; with no edges it is
    not yet a lattice node."""
    assert is_crystal_valid([]) is False, "an unbonded crystal was called valid"
    assert is_crystal_valid([{"edge_type": EdgeType.REQUIRES}]) is True


# ═══════════════════════════════════════════════════════════════
# CACHE LAYER
# ═══════════════════════════════════════════════════════════════

def test_cache_block_constructs_and_reports(r):
    cache = RAMCacheBlock()
    assert cache is not None
    assert hasattr(EvictionPolicy, "__members__")
    assert len(EvictionPolicy.__members__) >= 1
    r.message = f"{len(EvictionPolicy.__members__)} eviction policies declared"


def test_cache_line_round_trip_if_packable(r):
    """CacheLine is part of the wire surface if it packs; if it does not, say
    so rather than asserting nothing."""
    if not hasattr(CacheLine, "pack"):
        r.message = "CacheLine has no pack(); not a wire structure"
        return
    line = CacheLine()
    packed = line.pack()
    assert isinstance(packed, (bytes, bytearray))
    if hasattr(CacheLine, "unpack"):
        back = CacheLine.unpack(packed)
        got = back[0] if isinstance(back, tuple) else back
        assert got == line, "CacheLine round-trip differs"
        r.message = "CacheLine round-tripped"
    else:
        r.message = "CacheLine packs but has no unpack()"


# ═══════════════════════════════════════════════════════════════
# CIRCLE RULES — the inheritance invariant
# ═══════════════════════════════════════════════════════════════

def test_matrix_spec_and_levels(r):
    """QR version and error-correction level are wire-visible choices."""
    assert len(QRVersion.__members__) >= 1
    assert len(QRECLevel.__members__) >= 1
    spec = QRMatrixSpec()
    assert spec is not None
    r.message = (f"{len(QRVersion.__members__)} versions, "
                 f"{len(QRECLevel.__members__)} EC levels")


def test_rule_chain_resolver_constructs(r):
    resolver = RuleChainResolver()
    assert resolver.current_depth() is not None   # method, not a property
    r.message = f"depth {resolver.current_depth()} at construction"


def test_rules_propagate_down_never_up(r):
    """The module's stated invariant, in its own words:

        Higher Circle rules apply to Lower Circles.
        Rules propagate DOWN the chain, never UP.

    Unset fields use 0xFF/0xFFFF as the sentinel, so a child that declares
    nothing inherits its parent's value, and a child that declares one
    overrides it — for itself only."""
    resolver = RuleChainResolver()
    parent = CircleRuleSet(declaring_depth=0, chain_id=1, default_compression=2)
    child = CircleRuleSet(declaring_depth=1, chain_id=1)   # all unset

    resolver.push(parent)
    assert resolver.effective_compression() == 2, "parent's own rule did not apply"

    resolver.push(child)
    assert resolver.effective_compression() == 2, (
        "a child declaring nothing did not inherit from its parent — "
        "rules are not propagating DOWN")

    override = CircleRuleSet(declaring_depth=2, chain_id=1, default_compression=1)
    resolver.push(override)
    assert resolver.effective_compression() == 1, "a child could not override"

    resolver.pop()
    assert resolver.effective_compression() == 2, (
        "a child's rule survived its own pop — rules propagated UP")
    r.message = "inherit down, override locally, does not leak up"


def test_sibling_does_not_inherit(r):
    """The negative half, and the one worth having: a resolver that hands
    every rule to everyone satisfies 'propagates down' and is still wrong.

    Sibling A sets a value and is popped. Sibling B declares nothing. B must
    see the PARENT's value, never A's."""
    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                default_compression=2))

    resolver.push(CircleRuleSet(declaring_depth=1, chain_id=1,
                                default_compression=5))
    assert resolver.effective_compression() == 5
    resolver.pop()

    resolver.push(CircleRuleSet(declaring_depth=1, chain_id=1))   # unset
    got = resolver.effective_compression()
    assert got != 5, f"sibling B inherited sibling A's rule ({got}) — rules are not scoped to their chain"
    assert got == 2, f"sibling B should see the parent's 2, saw {got}"
    r.message = "siblings are scoped; B sees the parent, not A"


def test_depth_and_nesting_limits(r):
    """max_nesting_depth is a real limit: can_go_deeper must eventually say no,
    or a nested archive can recurse without bound."""
    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                max_nesting_depth=2))
    assert resolver.can_go_deeper() in (True, False)
    depths = 0
    while resolver.can_go_deeper() and depths < 50:
        resolver.push(CircleRuleSet(declaring_depth=resolver.current_depth() + 1,
                                    chain_id=1))
        depths += 1
    assert depths < 50, "can_go_deeper() never became False — nesting is unbounded"
    r.message = f"nesting stopped after {depths} pushes"


def test_effective_all_reports_every_resolved_rule(r):
    """effective_all is the summary the decoder would act on; it must agree
    with the individual accessors rather than being a second computation."""
    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                default_compression=2, ec_level=1))
    summary = resolver.effective_all()
    assert isinstance(summary, dict) and summary, "effective_all returned nothing"
    # effective_all reports resolved ENUMS; the accessors return the same
    # objects, so compare values rather than assuming either is a raw int.
    for key, accessor in (("compression", resolver.effective_compression),
                          ("ec_level", resolver.effective_ec_level)):
        match = [v for k, v in summary.items() if key in k.lower()]
        if match:
            got, want = match[0], accessor()
            # effective_all reports enum NAMES as strings; the accessors return
            # the enum members. Compare on name so the two representations are
            # checked against each other rather than assumed equal.
            want_name = getattr(want, "name", str(want))
            assert str(got) == want_name, (
                f"effective_all disagrees with effective_{key}: "
                f"{got!r} vs {want_name!r}")
    r.message = f"{len(summary)} rules resolved, consistent with accessors"


def test_circle_rule_set_round_trip(r):
    """CircleRuleSet is a wire structure — it packs into the archive."""
    rs = CircleRuleSet(declaring_depth=2, chain_id=7, default_compression=2,
                       ec_level=1, max_nesting_depth=4)
    packed = rs.pack()
    assert isinstance(packed, (bytes, bytearray)) and packed
    back = CircleRuleSet.unpack(packed)
    got = back[0] if isinstance(back, tuple) else back
    assert got.chain_id == 7, "chain_id lost — rules would apply to the wrong chain"
    assert got.declaring_depth == 2
    assert got.default_compression == 2
    assert got == rs, "CircleRuleSet round-trip differs"
    r.message = f"round-tripped in {len(packed)} bytes"



def test_sealed_rules_cannot_be_overridden_from_deeper(r):
    """REGRESSION. SEALED means no lower circle may override the field, and it
    could never fire.

    _resolve walked innermost -> outermost and set `sealed_at` only when it
    REACHED the sealing rule set — but the declaration that seals a field is
    always outward of the override it blocks, so the walk returned the deeper
    value and exited before ever seeing the seal. Every SEALED rule was
    silently ignored.

    Found by running the module's own __main__ self-test, which asserts this
    exact case and had never been executed because nothing imported the file.
    """
    from .qrcf_circle_rules import CircleRuleFlags

    resolver = RuleChainResolver()
    root = CircleRuleSet.root()
    root.ec_level = QRECLevel.H
    root.flags = CircleRuleFlags.SEALED
    resolver.push(root)

    # A deeper circle tries to override a sealed field.
    resolver.push(CircleRuleSet.for_depth(1, ec_level=QRECLevel.L))
    assert resolver.effective_ec_level() == QRECLevel.H, (
        "a deeper circle overrode a SEALED field — the seal did nothing")

    # And an UNSEALED field at the same depth must still be overridable, or
    # the fix would have sealed everything instead of the declared field.
    resolver2 = RuleChainResolver()
    open_root = CircleRuleSet.root()
    open_root.ec_level = QRECLevel.H
    resolver2.push(open_root)
    resolver2.push(CircleRuleSet.for_depth(1, ec_level=QRECLevel.L))
    assert resolver2.effective_ec_level() == QRECLevel.L, (
        "an unsealed field was treated as sealed")
    r.message = "sealed blocks the override; unsealed still allows it"


def test_circle_rules_module_self_test_passes(r):
    """qrcf_circle_rules ships a __main__ block that exercises inheritance,
    sealing, forking and depth limits. It asserted CircleRuleSet.pack() equals
    FIXED_SIZE — which was false from the first line — and nobody ran it.

    Running it here means it cannot rot again."""
    import runpy, sys, io, contextlib
    buf = io.StringIO()
    argv = sys.argv[:]
    sys.argv = ["qrcf_circle_rules"]
    try:
        with contextlib.redirect_stdout(buf):
            runpy.run_module("qren.qrcf.qrcf_circle_rules", run_name="__main__")
    except SystemExit as exc:
        assert not exc.code, f"module self-test exited {exc.code}"
    finally:
        sys.argv = argv
    out = buf.getvalue()
    assert "All Circle Rule Inheritance tests passed" in out, (
        f"self-test did not report success:\n{out[-400:]}")
    r.message = f"{out.count('[PASS]')} internal checks passed"


# ═══════════════════════════════════════════════════════════════
# WIRING — type headers through the real encode/decode path
# ═══════════════════════════════════════════════════════════════

def _encoded(block_type, header, payload=None):
    """Encode a block carrying a per-type header and decode it back."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder
    payload = payload if payload is not None else {"k": block_type.name}
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "x.qren.png")
        QRenEncoder().encode(payload, name="x", block_type=block_type,
                             type_header=header, output_path=out)
        return QRenDecoder().decode(out), payload


def test_type_headers_round_trip_through_the_real_encoder(r):
    """The wiring. Until now these four headers packed and unpacked in
    isolation and no archive had ever carried one."""
    from .qrcf_types_phase2 import TYPE_HEADERS
    import json

    cases = [
        (BlockType.CRYSTAL, CrystalLatticeHeader(lattice_degree=4)),
        (BlockType.VOID,    VoidJumpHeader.jump_to(depth=2, arc_id=7)),
        (BlockType.BONE,    BoneBlockHeader(pin_count=3,
                                            technorganic_profile=b"scaffold")),
        (BlockType.NESTED,  NestedQRenHeader(depth=1, arc_id=5,
                                             inner_qrcf_len=4096)),
    ]
    assert {bt for bt, _ in cases} == set(TYPE_HEADERS), (
        "this test does not cover every type in TYPE_HEADERS")

    for bt, header in cases:
        decoded, payload = _encoded(bt, header)
        assert decoded['valid'], f"{bt.name}: {decoded['validation_errors']}"
        assert decoded['data'] == json.dumps(payload).encode(), (
            f"{bt.name}: payload altered by carrying a type header")
        assert decoded['blocks'][0]['type_header'] == type(header).__name__
    r.message = f"{len(cases)} types carried their header through a real archive"



def test_type_header_object_is_exposed_with_its_values(r):
    """The class name proves a header was FOUND. It does not prove the fields
    came back — a header parsed at the wrong offset is still the right class
    and holds rubbish. So the decoder reports the values too, and this checks
    them through the public result rather than by reaching into internals."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder

    header = CrystalLatticeHeader(lattice_degree=4)
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "c.qren.png")
        QRenEncoder().encode({"k": 1}, name="c", block_type=BlockType.CRYSTAL,
                             type_header=header, output_path=out)
        decoded = QRenDecoder().decode(out)

    assert decoded['valid'], decoded['validation_errors']
    block = decoded['blocks'][0]
    assert block['type_header'] == "CrystalLatticeHeader"
    fields = block['type_header_fields']
    assert fields is not None, "the parsed header exposed no values"
    assert fields['lattice_degree'] == 4, (
        f"header found but its value is wrong: {fields}")
    assert fields['crystal_version'] == header.crystal_version
    r.message = f"values survived: {fields}"


def test_type_header_fields_are_json_safe(r):
    """This result travels out through the Vanilla Core flavor adapter as
    JSON. A header carrying raw bytes or an enum would serialise to a
    TypeError at the boundary, far from the cause."""
    import json
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder

    # NestedQRenHeader has both a bytes field and an enum field.
    header = NestedQRenHeader(depth=1, bracket_type=BracketType.SQUARE,
                              arc_id=5, inner_qrcf_len=4096,
                              inner_manifest_hash=bytes(range(32)))
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "n.qren.png")
        QRenEncoder().encode({"k": 1}, name="n", block_type=BlockType.NESTED,
                             type_header=header, output_path=out)
        decoded = QRenDecoder().decode(out)

    fields = decoded['blocks'][0]['type_header_fields']
    json.dumps(decoded['blocks'])            # must not raise
    assert fields['inner_manifest_hash'] == bytes(range(32)).hex(), (
        "bytes field was not rendered as hex")
    assert fields['bracket_type'] == BracketType.SQUARE.name, (
        "enum field was not rendered as its name")
    assert fields['inner_qrcf_len'] == 4096
    r.message = "bytes -> hex, enum -> name, whole result serialises"


def test_flag_is_set_only_when_a_header_is_present(r):
    """HAS_TYPE_HEADER must reflect reality in both directions. A flag set
    with no header desynchronises every following byte; a header with no flag
    is invisible to the reader."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder

    with tempfile.TemporaryDirectory() as tmpdir:
        bare = os.path.join(tmpdir, "bare.qren.png")
        QRenEncoder().encode({"k": 1}, name="bare", block_type=BlockType.CRYSTAL,
                             output_path=bare)
        got = QRenDecoder().decode(bare)
        assert got['valid'], got['validation_errors']
        assert got['blocks'][0]['type_header'] is None, (
            "a block encoded without a type header reported one")
        assert got['blocks'][0]['type_header_fields'] is None

        withhdr = os.path.join(tmpdir, "with.qren.png")
        QRenEncoder().encode({"k": 1}, name="with", block_type=BlockType.CRYSTAL,
                             type_header=CrystalLatticeHeader(lattice_degree=2),
                             output_path=withhdr)
        got2 = QRenDecoder().decode(withhdr)
        assert got2['valid'], got2['validation_errors']
        assert got2['blocks'][0]['type_header'] == "CrystalLatticeHeader"
        assert got2['blocks'][0]['type_header_fields']['lattice_degree'] == 2
    r.message = "absent stays absent, present carries its values"


def test_a_type_header_on_a_type_that_takes_none_is_refused(r):
    """TREE has no per-type header. Accepting one would write bytes no
    decoder knows to read back."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_types import QRenFormatError
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            QRenEncoder().encode({"k": 1}, name="t", block_type=BlockType.TREE,
                                 type_header=CrystalLatticeHeader(),
                                 output_path=os.path.join(tmpdir, "t.png"))
    except QRenFormatError:
        return
    raise AssertionError("TREE accepted a type header it defines no meaning for")


def test_the_wrong_header_class_is_refused(r):
    """CRYSTAL takes a CrystalLatticeHeader. A VoidJumpHeader packs to a
    different length, so accepting it would misalign the data region while
    looking entirely plausible."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_types import QRenFormatError
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            QRenEncoder().encode({"k": 1}, name="c", block_type=BlockType.CRYSTAL,
                                 type_header=VoidJumpHeader.reset(),
                                 output_path=os.path.join(tmpdir, "c.png"))
    except QRenFormatError:
        return
    raise AssertionError("CRYSTAL accepted a VoidJumpHeader")


def test_frame_stays_skippable_by_a_decoder_that_knows_neither(r):
    """The reason the type header lives INSIDE data_length.

    Put it between the block header and the data and its size would have to be
    known to skip the block — which requires knowing the type, which is
    exactly what an older decoder does not know. Inside data_length, the frame
    is still FIXED_SIZE + tag_len + data_length for everyone.

    Simulated by narrowing what this decoder recognises: the block type is
    rewritten to an unused code, so the reader is in the position of one that
    knows neither the type nor that a header is there."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder

    unused = next(c for c in range(1, 255) if c not in {b.value for b in BlockType})
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "c.qren.png")
        QRenEncoder().encode({"k": 1}, name="c", block_type=BlockType.CRYSTAL,
                             type_header=CrystalLatticeHeader(lattice_degree=4),
                             output_path=out)
        blob = open(out, "rb").read()

    dec = QRenDecoder(verify_integrity=False)
    clean = dec.decode_bytes(blob)
    bid = bytes.fromhex(clean['blocks'][0]['block_id'])
    i = blob.find(bid)
    assert i != -1
    patched = bytearray(blob)
    patched[i + 32] = unused

    out2 = dec.decode_bytes(bytes(patched))
    assert out2['valid'] is False, "an unknown type still reported valid"
    assert out2['block_count'] == 1, (
        "the frame was misread: the block was lost rather than preserved, "
        "which means data_length did not cover the type header"
    )
    r.message = "unknown-type reader skips the frame cleanly and keeps the block"


def test_resolver_supplies_defaults_to_the_encoder(r):
    """encode_with_rules was described as "the bridge between the rule
    inheritance system and the encoder" and nothing crossed it. The encoder
    now accepts a resolver and takes its effective compression from the
    inherited chain instead of a hardcoded default."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder
    from .qrcf_types import CompressionTier

    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                default_compression=CompressionTier.T1_LZ4))

    with tempfile.TemporaryDirectory() as tmpdir:
        plain = os.path.join(tmpdir, "plain.qren.png")
        ruled = os.path.join(tmpdir, "ruled.qren.png")
        a = QRenEncoder().encode({"k": 1}, name="p", output_path=plain)
        b = QRenEncoder().encode({"k": 1}, name="r", resolver=resolver,
                                 output_path=ruled)
        assert a['compression'] != b['compression'], (
            "the rule chain changed nothing — inheritance resolves and is "
            "then ignored")
        assert b['compression'] == CompressionTier.T1_LZ4.name
        assert QRenDecoder().decode(ruled)['valid']
    r.message = f"default {a['compression']} -> inherited {b['compression']}"


def test_an_explicit_argument_beats_an_inherited_rule(r):
    """Rules are defaults for blocks that did not choose, not policy imposed
    on blocks that did. A caller naming a tier means it."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_types import CompressionTier

    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                default_compression=CompressionTier.T1_LZ4))
    with tempfile.TemporaryDirectory() as tmpdir:
        got = QRenEncoder().encode(
            {"k": 1}, name="x", resolver=resolver,
            compression=CompressionTier.T2_ZSTD,
            output_path=os.path.join(tmpdir, "x.qren.png"))
    assert got['compression'] == CompressionTier.T2_ZSTD.name, (
        f"an inherited rule overrode an explicit argument: {got['compression']}")
    r.message = "explicit > inherited > default"


def test_a_zero_valued_enum_is_selectable(r):
    """REGRESSION, and it predates the resolver.

    CompressionTier.T0_NONE is 0x00 and NormalizationProfile.STRICT is 0x00 —
    both FALSY. The encoder chose with `compression or self.default_compression`,
    so an explicit request for no compression was silently discarded and the
    default used instead. Asking for T0_NONE had never worked, on the path
    every single block takes.

    An enum whose first member is zero cannot be tested for presence by
    truthiness."""
    from .qrcf_encoder import QRenEncoder
    from .qrcf_decoder import QRenDecoder
    from .qrcf_types import CompressionTier

    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "z.qren.png")
        got = QRenEncoder().encode({"k": 1}, name="z",
                                   compression=CompressionTier.T0_NONE,
                                   output_path=out)
        assert got['compression'] == CompressionTier.T0_NONE.name, (
            f"asked for T0_NONE, got {got['compression']} — a falsy enum "
            f"member was treated as absent")
        decoded = QRenDecoder().decode(out)
        assert decoded['valid'], decoded['validation_errors']
        assert decoded['data'] == b'{"k": 1}', "uncompressed payload did not survive"

        # And the same hazard on the rule path.
        resolver = RuleChainResolver()
        resolver.push(CircleRuleSet(declaring_depth=0, chain_id=1,
                                    default_compression=CompressionTier.T0_NONE))
        ruled = QRenEncoder().encode(
            {"k": 1}, name="zr", resolver=resolver,
            output_path=os.path.join(tmpdir, "zr.qren.png"))
        assert ruled['compression'] == CompressionTier.T0_NONE.name, (
            "an inherited T0_NONE was treated as absent")
    r.message = "T0_NONE selectable explicitly and by rule"

# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

def main():
    tests = [
        ("VoidJumpHeader Round-Trip",          test_void_jump_header),
        ("VOID Jump Semantics",                test_void_jump_semantics),
        ("BoneBlockHeader Round-Trip",         test_bone_block_header),
        ("BONE Pinning",                       test_bone_pinning),
        ("CrystalLatticeHeader Round-Trip",    test_crystal_lattice_header),
        ("NestedQRenHeader Round-Trip",        test_nested_qren_header),
        ("Headers Declare Size Honestly",      test_every_header_declares_its_size_honestly),
        ("Validators Are Callable",            test_validators_are_callable_at_all),
        ("ICE Contract Rejects Outgoing",      test_ice_contract_rejects_outgoing_edges),
        ("CRYSTAL Validity Needs A Bond",      test_crystal_validity_needs_a_bond),
        ("Cache Block Constructs",             test_cache_block_constructs_and_reports),
        ("CacheLine Round-Trip",               test_cache_line_round_trip_if_packable),
        ("Matrix Spec And Levels",             test_matrix_spec_and_levels),
        ("RuleChainResolver Constructs",       test_rule_chain_resolver_constructs),
        ("Rules Propagate Down Never Up",      test_rules_propagate_down_never_up),
        ("Sibling Does Not Inherit",           test_sibling_does_not_inherit),
        ("Depth And Nesting Limits",           test_depth_and_nesting_limits),
        ("effective_all Is Consistent",        test_effective_all_reports_every_resolved_rule),
        ("CircleRuleSet Round-Trip",           test_circle_rule_set_round_trip),
        ("SEALED Blocks Deeper Override",      test_sealed_rules_cannot_be_overridden_from_deeper),
        ("Module Self-Test Passes",            test_circle_rules_module_self_test_passes),
        ("Type Headers Round-Trip Encoded",    test_type_headers_round_trip_through_the_real_encoder),
        ("Type Header Values Survive",         test_type_header_object_is_exposed_with_its_values),
        ("Type Header Fields Are JSON-Safe",   test_type_header_fields_are_json_safe),
        ("Flag Tracks Header Presence",        test_flag_is_set_only_when_a_header_is_present),
        ("Header On Wrong Type Refused",       test_a_type_header_on_a_type_that_takes_none_is_refused),
        ("Wrong Header Class Refused",         test_the_wrong_header_class_is_refused),
        ("Frame Skippable By Older Reader",    test_frame_stays_skippable_by_a_decoder_that_knows_neither),
        ("Resolver Supplies Encoder Defaults", test_resolver_supplies_defaults_to_the_encoder),
        ("Explicit Beats Inherited Rule",      test_an_explicit_argument_beats_an_inherited_rule),
        ("Zero-Valued Enum Is Selectable",     test_a_zero_valued_enum_is_selectable),
    ]

    print("=" * 72)
    print("  QRenCode Phase 2 — Test Suite")
    print("  Type extensions and circle rule inheritance")
    print("=" * 72)
    print()

    results = [run_test(name, fn) for name, fn in tests]
    for res in results:
        mark = "PASS" if res.passed else "FAIL"
        extra = f": {res.message}" if res.message else ""
        print(f"  [{mark}] {res.name} ({res.duration:.1f}ms){extra}")

    passed = sum(1 for x in results if x.passed)
    failed = len(results) - passed
    print()
    print("-" * 72)
    print(f"  Results: {passed} passed, {failed} failed, {len(results)} total")
    if failed:
        print()
        print("  FAILED TESTS:")
        for res in results:
            if not res.passed:
                print(f"    x {res.name}: {res.message}")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
