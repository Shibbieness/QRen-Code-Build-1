"""
QRCF Phase 2 Type Extensions
==============================
Additions to qrcf_types.py for Phase 2.

Phase 1 wire formats are FROZEN. These are additive only.

New block type wire codes (Phase 2):
    0x08  NESTED   — complete QRenCode-within-QRenCode
    0x09  RUNIC    — pure Runic script, glyph-dominant executable
    0x0A  MYCELIUM — peer-network graph, distributed root-web
    0x0B  BONE     — Technorganic structural scaffold, pinned anchor
    0x0C  VOID     — QRVM non-linear jump instruction
    0x0D  CRYSTAL  — gemstone lattice, repeating network structure

ICE (0x02) vs CRYSTAL (0x0D) distinction:
    ICE     = snowflake — unique crystallization at a moment in time.
              No outgoing dependency edges. STRICT normalization.
              Every byte of this specific frozen snapshot matters.
              Can be cold-stored. Represents Crystal Slime B.
    CRYSTAL = gemstone lattice — repeating, networked, cross-referenced.
              Many outgoing EdgeType.DERIVED_FROM and REQUIRES edges.
              STRUCTURED normalization — the pattern is regular, order-
              canonicalized, reproducible. Represents HUB mutual data
              binding and network topology.
    Decoder can distinguish them: ICE has zero outgoing dependency edges.
    CRYSTAL has >= 1. The stress marker is in the dependency_graph.

BONE vs ICE distinction:
    ICE  = a frozen *state* — a sealed process or codebase at rest.
           Can be cold-stored. No structural role.
    BONE = a structural *role* — the scaffold other blocks attach to.
           Pinned in RAM Cache. Cannot be evicted while live dependents
           exist. QRVM enforces this. Other blocks hold REQUIRES edges
           pointing to BONE. BONE does not hold REQUIRES edges out.

VOID as QRVM instruction:
    VOID blocks are jump instructions, not data payloads.
    They contain a VoidJumpHeader — target_depth, target_arc_id,
    jump_type. QRVM routes VOID to its jump handler, not data decoder.
    Enables non-linear circle traversal without linear backtracking.
    Maps to Runic ○0 reset and ○≡○n jump semantics.

Synthesis sources:
    dRAM: MTL/MO separation, Pull/Simulate/Capture/Flush lifecycle,
          Tier model, RCache pinning, Ghost Process detection
    VI Builder: BONE as structural anchor (Living Index), Ghost Processes,
                Tier T0-T5 alignment with CompressionTier
    Runic: ArCircle/ArGlyph nesting, ○0 reset, ○n jump, BracketType
    QRen-Boot: RAM Cache geometry, BOOT_CAPABLE flag
    Build Tracker v3: RAMCacheBlock struct spec §5.1

This is NOT CodexOmega. Zero external dependencies.
"""

import struct
import hashlib
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .qrcf_types import (
    content_address, QRenFormatError, QRenIntegrityError,
    CompressionTier, NormalizationProfile,
    TrailerHeader, SectionEntry,
    XQPE_MAGIC,
)


# ═══════════════════════════════════════════════════════════════
# BLOCK TYPE — Phase 2 complete registry
# 0x01-0x07 FROZEN from Phase 1. 0x08-0x0D new in Phase 2.
# ═══════════════════════════════════════════════════════════════

# BlockType and BLOCK_NORMALIZATION were duplicated here, byte-identical to
# qrcf_types.py — two definitions of one concept with only one maintained,
# which is how an adapter's hand-rolled copy of a query silently diverged
# from its source earlier in this project. Verified identical (14 types,
# same codes, same profiles) before removal, then imported instead.
#
# The wire enum is now the single definition, and it also carries LIGHT
# (0x0E), which this file never had.
from .qrcf_types import BlockType, BLOCK_NORMALIZATION  # noqa: F401



# ── Default compression per block type ────────────────────────
BLOCK_COMPRESSION = {
    # Phase 1
    BlockType.TREE:      CompressionTier.T2_ZSTD,
    BlockType.ICE:       CompressionTier.T3_DELTA,   # versioned snapshot
    BlockType.FLAME:     CompressionTier.T2_ZSTD,
    BlockType.LIGHTNING: CompressionTier.T2_ZSTD,
    BlockType.FRACTAL:   CompressionTier.T4_FRACTAL,
    BlockType.GEOMETRIC: CompressionTier.T2_ZSTD,
    BlockType.AMORPHOUS: CompressionTier.T2_ZSTD,
    # Phase 2
    BlockType.NESTED:    CompressionTier.T2_ZSTD,   # inner handles own comp
    BlockType.RUNIC:     CompressionTier.T2_ZSTD,   # glyph scripts
    BlockType.MYCELIUM:  CompressionTier.T5_DEDUP,  # peer nodes deduplicate
    BlockType.BONE:      CompressionTier.T2_ZSTD,   # stable structural data
    BlockType.VOID:      CompressionTier.T0_NONE,   # jump header is tiny
    BlockType.CRYSTAL:   CompressionTier.T5_DEDUP,  # lattice deduplicates
    BlockType.CUSTOM:    CompressionTier.T2_ZSTD,
}

# ── Properties that affect QRVM behaviour ─────────────────────
# BONE blocks are pinned in RAM Cache while live REQUIRES edges exist.
# VOID blocks are routed to jump handler, not data decoder.
# RUNIC blocks are routed to Runic interpreter.
BLOCK_IS_PINNED     = {bt: bt == BlockType.BONE   for bt in BlockType}
BLOCK_IS_OPCODE     = {bt: bt == BlockType.VOID   for bt in BlockType}
BLOCK_IS_EXECUTABLE = {bt: bt in (BlockType.FLAME, BlockType.LIGHTNING,
                                   BlockType.VOID,  BlockType.RUNIC)
                        for bt in BlockType}


# ═══════════════════════════════════════════════════════════════
# ICE vs CRYSTAL — decoder-verifiable semantic distinction
# ═══════════════════════════════════════════════════════════════

def is_crystal_valid(dep_graph_edges: list) -> bool:
    """
    CRYSTAL blocks must have >= 1 outgoing REQUIRES or DERIVED_FROM edge.
    ICE blocks must have 0 outgoing edges.

    Called during Profile C decode to verify the semantic contract.
    Mismatch = log warning, not hard fail (semantic, not structural error).

    dep_graph_edges: list of edge dicts from Circle 2 dependency_graph['edges']
                     Each edge: {'from': block_id, 'to': block_id, 'type': int}
    """
    # Relative: this module lives inside the qrcf package. The absolute
    # form was a leftover from before the restructure and raised
    # ModuleNotFoundError on every call — never noticed because nothing
    # imported this module and nothing tested it.
    from .qrcf_types import EdgeType
    outgoing_types = {EdgeType.REQUIRES, EdgeType.DERIVED_FROM}
    return any(
        e.get('edge_type') in outgoing_types
        for e in dep_graph_edges
    )

def verify_ice_contract(block_id_hex: str, dep_graph_edges: list) -> bool:
    """ICE blocks must have zero outgoing dependency edges."""
    # Relative: this module lives inside the qrcf package. The absolute
    # form was a leftover from before the restructure and raised
    # ModuleNotFoundError on every call — never noticed because nothing
    # imported this module and nothing tested it.
    from .qrcf_types import EdgeType
    return not any(
        e.get('from') == block_id_hex and
        e.get('edge_type') in {EdgeType.REQUIRES, EdgeType.DERIVED_FROM}
        for e in dep_graph_edges
    )


# ═══════════════════════════════════════════════════════════════
# BRACKET TYPE — ArGlyph visual/semantic circle notation
# Runic ○n system: each bracket = a named ArGlyph container
# ═══════════════════════════════════════════════════════════════

class BracketType(IntEnum):
    """
    Bracket type for NESTED and VOID blocks.
    Maps directly to Runic ArGlyph/ArCircle system.

    []  SQUARE  = FRACTAL affinity — recursive, self-similar
    {}  CURLY   = TREE affinity    — structured hierarchy
    ()  PAREN   = AMORPHOUS affinity — free-form
    <>  ANGLE   = LIGHTNING affinity — fast-path signal

    Example nesting tree (Mark's notation, BracketType annotations):
        [Top ○0                              SQUARE  depth=0
          {Middle1 ○0                        CURLY   depth=1
            (Middle2a ○0                     PAREN   depth=2
              [Inner] ○0                     SQUARE  depth=3
              [Inner] ○0                     SQUARE  depth=3
            )
            (Middle2b ○0                     PAREN   depth=2
              (Middle3a ○0                   PAREN   depth=3
                {Inner} ○0                   CURLY   depth=4
                {Inner} ○0                   CURLY   depth=4
              )
              (Middle3b ○0                   PAREN   depth=3
                {Inner} ○0                   CURLY   depth=4
              )
              [Inner] ○0                     SQUARE  depth=3
            )
            (Inner) ○0                       PAREN   depth=2
          }
          {Inner} ○0                         CURLY   depth=1
        ]
    """
    SQUARE = 0x00   # [○]  FRACTAL semantic
    CURLY  = 0x01   # {○}  TREE semantic
    PAREN  = 0x02   # (○)  AMORPHOUS semantic
    ANGLE  = 0x03   # <○>  LIGHTNING semantic

BRACKET_BLOCK_AFFINITY = {
    BracketType.SQUARE: BlockType.FRACTAL,
    BracketType.CURLY:  BlockType.TREE,
    BracketType.PAREN:  BlockType.AMORPHOUS,
    BracketType.ANGLE:  BlockType.LIGHTNING,
}

BRACKET_OPEN  = {BracketType.SQUARE:'[', BracketType.CURLY:'{',
                 BracketType.PAREN:'(', BracketType.ANGLE:'<'}
BRACKET_CLOSE = {BracketType.SQUARE:']', BracketType.CURLY:'}',
                 BracketType.PAREN:')', BracketType.ANGLE:'>'}


# ═══════════════════════════════════════════════════════════════
# EVICTION POLICY — dRAM RCache Engine strategies
# MTL sets promotion_threshold (advice). MO runs eviction (action).
# BONE blocks ignore eviction policy — they are always pinned.
# ═══════════════════════════════════════════════════════════════

class EvictionPolicy(IntEnum):
    LRU = 0x00  # Least Recently Used — dRAM RCache default
    LFU = 0x01  # Least Frequently Used — stable hot-path data
    ARC = 0x02  # Adaptive Replacement Cache — MTL-observed adaptive


# ═══════════════════════════════════════════════════════════════
# VOID JUMP TYPE — QRVM non-linear circle traversal
# Maps to Runic ○0 (reset/close) and ○≡○n (jump-bind) semantics
# ═══════════════════════════════════════════════════════════════

class VoidJumpType(IntEnum):
    """
    Type of non-linear traversal performed by a VOID block.

    RESET    — equivalent to Runic ○0: close current circle, return
               to immediate parent. Linear backtrack one level.
               This is the simple case — same as closing a bracket.

    JUMP_UP  — jump N levels up the nesting tree without closing each
               intermediate circle. Fast backtrack to ancestor.
               target_depth is the absolute depth to jump to.

    JUMP_DOWN — jump into a specific named arc at a deeper level
                without traversing intervening circles sequentially.
                target_arc_id identifies the destination ArGlyph.

    ABSOLUTE — jump to an explicitly named arc_id at an explicit depth
               regardless of current position in the nesting tree.
               The QRVM saves current context (Warm Switch semantics)
               before jumping. Context is restoreable via JUMP_BACK.

    JUMP_BACK — return to the context saved by the last ABSOLUTE jump.
                Like a function return — goes back to saved position.
                Enables subroutine-style execution within the nesting
                tree without destroying the call site context.
    """
    RESET      = 0x00  # ○0 — close current, return to parent
    JUMP_UP    = 0x01  # Jump N levels up to target_depth
    JUMP_DOWN  = 0x02  # Jump into target_arc_id at deeper level
    ABSOLUTE   = 0x03  # Jump to (target_depth, target_arc_id) absolutely
    JUMP_BACK  = 0x04  # Return to last ABSOLUTE jump's saved context


# ═══════════════════════════════════════════════════════════════
# VOID JUMP HEADER — the payload of a VOID block
# A VOID block's entire data content is this header.
# No compression (T0_NONE) — it's tiny and must be fast.
# ═══════════════════════════════════════════════════════════════

@dataclass
class VoidJumpHeader:
    """
    QRVM jump instruction stored as a VOID block payload.

    Wire format (14 bytes — tiny by design):
        magic         : bytes  (4 bytes) — b"VOID"
        jump_type     : uint8  (1 byte)  — VoidJumpType enum
        target_depth  : uint8  (1 byte)  — absolute nesting depth to jump to
                                           (0 = top level, 0xFF = current)
        target_arc_id : uint16 (2 bytes) — ArGlyph number to jump into
                                           (0 = anonymous ○, 0xFFFF = current)
        flags         : uint16 (2 bytes) — VoidFlags bitmask
        reserved      : bytes  (4 bytes) — zero-filled, future use

    Total: 4+1+1+2+2+4 = 14 bytes. Uncompressed. Executed immediately
    by QRVM when encountered — not placed in data pipeline.

    Runic equivalents:
        RESET (○0):
            VoidJumpHeader(jump_type=RESET, target_depth=0xFF, target_arc_id=0xFFFF)
        ABSOLUTE jump to depth=2, arc_id=3 (○≡○3 at depth 2):
            VoidJumpHeader(jump_type=ABSOLUTE, target_depth=2, target_arc_id=3)
        Return from jump (close ○3):
            VoidJumpHeader(jump_type=JUMP_BACK, ...)
    """
    MAGIC = b"VOID"

    jump_type:     VoidJumpType = VoidJumpType.RESET
    target_depth:  int          = 0xFF    # 0xFF = current depth (for RESET)
    target_arc_id: int          = 0xFFFF  # 0xFFFF = current arc (for RESET)
    flags:         int          = 0

    FIXED_SIZE = 4 + 1 + 1 + 2 + 2 + 4   # 14 bytes

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.append(int(self.jump_type))
        buf.append(self.target_depth & 0xFF)
        buf.extend(struct.pack('>H', self.target_arc_id))
        buf.extend(struct.pack('>H', self.flags))
        buf.extend(b'\x00' * 4)  # reserved
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'VoidJumpHeader':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"VoidJumpHeader needs {cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Invalid VoidJumpHeader magic: {data[0:4]!r}")
        return cls(
            jump_type     = VoidJumpType(data[4]),
            target_depth  = data[5],
            target_arc_id = struct.unpack('>H', data[6:8])[0],
            flags         = struct.unpack('>H', data[8:10])[0],
        )

    @classmethod
    def reset(cls) -> 'VoidJumpHeader':
        """Factory: ○0 reset — close current circle, return to parent."""
        return cls(jump_type=VoidJumpType.RESET,
                   target_depth=0xFF, target_arc_id=0xFFFF)

    @classmethod
    def jump_to(cls, depth: int, arc_id: int,
                save_context: bool = True) -> 'VoidJumpHeader':
        """Factory: ABSOLUTE jump to (depth, arc_id)."""
        flags = VoidFlags.SAVE_CONTEXT if save_context else 0
        return cls(jump_type=VoidJumpType.ABSOLUTE,
                   target_depth=depth, target_arc_id=arc_id, flags=flags)

    @classmethod
    def jump_back(cls) -> 'VoidJumpHeader':
        """Factory: return from last ABSOLUTE jump."""
        return cls(jump_type=VoidJumpType.JUMP_BACK,
                   target_depth=0xFF, target_arc_id=0xFFFF)


class VoidFlags:
    """Bitmask for VoidJumpHeader.flags."""
    SAVE_CONTEXT   = 0x0001  # Save QRVM context before jumping (Warm Switch)
    HARD_RESET     = 0x0002  # On RESET: flush all state, not just close circle
    BROADCAST      = 0x0004  # Apply jump to all parallel QRVM instances
    CONDITIONAL    = 0x0008  # Jump only if FLAGS register condition is met


# ═══════════════════════════════════════════════════════════════
# BONE BLOCK HEADER — Technorganic structural scaffold prefix
# Prefixes the actual structural data of a BONE block.
# BONE blocks are pinned — QRVM cannot evict them while dependents live.
# ═══════════════════════════════════════════════════════════════

@dataclass
class BoneBlockHeader:
    """
    Header prefix for a BONE (0x0B) block.
    The structural scaffold that other blocks attach to via REQUIRES edges.

    Key architectural constraint: BONE blocks are pinned in the RAM Cache
    as long as any other block holds a REQUIRES edge pointing to them.
    QRVM enforces this. MO (Memory Orchestrator) checks pin_count before
    eviction. If pin_count > 0, eviction is rejected — not deferred, rejected.

    BONE is not a frozen state (ICE). It is a structural role.
    ICE says "I am finished." BONE says "I am the frame; build on me."

    Wire format (20 bytes):
        magic          : bytes  (4 bytes) — b"BONE"
        bone_version   : uint16 (2 bytes) — structure version
        pin_count      : uint32 (4 bytes) — live REQUIRES edges pointing here
                                            Updated at runtime by QRVM.
                                            Encoded value is snapshot at seal.
        flags          : uint16 (2 bytes) — BoneFlags bitmask
        technorganic_profile_len : uint16 (2 bytes) — length of profile bytes
        reserved       : bytes  (4 bytes) — zero-filled
        [technorganic_profile]   — variable, UTF-8 JSON or binary descriptor
    """
    MAGIC = b"BONE"

    bone_version:              int   = 1
    pin_count:                 int   = 0     # live REQUIRES edges at seal time
    flags:                     int   = 0
    technorganic_profile:      bytes = b''   # Technorganic descriptor payload

    FIXED_SIZE = 4 + 2 + 4 + 2 + 2 + 4  # 18 bytes + profile

    @property
    def profile_len(self) -> int:
        return len(self.technorganic_profile)

    @property
    def is_pinned(self) -> bool:
        """True if live dependents exist. MO must not evict."""
        return self.pin_count > 0

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.extend(struct.pack('>H', self.bone_version))
        buf.extend(struct.pack('>I', self.pin_count))
        buf.extend(struct.pack('>H', self.flags))
        buf.extend(struct.pack('>H', self.profile_len))
        buf.extend(b'\x00' * 4)  # reserved
        buf.extend(self.technorganic_profile)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> Tuple['BoneBlockHeader', int]:
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"BoneBlockHeader needs >={cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Invalid BoneBlockHeader magic: {data[0:4]!r}")
        bone_ver  = struct.unpack('>H', data[4:6])[0]
        pin_count = struct.unpack('>I', data[6:10])[0]
        flags     = struct.unpack('>H', data[10:12])[0]
        prof_len  = struct.unpack('>H', data[12:14])[0]
        # bytes 14-17 reserved
        profile   = data[18:18+prof_len]
        consumed  = 18 + prof_len
        return cls(bone_version=bone_ver, pin_count=pin_count,
                   flags=flags, technorganic_profile=profile), consumed


class BoneFlags:
    """Bitmask for BoneBlockHeader.flags."""
    TECHNORGANIC    = 0x0001  # Is a Technorganic biological-synthetic hybrid
    SYNTHETIC_ONLY  = 0x0002  # Pure synthetic skeleton, no biological component
    BIOLOGICAL_ONLY = 0x0004  # Pure biological structure
    LOAD_BEARING    = 0x0008  # Removing this BONE collapses dependent structure
    GROWTH_ANCHOR   = 0x0010  # TREE branches may grow from this BONE


# ═══════════════════════════════════════════════════════════════
# CRYSTAL LATTICE HEADER — repeating network structure prefix
# Distinguishes CRYSTAL from ICE at the decoder level.
# ICE: unique snapshot, no outgoing edges.
# CRYSTAL: lattice node, many cross-reference edges.
# ═══════════════════════════════════════════════════════════════

@dataclass
class CrystalLatticeHeader:
    """
    Header prefix for a CRYSTAL (0x0D) block.
    The gemstone lattice — regular, repeating, networked.

    Contrast with ICE (0x02):
        ICE     = snowflake. Unique. No outgoing deps. STRICT normalization.
                  This specific frozen moment, preserved exactly.
        CRYSTAL = gemstone. Regular repeating lattice. Many cross-refs.
                  STRUCTURED normalization — the pattern is what matters,
                  not the specific order of equivalent nodes.

    The lattice_degree field is the semantic stress marker.
    ICE lattice_degree = 0 (no outgoing connections).
    CRYSTAL lattice_degree >= 1 (it IS the connections).

    Wire format (20 bytes):
        magic           : bytes  (4 bytes) — b"XTAL"
        crystal_version : uint16 (2 bytes) — lattice spec version
        lattice_degree  : uint32 (4 bytes) — number of cross-reference edges
                                             (the "valence" of this lattice node)
        flags           : uint16 (2 bytes) — CrystalFlags bitmask
        reserved        : bytes  (8 bytes) — zero-filled, future lattice params
    """
    MAGIC = b"XTAL"

    crystal_version: int = 1
    lattice_degree:  int = 0   # 0 = not yet connected (being formed)
    flags:           int = 0

    FIXED_SIZE = 4 + 2 + 4 + 2 + 8  # 20 bytes

    @property
    def is_lattice_node(self) -> bool:
        """True if this CRYSTAL has established cross-reference connections."""
        return self.lattice_degree >= 1

    @property
    def valence(self) -> int:
        """Chemical metaphor: how many bonds does this crystal node have?"""
        return self.lattice_degree

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.extend(struct.pack('>H', self.crystal_version))
        buf.extend(struct.pack('>I', self.lattice_degree))
        buf.extend(struct.pack('>H', self.flags))
        buf.extend(b'\x00' * 8)  # reserved
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'CrystalLatticeHeader':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"CrystalLatticeHeader needs {cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Invalid CrystalLatticeHeader magic: {data[0:4]!r}")
        return cls(
            crystal_version = struct.unpack('>H', data[4:6])[0],
            lattice_degree  = struct.unpack('>I', data[6:10])[0],
            flags           = struct.unpack('>H', data[10:12])[0],
        )


class CrystalFlags:
    """Bitmask for CrystalLatticeHeader.flags."""
    HUB_LATTICE      = 0x0001  # Part of HUB mutual data binding network
    CROSS_QREN       = 0x0002  # Has cross-QRenCode EXTERNAL_REQ edges
    SEALED_LATTICE   = 0x0004  # Lattice is complete — no new edges permitted
    EIDOS_BOUND      = 0x0008  # Bound to an Eidos identity node
    SYNC_REQUIRED    = 0x0010  # Needs HUB synchronization pass


# ═══════════════════════════════════════════════════════════════
# CACHE LINE + RAM CACHE BLOCK (unchanged from earlier — included
# for completeness so this file is self-contained)
# ═══════════════════════════════════════════════════════════════

@dataclass
class CacheLine:
    """
    Single hot-path cache entry.
    Ghost detection: valid=False, dirty=True = orphaned write (VI Builder
    Ghost Process). BONE blocks get special treatment: is_pinned=True
    entries are excluded from eviction_candidates() regardless of policy.
    """
    address_tag:        bytes = field(default_factory=lambda: b'\x00'*32)
    valid:              bool  = True
    dirty:              bool  = False
    access_count:       int   = 0
    is_pinned:          bool  = False   # True for BONE block cache lines
    block_type:         int   = BlockType.AMORPHOUS  # wire code of cached block
    compressed_payload: bytes = b''

    FIXED_SIZE = 32 + 1 + 1 + 4 + 1 + 1 + 4  # 44 bytes

    @property
    def payload_len(self) -> int:
        return len(self.compressed_payload)

    @property
    def is_ghost(self) -> bool:
        """VI Builder Ghost Process: orphaned write, needs dRC repair."""
        return not self.valid and self.dirty

    @property
    def is_evictable(self) -> bool:
        """
        MO eviction check. Three reasons a line is NOT evictable:
        1. dirty  — needs flush first
        2. is_ghost — needs dRC repair first
        3. is_pinned — BONE block, has live dependents
        """
        return not self.dirty and not self.is_ghost and not self.is_pinned

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.address_tag[:32])
        buf.append(1 if self.valid else 0)
        buf.append(1 if self.dirty else 0)
        buf.extend(struct.pack('>I', self.access_count))
        buf.append(1 if self.is_pinned else 0)
        buf.append(int(self.block_type) & 0xFF)
        buf.extend(struct.pack('>I', self.payload_len))
        buf.extend(self.compressed_payload)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> Tuple['CacheLine', int]:
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"CacheLine needs >={cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        pos = 0
        addr    = data[pos:pos+32]; pos += 32
        valid   = bool(data[pos]);   pos += 1
        dirty   = bool(data[pos]);   pos += 1
        acnt    = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        pinned  = bool(data[pos]);   pos += 1
        btype   = data[pos];         pos += 1
        plen    = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        payload = data[pos:pos+plen]; pos += plen
        return cls(address_tag=addr, valid=valid, dirty=dirty,
                   access_count=acnt, is_pinned=pinned,
                   block_type=btype, compressed_payload=payload), pos


@dataclass
class RAMCacheBlock:
    """
    Encoded RAM Cache structure (Build Tracker v3 §5.1).
    dRAM Tier 3: portable, serialized, rehydratable.
    1 GB physical → 64 GB encoded → 100 GB equivalent workspace per unit.
    Scales linearly. Lazy expansion. Deterministic across machines.

    MTL/MO separation:
        promotion_threshold = MTL advice (when to promote)
        eviction_policy     = MO action strategy (how to evict)
    BONE cache lines are always excluded from eviction candidates.
    """
    MAGIC = b"RCCH"

    version:              int             = 1
    page_size:            int             = 4096
    line_count:           int             = 0
    associativity:        int             = 4
    eviction_policy:      EvictionPolicy  = EvictionPolicy.LRU
    promotion_threshold:  int             = 100
    cache_lines:          List[CacheLine] = field(default_factory=list)

    FIXED_HEADER_SIZE = 4 + 4 + 8 + 8 + 2 + 1 + 1 + 8 + 8  # 44 bytes

    @property
    def preload_count(self) -> int:
        return len(self.cache_lines)

    @property
    def ghost_lines(self) -> List[CacheLine]:
        return [cl for cl in self.cache_lines if cl.is_ghost]

    @property
    def pinned_lines(self) -> List[CacheLine]:
        return [cl for cl in self.cache_lines if cl.is_pinned]

    @property
    def has_ghosts(self) -> bool:
        return bool(self.ghost_lines)

    def eviction_candidates(self,
                             policy: Optional[EvictionPolicy] = None
                             ) -> List[CacheLine]:
        """
        MO: return evictable lines in priority order.
        Pinned (BONE), dirty, and ghost lines are never candidates.
        """
        p = policy or self.eviction_policy
        candidates = [cl for cl in self.cache_lines if cl.is_evictable]
        if p == EvictionPolicy.ARC:
            if not candidates:
                return []
            median = sorted(
                cl.access_count for cl in candidates
            )[len(candidates) // 2]
            lower = [cl for cl in candidates if cl.access_count <= median]
            return sorted(lower, key=lambda cl: cl.access_count)
        return sorted(candidates, key=lambda cl: cl.access_count)

    def should_promote(self, line: CacheLine) -> bool:
        """MTL advice: has this line earned promotion to persistent storage?"""
        return line.access_count >= self.promotion_threshold

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.extend(struct.pack('>I', self.version))
        buf.extend(struct.pack('>Q', self.page_size))
        buf.extend(struct.pack('>Q', self.line_count))
        buf.extend(struct.pack('>H', self.associativity))
        buf.append(int(self.eviction_policy))
        buf.append(0x00)
        buf.extend(struct.pack('>Q', self.promotion_threshold))
        buf.extend(struct.pack('>Q', self.preload_count))
        for line in self.cache_lines:
            buf.extend(line.pack())
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'RAMCacheBlock':
        if len(data) < cls.FIXED_HEADER_SIZE:
            raise QRenFormatError(
                f"RAMCacheBlock needs >={cls.FIXED_HEADER_SIZE} bytes"
            )
        pos = 0
        if data[pos:pos+4] != cls.MAGIC:
            raise QRenFormatError(f"Bad RAMCacheBlock magic")
        pos += 4
        ver    = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        pgsz   = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        lncnt  = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        assoc  = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
        evict  = EvictionPolicy(data[pos]);                pos += 1
        pos   += 1  # reserved
        promo  = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        pcount = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        lines = []
        for _ in range(pcount):
            line, consumed = CacheLine.unpack(data[pos:])
            lines.append(line)
            pos += consumed
        return cls(version=ver, page_size=pgsz, line_count=lncnt,
                   associativity=assoc, eviction_policy=evict,
                   promotion_threshold=promo, cache_lines=lines)

    @classmethod
    def create_empty(cls, page_size: int = 4096, associativity: int = 4,
                     line_count: int = 16384,
                     policy: EvictionPolicy = EvictionPolicy.LRU,
                     promotion_threshold: int = 100) -> 'RAMCacheBlock':
        """Factory: dRAM Pull phase — allocate working memory before simulation."""
        return cls(page_size=page_size, line_count=line_count,
                   associativity=associativity, eviction_policy=policy,
                   promotion_threshold=promotion_threshold, cache_lines=[])


# ═══════════════════════════════════════════════════════════════
# NESTED QREN HEADER (unchanged from previous iteration)
# ═══════════════════════════════════════════════════════════════

@dataclass
class NestedQRenHeader:
    """NESTED (0x08) block prefix — complete inner QRenCode."""
    MAGIC = b"NQRC"

    depth:               int          = 0
    bracket_type:        BracketType  = BracketType.SQUARE
    arc_id:              int          = 0
    flags:               int          = 0
    inner_qrcf_len:      int          = 0
    inner_manifest_hash: bytes        = field(default_factory=lambda: b'\x00'*32)

    FIXED_SIZE = 4 + 1 + 1 + 2 + 1 + 3 + 8 + 32  # 52 bytes

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.append(self.depth & 0xFF)
        buf.append(int(self.bracket_type) & 0xFF)
        buf.extend(struct.pack('>H', self.arc_id))
        buf.append(self.flags & 0xFF)
        buf.extend(b'\x00\x00\x00')
        buf.extend(struct.pack('>Q', self.inner_qrcf_len))
        buf.extend(self.inner_manifest_hash[:32])
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'NestedQRenHeader':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"NestedQRenHeader needs {cls.FIXED_SIZE} bytes"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Bad NestedQRenHeader magic: {data[0:4]!r}")
        return cls(
            depth              = data[4],
            bracket_type       = BracketType(data[5]),
            arc_id             = struct.unpack('>H', data[6:8])[0],
            flags              = data[8],
            inner_qrcf_len     = struct.unpack('>Q', data[12:20])[0],
            inner_manifest_hash= data[20:52],
        )


class NestedFlags:
    HAS_PNG       = 0x01
    EXECUTABLE    = 0x02
    HAS_RAM_CACHE = 0x04
    BOOT_CAPABLE  = 0x08
    SHARED_CACHE  = 0x10
    SEALED        = 0x20


# ═══════════════════════════════════════════════════════════════
# UTILITY — full block type reference table
# ═══════════════════════════════════════════════════════════════

BLOCK_TYPE_REFERENCE = {
    BlockType.TREE:      {'phase':1, 'norm':'SEMANTIC',    'comp':'T2+T3',   'pinned':False, 'opcode':False, 'analog':'WorldSeed organism'},
    BlockType.ICE:       {'phase':1, 'norm':'STRICT',      'comp':'T3+T5',   'pinned':False, 'opcode':False, 'analog':'Crystal Slime B — unique snowflake snapshot'},
    BlockType.FLAME:     {'phase':1, 'norm':'STRICT',      'comp':'T2',      'pinned':False, 'opcode':True,  'analog':'QRVM bytecode'},
    BlockType.LIGHTNING: {'phase':1, 'norm':'STRICT',      'comp':'T2 AOT',  'pinned':False, 'opcode':True,  'analog':'QRVM AOT fast-path'},
    BlockType.FRACTAL:   {'phase':1, 'norm':'STRICT',      'comp':'T4+T2',   'pinned':False, 'opcode':False, 'analog':'AI/ML weights, self-similar'},
    BlockType.GEOMETRIC: {'phase':1, 'norm':'STRUCTURED',  'comp':'T2',      'pinned':False, 'opcode':False, 'analog':'Cal\'s Castle grammar, invariants'},
    BlockType.AMORPHOUS: {'phase':1, 'norm':'LOOSE',       'comp':'T2+T5',   'pinned':False, 'opcode':False, 'analog':'Crystal Slime A — mutable'},
    BlockType.NESTED:    {'phase':2, 'norm':'BINARY',      'comp':'T2',      'pinned':False, 'opcode':False, 'analog':'Full QRenCode-within-QRenCode'},
    BlockType.RUNIC:     {'phase':2, 'norm':'STRICT',      'comp':'T2',      'pinned':False, 'opcode':True,  'analog':'Runic script → interpreter'},
    BlockType.MYCELIUM:  {'phase':2, 'norm':'SEMANTIC',    'comp':'T5',      'pinned':False, 'opcode':False, 'analog':'Peer-network graph, distributed root-web'},
    BlockType.BONE:      {'phase':2, 'norm':'BINARY',      'comp':'T2',      'pinned':True,  'opcode':False, 'analog':'Technorganic structural scaffold'},
    BlockType.VOID:      {'phase':2, 'norm':'STRICT',      'comp':'T0',      'pinned':False, 'opcode':True,  'analog':'QRVM circle-level jump instruction'},
    BlockType.CRYSTAL:   {'phase':2, 'norm':'STRUCTURED',  'comp':'T5',      'pinned':False, 'opcode':False, 'analog':'Gemstone lattice — repeating network'},
}


# ═══════════════════════════════════════════════════════════════
# SELF-TEST
# Run: python qrcf_types_phase2.py
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    print("=" * 60)
    print("  QRCF Phase 2 Type Extensions — Self-Test")
    print("=" * 60)

    # 1. BlockType registry completeness
    assert len([bt for bt in BlockType if bt != BlockType.CUSTOM]) == 13
    assert BlockType.BONE    == 0x0B
    assert BlockType.VOID    == 0x0C
    assert BlockType.CRYSTAL == 0x0D
    print("  [PASS] BlockType registry — 13 named types + CUSTOM")

    # 2. ICE vs CRYSTAL semantic distinction
    assert BLOCK_NORMALIZATION[BlockType.ICE]     == NormalizationProfile.STRICT
    assert BLOCK_NORMALIZATION[BlockType.CRYSTAL] == NormalizationProfile.STRUCTURED
    assert BLOCK_COMPRESSION[BlockType.ICE]       == CompressionTier.T3_DELTA
    assert BLOCK_COMPRESSION[BlockType.CRYSTAL]   == CompressionTier.T5_DEDUP
    # ICE: no outgoing edges
    assert verify_ice_contract('abc', []) is True
    assert verify_ice_contract('abc', [{'from':'abc','edge_type':1}]) is False
    # CRYSTAL: must have outgoing edges
    xtal_line = CrystalLatticeHeader(lattice_degree=3)
    assert xtal_line.is_lattice_node
    assert xtal_line.valence == 3
    print("  [PASS] ICE vs CRYSTAL semantic distinction — stress marker encoded")

    # 3. CrystalLatticeHeader round-trip
    ch = CrystalLatticeHeader(crystal_version=1, lattice_degree=7,
                               flags=CrystalFlags.HUB_LATTICE)
    packed = ch.pack()
    assert len(packed) == CrystalLatticeHeader.FIXED_SIZE
    ch2 = CrystalLatticeHeader.unpack(packed)
    assert ch2.lattice_degree == 7
    assert ch2.flags & CrystalFlags.HUB_LATTICE
    print(f"  [PASS] CrystalLatticeHeader round-trip ({len(packed)} bytes)")

    # 4. VoidJumpHeader — RESET (○0)
    vj = VoidJumpHeader.reset()
    packed = vj.pack()
    assert len(packed) == VoidJumpHeader.FIXED_SIZE  # 14 bytes — tiny
    vj2 = VoidJumpHeader.unpack(packed)
    assert vj2.jump_type == VoidJumpType.RESET
    assert vj2.target_depth == 0xFF
    print(f"  [PASS] VoidJumpHeader RESET (○0) round-trip ({len(packed)} bytes)")

    # 5. VoidJumpHeader — ABSOLUTE jump
    vj3 = VoidJumpHeader.jump_to(depth=2, arc_id=5, save_context=True)
    packed3 = vj3.pack()
    vj4 = VoidJumpHeader.unpack(packed3)
    assert vj4.jump_type == VoidJumpType.ABSOLUTE
    assert vj4.target_depth == 2
    assert vj4.target_arc_id == 5
    assert vj4.flags & VoidFlags.SAVE_CONTEXT
    print("  [PASS] VoidJumpHeader ABSOLUTE jump (depth=2, arc_id=5)")

    # 6. VoidJumpHeader — JUMP_BACK
    jb = VoidJumpHeader.jump_back()
    packed_jb = jb.pack()
    jb2 = VoidJumpHeader.unpack(packed_jb)
    assert jb2.jump_type == VoidJumpType.JUMP_BACK
    print("  [PASS] VoidJumpHeader JUMP_BACK (return from saved context)")

    # 7. BoneBlockHeader round-trip
    profile = b'{"type":"technorganic","load_bearing":true}'
    bh = BoneBlockHeader(pin_count=3,
                          flags=BoneFlags.TECHNORGANIC | BoneFlags.LOAD_BEARING,
                          technorganic_profile=profile)
    packed = bh.pack()
    bh2, consumed = BoneBlockHeader.unpack(packed)
    assert bh2.pin_count == 3
    assert bh2.is_pinned
    assert bh2.flags & BoneFlags.LOAD_BEARING
    assert bh2.technorganic_profile == profile
    print(f"  [PASS] BoneBlockHeader round-trip ({len(packed)} bytes, pinned=True)")

    # 8. BONE cache line pinning in RAMCacheBlock
    bone_line = CacheLine(address_tag=b'\xBB'*32, valid=True, dirty=False,
                          is_pinned=True, block_type=BlockType.BONE,
                          access_count=1, compressed_payload=b'scaffold')
    normal_line = CacheLine(address_tag=b'\xCC'*32, valid=True, dirty=False,
                             is_pinned=False, block_type=BlockType.AMORPHOUS,
                             access_count=1, compressed_payload=b'data')
    rcb = RAMCacheBlock.create_empty()
    rcb.cache_lines.extend([bone_line, normal_line])
    candidates = rcb.eviction_candidates()
    assert len(candidates) == 1              # only normal_line is evictable
    assert candidates[0].block_type == BlockType.AMORPHOUS
    assert len(rcb.pinned_lines) == 1
    print("  [PASS] BONE pinning in RAMCacheBlock — excluded from eviction")

    # 9. NestedQRenHeader (unchanged)
    nh = NestedQRenHeader(depth=3, bracket_type=BracketType.PAREN,
                          arc_id=7, inner_qrcf_len=2048,
                          inner_manifest_hash=b'\xAA'*32)
    packed = nh.pack()
    nh2 = NestedQRenHeader.unpack(packed)
    assert nh2.depth == 3
    assert nh2.bracket_type == BracketType.PAREN
    assert nh2.arc_id == 7
    print(f"  [PASS] NestedQRenHeader round-trip ({len(packed)} bytes)")

    # 10. Reference table completeness
    for bt in BlockType:
        if bt == BlockType.CUSTOM:
            continue
        assert bt in BLOCK_TYPE_REFERENCE, f"Missing reference: {bt}"
        assert bt in BLOCK_NORMALIZATION,   f"Missing normalization: {bt}"
        assert bt in BLOCK_COMPRESSION,     f"Missing compression: {bt}"
    print(f"  [PASS] All 13 types in reference, normalization, and compression tables")

    # 11. VOID and BONE are opcodes/pinned correctly flagged
    assert BLOCK_IS_OPCODE[BlockType.VOID]
    assert not BLOCK_IS_OPCODE[BlockType.BONE]
    assert BLOCK_IS_PINNED[BlockType.BONE]
    assert not BLOCK_IS_PINNED[BlockType.VOID]
    assert BLOCK_IS_EXECUTABLE[BlockType.RUNIC]
    assert BLOCK_IS_EXECUTABLE[BlockType.FLAME]
    print("  [PASS] QRVM routing flags — opcode/pinned/executable correct")

    print()
    print("  All Phase 2 type extension self-tests passed.")
    print("=" * 60)
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════
# TYPE HEADER REGISTRY
# ═══════════════════════════════════════════════════════════════
#
# Which block types carry a per-type header, and which class parses it.
# One mapping, consulted by both encoder and decoder, so the two cannot
# disagree about what a given type's frame looks like.

TYPE_HEADERS = {
    BlockType.VOID:    VoidJumpHeader,
    BlockType.BONE:    BoneBlockHeader,
    BlockType.CRYSTAL: CrystalLatticeHeader,
    BlockType.NESTED:  NestedQRenHeader,
}


def unpack_type_header(block_type, data: bytes):
    """Parse a per-type header, returning (header, bytes_consumed).

    The four header classes do not share a signature — BoneBlockHeader is
    variable-length and returns (header, consumed), the other three are fixed
    and return the header alone. Normalising that here means callers never
    have to know which is which, which is exactly the kind of per-class
    special case that goes wrong once a fifth type appears.
    """
    cls = TYPE_HEADERS.get(block_type)
    if cls is None:
        return None, 0
    result = cls.unpack(data)
    if isinstance(result, tuple):
        return result                      # (header, consumed)
    return result, cls.FIXED_SIZE


def pack_type_header(header) -> bytes:
    """Serialise a per-type header. Present for symmetry with unpack, so both
    directions are reached through this module rather than one being open-coded
    at the call site."""
    return header.pack() if header is not None else b""
