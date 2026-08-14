"""
QRCF Circle Rule Inheritance System
=====================================
Each Block is its own QRen Matrix.
Higher Circle rules apply to Lower Circles.
Rules propagate DOWN the chain, never UP.
Rules are scoped to their Circle Chain — siblings do not share rules.

This module implements:
  - CircleRuleSet   : declared rule set at a Circle level (wire format)
  - RuleChainResolver: resolves effective rules at any depth in a chain
  - BlockMatrixView  : treats any block as its own QRen Matrix
  - QRMatrixSpec     : Version 40 QR generation spec (big AF)

Rule Inheritance Model
----------------------
Think of it like scoped variable declarations in a programming language.
Or ArGlyph scope in Runic — a rule declared inside ○ ... ○0 applies
within that circle and all circles it contains. It does not escape upward.

    Circle 0 (host top-level):
        declares: default_compression = T2_ZSTD
                  ec_level = H
                  max_nesting_depth = 16

    Circle 1 (translation layer):
        inherits: T2_ZSTD, H, depth=16
        overrides: max_nesting_depth = 8  (tighter scope for this chain)

    Circle 2 (structural layer):
        inherits: T2_ZSTD, H, depth=8
        (no overrides — uses inherited rules entirely)

    Circle 3+ (data blocks):
        Each block MAY declare its own rule set for its sub-chain.
        A NESTED block at Circle 3 creates a new sub-chain with depth reset.
        A BONE block at Circle 3 declares pinning rules for its dependents.

The decoder resolves rules by walking UP the chain from the current block
to Circle 0, collecting the innermost (most specific) rule for each field.
This is O(depth) — bounded by max_nesting_depth.

Compression benefit:
    A block in Circle 5 of a chain that declared T4_FRACTAL at Circle 1
    does not need to re-encode its compression tier — the rule is inherited.
    Block headers in deep circles can omit inherited fields (use 0xFF
    as "inherit from parent" sentinel for all rule fields).

This module has ZERO external dependencies beyond Python stdlib.
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Dict, Any, Tuple

from .qrcf_types import (
    CompressionTier, NormalizationProfile,
    QRenFormatError,
)
from .qrcf_types_phase2 import BlockType, EvictionPolicy


# ═══════════════════════════════════════════════════════════════
# CONSTANTS — sentinel values for "inherit from parent"
# ═══════════════════════════════════════════════════════════════

INHERIT = 0xFF          # Single-byte sentinel: inherit this field from parent
INHERIT_U16 = 0xFFFF    # Two-byte sentinel
INHERIT_U32 = 0xFFFFFFFF


# ═══════════════════════════════════════════════════════════════
# QR MATRIX SPEC — Version 40, big AF
# ═══════════════════════════════════════════════════════════════

class QRVersion(IntEnum):
    """QR code version. Each version adds 4 modules per side."""
    V1   = 1    # 21×21   modules — minimal
    V10  = 10   # 57×57   modules
    V20  = 20   # 97×97   modules
    V30  = 30   # 137×137 modules
    V40  = 40   # 177×177 modules — MAXIMUM (big AF)

class QRECLevel(IntEnum):
    """QR error correction level."""
    L = 0x00   # ~7%  recovery — max data capacity
    M = 0x01   # ~15% recovery
    Q = 0x02   # ~25% recovery
    H = 0x03   # ~30% recovery — QRCF spec: Circle 0 uses H

# QR Version 40 capacities (binary mode, bytes)
QR_V40_CAPACITY = {
    QRECLevel.L: 2953,
    QRECLevel.M: 2331,
    QRECLevel.Q: 1663,
    QRECLevel.H: 1273,
}

# Circle 0 bootstrap payload = 86 bytes. With EC-H and V40 we have
# 1273 - 86 = 1187 bytes of remaining Circle 0 capacity for future use
# (boot manifest hash, additional pointers, etc.)
CIRCLE_0_BOOTSTRAP_SIZE = 86
CIRCLE_0_SPARE_CAPACITY_V40_H = QR_V40_CAPACITY[QRECLevel.H] - CIRCLE_0_BOOTSTRAP_SIZE


@dataclass
class QRMatrixSpec:
    """
    Specification for generating a QRen Matrix QR code.

    For QRen Coder production output: always Version 40, EC-H.
    The magic circle visual wraps around a 177×177 module QR.
    That gives the outer Futhark ring, middle Greek ring, and
    intermediate zone the full canvas they need.

    For nested inner QRenCodes: Version may be smaller depending
    on inner payload size. The encoder selects minimum sufficient
    version automatically unless override is set.

    Wire format (8 bytes — stored in Circle 1 translation layer):
        qr_version    : uint8  (1 byte)  — 1-40, 0=auto-select
        ec_level      : uint8  (1 byte)  — QRECLevel enum
        box_size_px   : uint16 (2 bytes) — pixels per module (for render)
        border_modules: uint8  (1 byte)  — quiet zone size in modules (min 4)
        flags         : uint8  (1 byte)  — QRMatrixFlags
        reserved      : bytes  (2 bytes) — zero-filled
    """
    qr_version:     int         = 0             # 0 = auto-select minimum
    ec_level:       QRECLevel   = QRECLevel.H   # Always H for QRCF spec
    box_size_px:    int         = 4             # pixels per QR module
    border_modules: int         = 4             # quiet zone (spec minimum = 4)
    flags:          int         = 0

    FIXED_SIZE = 1 + 1 + 2 + 1 + 1 + 2   # 8 bytes

    @property
    def module_count(self) -> int:
        """Width/height in modules for a given version."""
        v = self.qr_version if self.qr_version > 0 else 40
        return 21 + (v - 1) * 4

    @property
    def pixel_size(self) -> int:
        """Total image size in pixels including border."""
        return (self.module_count + 2 * self.border_modules) * self.box_size_px

    @property
    def data_capacity_bytes(self) -> int:
        """Usable data bytes in Circle 0 QR payload."""
        v = self.qr_version if self.qr_version > 0 else 40
        # Simplified capacity formula (binary mode, EC-H)
        # Real implementation uses qrcode library's version table
        if v == 40: return QR_V40_CAPACITY[self.ec_level]
        # Approximate: capacity scales roughly as v^2 * 0.27 for EC-H
        return max(17, int(v * v * 0.27))

    def pack(self) -> bytes:
        buf = bytearray()
        buf.append(self.qr_version & 0xFF)
        buf.append(int(self.ec_level) & 0xFF)
        buf.extend(struct.pack('>H', self.box_size_px))
        buf.append(self.border_modules & 0xFF)
        buf.append(self.flags & 0xFF)
        buf.extend(b'\x00\x00')
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'QRMatrixSpec':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(f"QRMatrixSpec needs {cls.FIXED_SIZE} bytes")
        return cls(
            qr_version     = data[0],
            ec_level       = QRECLevel(data[1]),
            box_size_px    = struct.unpack('>H', data[2:4])[0],
            border_modules = data[4],
            flags          = data[5],
        )

    @classmethod
    def production(cls) -> 'QRMatrixSpec':
        """
        Production QRen Matrix spec: Version 40, EC-H, 4px/module.
        177×177 modules + 4-module quiet zone each side.
        Total: (177 + 8) × 4 = 740px square minimum.
        This is the big AF QR code.
        """
        return cls(qr_version=40, ec_level=QRECLevel.H,
                   box_size_px=4, border_modules=4)

    @classmethod
    def nested(cls, inner_payload_size: int) -> 'QRMatrixSpec':
        """
        Auto-select minimum QR version for a nested inner QRenCode.
        Uses EC-H for integrity. Smallest version that fits.
        """
        for v in range(1, 41):
            spec = cls(qr_version=v, ec_level=QRECLevel.H)
            if spec.data_capacity_bytes >= inner_payload_size:
                return spec
        return cls.production()  # fallback: use V40


class QRMatrixFlags:
    """Bitmask for QRMatrixSpec.flags."""
    AUTO_VERSION    = 0x01  # Select minimum sufficient version automatically
    FORCE_V40       = 0x02  # Always use Version 40 regardless of payload size
    MAGIC_CIRCLE    = 0x04  # Render magic circle visual overlay around QR
    EMBED_RUNES     = 0x08  # Place Futhark/Greek runes in outer/inner rings
    HIGH_DPI        = 0x10  # 10px/module instead of 4px (higher resolution)


# ═══════════════════════════════════════════════════════════════
# CIRCLE RULE SET — declared rules at a Circle level
# ═══════════════════════════════════════════════════════════════

@dataclass
class CircleRuleSet:
    """
    A rule set declared at a specific Circle level in a QRen Matrix.
    Rules propagate DOWN the chain to all lower Circles reachable
    from this one. Rules do NOT propagate UP or sideways.

    This is the encoding of the ArGlyph scope rule:
        ○ (rules declared here apply inside ○ ... ○0)
        ○0 — rules end here, do not escape

    Sentinel values (INHERIT / INHERIT_U16 / INHERIT_U32) mean
    "use the value inherited from the parent Circle." The decoder
    resolves the effective value by walking UP the chain.

    Wire format (32 bytes fixed):
        magic                : bytes  (4 bytes)  — b"CRLS"
        ruleset_version      : uint8  (1 byte)   — version of this struct
        declaring_depth      : uint8  (1 byte)   — Circle depth that owns this
        chain_id             : uint16 (2 bytes)  — chain identifier (0=root)
        default_compression  : uint8  (1 byte)   — CompressionTier or INHERIT
        default_normalization: uint8  (1 byte)   — NormalizationProfile or INHERIT
        ec_level             : uint8  (1 byte)   — QRECLevel or INHERIT
        eviction_policy      : uint8  (1 byte)   — EvictionPolicy or INHERIT
        max_nesting_depth    : uint8  (1 byte)   — max ○ nesting or INHERIT
        growth_space_pct     : uint8  (1 byte)   — 0-100 or INHERIT
        qrvm_permissions     : uint16 (2 bytes)  — QRVMPermissions bitmask
        promotion_threshold  : uint32 (4 bytes)  — cache line promote or INHERIT
        flags                : uint16 (2 bytes)  — CircleRuleFlags
        reserved             : bytes  (8 bytes)  — zero-filled
    Total: 4+1+1+2+1+1+1+1+1+1+2+4+2+8 = 30... pad to 32.
    """
    MAGIC = b"CRLS"

    ruleset_version:       int = 1
    declaring_depth:       int = 0         # which Circle level owns this
    chain_id:              int = 0         # 0 = root chain
    default_compression:   int = INHERIT   # CompressionTier or INHERIT
    default_normalization: int = INHERIT   # NormalizationProfile or INHERIT
    ec_level:              int = INHERIT   # QRECLevel or INHERIT
    eviction_policy:       int = INHERIT   # EvictionPolicy or INHERIT
    max_nesting_depth:     int = INHERIT   # max ArCircle depth or INHERIT
    growth_space_pct:      int = INHERIT   # 0-100 or INHERIT
    qrvm_permissions:      int = INHERIT_U16  # QRVMPermissions or INHERIT
    promotion_threshold:   int = INHERIT_U32  # cache threshold or INHERIT
    flags:                 int = 0

    FIXED_SIZE = 32

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)                                       # 4
        buf.append(self.ruleset_version & 0xFF)                      # 1
        buf.append(self.declaring_depth & 0xFF)                      # 1
        buf.extend(struct.pack('>H', self.chain_id))                 # 2
        buf.append(self.default_compression & 0xFF)                  # 1
        buf.append(self.default_normalization & 0xFF)                # 1
        buf.append(self.ec_level & 0xFF)                             # 1
        buf.append(self.eviction_policy & 0xFF)                      # 1
        buf.append(self.max_nesting_depth & 0xFF)                    # 1
        buf.append(self.growth_space_pct & 0xFF)                     # 1
        buf.extend(struct.pack('>H', self.qrvm_permissions))         # 2
        buf.extend(struct.pack('>I', self.promotion_threshold))      # 4
        buf.extend(struct.pack('>H', self.flags))                    # 2
        # 10 reserved, not 8. The fields above total 22 bytes and
        # FIXED_SIZE is 32, declared in three places and used by unpack's
        # length guard; 8 made pack() produce 30 and fail its own assert
        # on the very first call. The module's __main__ self-test asserts
        # this exact equality — it had simply never been run, because
        # nothing imported this module.
        buf.extend(b'\x00' * 10)                                     # 10 reserved
        assert len(buf) == self.FIXED_SIZE, (
            f"CircleRuleSet packed {len(buf)} bytes, FIXED_SIZE is "
            f"{self.FIXED_SIZE}")
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'CircleRuleSet':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"CircleRuleSet needs {cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Bad CircleRuleSet magic: {data[0:4]!r}")
        return cls(
            ruleset_version       = data[4],
            declaring_depth       = data[5],
            chain_id              = struct.unpack('>H', data[6:8])[0],
            default_compression   = data[8],
            default_normalization = data[9],
            ec_level              = data[10],
            eviction_policy       = data[11],
            max_nesting_depth     = data[12],
            growth_space_pct      = data[13],
            qrvm_permissions      = struct.unpack('>H', data[14:16])[0],
            promotion_threshold   = struct.unpack('>I', data[16:20])[0],
            flags                 = struct.unpack('>H', data[20:22])[0],
        )

    # ── Factories ─────────────────────────────────────────────

    @classmethod
    def root(cls) -> 'CircleRuleSet':
        """
        Root rule set — Circle 0 defaults for a production QRen Matrix.
        Every rule is explicitly declared here. No INHERIT at root level.
        Lower circles may override any of these values.
        """
        return cls(
            declaring_depth       = 0,
            chain_id              = 0,
            default_compression   = CompressionTier.T2_ZSTD,
            default_normalization = NormalizationProfile.SEMANTIC,
            ec_level              = QRECLevel.H,
            eviction_policy       = EvictionPolicy.LRU,
            max_nesting_depth     = 16,
            growth_space_pct      = 15,
            qrvm_permissions      = QRVMPermissions.STANDARD,
            promotion_threshold   = 100,
        )

    @classmethod
    def for_depth(cls, depth: int, **overrides) -> 'CircleRuleSet':
        """
        Declare a rule set at a specific Circle depth.
        Only supply fields you want to override — rest will be INHERIT.
        """
        rs = cls(declaring_depth=depth)
        for k, v in overrides.items():
            setattr(rs, k, v)
        return rs


class CircleRuleFlags:
    """Bitmask for CircleRuleSet.flags."""
    SEALED          = 0x0001  # No lower circle may override these rules
    PROPAGATE_ONLY  = 0x0002  # This rule set only propagates, not declarative
    CHAIN_BOUNDARY  = 0x0004  # This depth is a chain boundary — sub-chains
                               # created below here start fresh rule inheritance
    BOOT_RULES      = 0x0008  # Rules apply to QRen-Boot execution context
    QRVM_RULES      = 0x0010  # Rules apply to QRVM execution context


class QRVMPermissions:
    """Bitmask for QRVM execution permissions within a Circle chain."""
    NONE            = 0x0000  # No execution permitted
    READ_DATA       = 0x0001  # Can read data blocks
    EXECUTE_FLAME   = 0x0002  # Can execute FLAME bytecode
    EXECUTE_LIGHT   = 0x0004  # Can execute LIGHTNING AOT
    EXECUTE_RUNIC   = 0x0008  # Can run Runic interpreter
    VOID_JUMPS      = 0x0010  # Can execute VOID jump instructions
    NEST_CREATE     = 0x0020  # Can create new NESTED sub-chains
    CACHE_PROMOTE   = 0x0040  # Can promote cache lines to persistent
    BONE_MODIFY     = 0x0080  # Can attach to / detach from BONE blocks
    BOOT_ACCESS     = 0x0100  # Can access QRen-Boot layer
    STANDARD        = (READ_DATA | EXECUTE_FLAME | EXECUTE_LIGHT |
                       VOID_JUMPS | NEST_CREATE | CACHE_PROMOTE)
    FULL            = 0xFFFF


# ═══════════════════════════════════════════════════════════════
# RULE CHAIN RESOLVER — effective rule lookup at any depth
# ═══════════════════════════════════════════════════════════════

class RuleChainResolver:
    """
    Resolves the effective value of any rule at a given Circle depth,
    following the downward inheritance model.

    Usage:
        resolver = RuleChainResolver()
        resolver.push(CircleRuleSet.root())          # Circle 0
        resolver.push(CircleRuleSet.for_depth(1,
            default_compression=CompressionTier.T4_FRACTAL))
        resolver.push(CircleRuleSet.for_depth(2))    # all inherited

        # At depth 2, compression = T4_FRACTAL (inherited from depth 1)
        comp = resolver.effective_compression()

    The resolver maintains an ordered stack of rule sets from highest
    (outermost, Circle 0) to lowest (current depth). Resolution walks
    from bottom to top, stopping at the first non-INHERIT value.

    Rule inheritance is per-field. A rule set at depth 3 can override
    just ec_level while inheriting everything else from depth 0.

    SEALED rules (CircleRuleFlags.SEALED) cannot be overridden by
    lower circles — the resolver enforces this.

    Chain boundaries (CircleRuleFlags.CHAIN_BOUNDARY): when a NESTED
    block is opened, the resolver creates a new sub-resolver with a
    fresh root inherited from the NESTED block's declared rules.
    The parent chain's rules do not automatically apply inside the
    NESTED block — the NESTED block is a new QRen Matrix with its
    own Circle 0.
    """

    def __init__(self):
        self._chain: List[CircleRuleSet] = []

    def push(self, ruleset: CircleRuleSet) -> 'RuleChainResolver':
        """Add a rule set at a new depth level. Returns self for chaining."""
        self._chain.append(ruleset)
        return self

    def pop(self) -> Optional[CircleRuleSet]:
        """○0 — close current circle, return to parent context."""
        return self._chain.pop() if self._chain else None

    def current_depth(self) -> int:
        return len(self._chain) - 1

    def _resolve(self, field: str, inherit_sentinel) -> Any:
        """
        Walk from innermost (current) to outermost (Circle 0).
        Return first non-INHERIT value found.

        SEALED rule sets: if the field is sealed at depth D, values
        declared at depth > D are ignored for that field.
        """
        # TWO passes, and the order is the whole correctness of SEALED.
        #
        # This used to be one pass walking innermost -> outermost, setting
        # sealed_at when it reached the sealing rule set. That can never work:
        # the declaration that seals a field is always OUTWARD of the override
        # it is meant to block, so the walk returned the deeper value and
        # exited before it ever saw the seal. SEALED silently did nothing.
        #
        # Pass 1 finds the shallowest depth that seals this field; pass 2
        # resolves while ignoring anything declared deeper than that.
        sealed_at: Optional[int] = None
        for rs in self._chain:                      # outermost -> innermost
            val = getattr(rs, field, inherit_sentinel)
            if rs.flags & CircleRuleFlags.SEALED and val != inherit_sentinel:
                sealed_at = rs.declaring_depth
                break                               # the shallowest seal wins

        for rs in reversed(self._chain):            # innermost -> outermost
            if sealed_at is not None and rs.declaring_depth > sealed_at:
                continue                            # deeper than the seal: ignored
            val = getattr(rs, field, inherit_sentinel)
            if val != inherit_sentinel:
                return val

        return inherit_sentinel  # no rule found — caller uses hardcoded default

    # ── Resolved rule accessors ───────────────────────────────

    def effective_compression(self) -> CompressionTier:
        v = self._resolve('default_compression', INHERIT)
        return CompressionTier(v) if v != INHERIT else CompressionTier.T2_ZSTD

    def effective_normalization(self) -> NormalizationProfile:
        v = self._resolve('default_normalization', INHERIT)
        return NormalizationProfile(v) if v != INHERIT else NormalizationProfile.SEMANTIC

    def effective_ec_level(self) -> QRECLevel:
        v = self._resolve('ec_level', INHERIT)
        return QRECLevel(v) if v != INHERIT else QRECLevel.H

    def effective_eviction_policy(self) -> EvictionPolicy:
        v = self._resolve('eviction_policy', INHERIT)
        return EvictionPolicy(v) if v != INHERIT else EvictionPolicy.LRU

    def effective_max_nesting_depth(self) -> int:
        v = self._resolve('max_nesting_depth', INHERIT)
        return v if v != INHERIT else 16

    def effective_growth_space_pct(self) -> int:
        v = self._resolve('growth_space_pct', INHERIT)
        return v if v != INHERIT else 15

    def effective_qrvm_permissions(self) -> int:
        v = self._resolve('qrvm_permissions', INHERIT_U16)
        return v if v != INHERIT_U16 else QRVMPermissions.STANDARD

    def effective_promotion_threshold(self) -> int:
        v = self._resolve('promotion_threshold', INHERIT_U32)
        return v if v != INHERIT_U32 else 100

    def effective_qr_matrix_spec(self) -> QRMatrixSpec:
        """
        Build the QRMatrixSpec for this chain's QR generation.
        Production chains always get Version 40 (FORCE_V40 is default).
        Nested chains auto-select minimum sufficient version.
        """
        ec = self.effective_ec_level()
        return QRMatrixSpec(
            qr_version=40,        # big AF — Version 40 always for production
            ec_level=ec,
            box_size_px=4,
            border_modules=4,
            flags=QRMatrixFlags.FORCE_V40 | QRMatrixFlags.MAGIC_CIRCLE |
                  QRMatrixFlags.EMBED_RUNES,
        )

    def effective_all(self) -> Dict[str, Any]:
        """Return all effective rules as a dict. Useful for logging/DataPic."""
        return {
            'compression':        self.effective_compression().name,
            'normalization':      self.effective_normalization().name,
            'ec_level':           self.effective_ec_level().name,
            'eviction_policy':    self.effective_eviction_policy().name,
            'max_nesting_depth':  self.effective_max_nesting_depth(),
            'growth_space_pct':   self.effective_growth_space_pct(),
            'qrvm_permissions':   hex(self.effective_qrvm_permissions()),
            'promotion_threshold':self.effective_promotion_threshold(),
            'current_depth':      self.current_depth(),
            'chain_length':       len(self._chain),
        }

    def fork_nested(self, nested_ruleset: Optional[CircleRuleSet] = None
                    ) -> 'RuleChainResolver':
        """
        Create a new resolver for a NESTED block (new QRen Matrix).
        The nested chain starts FRESH — it is a new QRen Matrix with
        its own Circle 0. Parent chain rules do NOT automatically carry
        over (this is the NESTED block as its own QRen Matrix principle).

        If nested_ruleset is provided, it becomes the root of the
        new chain. Otherwise a fresh default root is used.

        This matches the Runic ○≡○n semantic: opening a named nested
        circle creates a new scope. The parent scope does not bleed in.
        Optionally the nested QRenCode can declare rules that reference
        parent rules via QRVM inter-code communication (SHARED_CACHE).
        """
        child = RuleChainResolver()
        child.push(nested_ruleset or CircleRuleSet.root())
        return child

    def can_go_deeper(self) -> bool:
        """Check if the current depth is within max_nesting_depth."""
        return self.current_depth() < self.effective_max_nesting_depth()

    def depth_signature(self) -> str:
        """
        Human-readable depth signature.
        'C0→C1→C2' means we're at Circle 2 of a 3-level chain.
        Matches the ○ nesting notation in DataPic output.
        """
        return '→'.join(
            f"C{rs.declaring_depth}" for rs in self._chain
        ) or 'C0'


# ═══════════════════════════════════════════════════════════════
# BLOCK MATRIX VIEW — treat any block as its own QRen Matrix
# ═══════════════════════════════════════════════════════════════

@dataclass
class BlockMatrixView:
    """
    A view of any QRCF block as its own mini QRen Matrix.

    Each block has:
        Circle 0 = its BlockHeader (content address = bootstrap hash)
        Circle 1 = its normalization + compression rules (+ inherited)
        Circle 2 = its Runic tags (mini manifest / index)
        Circle 3 = its actual compressed payload (data plane)

    This maps the Block structure onto the Circle architecture exactly.
    A TREE block IS a QRen Matrix. A FRACTAL block IS a QRen Matrix.
    They just happen to be hosted inside a larger QRen Matrix's Circle 3+.

    This is the "each Block can be considered its own QRen Matrix" principle
    made explicit. The BlockMatrixView provides the metadata to treat it that
    way — resolve its effective rules, generate its QR representation, etc.

    The block's content_address (SHA-256) is its Circle 0 bootstrap.
    It's globally unique, content-addressed, and verifiable.
    """
    block_id:     bytes        # 32 bytes, SHA-256 — serves as Circle 0
    block_type:   BlockType
    runic_tags:   List[str]
    data_length:  int
    host_depth:   int          # which Circle of the host contains this block
    resolver:     RuleChainResolver  # the inherited rule chain at this block

    @property
    def circle_0(self) -> str:
        """Circle 0 = content address. The block's unique bootstrap identity."""
        return self.block_id.hex()

    @property
    def circle_1_rules(self) -> Dict[str, Any]:
        """Circle 1 = effective rules for this block's sub-chain."""
        return self.resolver.effective_all()

    @property
    def circle_2_index(self) -> Dict[str, Any]:
        """Circle 2 = mini manifest / Runic index for this block."""
        return {
            'block_id':   self.block_id.hex(),
            'block_type': self.block_type.name,
            'runic_tags': self.runic_tags,
            'host_depth': self.host_depth,
            'data_length':self.data_length,
        }

    @property
    def qr_spec(self) -> QRMatrixSpec:
        """The QR matrix spec for generating this block's QR code."""
        return self.resolver.effective_qr_matrix_spec()

    def describe(self) -> str:
        """One-line description for DataPic / log output."""
        rules = self.circle_1_rules
        return (
            f"Block[{self.block_type.name}] "
            f"depth={self.host_depth} "
            f"id={self.block_id.hex()[:12]}... "
            f"comp={rules['compression']} "
            f"tags={self.runic_tags}"
        )


# ═══════════════════════════════════════════════════════════════
# ENCODER INTEGRATION — produce big AF QR codes correctly
# ═══════════════════════════════════════════════════════════════

def build_qr_version40(payload: bytes, ec_level: QRECLevel = QRECLevel.H) -> bytes:
    """
    Generate a Version 40 QR code PNG from a payload.
    Version 40 = 177×177 modules. This is the big AF production QR.

    If payload exceeds capacity for V40 at the given EC level, raises
    QRenFormatError — Circle 0 payloads must fit in QR bootstrap.
    The XQPE trailer is unbounded (appended after PNG IEND chunk).
    Only Circle 0 (86 bytes) needs to fit in the QR itself.

    Falls back gracefully: zstd → zlib if not available.
    qrcode library required. PIL required. Both optional with fallback.
    """
    capacity = QR_V40_CAPACITY[ec_level]
    if len(payload) > capacity:
        raise QRenFormatError(
            f"Circle 0 payload ({len(payload)} bytes) exceeds V40 "
            f"EC-{ec_level.name} capacity ({capacity} bytes). "
            f"Circle 0 bootstrap is {CIRCLE_0_BOOTSTRAP_SIZE} bytes — "
            f"remaining capacity: {capacity - CIRCLE_0_BOOTSTRAP_SIZE} bytes."
        )

    try:
        import qrcode
        from PIL import Image
        import base64
        import io

        # Map our QRECLevel to qrcode library constants
        ec_map = {
            QRECLevel.L: qrcode.constants.ERROR_CORRECT_L,
            QRECLevel.M: qrcode.constants.ERROR_CORRECT_M,
            QRECLevel.Q: qrcode.constants.ERROR_CORRECT_Q,
            QRECLevel.H: qrcode.constants.ERROR_CORRECT_H,
        }

        qr = qrcode.QRCode(
            version=40,                     # FORCE Version 40 — big AF
            error_correction=ec_map[ec_level],
            box_size=4,                     # 4px per module
            border=4,                       # 4-module quiet zone (spec minimum)
        )
        qr.add_data(base64.b64encode(payload).decode('ascii'))
        qr.make(fit=False)                  # fit=False enforces V40 exactly

        img = qr.make_image(fill_color='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    except ImportError:
        # Fallback: minimal PNG with tEXt chunk (Phase 1 fallback)
        return _minimal_png_fallback(payload)


def _minimal_png_fallback(payload: bytes) -> bytes:
    """Minimal PNG fallback when qrcode/PIL not available."""
    import zlib, struct, base64

    def chunk(t: bytes, d: bytes) -> bytes:
        crc = struct.pack('>I', zlib.crc32(t + d) & 0xFFFFFFFF)
        return struct.pack('>I', len(d)) + t + d + crc

    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
    idat = chunk(b'IDAT', zlib.compress(b'\x00\xff'))
    text = chunk(b'tEXt', b'QRenCode\x00' + base64.b64encode(payload))
    iend = chunk(b'IEND', b'')
    return sig + ihdr + text + idat + iend


def encode_with_rules(data: bytes, resolver: RuleChainResolver,
                      block_type: Optional[BlockType] = None,
                      runic_tags: Optional[List[str]] = None) -> Dict:
    """
    Encode data using a rule chain resolver to determine effective rules.
    Returns the encoding parameters derived from the inherited rule chain.

    This is the bridge between the rule inheritance system and the encoder.
    The encoder calls this to get effective compression/normalization/EC
    for each block instead of using hardcoded defaults.

    Does NOT perform actual encoding — that's QRenEncoder's job.
    Returns a dict of effective parameters ready to pass to QRenEncoder.encode().
    """
    return {
        'compression':         resolver.effective_compression(),
        'normalization':       resolver.effective_normalization(),
        'qr_matrix_spec':      resolver.effective_qr_matrix_spec(),
        'growth_space_pct':    resolver.effective_growth_space_pct(),
        'promotion_threshold': resolver.effective_promotion_threshold(),
        'qrvm_permissions':    resolver.effective_qrvm_permissions(),
        'block_type':          block_type,
        'runic_tags':          runic_tags or [],
        'depth_signature':     resolver.depth_signature(),
        'max_depth':           resolver.effective_max_nesting_depth(),
        'can_go_deeper':       resolver.can_go_deeper(),
    }


# ═══════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    print("=" * 65)
    print("  QRCF Circle Rule Inheritance + QR Matrix Spec — Self-Test")
    print("=" * 65)

    # 1. QRMatrixSpec — Version 40 production spec
    spec = QRMatrixSpec.production()
    assert spec.qr_version    == 40
    assert spec.ec_level      == QRECLevel.H
    assert spec.module_count  == 177           # 21 + 39×4 = 177
    assert spec.data_capacity_bytes == 1273    # V40/H
    assert spec.pixel_size    == (177 + 8) * 4 # 740px
    assert spec.data_capacity_bytes >= CIRCLE_0_BOOTSTRAP_SIZE
    spare = spec.data_capacity_bytes - CIRCLE_0_BOOTSTRAP_SIZE
    print(f"  [PASS] QRMatrixSpec V40/H: 177×177 modules, 740px, "
          f"{spare}B spare in Circle 0")

    # 2. QRMatrixSpec auto-select for nested
    small_spec = QRMatrixSpec.nested(50)
    assert small_spec.qr_version < 40   # small payload, small version
    print(f"  [PASS] QRMatrixSpec nested auto-select: V{small_spec.qr_version} "
          f"for 50-byte inner payload")

    # 3. CircleRuleSet pack/unpack round-trip
    rs = CircleRuleSet.root()
    packed = rs.pack()
    assert len(packed) == CircleRuleSet.FIXED_SIZE
    rs2 = CircleRuleSet.unpack(packed)
    assert rs2.default_compression == CompressionTier.T2_ZSTD
    assert rs2.ec_level == QRECLevel.H
    assert rs2.max_nesting_depth == 16
    print(f"  [PASS] CircleRuleSet root round-trip ({len(packed)} bytes)")

    # 4. Rule inheritance — override propagates down, not up
    resolver = RuleChainResolver()
    resolver.push(CircleRuleSet.root())   # C0: T2_ZSTD, EC-H, depth=16

    # C1 overrides compression to T4_FRACTAL
    resolver.push(CircleRuleSet.for_depth(1,
        default_compression=CompressionTier.T4_FRACTAL))

    # C2 inherits everything from C1 (no overrides)
    resolver.push(CircleRuleSet.for_depth(2))

    assert resolver.effective_compression() == CompressionTier.T4_FRACTAL
    assert resolver.effective_ec_level() == QRECLevel.H   # from C0
    assert resolver.effective_max_nesting_depth() == 16   # from C0
    assert resolver.current_depth() == 2
    print("  [PASS] Rule inheritance: T4_FRACTAL at C1 propagates to C2")

    # 5. Pop back to C1, rule still T4_FRACTAL
    resolver.pop()  # ○0 — close C2
    assert resolver.current_depth() == 1
    assert resolver.effective_compression() == CompressionTier.T4_FRACTAL
    print("  [PASS] After ○0 pop: back at C1, rules preserved correctly")

    # 6. SEALED rule — cannot be overridden by deeper circles
    resolver2 = RuleChainResolver()
    sealed_root = CircleRuleSet.root()
    sealed_root.ec_level = QRECLevel.H
    sealed_root.flags = CircleRuleFlags.SEALED
    resolver2.push(sealed_root)
    # Try to override ec_level at C1 — should be blocked
    resolver2.push(CircleRuleSet.for_depth(1, ec_level=QRECLevel.L))
    # Because root is SEALED, the C1 override is ignored
    assert resolver2.effective_ec_level() == QRECLevel.H
    print("  [PASS] SEALED rule at C0 blocks override at C1")

    # 7. Fork nested — new chain, fresh rules (parent does not bleed in)
    child_resolver = resolver.fork_nested()
    # Child chain starts at C0 with default root rules
    # The parent's T4_FRACTAL compression does NOT carry over
    assert child_resolver.effective_compression() == CompressionTier.T2_ZSTD
    assert child_resolver.current_depth() == 0
    print("  [PASS] Fork nested: child chain isolated from parent (new QRen Matrix)")

    # 8. can_go_deeper check
    deep = RuleChainResolver()
    deep.push(CircleRuleSet.for_depth(0, max_nesting_depth=3))
    for i in range(1, 4):
        assert deep.can_go_deeper()
        deep.push(CircleRuleSet.for_depth(i))
    assert not deep.can_go_deeper()  # at max depth 3
    print("  [PASS] can_go_deeper: depth limit enforced (max=3)")

    # 9. BlockMatrixView — each block is its own QRen Matrix
    import os
    test_id = os.urandom(32)
    view = BlockMatrixView(
        block_id=test_id, block_type=BlockType.FRACTAL,
        runic_tags=['ᚨᚱᛇ', 'ml-weights'],
        data_length=1024, host_depth=3, resolver=resolver
    )
    assert view.circle_0 == test_id.hex()
    assert 'FRACTAL' in view.circle_2_index['block_type']
    assert view.qr_spec.qr_version == 40
    print(f"  [PASS] BlockMatrixView: FRACTAL block at depth=3 "
          f"is its own QRen Matrix (V40/H)")

    # 10. encode_with_rules integration
    params = encode_with_rules(b'test data', resolver,
                               block_type=BlockType.TREE,
                               runic_tags=['ᛇᛚᛜ'])
    assert params['compression'] == CompressionTier.T4_FRACTAL  # inherited
    assert params['qr_matrix_spec'].qr_version == 40
    assert params['block_type'] == BlockType.TREE
    print("  [PASS] encode_with_rules: inherited T4_FRACTAL, V40 QR spec")

    # 11. Depth signature readability
    assert '→' in resolver.depth_signature()
    print(f"  [PASS] Depth signature: '{resolver.depth_signature()}'")

    print()
    print("  All Circle Rule Inheritance tests passed.")
    print(f"  Production QR matrix: 177×177 modules, "
          f"{QRMatrixSpec.production().pixel_size}px, EC-H")
    print("=" * 65)
    sys.exit(0)
