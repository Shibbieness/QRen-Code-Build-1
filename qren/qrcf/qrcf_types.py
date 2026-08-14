"""
QRCF Types & Constants — QRenCode Container Format v1
======================================================

Foundational type definitions, constants, enumerations, and error classes
for the QRenCode system. This module has ZERO external dependencies beyond
the Python standard library.

STATUS: PHASE 1 FROZEN. Wire format locked. 15/15 tests verified.
This is the canonical qrcf_types.py as verified in the original build session.

This is NOT CodexOmega. This is QRenCode — a standalone system.

Wire format spec: sub-skills/core-encoder/a_skill.md
Block type spec:  sub-skills/block-types/e_skill.md
"""

import struct
import hashlib
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional, Any


# ═══════════════════════════════════════════════════════════════
# MAGIC BYTES & VERSION
# ═══════════════════════════════════════════════════════════════

QREN_MAGIC = b"QREN"
XQPE_MAGIC = b"XQPE\xAB\xCD\x00\x01"
QRCF_VERSION_MAJOR = 1
QRCF_VERSION_MINOR = 0
QRCF_VERSION = (QRCF_VERSION_MAJOR << 8) | QRCF_VERSION_MINOR  # 0x0100
MIN_TRAILER_SIZE = 32 + 44 + 32


# ═══════════════════════════════════════════════════════════════
# BLOCK TYPES
# ═══════════════════════════════════════════════════════════════

class BlockType(IntEnum):
    """Seven canonical Phase 1 block types + Phase 2 extensions + custom."""
    TREE        = 0x01  # Structured hierarchies, branching growth
    ICE         = 0x02  # Frozen, crystallized stable data (Snowflake)
    FLAME       = 0x03  # Transient, executable, consumable logic
    LIGHTNING   = 0x04  # Fast-path, deterministic execution
    FRACTAL     = 0x05  # Self-similar, recursive (AI/ML)
    GEOMETRIC   = 0x06  # Regular, predictable layouts
    AMORPHOUS   = 0x07  # Free-form, evolving user data (Slime)
    # Phase 2 additions
    NESTED      = 0x08  # QRenCode-within-QRenCode
    RUNIC       = 0x09  # Pure Runic script payload
    MYCELIUM    = 0x0A  # Distributed peer-network complement to TREE
    BONE        = 0x0B  # Structural scaffold, pinned, QRVM-tracked
    VOID        = 0x0C  # Non-linear traversal primitive (QRVM opcodes)
    CRYSTAL     = 0x0D  # Repeating lattice, bonded by dependency edges
    # Declared in block_types.py since its introduction but missing here,
    # which made it classifiable and NOT encodable — and an archive
    # carrying 0x0E would have been silently dropped by every decoder.
    LIGHT       = 0x0E  # Self-describing navigation: index, glossary, routing table
    CUSTOM      = 0xFF  # User-defined


# ═══════════════════════════════════════════════════════════════
# COMPRESSION TIERS
# ═══════════════════════════════════════════════════════════════

class CompressionTier(IntEnum):
    T0_NONE     = 0x00  # No compression (VOID opcodes, small metadata)
    T1_LZ4      = 0x01  # Fast-access (Circles 1 and 2 always use T1)
    T2_ZSTD     = 0x02  # General storage (default for data blocks)
    T3_DELTA    = 0x03  # Versioned blocks — stub → T2 in Phase 1
    T4_FRACTAL  = 0x04  # Self-similar / ML weights — stub → T2 in Phase 1
    T5_DEDUP    = 0x05  # Cross-block global CAS dedup — stub → T2 in Phase 1


# ═══════════════════════════════════════════════════════════════
# NORMALIZATION PROFILES
# ═══════════════════════════════════════════════════════════════

class NormalizationProfile(IntEnum):
    STRICT      = 0x00  # Every byte matters (code, models, bytecode)
    SEMANTIC    = 0x01  # Whitespace normalized, order canonicalized
    STRUCTURED  = 0x02  # Schema-aware ordering (config, manifests)
    LOOSE       = 0x03  # Whitespace ignored (user notes, free-form)
    BINARY      = 0x04  # No normalization (raw bytes, NESTED, BONE)


# Default normalization per block type (code-confirmed)
BLOCK_NORMALIZATION = {
    BlockType.TREE:      NormalizationProfile.SEMANTIC,
    BlockType.ICE:       NormalizationProfile.STRICT,
    BlockType.FLAME:     NormalizationProfile.STRICT,
    BlockType.LIGHTNING: NormalizationProfile.STRICT,
    BlockType.FRACTAL:   NormalizationProfile.STRICT,
    BlockType.GEOMETRIC: NormalizationProfile.STRUCTURED,
    BlockType.AMORPHOUS: NormalizationProfile.LOOSE,
    BlockType.NESTED:    NormalizationProfile.BINARY,
    BlockType.RUNIC:     NormalizationProfile.STRICT,
    BlockType.MYCELIUM:  NormalizationProfile.SEMANTIC,
    BlockType.BONE:      NormalizationProfile.BINARY,
    BlockType.VOID:      NormalizationProfile.STRICT,
    BlockType.CRYSTAL:   NormalizationProfile.STRUCTURED,
    # An index or routing table is schema-ordered content, same as CRYSTAL.
    BlockType.LIGHT:     NormalizationProfile.STRUCTURED,
    BlockType.CUSTOM:    NormalizationProfile.BINARY,
}


# ═══════════════════════════════════════════════════════════════
# DEPENDENCY EDGE TYPES (Runic DSL)
# ═══════════════════════════════════════════════════════════════

class EdgeType(IntEnum):
    """Runic dependency edge types. Wire codes for Circle 2 dependency_graph."""
    REQUIRES     = 0x01  # ᚱ (Raidho)  — block A depends on block B
    CALLS        = 0x02  # ᚲ (Kenaz)   — block A invokes block B (execution)
    CONTAINS     = 0x03  # ᚨ (Ansuz)   — block A is composed of block B
    DERIVED_FROM = 0x04  # ᚹ (Wunjo)   — block A lineage from block B
    CONTEXTUAL   = 0x05  # ᚾ (Naudiz)  — block A is environment of block B
    EXTERNAL_REQ = 0x06  # ᚱ-EXT       — cross-QRenCode requires


# ═══════════════════════════════════════════════════════════════
# FLAGS
# ═══════════════════════════════════════════════════════════════

class QRCFFlags:
    """Bitmask flags for QRCF trailer flags field (uint32)."""
    INTEGRITY_MERKLE   = 0x0001
    INTEGRITY_SIGNED   = 0x0002
    BOOT_CAPABLE       = 0x0004
    HAS_RAM_CACHE      = 0x0008
    HAS_EXECUTABLE     = 0x0010
    HAS_VERSION_GRAPH  = 0x0020
    GROWTH_RESERVED    = 0x0040


class BlockHeaderFlags:
    """Bitmask flags for BlockHeader flags byte (uint8)."""
    NADA_PROTECTED = 0x01  # Survival-protected — no auto-delete, two-step release
    SUSPENDED      = 0x02  # Block in suspended state (sleeping, not deleted)
    GHOST          = 0x04  # Source removed, block still usable (Ghost BONE)
    RESERVED       = 0x08  # Zero, future use
    # A per-type header (VoidJump / Bone / CrystalLattice / NestedQRen)
    # sits at the front of the data region, uncompressed, and is counted
    # INSIDE data_length. Keeping it inside means the block frame is
    # still FIXED_SIZE + tag_len + data_length, so a decoder that does
    # not know this type skips exactly the right number of bytes and
    # lands on the next block — see _extract_data_blocks.
    HAS_TYPE_HEADER = 0x10


# ═══════════════════════════════════════════════════════════════
# WIRE FORMAT DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

@dataclass
class SectionEntry:
    """
    XQPE Section Directory entry. 52 bytes. FROZEN.
    Points to one Circle's data within the trailer.

    Wire format (52 bytes):
        circle_id : uint32  (4 bytes)
        offset    : uint64  (8 bytes) — from trailer start
        length    : uint64  (8 bytes)
        hash      : bytes   (32 bytes) — SHA-256 of circle data
    """
    circle_id: int
    offset: int
    length: int
    hash: bytes  # 32 bytes SHA-256

    PACKED_SIZE = 4 + 8 + 8 + 32  # 52 bytes

    def pack(self) -> bytes:
        return (
            struct.pack('>I', self.circle_id)
            + struct.pack('>Q', self.offset)
            + struct.pack('>Q', self.length)
            + self.hash
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'SectionEntry':
        if len(data) < cls.PACKED_SIZE:
            raise QRenFormatError(
                f"SectionEntry needs {cls.PACKED_SIZE} bytes, got {len(data)}"
            )
        circle_id = struct.unpack('>I', data[0:4])[0]
        offset    = struct.unpack('>Q', data[4:12])[0]
        length    = struct.unpack('>Q', data[12:20])[0]
        hash_b    = data[20:52]
        return cls(circle_id=circle_id, offset=offset, length=length, hash=hash_b)


@dataclass
class BlockHeader:
    """
    Header for an individual data block within a Circle. 48+ bytes. FROZEN.

    Wire format (variable, minimum 48 bytes):
        block_id        : bytes  (32 bytes) — SHA-256 content address of RAW data
        block_type      : uint8  (1 byte)
        normalization   : uint8  (1 byte)
        compression     : uint8  (1 byte)
        flags           : uint8  (1 byte)
        data_length     : uint64 (8 bytes) — length of COMPRESSED data following header
        runic_tag_count : uint16 (2 bytes) — byte length of runic tags
        reserved        : bytes  (2 bytes)
        [runic_tags]    : variable — null-separated UTF-8 strings
    """
    block_id: bytes
    block_type: BlockType
    normalization: NormalizationProfile
    compression: CompressionTier
    flags: int               # Block-level flags (BlockHeaderFlags bitmask)
    data_length: int         # Length of COMPRESSED data following header
    runic_tags: List[str] = field(default_factory=list)

    FIXED_SIZE = 32 + 1 + 1 + 1 + 1 + 8 + 2 + 2  # 48 bytes

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.block_id)
        buf.append(int(self.block_type))
        buf.append(int(self.normalization))
        buf.append(int(self.compression))
        buf.append(self.flags & 0xFF)
        buf.extend(struct.pack('>Q', self.data_length))
        # Encode runic tags as null-separated UTF-8
        tag_data = b'\x00'.join(
            t.encode('utf-8') for t in self.runic_tags
        ) if self.runic_tags else b''
        buf.extend(struct.pack('>H', len(tag_data)))
        buf.extend(b'\x00\x00')  # reserved
        buf.extend(tag_data)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes):
        """
        Deserialize block header.
        Returns (BlockHeader, bytes_consumed).
        bytes_consumed includes the fixed header + tag bytes.
        """
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"BlockHeader needs >={cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        pos = 0
        block_id = data[pos:pos+32]; pos += 32
        block_type = BlockType(data[pos]); pos += 1
        norm = NormalizationProfile(data[pos]); pos += 1
        comp = CompressionTier(data[pos]); pos += 1
        flags = data[pos]; pos += 1
        data_length = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        tag_len = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
        pos += 2  # reserved
        tags = []
        if tag_len > 0:
            tag_bytes = data[pos:pos+tag_len]
            tags = [t.decode('utf-8') for t in tag_bytes.split(b'\x00') if t]
            pos += tag_len
        header = cls(
            block_id=block_id, block_type=block_type, normalization=norm,
            compression=comp, flags=flags, data_length=data_length,
            runic_tags=tags
        )
        return header, pos


@dataclass
class TrailerHeader:
    """
    QRCF Trailer header. 36 bytes. FROZEN.

    Wire format (36 bytes):
        magic       : bytes  (8 bytes) — XQPE_MAGIC
        version     : uint16 (2 bytes)
        trailer_len : uint64 (8 bytes) — total trailer length
        offset_c1   : uint64 (8 bytes) — offset to Circle 1 from trailer start
        num_circles : uint32 (4 bytes)
        flags       : uint32 (4 bytes)
        reserved    : bytes  (2 bytes)
    """
    version: int
    trailer_len: int
    offset_c1: int
    num_circles: int
    flags: int

    PACKED_SIZE = 8 + 2 + 8 + 8 + 4 + 4 + 2  # 36 bytes

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(XQPE_MAGIC)
        buf.extend(struct.pack('>H', self.version))
        buf.extend(struct.pack('>Q', self.trailer_len))
        buf.extend(struct.pack('>Q', self.offset_c1))
        buf.extend(struct.pack('>I', self.num_circles))
        buf.extend(struct.pack('>I', self.flags))
        buf.extend(b'\x00\x00')  # reserved
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'TrailerHeader':
        if len(data) < cls.PACKED_SIZE:
            raise QRenFormatError(
                f"TrailerHeader needs {cls.PACKED_SIZE} bytes, got {len(data)}"
            )
        magic = data[0:8]
        if magic != XQPE_MAGIC:
            raise QRenFormatError(f"Invalid XQPE magic: {magic!r}")
        version     = struct.unpack('>H', data[8:10])[0]
        trailer_len = struct.unpack('>Q', data[10:18])[0]
        offset_c1   = struct.unpack('>Q', data[18:26])[0]
        num_circles = struct.unpack('>I', data[26:30])[0]
        flags       = struct.unpack('>I', data[30:34])[0]
        return cls(version=version, trailer_len=trailer_len, offset_c1=offset_c1,
                   num_circles=num_circles, flags=flags)


@dataclass
class IntegrityBlock:
    """
    QRCF Integrity Block. 72+ bytes. FROZEN.

    Wire format:
        magic        : bytes  (4 bytes) — b'INTG'
        version      : uint16 (2 bytes)
        merkle_root  : bytes  (32 bytes) — Merkle root over all section hashes
        userseed_hash: bytes  (32 bytes) — SHA-256 of UserSeed (zeros in Phase 1)
        sig_len      : uint16 (2 bytes)
        signature    : bytes  (variable)
    """
    MAGIC = b'INTG'
    FIXED_SIZE = 4 + 2 + 32 + 32 + 2  # 72 bytes

    merkle_root: bytes = field(default_factory=lambda: b'\x00' * 32)
    userseed_hash: bytes = field(default_factory=lambda: b'\x00' * 32)
    signature: bytes = b''

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)
        buf.extend(struct.pack('>H', QRCF_VERSION))
        buf.extend(self.merkle_root)
        buf.extend(self.userseed_hash)
        buf.extend(struct.pack('>H', len(self.signature)))
        buf.extend(self.signature)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'IntegrityBlock':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(
                f"IntegrityBlock needs >={cls.FIXED_SIZE} bytes, got {len(data)}"
            )
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Invalid integrity magic: {data[0:4]!r}")
        merkle   = data[6:38]
        userseed = data[38:70]
        sig_len  = struct.unpack('>H', data[70:72])[0]
        sig      = data[72:72+sig_len] if sig_len > 0 else b''
        return cls(merkle_root=merkle, userseed_hash=userseed, signature=sig)


# ═══════════════════════════════════════════════════════════════
# ERROR CLASSES
# ═══════════════════════════════════════════════════════════════

class QRenError(Exception):
    """Base error for all QRenCode operations."""

class QRenFormatError(QRenError):
    """XQPE/QRCF structural or parsing error."""

class QRenIntegrityError(QRenError):
    """Checksum, hash, or signature verification failure."""

class QRenCompressionError(QRenError):
    """Compression or decompression failure."""

class QRenBlockError(QRenError):
    """Block-level encoding or decoding error."""


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def content_address(data: bytes) -> bytes:
    """SHA-256 content address (CAS). Identity of a block. Returns 32 bytes."""
    return hashlib.sha256(data).digest()

def content_address_hex(data: bytes) -> str:
    """SHA-256 content address as hex string."""
    return hashlib.sha256(data).hexdigest()

def merkle_root(hashes: List[bytes]) -> bytes:
    """
    Compute Merkle root from a list of 32-byte SHA-256 hashes.
    Empty → 32 zero bytes. Single → that hash. Multiple → tree.
    """
    if not hashes:
        return b'\x00' * 32
    if len(hashes) == 1:
        return hashes[0]
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # Pad odd count by duplicating last
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(hashlib.sha256(layer[i] + layer[i+1]).digest())
        layer = next_layer
    return layer[0]

def auto_detect_block_type(data: bytes, filename: str = "") -> 'BlockType':
    """
    Auto-detect block type from content and filename.
    Extension check first, then content sniffing.
    Default: AMORPHOUS (entropy is unknown — per spec).
    """
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext in ('py', 'js', 'ts', 'rs', 'c', 'cpp', 'h', 'java', 'go', 'rb', 'sh'):
        return BlockType.TREE
    if ext in ('pt', 'pth', 'h5', 'hdf5', 'onnx', 'pb', 'tflite', 'safetensors'):
        return BlockType.FRACTAL
    if ext in ('json', 'yaml', 'yml', 'toml', 'xml', 'xsd', 'proto'):
        return BlockType.GEOMETRIC
    if ext in ('iso', 'img', 'exe', 'elf', 'wasm', 'bin'):
        return BlockType.FLAME
    if ext in ('lock', 'sum', 'checksum'):
        return BlockType.ICE

    try:
        text = data[:1024].decode('utf-8', errors='strict')
        if any(kw in text for kw in ('def ', 'function ', 'class ', 'import ', '#include')):
            return BlockType.TREE
        if text.lstrip().startswith(('{', '[')):
            return BlockType.GEOMETRIC
    except (UnicodeDecodeError, ValueError):
        pass

    return BlockType.AMORPHOUS

def compute_growth_space(data_len: int, growth_pct: int = 15) -> int:
    """Compute growth space size. Maximum of 64 bytes or percentage of data."""
    return max(64, int(data_len * growth_pct / 100))
