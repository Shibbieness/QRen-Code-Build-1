"""
QRCF Types & Constants — QRenCode Container Format v1
======================================================

Foundational type definitions, constants, enumerations, and error classes
for the QRenCode system. This module has ZERO external dependencies beyond
the Python standard library.

Specification Authority:
  - QRCF v1 Container Format (Improvements & Mod Specs doc)
  - XQPE Section Directory (64-bit offsets)
  - Block Type Codes (QRen_Coder_Build_Gameplan)
  - Compression Tiers T0-T5 (Improvements doc)
  - Normalization Profiles (QRe_System.txt)

This is NOT CodexOmega. This is QRenCode — a standalone system.
"""

import struct
import hashlib
from enum import IntEnum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

# ═══════════════════════════════════════════════════════════════
# MAGIC BYTES & VERSION
# ═══════════════════════════════════════════════════════════════

# Circle 0 QR payload magic (4 bytes, in the QR data itself)
QREN_MAGIC = b"QREN"

# XQPE trailer magic (8 bytes, at start of appended binary region)
XQPE_MAGIC = b"XQPE\xAB\xCD\x00\x01"

# Current format version
QRCF_VERSION_MAJOR = 1
QRCF_VERSION_MINOR = 0
QRCF_VERSION = (QRCF_VERSION_MAJOR << 8) | QRCF_VERSION_MINOR  # 0x0100

# Minimum valid trailer size: magic(8) + trailer_len(8) + offset_C1(8) +
# num_circles(4) + flags(4) + at least 1 section entry + integrity
MIN_TRAILER_SIZE = 32 + 44 + 32  # header + 1 SectionEntry + min integrity


# ═══════════════════════════════════════════════════════════════
# BLOCK TYPES (from QRen spec, byte codes locked)
# ═══════════════════════════════════════════════════════════════

class BlockType(IntEnum):
    """Seven canonical block types + custom."""
    TREE        = 0x01  # Structured hierarchies, branching growth
    ICE         = 0x02  # Frozen, crystallized stable data (Snowflake)
    FLAME       = 0x03  # Transient, executable, consumable logic
    LIGHTNING   = 0x04  # Fast-path, deterministic execution
    FRACTAL     = 0x05  # Self-similar, recursive (AI/ML)
    GEOMETRIC   = 0x06  # Regular, predictable layouts
    AMORPHOUS   = 0x07  # Free-form, evolving user data (Slime)
    CUSTOM      = 0xFF  # User-defined


# ═══════════════════════════════════════════════════════════════
# COMPRESSION TIERS (T0-T5, from Improvements doc)
# ═══════════════════════════════════════════════════════════════

class CompressionTier(IntEnum):
    """Tiered compression model. Blocks may be multi-tier encoded."""
    T0_NONE     = 0x00  # No compression (small metadata)
    T1_LZ4      = 0x01  # Fast-access data
    T2_ZSTD     = 0x02  # General storage (default)
    T3_DELTA    = 0x03  # Versioned blocks (delta from base)
    T4_FRACTAL  = 0x04  # Self-similar / ML weights
    T5_DEDUP    = 0x05  # Cross-block global CAS deduplication


# ═══════════════════════════════════════════════════════════════
# NORMALIZATION PROFILES (from QRe_System.txt)
# ═══════════════════════════════════════════════════════════════

class NormalizationProfile(IntEnum):
    """Normalization tied to block type, hierarchical."""
    STRICT      = 0x00  # Every byte matters (code, models)
    SEMANTIC    = 0x01  # Whitespace normalized (text archives)
    STRUCTURED  = 0x02  # Ordering canonicalized
    LOOSE       = 0x03  # Whitespace ignored (user notes)
    BINARY      = 0x04  # No normalization whatsoever


# Default normalization per block type
BLOCK_NORMALIZATION = {
    BlockType.TREE:      NormalizationProfile.SEMANTIC,
    BlockType.ICE:       NormalizationProfile.STRICT,
    BlockType.FLAME:     NormalizationProfile.STRICT,
    BlockType.LIGHTNING:  NormalizationProfile.STRICT,
    BlockType.FRACTAL:   NormalizationProfile.STRICT,
    BlockType.GEOMETRIC: NormalizationProfile.STRUCTURED,
    BlockType.AMORPHOUS: NormalizationProfile.LOOSE,
    BlockType.CUSTOM:    NormalizationProfile.BINARY,
}


# ═══════════════════════════════════════════════════════════════
# DEPENDENCY EDGE TYPES (Runic DSL, from QRe_System.txt)
# ═══════════════════════════════════════════════════════════════

class EdgeType(IntEnum):
    """Runic dependency edge types."""
    REQUIRES     = 0x01  # ᚱ (Raidho)  — dependency
    CALLS        = 0x02  # ᚲ (Kenaz)   — execution invocation
    CONTAINS     = 0x03  # ᚨ (Ansuz)   — composition
    DERIVED_FROM = 0x04  # ᚹ (Wunjo)   — lineage
    CONTEXTUAL   = 0x05  # ᚾ (Naudiz)  — environment
    EXTERNAL_REQ = 0x06  # ᚱ-EXT       — cross-QRenCode requires


# ═══════════════════════════════════════════════════════════════
# FLAGS (QRCF trailer flags field)
# ═══════════════════════════════════════════════════════════════

class QRCFFlags:
    """Bitmask flags for the QRCF trailer flags field (uint32)."""
    INTEGRITY_MERKLE   = 0x0001  # Has Merkle root integrity
    INTEGRITY_SIGNED   = 0x0002  # Has UserSeed signature
    BOOT_CAPABLE       = 0x0004  # QRen-Boot enabled
    HAS_RAM_CACHE      = 0x0008  # Contains RAM Cache blocks
    HAS_EXECUTABLE     = 0x0010  # Contains Flame/Lightning blocks
    HAS_VERSION_GRAPH  = 0x0020  # Contains version DAG
    GROWTH_RESERVED    = 0x0040  # Growth space pre-allocated


# ═══════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

@dataclass
class SectionEntry:
    """
    XQPE Section Directory entry.
    Points to one Circle's data within the trailer.
    
    Wire format (44 bytes):
        circle_id : uint32  (4 bytes)
        offset    : uint64  (8 bytes) — from trailer start
        length    : uint64  (8 bytes)
        hash      : bytes   (32 bytes) — SHA-256
    """
    circle_id: int
    offset: int
    length: int
    hash: bytes  # 32 bytes SHA-256

    PACKED_SIZE = 4 + 8 + 8 + 32  # 52 bytes

    def pack(self) -> bytes:
        """Serialize to wire format."""
        return (
            struct.pack('>I', self.circle_id)
            + struct.pack('>Q', self.offset)
            + struct.pack('>Q', self.length)
            + self.hash
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'SectionEntry':
        """Deserialize from wire format."""
        if len(data) < cls.PACKED_SIZE:
            raise QRenFormatError(f"SectionEntry needs {cls.PACKED_SIZE} bytes, got {len(data)}")
        circle_id = struct.unpack('>I', data[0:4])[0]
        offset = struct.unpack('>Q', data[4:12])[0]
        length = struct.unpack('>Q', data[12:20])[0]
        hash_bytes = data[20:52]
        return cls(circle_id=circle_id, offset=offset, length=length, hash=hash_bytes)


@dataclass
class BlockHeader:
    """
    Header for an individual data block within a Circle.
    
    Wire format (variable, minimum 48 bytes):
        block_id        : bytes  (32 bytes) — SHA-256 content address
        block_type      : uint8  (1 byte)
        normalization   : uint8  (1 byte)
        compression     : uint8  (1 byte)
        flags           : uint8  (1 byte)
        data_length     : uint64 (8 bytes)
        runic_tag_count : uint16 (2 bytes)
        reserved        : bytes  (2 bytes)
        [runic_tags]    : variable
    """
    block_id: bytes          # 32 bytes, SHA-256 of raw content
    block_type: BlockType
    normalization: NormalizationProfile
    compression: CompressionTier
    flags: int               # Block-level flags
    data_length: int         # Length of compressed data following header
    runic_tags: List[str] = field(default_factory=list)

    FIXED_SIZE = 32 + 1 + 1 + 1 + 1 + 8 + 2 + 2  # 48 bytes

    def pack(self) -> bytes:
        """Serialize block header."""
        buf = bytearray()
        buf.extend(self.block_id)
        buf.append(int(self.block_type))
        buf.append(int(self.normalization))
        buf.append(int(self.compression))
        buf.append(self.flags & 0xFF)
        buf.extend(struct.pack('>Q', self.data_length))
        
        # Encode runic tags as UTF-8, length-prefixed
        tag_data = b'\x00'.join(t.encode('utf-8') for t in self.runic_tags) if self.runic_tags else b''
        buf.extend(struct.pack('>H', len(tag_data)))
        buf.extend(b'\x00\x00')  # reserved
        buf.extend(tag_data)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> tuple:
        """Deserialize block header. Returns (BlockHeader, bytes_consumed)."""
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(f"BlockHeader needs >={cls.FIXED_SIZE} bytes, got {len(data)}")
        
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
    QRCF Trailer header — the first bytes after the PNG image.
    
    Wire format (32 bytes):
        magic       : bytes  (8 bytes) — XQPE_MAGIC
        version     : uint16 (2 bytes)
        trailer_len : uint64 (8 bytes) — total trailer length
        offset_c1   : uint64 (8 bytes) — offset to Circle 1 from trailer start
        num_circles : uint32 (4 bytes)
        flags       : uint32 (4 bytes)
        reserved    : bytes  (2 bytes, padding to alignment, included in the 32 due to rounding for 36; but we define as 32+4 below)
    """
    # Note: the actual header is exactly 34 bytes. We pad to 36 for alignment.
    version: int
    trailer_len: int
    offset_c1: int
    num_circles: int
    flags: int

    PACKED_SIZE = 8 + 2 + 8 + 8 + 4 + 4 + 2  # 36 bytes (with 2 padding)

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(XQPE_MAGIC)                          # 8 bytes
        buf.extend(struct.pack('>H', self.version))      # 2 bytes
        buf.extend(struct.pack('>Q', self.trailer_len))  # 8 bytes
        buf.extend(struct.pack('>Q', self.offset_c1))    # 8 bytes
        buf.extend(struct.pack('>I', self.num_circles))  # 4 bytes
        buf.extend(struct.pack('>I', self.flags))        # 4 bytes
        buf.extend(b'\x00\x00')                          # 2 bytes reserved
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'TrailerHeader':
        if len(data) < cls.PACKED_SIZE:
            raise QRenFormatError(f"TrailerHeader needs {cls.PACKED_SIZE} bytes, got {len(data)}")
        
        magic = data[0:8]
        if magic != XQPE_MAGIC:
            raise QRenFormatError(f"Invalid XQPE magic: {magic!r}")
        
        version = struct.unpack('>H', data[8:10])[0]
        trailer_len = struct.unpack('>Q', data[10:18])[0]
        offset_c1 = struct.unpack('>Q', data[18:26])[0]
        num_circles = struct.unpack('>I', data[26:30])[0]
        flags = struct.unpack('>I', data[30:34])[0]
        # bytes 34-35 are reserved padding
        
        return cls(version=version, trailer_len=trailer_len,
                   offset_c1=offset_c1, num_circles=num_circles, flags=flags)


@dataclass
class IntegrityBlock:
    """
    Integrity block at the end of the trailer.
    Contains Merkle root over all sections and optional UserSeed binding.
    
    Wire format (variable, minimum 40 bytes):
        magic         : bytes  (4 bytes) — b"INTG"
        version       : uint16 (2 bytes)
        merkle_root   : bytes  (32 bytes) — SHA-256
        userseed_hash : bytes  (32 bytes) — SHA-256 or zeros
        signature_len : uint16 (2 bytes)
        [signature]   : bytes  (variable, optional)
    """
    MAGIC = b"INTG"
    
    merkle_root: bytes     # 32 bytes
    userseed_hash: bytes   # 32 bytes (all zeros if no UserSeed)
    signature: bytes = b'' # optional
    
    FIXED_SIZE = 4 + 2 + 32 + 32 + 2  # 72 bytes

    def pack(self) -> bytes:
        buf = bytearray()
        buf.extend(self.MAGIC)                                    # 4
        buf.extend(struct.pack('>H', 1))                          # 2 (version)
        buf.extend(self.merkle_root)                              # 32
        buf.extend(self.userseed_hash)                            # 32
        buf.extend(struct.pack('>H', len(self.signature)))        # 2
        buf.extend(self.signature)
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> 'IntegrityBlock':
        if len(data) < cls.FIXED_SIZE:
            raise QRenFormatError(f"IntegrityBlock needs >={cls.FIXED_SIZE} bytes")
        if data[0:4] != cls.MAGIC:
            raise QRenFormatError(f"Invalid integrity magic: {data[0:4]!r}")
        
        # version = struct.unpack('>H', data[4:6])[0]
        merkle = data[6:38]
        userseed = data[38:70]
        sig_len = struct.unpack('>H', data[70:72])[0]
        sig = data[72:72+sig_len] if sig_len > 0 else b''
        return cls(merkle_root=merkle, userseed_hash=userseed, signature=sig)


# ═══════════════════════════════════════════════════════════════
# ERROR CLASSES
# ═══════════════════════════════════════════════════════════════

class QRenError(Exception):
    """Base error for all QRenCode operations."""
    pass

class QRenFormatError(QRenError):
    """XQPE/QRCF structural or parsing error."""
    pass

class QRenIntegrityError(QRenError):
    """Checksum, hash, or signature verification failure."""
    pass

class QRenCompressionError(QRenError):
    """Compression or decompression failure."""
    pass

class QRenBlockError(QRenError):
    """Block-level encoding or decoding error."""
    pass


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def content_address(data: bytes) -> bytes:
    """SHA-256 content address (CAS). Returns 32 bytes."""
    return hashlib.sha256(data).digest()

def content_address_hex(data: bytes) -> str:
    """SHA-256 content address as hex string."""
    return hashlib.sha256(data).hexdigest()

def merkle_root(hashes: List[bytes]) -> bytes:
    """
    Compute Merkle root from a list of 32-byte SHA-256 hashes.
    If empty, returns 32 zero bytes. If single, returns that hash.
    """
    if not hashes:
        return b'\x00' * 32
    if len(hashes) == 1:
        return hashes[0]
    
    # Pad to even count by duplicating last
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i+1]
            next_layer.append(hashlib.sha256(combined).digest())
        layer = next_layer
    return layer[0]


def auto_detect_block_type(data: bytes, filename: str = "") -> BlockType:
    """
    Auto-detect block type from content and filename.
    Default: AMORPHOUS (per spec — user didn't specify).
    """
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    
    # Code extensions → TREE (structured hierarchy)
    if ext in ('py', 'js', 'ts', 'rs', 'c', 'cpp', 'h', 'java', 'go', 'rb', 'sh'):
        return BlockType.TREE
    
    # ML model extensions → FRACTAL
    if ext in ('pt', 'pth', 'h5', 'hdf5', 'onnx', 'pb', 'tflite', 'safetensors'):
        return BlockType.FRACTAL
    
    # Config/schema → GEOMETRIC
    if ext in ('json', 'yaml', 'yml', 'toml', 'xml', 'xsd', 'proto'):
        return BlockType.GEOMETRIC
    
    # ISO/executable → FLAME
    if ext in ('iso', 'img', 'exe', 'elf', 'wasm', 'bin'):
        return BlockType.FLAME
    
    # Frozen/versioned → ICE
    if ext in ('lock', 'sum', 'checksum'):
        return BlockType.ICE
    
    # Try content sniffing
    try:
        text = data[:1024].decode('utf-8', errors='strict')
        # Looks like code?
        if any(kw in text for kw in ('def ', 'function ', 'class ', 'import ', '#include')):
            return BlockType.TREE
        # Looks like JSON/config?
        if text.lstrip().startswith(('{', '[')):
            return BlockType.GEOMETRIC
    except (UnicodeDecodeError, ValueError):
        pass
    
    return BlockType.AMORPHOUS
