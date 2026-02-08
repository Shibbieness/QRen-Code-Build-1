"""
QRCF Encoder — QRenCode Container Format v1 Encoder
=====================================================

Encodes structured data into a QRCF container:
  PNG image (Circle 0 QR code) + XQPE binary trailer

Phase 1 scope:
  - XQPE trailer with section directory and 64-bit offsets
  - Circle 0: QR bootstrap (magic, version, pointers)
  - Circle 1: Translation layer (codec registry, block type map)
  - Circle 2: Manifest + Runic index (metadata-only plane)
  - Circle 3: Data blocks (typed, compressed, content-addressed)
  - Integrity block with Merkle root
  - Round-trip: data → QRCF file → data (verified)
  - .xqmem standalone output (XQPE bytes, no QR wrapper)

This is NOT CodexOmega. No external DB. Fully self-contained.
"""

import io
import os
import json
import time
import zlib
import struct
import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path

from qrcf_types import (
    QREN_MAGIC, XQPE_MAGIC, QRCF_VERSION,
    BlockType, CompressionTier, NormalizationProfile, EdgeType,
    QRCFFlags, SectionEntry, BlockHeader, TrailerHeader, IntegrityBlock,
    QRenError, QRenFormatError, QRenCompressionError, QRenBlockError,
    content_address, merkle_root, auto_detect_block_type,
    BLOCK_NORMALIZATION,
)

# Optional dependencies: prefer zstd/lz4 if available, fall back to zlib
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

# Optional: QR code generation
try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# Optional: PNG image support
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ═══════════════════════════════════════════════════════════════
# COMPRESSION ENGINE
# ═══════════════════════════════════════════════════════════════

class CompressionEngine:
    """Multi-tier compression following the T0-T5 model."""

    @staticmethod
    def compress(data: bytes, tier: CompressionTier) -> bytes:
        """Compress data using the specified tier."""
        if tier == CompressionTier.T0_NONE:
            return data
        elif tier == CompressionTier.T1_LZ4:
            if HAS_LZ4:
                return lz4.frame.compress(data)
            # Fallback to zlib level 1 (fast)
            return zlib.compress(data, level=1)
        elif tier == CompressionTier.T2_ZSTD:
            if HAS_ZSTD:
                cctx = zstd.ZstdCompressor(level=9)
                return cctx.compress(data)
            # Fallback to zlib level 9
            return zlib.compress(data, level=9)
        elif tier in (CompressionTier.T3_DELTA, CompressionTier.T4_FRACTAL,
                      CompressionTier.T5_DEDUP):
            # Phase 1: these advanced tiers fall back to T2_ZSTD behavior
            if HAS_ZSTD:
                cctx = zstd.ZstdCompressor(level=9)
                return cctx.compress(data)
            return zlib.compress(data, level=9)
        else:
            return zlib.compress(data, level=9)

    @staticmethod
    def decompress(data: bytes, tier: CompressionTier) -> bytes:
        """Decompress data from the specified tier."""
        if tier == CompressionTier.T0_NONE:
            return data
        elif tier == CompressionTier.T1_LZ4:
            if HAS_LZ4:
                return lz4.frame.decompress(data)
            return zlib.decompress(data)
        elif tier == CompressionTier.T2_ZSTD:
            if HAS_ZSTD:
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data, max_output_size=1 * 1024 * 1024 * 1024)
            return zlib.decompress(data)
        elif tier in (CompressionTier.T3_DELTA, CompressionTier.T4_FRACTAL,
                      CompressionTier.T5_DEDUP):
            if HAS_ZSTD:
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data, max_output_size=1 * 1024 * 1024 * 1024)
            return zlib.decompress(data)
        else:
            return zlib.decompress(data)


# ═══════════════════════════════════════════════════════════════
# ENCODER
# ═══════════════════════════════════════════════════════════════

class QRenEncoder:
    """
    QRCF v1 Encoder.
    
    Encodes data into a QRenCode Container Format file:
      [PNG Image with QR code] + [XQPE Binary Trailer]
    
    Usage:
        encoder = QRenEncoder()
        result = encoder.encode(
            data=my_bytes_or_dict,
            name="my_archive",
            block_type=BlockType.TREE,
            output_path="archive.qren.png"
        )
    """

    def __init__(self, 
                 default_compression: CompressionTier = CompressionTier.T2_ZSTD,
                 growth_space_percent: int = 15):
        self.default_compression = default_compression
        self.growth_space_percent = growth_space_percent
        self.compressor = CompressionEngine()

    def encode(self,
               data: Any,
               name: str = "archive",
               block_type: Optional[BlockType] = None,
               compression: Optional[CompressionTier] = None,
               runic_tags: Optional[List[str]] = None,
               metadata: Optional[Dict] = None,
               filename_hint: str = "",
               output_path: Optional[str] = None,
               output_xqmem: bool = False) -> dict:
        """
        Encode data into a QRCF container.
        
        Args:
            data: Input data. bytes, str, dict, list, or any JSON-serializable.
            name: Human-readable archive name.
            block_type: Block type. None = auto-detect, default AMORPHOUS.
            compression: Compression tier. None = use default.
            runic_tags: Semantic tags for Runic index.
            metadata: Additional metadata dict.
            filename_hint: Original filename for auto-detection.
            output_path: File path for .qren.png output.
            output_xqmem: Also write .xqmem (raw XQPE bytes).
        
        Returns:
            dict with archive_id, checksums, sizes, paths.
        """
        # ── 1. Serialize input data to bytes ──
        raw_bytes = self._serialize(data)
        
        # ── 2. Determine block type ──
        if block_type is None:
            block_type = auto_detect_block_type(raw_bytes, filename_hint)
        
        # ── 3. Determine compression ──
        comp = compression or self.default_compression
        
        # ── 4. Determine normalization ──
        norm = BLOCK_NORMALIZATION.get(block_type, NormalizationProfile.LOOSE)
        
        # ── 5. Compress data ──
        compressed = self.compressor.compress(raw_bytes, comp)
        
        # ── 6. Content-address the raw data ──
        block_id = content_address(raw_bytes)
        
        # ── 7. Build the data block (Circle 3) ──
        block_header = BlockHeader(
            block_id=block_id,
            block_type=block_type,
            normalization=norm,
            compression=comp,
            flags=0,
            data_length=len(compressed),
            runic_tags=runic_tags or []
        )
        circle_3_data = block_header.pack() + compressed
        
        # ── 8. Add growth space ──
        growth_size = max(64, int(len(circle_3_data) * self.growth_space_percent / 100))
        circle_3_data += b'\x00' * growth_size
        
        # ── 9. Build Circle 1 (Translation Layer) ──
        circle_1_data = self._build_circle_1(comp, block_type, norm)
        
        # ── 10. Build Circle 2 (Manifest + Index) ──
        archive_id = str(uuid.uuid4())
        circle_2_data = self._build_circle_2(
            archive_id=archive_id, name=name,
            block_headers=[block_header],
            metadata=metadata or {},
            runic_tags=runic_tags or []
        )
        
        # ── 11. Compute section hashes ──
        h1 = content_address(circle_1_data)
        h2 = content_address(circle_2_data)
        h3 = content_address(circle_3_data)
        
        # ── 12. Build section directory ──
        # Offsets are relative to trailer start, computed after header + directory
        header_size = TrailerHeader.PACKED_SIZE
        dir_size = 3 * SectionEntry.PACKED_SIZE  # 3 circles
        
        c1_offset = header_size + dir_size
        c2_offset = c1_offset + len(circle_1_data)
        c3_offset = c2_offset + len(circle_2_data)
        
        sections = [
            SectionEntry(circle_id=1, offset=c1_offset, length=len(circle_1_data), hash=h1),
            SectionEntry(circle_id=2, offset=c2_offset, length=len(circle_2_data), hash=h2),
            SectionEntry(circle_id=3, offset=c3_offset, length=len(circle_3_data), hash=h3),
        ]
        
        # ── 13. Build integrity block ──
        merkle = merkle_root([h1, h2, h3])
        integrity = IntegrityBlock(
            merkle_root=merkle,
            userseed_hash=b'\x00' * 32,  # No UserSeed in Phase 1
            signature=b''
        )
        integrity_data = integrity.pack()
        
        # ── 14. Compute total trailer length ──
        trailer_len = (header_size + dir_size
                       + len(circle_1_data) + len(circle_2_data)
                       + len(circle_3_data) + len(integrity_data))
        
        # ── 15. Build trailer header ──
        flags = QRCFFlags.INTEGRITY_MERKLE
        if growth_size > 0:
            flags |= QRCFFlags.GROWTH_RESERVED
        
        trailer_header = TrailerHeader(
            version=QRCF_VERSION,
            trailer_len=trailer_len,
            offset_c1=c1_offset,
            num_circles=3,
            flags=flags
        )
        
        # ── 16. Assemble full trailer ──
        trailer = bytearray()
        trailer.extend(trailer_header.pack())
        for s in sections:
            trailer.extend(s.pack())
        trailer.extend(circle_1_data)
        trailer.extend(circle_2_data)
        trailer.extend(circle_3_data)
        trailer.extend(integrity_data)
        trailer = bytes(trailer)
        
        # Verify trailer length
        assert len(trailer) == trailer_len, \
            f"Trailer length mismatch: expected {trailer_len}, got {len(trailer)}"
        
        # ── 17. Build Circle 0 QR payload ──
        qr_payload = self._build_circle_0(
            archive_id=archive_id,
            trailer_len=trailer_len,
            num_circles=3,
            manifest_hash=h2
        )
        
        # ── 18. Generate QR image ──
        qr_image_bytes = self._generate_qr_image(qr_payload)
        
        # ── 19. Assemble final QRCF file (PNG + trailer) ──
        qrcf_data = qr_image_bytes + trailer
        
        # ── 20. Write output files ──
        paths = {}
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(qrcf_data)
            paths['qrcf'] = output_path
        
        if output_xqmem:
            xqmem_path = (output_path or f"{name}.qren.png").rsplit('.', 2)[0] + '.xqmem'
            with open(xqmem_path, 'wb') as f:
                f.write(trailer)
            paths['xqmem'] = xqmem_path
        
        return {
            'archive_id': archive_id,
            'name': name,
            'block_type': block_type.name,
            'compression': comp.name,
            'normalization': norm.name,
            'block_id': block_id.hex(),
            'merkle_root': merkle.hex(),
            'size_original': len(raw_bytes),
            'size_compressed': len(compressed),
            'size_trailer': len(trailer),
            'size_qrcf': len(qrcf_data),
            'compression_ratio': round(len(raw_bytes) / max(len(compressed), 1), 2),
            'growth_reserved': growth_size,
            'num_circles': 3,
            'paths': paths,
            'checksum': content_address(qrcf_data).hex(),
        }

    # ─── Circle Builders ──────────────────────────────────────

    def _build_circle_0(self, archive_id: str, trailer_len: int,
                         num_circles: int, manifest_hash: bytes) -> bytes:
        """
        Build Circle 0 QR payload.
        
        Contains ONLY: magic, version, pointer info, manifest hash.
        MUST NOT contain semantic data or executable logic.
        """
        payload = bytearray()
        payload.extend(QREN_MAGIC)                              # 4: magic
        payload.extend(struct.pack('>H', QRCF_VERSION))         # 2: version
        payload.extend(struct.pack('>Q', trailer_len))           # 8: trailer length
        payload.extend(struct.pack('>I', num_circles))           # 4: circle count
        payload.extend(manifest_hash)                            # 32: manifest hash
        payload.extend(archive_id[:36].encode('ascii'))          # 36: archive ID
        return bytes(payload)

    def _build_circle_1(self, compression: CompressionTier,
                         block_type: BlockType,
                         normalization: NormalizationProfile) -> bytes:
        """
        Build Circle 1: Translation Layer.
        
        Formal decoding descriptor:
          - Enumerated compression codecs available
          - Normalization registry
          - Block-type registry
          - RAM Cache geometry defaults (placeholder for Phase 1)
        """
        translation = {
            'schema_version': 1,
            'compression_codecs': {
                tier.name: tier.value for tier in CompressionTier
            },
            'normalization_profiles': {
                prof.name: prof.value for prof in NormalizationProfile
            },
            'block_type_registry': {
                bt.name: bt.value for bt in BlockType
            },
            'default_compression': compression.name,
            'default_normalization': normalization.name,
            'ram_cache_geometry': {
                'page_size': 4096,
                'line_count': 0,
                'associativity': 4,
                'eviction_policy': 'LRU'
            },
            'features': {
                'has_zstd': HAS_ZSTD,
                'has_lz4': HAS_LZ4,
                'fallback_compression': 'zlib'
            }
        }
        raw = json.dumps(translation, separators=(',', ':')).encode('utf-8')
        # Circle 1 is compressed with T1 (fast access)
        return self.compressor.compress(raw, CompressionTier.T1_LZ4)

    def _build_circle_2(self, archive_id: str, name: str,
                         block_headers: List[BlockHeader],
                         metadata: dict, runic_tags: List[str]) -> bytes:
        """
        Build Circle 2: Structural Layer (Index + Manifest + Dependency Plane).
        
        Contains metadata ONLY — no bulk data.
        """
        manifest = {
            'manifest_id': archive_id,
            'name': name,
            'schema_version': 1,
            'created': int(time.time()),
            'block_count': len(block_headers),
            'blocks': [{
                'block_id': bh.block_id.hex(),
                'block_type': bh.block_type.name,
                'normalization': bh.normalization.name,
                'compression': bh.compression.name,
                'data_length': bh.data_length,
                'runic_tags': bh.runic_tags,
            } for bh in block_headers],
            'runic_index': {
                'tags': runic_tags,
                'tag_to_blocks': {tag: [bh.block_id.hex() for bh in block_headers
                                        if tag in bh.runic_tags]
                                  for tag in runic_tags}
            },
            'dependency_graph': {
                'nodes': [bh.block_id.hex() for bh in block_headers],
                'edges': []  # Phase 1: no cross-block dependencies yet
            },
            'version_table': {
                'current_version': 1,
                'versions': [{
                    'version_id': 1,
                    'parent_version_id': None,
                    'timestamp': int(time.time()),
                    'change_summary': 'Initial creation',
                    'is_sealed': False,
                }]
            },
            'metadata': metadata,
        }
        raw = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
        return self.compressor.compress(raw, CompressionTier.T1_LZ4)

    # ─── Serialization ────────────────────────────────────────

    def _serialize(self, data: Any) -> bytes:
        """Serialize input to bytes. Accepts bytes, str, dict, list, or JSON-able."""
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode('utf-8')
        elif isinstance(data, (dict, list, tuple, int, float, bool)):
            return json.dumps(data, default=str, ensure_ascii=False).encode('utf-8')
        else:
            # Try JSON as last resort
            return json.dumps(data, default=str).encode('utf-8')

    # ─── QR Generation ────────────────────────────────────────

    def _generate_qr_image(self, payload: bytes) -> bytes:
        """Generate a PNG image containing the Circle 0 QR code."""
        if HAS_QRCODE and HAS_PIL:
            import base64
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=4,
                border=2
            )
            # Encode payload as base64 for QR (binary QR is less supported)
            qr.add_data(base64.b64encode(payload).decode('ascii'))
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            return buf.getvalue()
        else:
            # Fallback: generate a minimal valid PNG with embedded payload
            return self._generate_minimal_png(payload)

    def _generate_minimal_png(self, payload: bytes) -> bytes:
        """
        Generate a minimal valid PNG image that embeds the Circle 0 payload
        in a tEXt chunk. Works without any image libraries.
        """
        # Minimal 1x1 white PNG
        def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
            import struct, zlib as _zlib
            length = struct.pack('>I', len(data))
            crc = struct.pack('>I', _zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
            return length + chunk_type + data + crc
        
        # PNG signature
        signature = b'\x89PNG\r\n\x1a\n'
        
        # IHDR: 1x1 pixel, 8-bit grayscale
        ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)
        ihdr = png_chunk(b'IHDR', ihdr_data)
        
        # IDAT: single white pixel (filter byte 0 + pixel value 255)
        raw_row = b'\x00\xff'
        idat_data = zlib.compress(raw_row)
        idat = png_chunk(b'IDAT', idat_data)
        
        # tEXt chunk: embed Circle 0 payload as "QRenCode" text
        import base64
        text_data = b'QRenCode\x00' + base64.b64encode(payload)
        text_chunk = png_chunk(b'tEXt', text_data)
        
        # IEND
        iend = png_chunk(b'IEND', b'')
        
        return signature + ihdr + text_chunk + idat + iend
