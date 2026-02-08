"""
QRCF Decoder — QRenCode Container Format v1 Decoder
=====================================================

Decodes QRCF containers (PNG + XQPE trailer) back to data.
Implements decoder compliance profiles A through C (Phase 1).

Profile A (Minimal): Read bytes, verify invariants.
Profile B (Structural): Resolve blocks, circles, references.
Profile C (Semantic): Block semantics, runic tags, manifest.
Profile D (Full Native): Deferred to Phase 2+ (visual decoding, QRVM).

Also decodes .xqmem standalone files (raw XQPE trailer).

This is NOT CodexOmega. No external DB. Fully self-contained.
"""

import io
import json
import struct
import hashlib
import base64
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from qrcf_types import (
    QREN_MAGIC, XQPE_MAGIC, QRCF_VERSION,
    BlockType, CompressionTier, NormalizationProfile,
    SectionEntry, BlockHeader, TrailerHeader, IntegrityBlock,
    QRenError, QRenFormatError, QRenIntegrityError, QRenCompressionError,
    content_address, merkle_root,
)
from qrcf_encoder import CompressionEngine


# ═══════════════════════════════════════════════════════════════
# DECODER
# ═══════════════════════════════════════════════════════════════

class QRenDecoder:
    """
    QRCF v1 Decoder.
    
    Reads a .qren.png (QRCF container) or .xqmem (standalone XQPE)
    file and extracts data blocks.
    
    Usage:
        decoder = QRenDecoder()
        result = decoder.decode("archive.qren.png")
        data = result['data']       # Extracted bytes
        manifest = result['manifest']  # Circle 2 metadata
    """

    def __init__(self, verify_integrity: bool = True):
        self.verify_integrity = verify_integrity
        self.compressor = CompressionEngine()

    # ─── Main Entry Points ────────────────────────────────────

    def decode(self, filepath: str) -> dict:
        """
        Decode a QRCF container or .xqmem file.
        
        Args:
            filepath: Path to .qren.png or .xqmem file.
        
        Returns:
            dict with 'data', 'manifest', 'translation', 'integrity', etc.
        """
        filepath = str(filepath)
        raw = Path(filepath).read_bytes()
        
        if filepath.endswith('.xqmem'):
            return self._decode_xqmem(raw)
        else:
            return self._decode_qrcf(raw)

    def decode_bytes(self, data: bytes, is_xqmem: bool = False) -> dict:
        """Decode from in-memory bytes."""
        if is_xqmem:
            return self._decode_xqmem(data)
        return self._decode_qrcf(data)

    # ─── QRCF Decoding (PNG + Trailer) ────────────────────────

    def _decode_qrcf(self, data: bytes) -> dict:
        """
        Decode a full QRCF container (PNG image + XQPE trailer).
        
        Strategy: locate the XQPE magic in the file, everything
        from that point forward is the trailer.
        """
        # ── Step 1: Find the XQPE trailer ──
        trailer_offset = self._find_trailer(data)
        if trailer_offset < 0:
            raise QRenFormatError(
                "No XQPE trailer found. This may be a standard QR code "
                "(Profile A decode: metadata only from QR layer)."
            )
        
        trailer = data[trailer_offset:]
        png_data = data[:trailer_offset]
        
        # ── Step 2: Try to extract Circle 0 from PNG ──
        circle_0 = self._extract_circle_0(png_data)
        
        # ── Step 3: Decode the trailer ──
        result = self._decode_trailer(trailer)
        result['circle_0'] = circle_0
        result['png_size'] = len(png_data)
        result['trailer_offset'] = trailer_offset
        result['total_size'] = len(data)
        
        return result

    def _decode_xqmem(self, data: bytes) -> dict:
        """Decode a standalone .xqmem file (raw XQPE trailer)."""
        if not data[:8] == XQPE_MAGIC:
            raise QRenFormatError("Invalid .xqmem file: missing XQPE magic")
        return self._decode_trailer(data)

    # ─── Trailer Decoding ─────────────────────────────────────

    def _decode_trailer(self, trailer: bytes) -> dict:
        """
        Decode an XQPE trailer. This is the core decode path.
        
        Implements Profile A → B → C progressively.
        """
        # ══ PROFILE A: Read bytes, verify invariants ══
        
        # Parse trailer header
        header = TrailerHeader.unpack(trailer)
        
        if header.version != QRCF_VERSION:
            # Forward compatibility: warn but proceed
            pass
        
        # Parse section directory
        dir_offset = TrailerHeader.PACKED_SIZE
        sections = []
        for i in range(header.num_circles):
            entry_start = dir_offset + (i * SectionEntry.PACKED_SIZE)
            entry_end = entry_start + SectionEntry.PACKED_SIZE
            if entry_end > len(trailer):
                raise QRenFormatError(
                    f"Section directory truncated at entry {i}: "
                    f"need {entry_end} bytes, have {len(trailer)}"
                )
            entry = SectionEntry.unpack(trailer[entry_start:entry_end])
            sections.append(entry)
        
        # ── Verify section hashes (Profile A integrity) ──
        section_hashes = []
        validation_errors = []
        for sec in sections:
            sec_data = trailer[sec.offset:sec.offset + sec.length]
            if len(sec_data) != sec.length:
                validation_errors.append(
                    f"Circle {sec.circle_id}: truncated (expected {sec.length}, "
                    f"got {len(sec_data)} bytes)"
                )
                section_hashes.append(b'\x00' * 32)
                continue
            
            computed_hash = content_address(sec_data)
            section_hashes.append(computed_hash)
            
            if self.verify_integrity and computed_hash != sec.hash:
                validation_errors.append(
                    f"Circle {sec.circle_id}: hash mismatch "
                    f"(expected {sec.hash.hex()[:16]}..., "
                    f"got {computed_hash.hex()[:16]}...)"
                )
        
        # ── Parse integrity block ──
        integrity_offset = max(s.offset + s.length for s in sections) if sections else 0
        integrity = None
        if integrity_offset < len(trailer):
            try:
                integrity = IntegrityBlock.unpack(trailer[integrity_offset:])
                
                # Verify Merkle root
                if self.verify_integrity:
                    expected_merkle = merkle_root(section_hashes)
                    if integrity.merkle_root != expected_merkle:
                        validation_errors.append(
                            f"Merkle root mismatch "
                            f"(expected {expected_merkle.hex()[:16]}..., "
                            f"got {integrity.merkle_root.hex()[:16]}...)"
                        )
            except QRenFormatError:
                validation_errors.append("Integrity block malformed or missing")

        profile_a = {
            'header': {
                'version': header.version,
                'trailer_len': header.trailer_len,
                'num_circles': header.num_circles,
                'flags': header.flags,
            },
            'sections': [{
                'circle_id': s.circle_id,
                'offset': s.offset,
                'length': s.length,
                'hash': s.hash.hex(),
            } for s in sections],
            'integrity': {
                'merkle_root': integrity.merkle_root.hex() if integrity else None,
                'userseed_hash': integrity.userseed_hash.hex() if integrity else None,
                'has_signature': len(integrity.signature) > 0 if integrity else False,
            },
            'validation_errors': validation_errors,
            'valid': len(validation_errors) == 0,
        }
        
        # ══ PROFILE B: Resolve blocks, circles, references ══
        
        translation = None
        manifest = None
        data_blocks = []
        
        for sec in sections:
            sec_data = trailer[sec.offset:sec.offset + sec.length]
            
            if sec.circle_id == 1:
                # Circle 1: Translation Layer
                try:
                    raw = self.compressor.decompress(sec_data, CompressionTier.T1_LZ4)
                    translation = json.loads(raw.decode('utf-8'))
                except Exception as e:
                    validation_errors.append(f"Circle 1 decode failed: {e}")
                    
            elif sec.circle_id == 2:
                # Circle 2: Manifest + Index
                try:
                    raw = self.compressor.decompress(sec_data, CompressionTier.T1_LZ4)
                    manifest = json.loads(raw.decode('utf-8'))
                except Exception as e:
                    validation_errors.append(f"Circle 2 decode failed: {e}")
                    
            elif sec.circle_id >= 3:
                # Circle 3+: Data blocks
                try:
                    blocks = self._extract_data_blocks(sec_data)
                    data_blocks.extend(blocks)
                except Exception as e:
                    validation_errors.append(f"Circle {sec.circle_id} decode failed: {e}")
        
        # ══ PROFILE C: Block semantics, extract primary data ══
        
        primary_data = None
        if data_blocks:
            primary_data = data_blocks[0]['data']
        
        return {
            'profile_a': profile_a,
            'translation': translation,
            'manifest': manifest,
            'blocks': [{
                'block_id': b['block_id'],
                'block_type': b['block_type'],
                'normalization': b['normalization'],
                'compression': b['compression'],
                'runic_tags': b['runic_tags'],
                'data_length': len(b['data']),
            } for b in data_blocks],
            'data': primary_data,
            'block_count': len(data_blocks),
            'validation_errors': validation_errors,
            'valid': len(validation_errors) == 0,
        }

    # ─── Block Extraction ─────────────────────────────────────

    def _extract_data_blocks(self, circle_data: bytes) -> List[dict]:
        """
        Extract data blocks from a Circle 3+ data section.
        Handles growth space (trailing zeros) gracefully.
        """
        blocks = []
        pos = 0
        
        while pos < len(circle_data):
            # Check for growth space (all zeros)
            remaining = circle_data[pos:]
            if remaining == b'\x00' * len(remaining):
                break  # Growth space reached
            
            # Need at least a minimum header
            if len(remaining) < BlockHeader.FIXED_SIZE:
                break
            
            try:
                block_header, header_bytes = BlockHeader.unpack(remaining)
            except (QRenFormatError, ValueError):
                break  # Malformed or growth space
            
            # Extract compressed data
            data_start = header_bytes
            data_end = data_start + block_header.data_length
            
            if data_end > len(remaining):
                break  # Truncated block
            
            compressed_data = remaining[data_start:data_end]
            
            # Decompress
            try:
                raw_data = self.compressor.decompress(
                    compressed_data, block_header.compression
                )
            except Exception as e:
                raise QRenCompressionError(
                    f"Block {block_header.block_id.hex()[:16]} "
                    f"decompression failed: {e}"
                )
            
            # Verify content address
            if self.verify_integrity:
                computed_id = content_address(raw_data)
                if computed_id != block_header.block_id:
                    raise QRenIntegrityError(
                        f"Block content address mismatch: "
                        f"header says {block_header.block_id.hex()[:16]}..., "
                        f"data hashes to {computed_id.hex()[:16]}..."
                    )
            
            blocks.append({
                'block_id': block_header.block_id.hex(),
                'block_type': block_header.block_type.name,
                'normalization': block_header.normalization.name,
                'compression': block_header.compression.name,
                'runic_tags': block_header.runic_tags,
                'data': raw_data,
            })
            
            pos += header_bytes + block_header.data_length
        
        return blocks

    # ─── Trailer Location ─────────────────────────────────────

    def _find_trailer(self, data: bytes) -> int:
        """
        Locate the XQPE trailer in a QRCF file.
        
        Strategy: search for XQPE_MAGIC bytes. The trailer starts
        after the PNG IEND chunk.
        """
        # Method 1: Find XQPE magic directly
        idx = data.find(XQPE_MAGIC)
        if idx >= 0:
            return idx
        
        # Method 2: Find PNG IEND and look right after
        iend_marker = b'IEND'
        idx = data.find(iend_marker)
        if idx >= 0:
            # IEND chunk: 4 bytes length + 4 bytes "IEND" + 4 bytes CRC
            # The actual end is 4 bytes after "IEND" (for CRC)
            png_end = idx + 4 + 4  # past "IEND" + CRC
            if png_end < len(data):
                # Check if what follows is XQPE
                if data[png_end:png_end+8] == XQPE_MAGIC:
                    return png_end
        
        return -1

    # ─── Circle 0 Extraction ──────────────────────────────────

    def _extract_circle_0(self, png_data: bytes) -> Optional[dict]:
        """
        Extract Circle 0 payload from the PNG image.
        
        Tries multiple strategies:
        1. QR code scanning (if libraries available)
        2. PNG tEXt chunk extraction (fallback)
        """
        # Try tEXt chunk extraction (always works)
        circle_0 = self._extract_from_text_chunk(png_data)
        if circle_0:
            return circle_0
        
        # Try QR scanning if available
        try:
            from pyzbar.pyzbar import decode as qr_decode
            from PIL import Image
            img = Image.open(io.BytesIO(png_data))
            results = qr_decode(img)
            if results:
                payload = base64.b64decode(results[0].data)
                return self._parse_circle_0(payload)
        except (ImportError, Exception):
            pass
        
        return None

    def _extract_from_text_chunk(self, png_data: bytes) -> Optional[dict]:
        """Extract Circle 0 from PNG tEXt chunk (keyword: QRenCode)."""
        # Search for tEXt chunk with "QRenCode" keyword
        search = b'QRenCode\x00'
        idx = png_data.find(search)
        if idx < 0:
            return None
        
        # tEXt chunk: [4 len][4 "tEXt"][keyword\0value][4 CRC]
        # The keyword+value starts 8 bytes before the keyword
        # Actually we found "QRenCode\x00" inside the chunk data
        value_start = idx + len(search)
        
        # Find the end of the base64 data (before next chunk)
        # PNG chunks are length-prefixed, but for robustness we look for
        # the next chunk type or the end
        chunk_end = png_data.find(b'IDAT', value_start)
        if chunk_end < 0:
            chunk_end = png_data.find(b'IEND', value_start)
        if chunk_end < 0:
            return None
        
        # Back up 8 bytes (4 length + 4 CRC of tEXt chunk) 
        # Actually just grab up to a reasonable boundary
        b64_data = png_data[value_start:chunk_end]
        # Strip any CRC/length bytes at the end (non-base64 chars)
        b64_data = bytes(b for b in b64_data if b in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        
        try:
            payload = base64.b64decode(b64_data)
            return self._parse_circle_0(payload)
        except Exception:
            return None

    def _parse_circle_0(self, payload: bytes) -> dict:
        """Parse the Circle 0 binary payload."""
        if len(payload) < 50:
            return {'raw': payload.hex(), 'parsed': False}
        
        pos = 0
        magic = payload[pos:pos+4]; pos += 4
        if magic != QREN_MAGIC:
            return {'raw': payload.hex(), 'parsed': False}
        
        version = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        trailer_len = struct.unpack('>Q', payload[pos:pos+8])[0]; pos += 8
        num_circles = struct.unpack('>I', payload[pos:pos+4])[0]; pos += 4
        manifest_hash = payload[pos:pos+32].hex(); pos += 32
        archive_id = payload[pos:pos+36].decode('ascii', errors='replace'); pos += 36
        
        return {
            'parsed': True,
            'magic': magic.decode('ascii'),
            'version': version,
            'trailer_len': trailer_len,
            'num_circles': num_circles,
            'manifest_hash': manifest_hash,
            'archive_id': archive_id.strip('\x00'),
        }


# ═══════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def decode_file(filepath: str, verify: bool = True) -> dict:
    """Convenience: decode a QRCF file in one call."""
    return QRenDecoder(verify_integrity=verify).decode(filepath)

def decode_xqmem(filepath: str, verify: bool = True) -> dict:
    """Convenience: decode a .xqmem file in one call."""
    return QRenDecoder(verify_integrity=verify).decode(filepath)
