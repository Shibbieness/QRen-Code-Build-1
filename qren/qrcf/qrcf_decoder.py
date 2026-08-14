"""
QRCF Decoder — QRenCode Container Format v1 Decoder
=====================================================

Decodes QRCF containers (PNG + XQPE trailer) back to data.
Also decodes .xqmem standalone files (raw XQPE trailer).

STATUS: PHASE 1 COMPLETE. 15/15 tests verified.
This is the canonical qrcf_decoder.py as verified in the original build session.

Profile A (Minimal): Read bytes, verify section hashes, Merkle root.
Profile B (Structural): Resolve circles, decompress, parse manifest.
Profile C (Semantic): Block semantics, Runic tags, content_address verify.
Profile D (Full Native): Deferred to Phase 2+ (QRVM, visual decoding, growth).

This is NOT CodexOmega. No external DB. Fully self-contained.
"""

import io
import json
import struct
import hashlib
import base64
from typing import Any, Dict, List, Optional
from pathlib import Path

from .qrcf_types import (
    BlockHeaderFlags,
    QREN_MAGIC, XQPE_MAGIC, QRCF_VERSION,
    BlockType, CompressionTier, NormalizationProfile,
    SectionEntry, BlockHeader, TrailerHeader, IntegrityBlock,
    QRenError, QRenFormatError, QRenIntegrityError, QRenCompressionError,
    content_address, merkle_root,
)
from .qrcf_encoder import CompressionEngine



def _summarize_type_header(header):
    """Render a per-type header as JSON-safe fields.

    The class name alone proves a header was FOUND; it does not prove the
    fields came back. A header parsed at the wrong offset is still the right
    class and holds rubbish, so the values have to be visible to be checked —
    by a test, and by anyone debugging an archive.

    Bytes become hex and enums become names, because this result travels out
    through the Vanilla Core flavor adapter as JSON.
    """
    if header is None:
        return None
    import dataclasses
    out = {}
    for f in dataclasses.fields(header):
        v = getattr(header, f.name)
        if isinstance(v, (bytes, bytearray)):
            out[f.name] = v.hex()
        elif hasattr(v, "name") and hasattr(v, "value"):
            out[f.name] = v.name
        else:
            out[f.name] = v
    return out


class QRenDecoder:
    """
    QRCF v1 Decoder.

    Reads a .qren.png (QRCF container) or .xqmem (standalone XQPE)
    file and extracts data blocks.

    Usage:
        decoder = QRenDecoder()
        result = decoder.decode("archive.qren.png")
        data = result['data']
        manifest = result['manifest']
    """

    def __init__(self, verify_integrity: bool = True):
        self.verify_integrity = verify_integrity
        self.compressor = CompressionEngine()

    # ─── Main Entry Points ────────────────────────────────────

    def decode(self, filepath: str) -> dict:
        """Decode a QRCF container or .xqmem file."""
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
        """Decode a full QRCF container (PNG image + XQPE trailer)."""
        trailer_offset = self._find_trailer(data)
        if trailer_offset < 0:
            raise QRenFormatError(
                "No XQPE trailer found. This may be a standard QR code "
                "(Profile A decode: metadata only from QR layer)."
            )
        trailer = data[trailer_offset:]
        png_data = data[:trailer_offset]
        circle_0 = self._extract_circle_0(png_data)
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
        """Decode an XQPE trailer. Core decode path. Profile A → B → C."""

        # ══ PROFILE A: Read bytes, verify invariants ══

        header = TrailerHeader.unpack(trailer)

        # Parse section directory
        dir_offset = TrailerHeader.PACKED_SIZE
        sections = []
        for i in range(header.num_circles):
            entry_start = dir_offset + (i * SectionEntry.PACKED_SIZE)
            entry_end = entry_start + SectionEntry.PACKED_SIZE
            if entry_end > len(trailer):
                raise QRenFormatError(f"Section directory truncated at entry {i}")
            entry = SectionEntry.unpack(trailer[entry_start:entry_end])
            sections.append(entry)

        # Verify section hashes
        section_hashes = []
        validation_errors = []
        for sec in sections:
            sec_data = trailer[sec.offset:sec.offset + sec.length]
            if len(sec_data) != sec.length:
                validation_errors.append(
                    f"Circle {sec.circle_id}: truncated "
                    f"(expected {sec.length}, got {len(sec_data)} bytes)"
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

        # Parse and verify integrity block
        integrity_offset = max(s.offset + s.length for s in sections) if sections else 0
        integrity = None
        if integrity_offset < len(trailer):
            try:
                integrity = IntegrityBlock.unpack(trailer[integrity_offset:])
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

        # ══ PROFILE B: Resolve circles ══

        translation = None
        manifest = None
        data_blocks = []

        for sec in sections:
            sec_data = trailer[sec.offset:sec.offset + sec.length]

            if sec.circle_id == 1:
                # Circle 1: Translation Layer (LZ4-compressed JSON)
                try:
                    raw = self.compressor.decompress(sec_data, CompressionTier.T1_LZ4)
                    translation = json.loads(raw.decode('utf-8'))
                except Exception as e:
                    validation_errors.append(f"Circle 1 decode failed: {e}")

            elif sec.circle_id == 2:
                # Circle 2: Manifest + Index (LZ4-compressed JSON)
                try:
                    raw = self.compressor.decompress(sec_data, CompressionTier.T1_LZ4)
                    manifest = json.loads(raw.decode('utf-8'))
                except Exception as e:
                    validation_errors.append(f"Circle 2 decode failed: {e}")

            elif sec.circle_id >= 3:
                # Circle 3+: Data blocks (raw BlockHeader + per-block compressed data)
                try:
                    blocks, block_errors = self._extract_data_blocks(sec_data)
                    data_blocks.extend(blocks)
                    # Errors from extraction must reach validation_errors, or
                    # `valid` is computed from a path that never learns blocks
                    # were dropped — which is exactly how an archive with an
                    # unknown block type reported valid: True, blocks: 0.
                    validation_errors.extend(block_errors)
                except Exception as e:
                    validation_errors.append(f"Circle {sec.circle_id} decode failed: {e}")

        # ══ PROFILE C: Extract primary data ══

        primary_data = None
        decoded = [b for b in data_blocks if b.get('decoded', True)]
        if decoded:
            primary_data = decoded[0]['data']

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
                'data_length': len(b['data']) if b.get('data') is not None else 0,
                'decoded': b.get('decoded', True),
                'type_header': type(b['type_header']).__name__
                                if b.get('type_header') is not None else None,
                'type_header_fields': _summarize_type_header(b.get('type_header')),
            } for b in data_blocks],
            'data': primary_data,
            'block_count': len(data_blocks),
            'validation_errors': validation_errors,
            'valid': len(validation_errors) == 0,
        }

    # ─── Block Extraction ─────────────────────────────────────

    def _extract_data_blocks(self, circle_data: bytes):
        """
        Extract data blocks from a Circle 3+ data section.

        Returns (blocks, errors). The errors half is the fix: this loop used to
        collapse three different situations into one `break`, and only one of
        them is a clean stop.

          growth space     trailing zeros — the section is simply over
          truncated        the archive is damaged
          unknown type     the archive is FINE and this decoder is older

        The third was the dangerous one. `BlockHeader.unpack` calls
        `BlockType(byte)`, which raises ValueError on a code it does not know;
        the old `except (QRenFormatError, ValueError): break` read that as
        "growth space reached" and returned the blocks collected so far —
        usually none. Because `valid` is computed from validation_errors on a
        separate path, the caller was told `valid: True, blocks: 0, data: None`.

        A newer archive decoded as valid and empty. Silent total data loss.

        Two changes. Unknown codes are now reported rather than swallowed, and
        because the header layout is position-fixed, an unknown TYPE does not
        prevent reading the block's LENGTH — so the block is preserved as raw
        bytes and the loop continues to the next one instead of abandoning the
        rest of the section.
        """
        blocks = []
        errors = []
        pos = 0

        known_types = {b.value for b in BlockType}
        known_norms = {n.value for n in NormalizationProfile}
        known_comps = {c.value for c in CompressionTier}

        while pos < len(circle_data):
            remaining = circle_data[pos:]

            # Growth space: the one clean stop.
            if remaining == b'\x00' * len(remaining):
                break

            if len(remaining) < BlockHeader.FIXED_SIZE:
                errors.append(
                    f"truncated block at offset {pos}: {len(remaining)} bytes "
                    f"remain, a header needs {BlockHeader.FIXED_SIZE}"
                )
                break

            # A zero block_id is also growth space, not a block.
            if remaining[:32] == b'\x00' * 32:
                break

            # Peek the fixed-position header fields WITHOUT coercing them to
            # enums, so an unrecognised value is reported as itself rather than
            # as the end of the section.
            raw_type = remaining[32]
            raw_norm = remaining[33]
            raw_comp = remaining[34]
            data_length = struct.unpack('>Q', remaining[36:44])[0]
            tag_len = struct.unpack('>H', remaining[44:46])[0]
            frame_end = BlockHeader.FIXED_SIZE + tag_len + data_length

            if frame_end > len(remaining):
                errors.append(
                    f"truncated block at offset {pos}: header declares "
                    f"{frame_end} bytes, only {len(remaining)} remain"
                )
                break

            unknown = []
            if raw_type not in known_types:
                unknown.append(f"block type 0x{raw_type:02X}")
            if raw_norm not in known_norms:
                unknown.append(f"normalization 0x{raw_norm:02X}")
            if raw_comp not in known_comps:
                unknown.append(f"compression tier 0x{raw_comp:02X}")

            if unknown:
                # The archive is probably valid and this decoder is older.
                # Say so, keep the bytes, and carry on to the next block.
                errors.append(
                    f"unrecognised {', '.join(unknown)} at offset {pos} — this "
                    f"archive was likely written by a newer QRen. "
                    f"{data_length} bytes preserved undecoded."
                )
                blocks.append({
                    'block_id': remaining[:32].hex(),
                    'block_type': f"UNKNOWN(0x{raw_type:02X})",
                    'normalization': f"0x{raw_norm:02X}",
                    'compression': f"0x{raw_comp:02X}",
                    'runic_tags': [],
                    'data': None,
                    'raw': bytes(remaining[BlockHeader.FIXED_SIZE + tag_len:frame_end]),
                    'decoded': False,
                })
                pos += frame_end
                continue

            try:
                block_header, header_bytes = BlockHeader.unpack(remaining)
            except (QRenFormatError, ValueError) as exc:
                errors.append(f"malformed block header at offset {pos}: {exc}")
                break

            data_start = header_bytes
            data_end = data_start + block_header.data_length

            if data_end > len(remaining):
                errors.append(
                    f"truncated block body at offset {pos}: needs {data_end} "
                    f"bytes, {len(remaining)} remain"
                )
                break

            data_region = remaining[data_start:data_end]

            # Per-type header, if this block carries one. It lives
            # uncompressed at the front of the data region and is counted
            # inside data_length, so the frame arithmetic above is unaffected
            # and an older decoder still skips exactly one block.
            type_header = None
            if block_header.flags & BlockHeaderFlags.HAS_TYPE_HEADER:
                from .qrcf_types_phase2 import TYPE_HEADERS, unpack_type_header
                if block_header.block_type not in TYPE_HEADERS:
                    errors.append(
                        f"block at offset {pos} sets HAS_TYPE_HEADER but "
                        f"{block_header.block_type.name} defines none"
                    )
                else:
                    try:
                        type_header, consumed = unpack_type_header(
                            block_header.block_type, data_region)
                        data_region = data_region[consumed:]
                    except Exception as exc:
                        errors.append(
                            f"{block_header.block_type.name} type header at "
                            f"offset {pos} did not parse: {exc}"
                        )
                        type_header = None

            compressed_data = data_region

            try:
                raw_data = self.compressor.decompress(
                    compressed_data, block_header.compression
                )
            except Exception as e:
                raise QRenCompressionError(
                    f"Block {block_header.block_id.hex()[:16]} "
                    f"decompression failed: {e}"
                )

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
                'decoded': True,
                'type_header': type_header,
            })

            pos += data_end

        return blocks, errors

    # ─── Trailer Location ─────────────────────────────────────

    def _find_trailer(self, data: bytes) -> int:
        """Locate the XQPE trailer in a QRCF file."""
        idx = data.find(XQPE_MAGIC)
        if idx >= 0:
            return idx
        # Fallback: find PNG IEND and look right after
        iend_marker = b'IEND'
        idx = data.find(iend_marker)
        if idx >= 0:
            png_end = idx + 4 + 4  # past "IEND" + CRC
            if png_end < len(data) and data[png_end:png_end+8] == XQPE_MAGIC:
                return png_end
        return -1

    # ─── Circle 0 Extraction ──────────────────────────────────

    def _extract_circle_0(self, png_data: bytes) -> Optional[dict]:
        """Extract Circle 0 payload from PNG tEXt chunk or QR scan."""
        circle_0 = self._extract_from_text_chunk(png_data)
        if circle_0:
            return circle_0
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
        search = b'QRenCode\x00'
        idx = png_data.find(search)
        if idx < 0:
            return None
        value_start = idx + len(search)
        chunk_end = png_data.find(b'IDAT', value_start)
        if chunk_end < 0:
            chunk_end = png_data.find(b'IEND', value_start)
        if chunk_end < 0:
            return None
        b64_data = png_data[value_start:chunk_end]
        b64_data = bytes(
            b for b in b64_data
            if b in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        )
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
        version     = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        trailer_len = struct.unpack('>Q', payload[pos:pos+8])[0]; pos += 8
        num_circles = struct.unpack('>I', payload[pos:pos+4])[0]; pos += 4
        manifest_hash = payload[pos:pos+32].hex(); pos += 32
        archive_id  = payload[pos:pos+36].decode('ascii', errors='replace')
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
