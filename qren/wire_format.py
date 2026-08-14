"""
QRCF — QRenCode Container Format. The byte-level wire format for QRen blocks.

Layout (all multi-byte integers big-endian):

    offset  size  field
    0       4     magic = b'SAIP'
    4       1     block_type (wire code, e.g. 0x01)
    5       1     flags bitmask (NADA_PROTECTED / EMBER / EXECUTABLE)
    6       4     metadata_length
    10      4     payload_length
    14      *     metadata (UTF-8 JSON, metadata_length bytes)
    14+ml   *     payload (raw bytes, payload_length bytes)

This is the format Mode 2 (Machine <-> Circle) and the "type(input) begins
with 4-byte QRCF magic (SAIP)" detection in the Magic Circle both depend on.
"""

import json
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from qren.block_types import BlockType, get as get_block_type

MAGIC = b'SAIP'
_HEADER_STRUCT = struct.Struct('>4sBBII')  # magic, block_type, flags, meta_len, payload_len

FLAG_NADA_PROTECTED = 0b001
FLAG_EMBER = 0b010
FLAG_EXECUTABLE = 0b100


class QRCFDecodeError(ValueError):
    pass


@dataclass
class QRCFBlock:
    block_type: int                       # wire code
    payload: bytes = b''
    metadata: Dict[str, Any] = field(default_factory=dict)
    nada_protected: bool = False
    ember: bool = False

    @property
    def block_type_info(self) -> Optional[BlockType]:
        return get_block_type(self.block_type)

    def _flags(self) -> int:
        flags = 0
        if self.nada_protected:
            flags |= FLAG_NADA_PROTECTED
        if self.ember:
            flags |= FLAG_EMBER
        info = self.block_type_info
        if info and info.executable:
            flags |= FLAG_EXECUTABLE
        return flags

    def encode(self) -> bytes:
        meta_bytes = json.dumps(self.metadata, ensure_ascii=False).encode('utf-8')
        header = _HEADER_STRUCT.pack(MAGIC, self.block_type, self._flags(), len(meta_bytes), len(self.payload))
        return header + meta_bytes + self.payload

    @classmethod
    def decode(cls, data: bytes) -> 'QRCFBlock':
        if len(data) < _HEADER_STRUCT.size:
            raise QRCFDecodeError(f"Data too short for QRCF header: {len(data)} bytes")

        magic, block_type, flags, meta_len, payload_len = _HEADER_STRUCT.unpack_from(data, 0)
        if magic != MAGIC:
            raise QRCFDecodeError(f"Bad magic bytes: {magic!r} (expected {MAGIC!r})")

        offset = _HEADER_STRUCT.size
        meta_bytes = data[offset:offset + meta_len]
        offset += meta_len
        payload = data[offset:offset + payload_len]

        if len(meta_bytes) != meta_len or len(payload) != payload_len:
            raise QRCFDecodeError("Truncated QRCF block: declared lengths exceed available data")

        try:
            metadata = json.loads(meta_bytes.decode('utf-8')) if meta_bytes else {}
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise QRCFDecodeError(f"Bad metadata JSON: {e}")

        return cls(
            block_type=block_type,
            payload=payload,
            metadata=metadata,
            nada_protected=bool(flags & FLAG_NADA_PROTECTED),
            ember=bool(flags & FLAG_EMBER),
        )


def has_qrcf_magic(data: bytes) -> bool:
    """Mode-detection primitive: 'input begins with 4-byte QRCF magic (SAIP)'."""
    return isinstance(data, (bytes, bytearray)) and bytes(data[:4]) == MAGIC
