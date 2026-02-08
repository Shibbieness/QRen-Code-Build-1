"""
QRenCode — QRenCode Container Format (QRCF) v1
================================================

Self-contained encoder/decoder for the QRenCode system.
Produces hybrid PNG+XQPE containers and standalone .xqmem files.

This is NOT CodexOmega. This is a standalone format + runtime system.
"""

from qrcf_types import (
    BlockType, CompressionTier, NormalizationProfile, EdgeType,
    QRenError, QRenFormatError, QRenIntegrityError,
)
from qrcf_encoder import QRenEncoder
from qrcf_decoder import QRenDecoder, decode_file

__version__ = "1.0.0-phase1"
__all__ = [
    'QRenEncoder', 'QRenDecoder', 'decode_file',
    'BlockType', 'CompressionTier', 'NormalizationProfile', 'EdgeType',
    'QRenError', 'QRenFormatError', 'QRenIntegrityError',
]
