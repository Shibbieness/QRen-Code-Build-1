"""
QRCF — QRenCode Container Format v1. Vendored from the qren-coder skill's
modules/qren_coder/ package, which describes it as "NOT CodexOmega... a
standalone format + runtime system." Phase 1 wire format FROZEN, 15/15
tests passing in the original build session (verified again in this repo
by test_phase1.py — see qren/README or the commit that added this).

Distinct from the rest of qren/ (block_types.py, wire_format.py, tokens.py,
magic_circle.py): those implement the *ml-filesystem-monolith* sub-skill C
magic-circle spec's own minimal illustrative wire format, appropriate to
that document's scope. This package is the real, separately-developed,
separately-tested QRenCode format that qren-coder ships. The two were
never meant to be the same artifact — see qren/__init__.py for the full
relationship.

Package contents:
  qrcf_types.py          — wire format: block-type enum, compression tiers,
                            normalization profiles, headers
  qrcf_encoder.py        — encoder (Circle 0/1/2/3 builders)
  qrcf_decoder.py        — decoder (Profile A/B/C, integrity verification)
  qrcf_types_phase2.py   — Tier-2 per-type headers, validators, cache layer
  qrcf_circle_rules.py   — circle rule inheritance (CircleRuleSet,
                            RuleChainResolver)
  test_phase1.py         — wire format / round-trip suite
  test_phase2.py         — Tier-2 header, validator and rule-chain suite

Both suites use their own runner, not unittest. Invoke them as modules:

    python -m qren.qrcf.test_phase1
    python -m qren.qrcf.test_phase2

`python -m unittest qren.qrcf.test_phase1` collects zero tests and reports
OK — the most convincing possible way to run nothing at all.

History worth keeping: this package once carried its own duplicate copy of
`BlockType` in qrcf_types_phase2.py, and block_types.py one level up carried
a third. All three agreed by luck; nothing checked. The duplicate is now an
import, LIGHT (0x0E) was added to the wire enum so it is encodable rather
than only classifiable, and test_phase1's `test_block_type_definitions_agree`
fails if the layers ever drift apart again.
"""

from .qrcf_types import (
    BlockType,
    CompressionTier,
    NormalizationProfile,
    EdgeType,
    QRenError,
    QRenFormatError,
    QRenIntegrityError,
    QRenCompressionError,
    QRenBlockError,
    content_address,
    merkle_root,
    auto_detect_block_type,
    BLOCK_NORMALIZATION,
)
from .qrcf_encoder import QRenEncoder
from .qrcf_decoder import QRenDecoder, decode_file

__version__ = "1.0.0"
__all__ = [
    'QRenEncoder', 'QRenDecoder', 'decode_file',
    'BlockType', 'CompressionTier', 'NormalizationProfile', 'EdgeType',
    'QRenError', 'QRenFormatError', 'QRenIntegrityError',
    'QRenCompressionError', 'QRenBlockError',
    'content_address', 'merkle_root', 'auto_detect_block_type',
]
