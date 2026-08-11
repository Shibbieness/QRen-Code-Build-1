"""
QRenCode Phase 1 — Test Harness & Demonstration
=================================================

Round-trip verification: data → QRCF → data
Tests all Phase 1 functionality:
  1. QRCF container encode/decode (PNG + XQPE trailer)
  2. .xqmem standalone encode/decode
  3. Multiple block types with auto-detection
  4. Integrity verification (section hashes, Merkle root, CAS)
  5. Compression tier validation
  6. Circle 0/1/2/3 structure verification
  7. Runic tag encoding/decoding
  8. Growth space handling
  9. MVQ (Minimum Viable QRenCode) validation
  10. Error handling (truncation, corruption, missing data)

Run: python test_phase1.py
"""

import os
import sys
import json
import time
import hashlib
import tempfile
import traceback
from pathlib import Path

# Ensure we can import from current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from qrcf_types import (
    QREN_MAGIC, XQPE_MAGIC, QRCF_VERSION,
    BlockType, CompressionTier, NormalizationProfile,
    SectionEntry, BlockHeader, TrailerHeader, IntegrityBlock,
    QRenFormatError, QRenIntegrityError,
    content_address, merkle_root, auto_detect_block_type,
)
from qrcf_encoder import QRenEncoder
from qrcf_decoder import QRenDecoder


# ═══════════════════════════════════════════════════════════════
# TEST INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════

class TestResult:
    def __init__(self, name):
        self.name = name
        self.passed = False
        self.message = ""
        self.elapsed = 0.0

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"  [{status}] {self.name} ({self.elapsed:.1f}ms){': ' + self.message if self.message else ''}"


def run_test(name, func):
    """Run a single test, catching exceptions."""
    result = TestResult(name)
    start = time.time()
    try:
        func(result)
        result.passed = True
    except AssertionError as e:
        result.message = str(e) or "Assertion failed"
    except Exception as e:
        result.message = f"{type(e).__name__}: {e}"
    result.elapsed = (time.time() - start) * 1000
    return result


# ═══════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════

def test_types_serialization(r):
    """Test SectionEntry, BlockHeader, TrailerHeader, IntegrityBlock round-trip."""
    # SectionEntry
    se = SectionEntry(circle_id=3, offset=1024, length=2048,
                      hash=b'\xAB' * 32)
    packed = se.pack()
    assert len(packed) == SectionEntry.PACKED_SIZE, f"SectionEntry packed size: {len(packed)}"
    se2 = SectionEntry.unpack(packed)
    assert se2.circle_id == 3
    assert se2.offset == 1024
    assert se2.length == 2048
    assert se2.hash == b'\xAB' * 32
    
    # TrailerHeader
    th = TrailerHeader(version=QRCF_VERSION, trailer_len=9999,
                       offset_c1=256, num_circles=3, flags=0x0001)
    packed = th.pack()
    assert len(packed) == TrailerHeader.PACKED_SIZE
    th2 = TrailerHeader.unpack(packed)
    assert th2.version == QRCF_VERSION
    assert th2.trailer_len == 9999
    assert th2.num_circles == 3
    assert th2.flags == 0x0001
    
    # BlockHeader
    bh = BlockHeader(
        block_id=b'\x01' * 32,
        block_type=BlockType.TREE,
        normalization=NormalizationProfile.SEMANTIC,
        compression=CompressionTier.T2_ZSTD,
        flags=0,
        data_length=512,
        runic_tags=['\u16DE\u16A8\u16CF\u16A8', 'code']
    )
    packed = bh.pack()
    bh2, consumed = BlockHeader.unpack(packed)
    assert bh2.block_type == BlockType.TREE
    assert bh2.normalization == NormalizationProfile.SEMANTIC
    assert bh2.compression == CompressionTier.T2_ZSTD
    assert bh2.data_length == 512
    assert len(bh2.runic_tags) == 2
    assert bh2.runic_tags[1] == 'code'
    
    # IntegrityBlock
    ib = IntegrityBlock(merkle_root=b'\xCC' * 32,
                        userseed_hash=b'\x00' * 32,
                        signature=b'')
    packed = ib.pack()
    ib2 = IntegrityBlock.unpack(packed)
    assert ib2.merkle_root == b'\xCC' * 32
    assert ib2.userseed_hash == b'\x00' * 32


def test_merkle_root(r):
    """Test Merkle root computation."""
    # Empty → zeros
    assert merkle_root([]) == b'\x00' * 32
    
    # Single → same hash
    h = content_address(b'hello')
    assert merkle_root([h]) == h
    
    # Two hashes → combined
    h1 = content_address(b'hello')
    h2 = content_address(b'world')
    root = merkle_root([h1, h2])
    expected = hashlib.sha256(h1 + h2).digest()
    assert root == expected
    
    # Three hashes (odd count → pad)
    h3 = content_address(b'test')
    root3 = merkle_root([h1, h2, h3])
    assert len(root3) == 32
    assert root3 != root  # Different from 2-hash root


def test_auto_detect(r):
    """Test block type auto-detection."""
    assert auto_detect_block_type(b'', 'code.py') == BlockType.TREE
    assert auto_detect_block_type(b'', 'model.pt') == BlockType.FRACTAL
    assert auto_detect_block_type(b'', 'config.json') == BlockType.GEOMETRIC
    assert auto_detect_block_type(b'', 'os.iso') == BlockType.FLAME
    assert auto_detect_block_type(b'', 'notes.txt') == BlockType.AMORPHOUS
    
    # Content sniffing
    assert auto_detect_block_type(b'def hello():\n    pass', '') == BlockType.TREE
    assert auto_detect_block_type(b'{"key": "value"}', '') == BlockType.GEOMETRIC
    assert auto_detect_block_type(b'\x00\x01\x02\x03', '') == BlockType.AMORPHOUS


def test_basic_roundtrip(r):
    """Test basic encode → decode round-trip with dict data."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    test_data = {
        "name": "QRenCode Phase 1 Test",
        "version": 1,
        "items": ["alpha", "beta", "gamma"],
        "nested": {"key": "value", "count": 42}
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "test.qren.png")
        
        result = encoder.encode(
            data=test_data,
            name="test_basic",
            block_type=BlockType.GEOMETRIC,
            runic_tags=["test", "phase1"],
            output_path=outpath,
            output_xqmem=True
        )
        
        assert os.path.exists(outpath), "QRCF file not created"
        assert result['block_type'] == 'GEOMETRIC'
        assert result['compression_ratio'] > 0
        assert result['num_circles'] == 3
        
        # Decode
        decoded = decoder.decode(outpath)
        assert decoded['valid'], f"Decode errors: {decoded['validation_errors']}"
        assert decoded['data'] is not None, "No data extracted"
        
        # Verify round-trip
        reconstructed = json.loads(decoded['data'].decode('utf-8'))
        assert reconstructed == test_data, \
            f"Round-trip mismatch:\n  Original: {test_data}\n  Decoded:  {reconstructed}"
        
        # Verify manifest
        assert decoded['manifest'] is not None
        assert decoded['manifest']['name'] == 'test_basic'
        assert decoded['manifest']['block_count'] == 1
        
        # Verify translation layer
        assert decoded['translation'] is not None
        assert 'compression_codecs' in decoded['translation']
        assert 'block_type_registry' in decoded['translation']
        
        r.message = f"Encoded {result['size_original']}B → {result['size_qrcf']}B, ratio {result['compression_ratio']}:1"


def test_string_roundtrip(r):
    """Test round-trip with string data."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    test_string = "Hello, QRenCode! 🌳⚡🔥❄️ Unicode works."
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "string.qren.png")
        result = encoder.encode(data=test_string, name="string_test",
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        assert decoded['valid']
        assert decoded['data'].decode('utf-8') == test_string


def test_bytes_roundtrip(r):
    """Test round-trip with raw binary data."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    test_bytes = bytes(range(256)) * 100  # 25.6 KB of all byte values
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "binary.qren.png")
        result = encoder.encode(data=test_bytes, name="binary_test",
                                 block_type=BlockType.AMORPHOUS,
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        assert decoded['valid']
        assert decoded['data'] == test_bytes, "Binary round-trip mismatch"
        r.message = f"{len(test_bytes)}B → {result['size_compressed']}B compressed"


def test_xqmem_roundtrip(r):
    """Test .xqmem standalone file round-trip."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    test_data = {"standalone": True, "format": "xqmem"}
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "test.qren.png")
        result = encoder.encode(data=test_data, name="xqmem_test",
                                 output_path=outpath, output_xqmem=True)
        
        xqmem_path = result['paths']['xqmem']
        assert os.path.exists(xqmem_path), ".xqmem file not created"
        
        decoded = decoder.decode(xqmem_path)
        assert decoded['valid']
        reconstructed = json.loads(decoded['data'].decode('utf-8'))
        assert reconstructed == test_data


def test_all_block_types(r):
    """Test encoding with every block type."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    for bt in BlockType:
        if bt == BlockType.CUSTOM:
            continue
        
        test_data = f"Block type test: {bt.name}"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            outpath = os.path.join(tmpdir, f"{bt.name.lower()}.qren.png")
            result = encoder.encode(data=test_data, name=f"test_{bt.name}",
                                     block_type=bt, output_path=outpath)
            assert result['block_type'] == bt.name
            
            decoded = decoder.decode(outpath)
            assert decoded['valid'], f"{bt.name} decode errors: {decoded['validation_errors']}"
            assert decoded['data'].decode('utf-8') == test_data
    
    r.message = f"All {len(BlockType) - 1} block types passed"


def test_runic_tags(r):
    """Test Runic tag encoding and retrieval."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    tags = ['\u16DE\u16A8\u16CF\u16A8',  # ᛞᚨᛏᚨ (Data)
            '\u16CF\u16B1\u16A8\u16D3\u16BE',  # ᛏᚱᚨᛁᚾ (Train)
            '\u16B2\u16A8\u16B2\u16BA\u16D6']  # ᚲᚨᚲᚺᛖ (Cache)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "runic.qren.png")
        result = encoder.encode(
            data={"runic": "test"},
            name="runic_test",
            runic_tags=tags,
            output_path=outpath
        )
        
        decoded = decoder.decode(outpath)
        assert decoded['valid']
        
        # Check tags in manifest
        assert decoded['manifest'] is not None
        index = decoded['manifest']['runic_index']
        assert set(index['tags']) == set(tags)
        
        # Check tags in block header
        assert len(decoded['blocks']) == 1
        assert set(decoded['blocks'][0]['runic_tags']) == set(tags)
    
    r.message = f"Round-tripped {len(tags)} Runic tags"


def test_integrity_verification(r):
    """Test that corrupted data is detected."""
    encoder = QRenEncoder()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "integrity.qren.png")
        encoder.encode(data="integrity test", name="integrity",
                        output_path=outpath)
        
        # Read and corrupt the file
        data = Path(outpath).read_bytes()
        
        # Flip a byte in the trailer (near the end, in data block area)
        corrupted = bytearray(data)
        corrupt_pos = len(data) - 100  # Near end, in circle 3 data
        corrupted[corrupt_pos] ^= 0xFF
        corrupted = bytes(corrupted)
        
        # Decode with verification — should detect corruption
        decoder_strict = QRenDecoder(verify_integrity=True)
        decoded = decoder_strict.decode_bytes(corrupted)
        assert not decoded['valid'], "Corruption should have been detected"
        assert len(decoded['validation_errors']) > 0
        
        r.message = f"Corruption detected: {decoded['validation_errors'][0][:60]}"


def test_circle_0_extraction(r):
    """Test Circle 0 metadata extraction from PNG."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "circle0.qren.png")
        result = encoder.encode(data="circle 0 test", name="c0_test",
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        c0 = decoded.get('circle_0')
        assert c0 is not None, "Circle 0 not extracted"
        assert c0.get('parsed', False), f"Circle 0 not parsed: {c0}"
        assert c0.get('magic') == 'QREN'
        assert c0.get('num_circles') == 3


def test_growth_space(r):
    """Test growth space reservation."""
    encoder = QRenEncoder(growth_space_percent=20)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "growth.qren.png")
        result = encoder.encode(data="growth test data", name="growth",
                                 output_path=outpath)
        
        assert result['growth_reserved'] > 0
        r.message = f"Growth reserved: {result['growth_reserved']} bytes ({encoder.growth_space_percent}%)"


def test_large_data(r):
    """Test with ~100KB of data."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    # Generate ~100KB of structured data
    large_data = {
        "records": [
            {"id": i, "name": f"record_{i}", "value": f"{'x' * 100}"}
            for i in range(500)
        ]
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "large.qren.png")
        result = encoder.encode(data=large_data, name="large_test",
                                 block_type=BlockType.GEOMETRIC,
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        assert decoded['valid']
        reconstructed = json.loads(decoded['data'].decode('utf-8'))
        assert len(reconstructed['records']) == 500
        
        r.message = (f"{result['size_original']}B → {result['size_compressed']}B "
                     f"({result['compression_ratio']}:1)")


def test_mvq_validation(r):
    """
    Validate Minimum Viable QRenCode (MVQ) requirements:
    1. Circle 0 QR with XQPE header ✓
    2. Circle 1 translation layer ✓
    3. One data block (Circle 3) ✓
    4. Integrity block ✓
    """
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "mvq.qren.png")
        result = encoder.encode(data="MVQ test", name="mvq",
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        
        # MVQ Requirement 1: Circle 0 present
        assert decoded.get('circle_0') is not None, "MVQ: Circle 0 missing"
        
        # MVQ Requirement 2: Circle 1 (translation) present
        assert decoded.get('translation') is not None, "MVQ: Circle 1 (translation) missing"
        
        # MVQ Requirement 3: At least one data block
        assert decoded.get('block_count', 0) >= 1, "MVQ: No data blocks"
        
        # MVQ Requirement 4: Integrity block present
        assert decoded['profile_a']['integrity']['merkle_root'] is not None, \
            "MVQ: Integrity block missing"
        
        # Overall validity
        assert decoded['valid'], f"MVQ validation failed: {decoded['validation_errors']}"
        
        r.message = "All 4 MVQ requirements satisfied"


def test_empty_data(r):
    """Test encoding empty data."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "empty.qren.png")
        result = encoder.encode(data=b"", name="empty",
                                 output_path=outpath)
        
        decoded = decoder.decode(outpath)
        assert decoded['valid']
        assert decoded['data'] == b""



def test_unknown_block_type_is_not_silent(r):
    """REGRESSION. An archive carrying a block type this decoder does not know
    must report valid=False and preserve the bytes.

    Before the fix this was total silent data loss reported as success:
    BlockHeader.unpack calls BlockType(byte), which raises ValueError on an
    unknown code; _extract_data_blocks caught that as "growth space reached"
    and stopped; and `valid` was computed from validation_errors on a separate
    path that never learned blocks had been dropped. A newer archive decoded
    as `valid: True, blocks: 0, data: None`.

    The block frame is located by its block_id — the content address of the
    payload, which is unique in the archive — rather than by scanning for a
    matching type byte. An earlier draft of this test scanned, hit an
    unrelated 0x01 inside the PNG data, patched a random byte and passed
    against the broken decoder. A regression test that can find the wrong
    thing is worse than none.
    """
    encoder = QRenEncoder()
    # verify_integrity=False ON PURPOSE, and this is the crux of the test.
    #
    # Patching a type byte also invalidates the circle hash and merkle
    # root, so with integrity on the archive is rejected by the hash check
    # and the unknown-type path is never reached — the test would pass
    # against the broken decoder for entirely the wrong reason.
    #
    # A genuine archive from a newer QRen carries CORRECT hashes and an
    # unknown type. Turning integrity off is how a locally-forged block
    # reproduces that shape. With it off, the pre-fix decoder returns
    # valid=True, block_count=0, data=None, errors=[] — the defect, bare.
    decoder = QRenDecoder(verify_integrity=False)

    unused = next(c for c in range(0x01, 0xFF)
                  if c not in {b.value for b in BlockType})

    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "unknown.qren.png")
        encoder.encode(data={"payload": "must not vanish"}, name="unknown",
                       block_type=BlockType.TREE, output_path=outpath)
        with open(outpath, "rb") as fh:
            blob = fh.read()

        # Sanity: it decodes cleanly before we touch it.
        clean = decoder.decode_bytes(blob)
        assert clean['valid'], "fixture archive is not valid before patching"
        assert clean['block_count'] == 1, "expected exactly one block"

        block_id = bytes.fromhex(clean['blocks'][0]['block_id'])
        idx = blob.find(block_id)
        assert idx != -1, "could not locate the block frame by its block_id"
        assert blob[idx + 32] == BlockType.TREE.value, \
            "block_id found but the type byte is not where the layout says"

        patched = bytearray(blob)
        patched[idx + 32] = unused
        decoded = decoder.decode_bytes(bytes(patched))

        assert decoded['valid'] is False, (
            "an archive with an unknown block type reported valid=True — "
            "this is the silent data-loss regression"
        )
        assert decoded['validation_errors'], "no validation error was recorded"
        assert any("unrecognised" in e.lower() or "unknown" in e.lower()
                   for e in decoded['validation_errors']), \
            f"error does not name the cause: {decoded['validation_errors']}"
        assert decoded['block_count'] >= 1, (
            "the unknown block was dropped entirely; an unknown type is not a "
            "reason to lose bytes"
        )


def test_growth_space_still_stops_cleanly(r):
    """The counterpart. Making unknown types loud must not make growth space
    loud — trailing zeros are a normal, valid end of section."""
    encoder = QRenEncoder()
    decoder = QRenDecoder()
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, "growth.qren.png")
        encoder.encode(data={"a": 1}, name="growth", output_path=outpath)
        decoded = decoder.decode(outpath)
        assert decoded['valid'], \
            f"growth space was reported as an error: {decoded['validation_errors']}"
        assert decoded['validation_errors'] == []
        assert decoded['data'] is not None

# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

def main():
    tests = [
        ("Type Serialization Round-Trip", test_types_serialization),
        ("Merkle Root Computation", test_merkle_root),
        ("Auto-Detect Block Type", test_auto_detect),
        ("Basic Dict Round-Trip", test_basic_roundtrip),
        ("String Round-Trip", test_string_roundtrip),
        ("Binary Round-Trip", test_bytes_roundtrip),
        ("XQMEM Standalone Round-Trip", test_xqmem_roundtrip),
        ("All Block Types", test_all_block_types),
        ("Runic Tag Round-Trip", test_runic_tags),
        ("Integrity Verification", test_integrity_verification),
        ("Circle 0 Extraction", test_circle_0_extraction),
        ("Growth Space Reservation", test_growth_space),
        ("Large Data (~100KB)", test_large_data),
        ("MVQ Validation", test_mvq_validation),
        ("Empty Data", test_empty_data),
        ("Unknown Block Type Is Not Silent", test_unknown_block_type_is_not_silent),
        ("Growth Space Still Stops Cleanly", test_growth_space_still_stops_cleanly),
    ]
    
    print("=" * 72)
    print("  QRenCode Phase 1 — Test Suite")
    print("  QRCF Container Format v1 Encoder/Decoder")
    print("=" * 72)
    print()
    
    results = []
    for name, func in tests:
        result = run_test(name, func)
        results.append(result)
        print(result)
    
    print()
    print("-" * 72)
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total_ms = sum(r.elapsed for r in results)
    
    print(f"  Results: {passed} passed, {failed} failed, "
          f"{len(results)} total ({total_ms:.0f}ms)")
    
    if failed > 0:
        print()
        print("  FAILED TESTS:")
        for r in results:
            if not r.passed:
                print(f"    • {r.name}: {r.message}")
    
    print("=" * 72)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
