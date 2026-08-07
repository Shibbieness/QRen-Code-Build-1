"""Tests for the Vanilla Core flavor adapter.

Deliberately does not import vanilla_core — the adapter must stay usable on
its own, so these drive it exactly the way any host would: run(capability,
params). Run: python -m unittest test_flavor -v
"""

import tempfile
import unittest
from pathlib import Path

import vanilla_flavor
from vanilla_flavor import FlavorError, run


def _encode_to(tmp: str, data=None, **kw) -> dict:
    return run(
        "encode",
        {
            "data": data if data is not None else {"a": 1, "b": "hello world hello world"},
            "output": str(Path(tmp) / "t.qren.png"),
            **kw,
        },
    )


class TestContract(unittest.TestCase):
    def test_declared_capabilities_all_dispatch(self):
        for cap in vanilla_flavor.CAPABILITIES:
            self.assertIn(cap, vanilla_flavor._DISPATCH, f"{cap} declared but not dispatchable")

    def test_unknown_capability_raises(self):
        with self.assertRaises(FlavorError):
            run("not-a-capability", {})

    def test_default_capability_is_self_test(self):
        self.assertTrue(run(None, {})["ok"])

    def test_missing_required_param_raises(self):
        with self.assertRaises(FlavorError):
            run("decode", {})


class TestRoundTrip(unittest.TestCase):
    def test_self_test_round_trips(self):
        result = run("self-test", {})
        self.assertTrue(result["ok"])
        self.assertTrue(result["valid"])
        self.assertIn("vanilla", result["round_tripped"])

    def test_encode_decode_round_trip(self):
        payload = {"x": list(range(50)), "s": "round trip " * 20}
        with tempfile.TemporaryDirectory() as tmp:
            enc = _encode_to(tmp, data=payload)
            dec = run("decode", {"path": enc["paths"]["xqmem"]})
        self.assertEqual(dec["data_encoding"], "utf-8")
        self.assertIn("round trip", dec["data"])
        self.assertTrue(dec["valid"])

    def test_block_type_is_honored(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_encode_to(tmp, block_type="FRACTAL")["block_type"], "FRACTAL")

    def test_unknown_block_type_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FlavorError):
                _encode_to(tmp, block_type="NOT_A_BLOCK")

    def test_unknown_compression_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FlavorError):
                _encode_to(tmp, compression="NOT_A_TIER")


class TestVerify(unittest.TestCase):
    def test_intact_archive_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            enc = _encode_to(tmp)
            self.assertTrue(run("verify", {"path": enc["paths"]["xqmem"]})["ok"])

    def test_corrupted_archive_fails_verification(self):
        """Regression: integrity failures surface in the decode result as
        valid=False, not only as a raised exception. An adapter that checks
        only for exceptions reports corrupted archives as ok."""
        with tempfile.TemporaryDirectory() as tmp:
            enc = _encode_to(tmp)
            src = Path(enc["paths"]["xqmem"])
            raw = bytearray(src.read_bytes())
            for divisor in (3, 7, 11):
                blob = bytearray(raw)
                blob[len(blob) // divisor] ^= 0xFF
                bad = Path(tmp) / f"bad{divisor}.xqmem"
                bad.write_bytes(bytes(blob))
                result = run("verify", {"path": str(bad)})
                self.assertFalse(result["ok"], f"corruption at len/{divisor} not detected")
                self.assertTrue(result["validation_errors"])

    def test_missing_file_raises(self):
        with self.assertRaises(FlavorError):
            run("verify", {"path": "/nonexistent/nope.xqmem"})


class TestBlockTypes(unittest.TestCase):
    def test_lists_canonical_types_and_tiers(self):
        result = run("block-types", {})
        names = {b["name"] for b in result["block_types"]}
        self.assertTrue({"TREE", "ICE", "FLAME", "FRACTAL", "AMORPHOUS"} <= names)
        self.assertTrue(any(t["name"] == "T2_ZSTD" for t in result["compression_tiers"]))


if __name__ == "__main__":
    unittest.main()
