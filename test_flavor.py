"""Tests for the Vanilla Core flavor adapter.

Deliberately does not import vanilla_core — the adapter must stay usable on
its own, so these drive it exactly the way any host would: run(capability,
params). Run: python -m unittest test_flavor -v
"""

import base64
import json
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

    def test_every_dispatchable_capability_is_declared(self):
        """The other direction from the test above. A handler that works but
        is not in CAPABILITIES is invisible to any host that reads the
        manifest to decide what this flavor can do."""
        for cap in vanilla_flavor._DISPATCH:
            self.assertIn(cap, vanilla_flavor.CAPABILITIES,
                          f"{cap} is dispatchable but undeclared")

    def test_manifest_matches_the_code(self):
        """flavor.toml is what a host reads before importing anything. Two
        lists of capabilities with nothing checking them against each other
        is how a manifest starts promising a capability that was renamed."""
        import tomllib

        manifest = tomllib.loads((Path(__file__).parent / "flavor.toml").read_text())
        self.assertEqual(set(manifest["flavor"]["capabilities"]),
                         set(vanilla_flavor.CAPABILITIES))
        self.assertEqual(manifest["flavor"]["entrypoint"], "vanilla_flavor:run")


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


# ══════════════════════════════════════════════════════════════════════════
# Semantic layer — the four capabilities added when the two QRen copies were
# consolidated onto one package. Each was written before the capability was
# added to CAPABILITIES, so the manifest never promised an untested claim.
# ══════════════════════════════════════════════════════════════════════════


class TestClassify(unittest.TestCase):
    def test_classifies_by_extension(self):
        result = run("classify", {"content": "def hello(): pass",
                                  "filename": "m.py"})
        self.assertIsNotNone(result["type_code"])
        self.assertFalse(result["uncertain"])

    def test_explicit_declaration_wins(self):
        """CASL floor invariant 3. A caller that has already decided must not
        be overruled by a sniffing rule."""
        result = run("classify", {"content": "nothing in particular",
                                  "filename": "x.unknown",
                                  "metadata": {"declared_type": "0x0B"}})
        self.assertEqual(result["type_code"], "0x0B")
        self.assertTrue(result["declaration_respected"])
        self.assertEqual(result["confidence"], 1.0)

    def test_unclassifiable_content_is_uncertain_not_guessed(self):
        result = run("classify", {"content": "zzz random noise",
                                  "filename": "x.unknown"})
        self.assertTrue(result["uncertain"])

    def test_non_ascii_text_is_not_mistaken_for_runic(self):
        """REGRESSION. The runic rule was `"[ᚠ-᛿]".encode("utf-8")`, which
        produces a BYTE class spanning 0xA0-0xE1 rather than a codepoint
        range. That is the lead byte of nearly every non-ASCII script, so
        ordinary accented, Greek and Japanese text all came back RUNIC at
        0.85 confidence with uncertain=False.

        A misclassification is worse than a refusal here: uncertain=False is
        the classifier telling the caller not to look any further."""
        for text in ("café", "naïve résumé", "Grüße", "ΑΒΓΔ", "日本語のテキスト"):
            result = run("classify", {"content": text, "filename": "x.unknown"})
            self.assertNotEqual(result["type_name"], "RUNIC",
                                f"{text!r} classified as runic")

    def test_actual_runic_glyphs_are_still_detected(self):
        """The other half. A fix that stopped matching runic text would trade
        a false positive for a false negative and pass the test above."""
        for text in ("ᚠᚡᚢ", "ᚠ at the start", "ends with ᛿"):
            result = run("classify", {"content": text, "filename": "x.unknown"})
            self.assertEqual(result["type_name"], "RUNIC",
                             f"{text!r} is runic and was not detected")

    def test_content_hash_is_echoed_and_content_unmodified(self):
        """CASL floor invariant 1, checked across the adapter boundary: the
        hash the classifier returns must be the hash of what we sent, not of
        something the adapter normalized on the way in."""
        import hashlib

        body = "a payload the adapter must not touch\n"
        result = run("classify", {"content": body, "filename": "n.txt"})
        self.assertEqual(result["echoed_content_hash"],
                         hashlib.sha256(body.encode("utf-8")).hexdigest())

    def test_identical_input_gives_identical_output(self):
        """CASL floor invariant 4."""
        params = {"content": "ambiguous", "filename": "x.unknown"}
        first = run("classify", dict(params))
        for _ in range(5):
            self.assertEqual(run("classify", dict(params)), first)

    def test_result_is_json_serializable(self):
        json.dumps(run("classify", {"content": "x", "filename": "a.py"}))

    def test_missing_content_raises(self):
        with self.assertRaises(FlavorError):
            run("classify", {"filename": "a.py"})

    def test_non_text_content_raises_rather_than_str_coercing(self):
        """str()-ing an int would classify the string '5', which is a
        different question than the caller asked."""
        with self.assertRaises(FlavorError):
            run("classify", {"content": 5})


class TestSlimePhase(unittest.TestCase):
    def test_amorphous_without_a_trigger_does_not_advance(self):
        """The lifecycle is trigger-driven. A phase that advanced merely
        because it was asked would make the triggers decorative."""
        result = run("slime-phase", {"identity": "b1"})
        self.assertFalse(result["advanced"])
        self.assertEqual(result["state"], "AMORPHOUS")
        self.assertEqual(result["block_type"], "AMORPHOUS")

    def test_a_trigger_advances_amorphous_to_ice(self):
        result = run("slime-phase", {"identity": "b1",
                                     "triggers": ["diff_count"]})
        self.assertTrue(result["advanced"])
        self.assertEqual(result["state_from"], "AMORPHOUS")
        self.assertEqual(result["state"], "ICE")
        self.assertEqual(result["block_code"], "0x02")

    def test_ice_advances_to_crystal(self):
        result = run("slime-phase", {"identity": "b1", "state": "ICE",
                                     "triggers": ["dependency_saturation"]})
        self.assertEqual(result["state"], "CRYSTAL")
        self.assertEqual(result["block_code"], "0x0D")

    def test_crystal_is_terminal(self):
        result = run("slime-phase", {"identity": "b1", "state": "CRYSTAL",
                                     "triggers": ["explicit_flag"]})
        self.assertFalse(result["advanced"])
        self.assertFalse(result["can_advance"])
        self.assertEqual(result["state"], "CRYSTAL")

    def test_advance_false_inspects_without_moving(self):
        result = run("slime-phase", {"identity": "b1", "triggers": ["diff_count"],
                                     "advance": False})
        self.assertFalse(result["advanced"])
        self.assertTrue(result["can_advance"])
        self.assertEqual(result["state"], "AMORPHOUS")

    def test_unknown_trigger_raises(self):
        with self.assertRaises(FlavorError):
            run("slime-phase", {"identity": "b1", "triggers": ["wishful_thinking"]})

    def test_unknown_state_raises(self):
        with self.assertRaises(FlavorError):
            run("slime-phase", {"identity": "b1", "state": "MOLTEN"})

    def test_crystal_baby_fusion_of_two_ice_parents(self):
        result = run("slime-phase", {"identity": "a", "state": "ICE",
                                     "fuse_with": "b"})
        self.assertEqual(result["operation"], "crystal-baby-fusion")
        self.assertEqual(result["state"], "CRYSTAL")
        self.assertNotIn(result["identity"], ("a", "b"))
        self.assertEqual(result["parents"], ["a", "b"])

    def test_fusion_identity_is_derived_and_stable(self):
        first = run("slime-phase", {"identity": "a", "state": "ICE", "fuse_with": "b"})
        again = run("slime-phase", {"identity": "a", "state": "ICE", "fuse_with": "b"})
        self.assertEqual(first["identity"], again["identity"])

    def test_fusion_refuses_a_non_ice_parent(self):
        """Reported as a FlavorError, not leaked as a raw ValueError — a
        refused fusion is an answer about the input, not an adapter fault."""
        with self.assertRaises(FlavorError):
            run("slime-phase", {"identity": "a", "state": "AMORPHOUS",
                                "fuse_with": "b"})


class TestTokens(unittest.TestCase):
    def test_lists_all_three_runic_tokens(self):
        result = run("tokens", {})
        self.assertEqual(result["count"], 3)
        self.assertEqual({t["name"] for t in result["tokens"]},
                         {"Training Block", "Enhanced Agent", "Integration Failure"})

    def test_each_token_maps_to_a_real_block_type(self):
        for token in run("tokens", {})["tokens"]:
            self.assertIsNotNone(token["block_type"],
                                 f"{token['token']} has no block type")

    def test_state_is_computed_from_the_build_not_the_document(self):
        """EA is EMBER in the source document because IF#6 and IF#7 were
        unwired there. Both are wired in this stack, so the live state is
        active. A token reporting a doc snapshot would be stating something
        false about the code."""
        ea = run("tokens", {"token": "EA"})["tokens"][0]
        self.assertEqual(ea["state"], "active")

    def test_lookup_by_symbol_and_by_name(self):
        self.assertEqual(run("tokens", {"token": "⟨TB⟩"})["count"], 1)
        self.assertEqual(run("tokens", {"token": "TB"})["count"], 1)

    def test_unknown_token_raises(self):
        with self.assertRaises(FlavorError):
            run("tokens", {"token": "ZZ"})

    def test_result_is_json_serializable(self):
        json.dumps(run("tokens", {}))


class TestCircle(unittest.TestCase):
    def test_plain_text_is_mode_1(self):
        result = run("circle", {"input": "what block type is this"})
        self.assertEqual(result["io_mode"], "mode_1_natural_language")
        self.assertEqual(result["input_block_type"], "AMORPHOUS")
        self.assertIn("what block type is this", result["output"])

    def test_qrcf_bytes_are_detected_as_mode_2(self):
        """Mode detection is by magic bytes, not by a caller-supplied flag —
        the flag is what a caller gets wrong."""
        from qren.tokens import TB

        wire = TB.to_block(payload=b"training").encode()
        result = run("circle", {"input": base64.b64encode(wire).decode(),
                                "input_encoding": "base64"})
        self.assertEqual(result["io_mode"], "mode_2_qrcf_native")
        self.assertEqual(result["routed_context"], "training_block_context")

    def test_mode_2_output_round_trips_back_to_a_block(self):
        from qren.tokens import EA
        from qren.wire_format import QRCFBlock

        wire = EA.to_block(payload=b"agent").encode()
        result = run("circle", {"input": base64.b64encode(wire).decode(),
                                "input_encoding": "base64"})
        self.assertEqual(result["output"]["encoding"], "base64")
        back = QRCFBlock.decode(base64.b64decode(result["output"]["value"]))
        self.assertEqual(back.payload, b"agent")
        self.assertEqual(back.metadata["token"], "⟨EA⟩")

    def test_unrecognised_token_routes_to_a_generic_context(self):
        """Routing must not fail closed on a block it has no token for —
        every block reaches some context or the boundary drops traffic."""
        result = run("circle", {"input": "plain"})
        self.assertEqual(result["routed_context"], "generic_amorphous_context")

    def test_mode_3a_forces_nl_to_block(self):
        result = run("circle", {"input": "describe this", "mode": "3A"})
        self.assertEqual(result["io_mode"], "mode_3a_nl_to_qrcf")
        self.assertEqual(result["output"]["block"]["encoding"], "base64")

    def test_mode_3b_requires_bytes(self):
        with self.assertRaises(FlavorError):
            run("circle", {"input": "not bytes", "mode": "3B"})

    def test_unknown_mode_raises(self):
        with self.assertRaises(FlavorError):
            run("circle", {"input": "x", "mode": "9Z"})

    def test_bad_base64_raises_flavor_error(self):
        with self.assertRaises(FlavorError):
            run("circle", {"input": "not!valid!base64", "input_encoding": "base64"})

    def test_output_is_json_serializable_in_every_mode(self):
        """Mode 2 and 3A carry raw wire bytes. Returning them unchanged
        would break the one contract this adapter exists to satisfy."""
        from qren.tokens import IF

        wire = IF.to_block(payload=b"\x00\xff").encode()
        b64 = base64.b64encode(wire).decode()
        for params in ({"input": "text"},
                       {"input": b64, "input_encoding": "base64"},
                       {"input": "text", "mode": "3A"},
                       {"input": b64, "input_encoding": "base64", "mode": "3B"}):
            json.dumps(run("circle", dict(params)))


if __name__ == "__main__":
    unittest.main()
