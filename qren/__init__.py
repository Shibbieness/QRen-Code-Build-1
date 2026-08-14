"""
QRen — everything the skill stack's various QRen-named skills describe,
pulled into one place. Self-contained: no import dependency on
sovereign_py/ or vi_builder/; those systems could adopt QRen encoding, but
QRen doesn't require either to exist.

This package now has two layers, deliberately kept separate rather than
forced into one artificial wire format:

  qren/ (this level)     — block_types.py, wire_format.py, tokens.py,
                            crystal_slime.py, magic_circle.py, classifier.py.
                            Implements ml-filesystem-monolith sub-skill C's
                            own magic-circle spec: the 14(+CUSTOM)-type
                            taxonomy, a minimal illustrative wire format
                            (SAIP magic), the TB/EA/IF tokens, Crystal
                            Slime, and the three-mode I/O boundary.

  qren/qrcf/              — the real, separately-tested QRenCode Container
                            Format (QREN/XQPE magic, PNG+trailer container,
                            Circle 0-3 structure, Merkle integrity,
                            circle-rule inheritance). qren-coder describes
                            this explicitly as "NOT CodexOmega... a
                            standalone format + runtime system" — it was
                            never meant to be the same artifact as the
                            magic-circle layer above, so it isn't force-fit
                            into one.

  classifier.py            — vendored from qren-type-system's Skill #1
                            (block-type-classifier-v1 + Skill #16's
                            auto-detection-ruleset): a deterministic,
                            CASL-floor-tested classifier that reads a
                            file's content/extension and returns a block
                            type with a confidence score. Shares this
                            package's block_types.py registry rather than
                            duplicating it.

Both wire formats independently encode/decode the same conceptual block
type taxonomy; they intentionally do not share bytes on the wire. Bridging
them (translating one container format into the other) is future work if
it's ever actually needed, not assumed here.

Layout note
-----------
This package lives in a `qren/` subdirectory rather than at the repository
root because the root directory name contains hyphens and so can never be a
Python package. Putting it here means `python -m qren.qrcf.test_phase1` works
from a fresh checkout, and vendoring into another tree is a plain directory
copy with no import rewriting.

The adapter (`vanilla_flavor.py`) and its tests sit at the repository root,
one level above, so the vendorable unit stays free of host-contract code.

This directory was, until consolidation, duplicated across two repositories.
The copies had diverged: one held six extra block types and the phase-2 work,
the other held the flavor adapter and a regression test for a falsy-enum bug
that existed in both. Neither was a superset of the other in what mattered,
which is why the merge was done by carrying tests across rather than by
picking the copy with the higher count.
"""
