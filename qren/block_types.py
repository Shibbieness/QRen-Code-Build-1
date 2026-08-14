"""
QRen block type taxonomy — 14 types across three phases.

Per ml-filesystem-monolith sub-skill C ("QRen Magic Circle"): the block type
is the 1-byte wire code that declares what a block IS and how it is routed.
Phase 1 codes are frozen; Phase 2 codes are specified but were, until this
module, never given a Python implementation. LIGHT (0x0E) is the newest
addition (self-describing navigation type).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class BlockType:
    wire_code: int              # e.g. 0x01
    name: str
    phase: int                  # 1 or 2 (LIGHT is phase 2)
    core_property: str
    executable: bool = False
    pinned: bool = False
    crystal_slime: Optional[str] = None   # 'A' | 'B' | 'C' | None
    monolith_instances: str = ''

    @property
    def hex_code(self) -> str:
        return f"0x{self.wire_code:02X}"


# Phase 1 — Frozen Wire Codes
TREE = BlockType(0x01, 'TREE', 1, 'Living hierarchy, grows by branching',
                  crystal_slime=None, monolith_instances='All .py source files, source archive')
ICE = BlockType(0x02, 'ICE', 1, 'Frozen identity, zero outgoing edges',
                 crystal_slime='B', monolith_instances='Gameplans, capsule cores, fossil')
FLAME = BlockType(0x03, 'FLAME', 1, 'Executable, CALS Build mode', executable=True,
                   monolith_instances='integration.py, start.sh (EMBER = suspended)')
LIGHTNING = BlockType(0x04, 'LIGHTNING', 1, 'Deterministic fast path, AOT', executable=True,
                       monolith_instances='QUICK_FIX_GUIDE.md, routing tables')
FRACTAL = BlockType(0x05, 'FRACTAL', 1, 'Self-similar, recursive, T4 compression',
                     monolith_instances='Echo sub-skills, MONOLITH_ARCHITECTURE.md')
GEOMETRIC = BlockType(0x06, 'GEOMETRIC', 1, 'Structured, default navigation',
                       monolith_instances='Codex files, indexes, TAG_REGISTRY')
AMORPHOUS = BlockType(0x07, 'AMORPHOUS', 1, 'Mutable, pre-crystallization', crystal_slime='A',
                       monolith_instances='UI files, transcript, future update slots')

# Phase 2 — Specified Wire Codes
NESTED = BlockType(0x08, 'NESTED', 2, 'World within world, sub-capsule',
                    monolith_instances='Sub-capsules, magic circle QRVM')
RUNIC = BlockType(0x09, 'RUNIC', 2, 'Executable Runic ArCircle', executable=True,
                   monolith_instances='runic_native_subsystem.py, magic circle spec')
MYCELIUM = BlockType(0x0A, 'MYCELIUM', 2, 'Peer network, no root',
                      monolith_instances='Dependency maps, CALS mesh')
BONE = BlockType(0x0B, 'BONE', 2, 'Load-bearing scaffold, PINNED', pinned=True,
                  monolith_instances='Gameplans, config.py, database.py')
VOID = BlockType(0x0C, 'VOID', 2, 'Jump instruction, scope-close',
                  monolith_instances='ODIIS calls, ArCircle resets, EMBER gaps')
CRYSTAL = BlockType(0x0D, 'CRYSTAL', 2, 'Lattice, >=1 outgoing edge', crystal_slime='C',
                     monolith_instances='Integration Map, enhancements.py')

# New — self-describing navigation type
LIGHT = BlockType(0x0E, 'LIGHT', 2, 'Index / Glossary / Map Key / Routing Table',
                   monolith_instances='MASTER_INDEX.md, ROUTING_DESCRIPTION.md, BLOCK_TYPE_CATALOGUE.md')

# Escape hatch — confirmed live in both qren-coder's BlockType(IntEnum) and
# qren-type-system's block-type-classifier BLOCK_TYPES registry, though not
# named in the ml-filesystem-monolith sub-skill C taxonomy table itself.
CUSTOM = BlockType(0xFF, 'CUSTOM', 2, 'User-defined, no canonical type applies',
                    monolith_instances='Fallback when no other type fits; declared explicitly in metadata')

ALL_TYPES: List[BlockType] = [
    TREE, ICE, FLAME, LIGHTNING, FRACTAL, GEOMETRIC, AMORPHOUS,
    NESTED, RUNIC, MYCELIUM, BONE, VOID, CRYSTAL, LIGHT, CUSTOM,
]

BY_WIRE_CODE: Dict[int, BlockType] = {bt.wire_code: bt for bt in ALL_TYPES}
BY_NAME: Dict[str, BlockType] = {bt.name: bt for bt in ALL_TYPES}

# LIGHT's geometric shape vocabulary (spec: "13 geometric shapes with
# spatial orientation placed in a 3x3 grid"). Encoded here as the subset
# actually named in the spec; the full 13-shape catalogue lives in the
# qren-block-types capsule (not mounted) — this is the documented core,
# not silently expanded to a fabricated full set.
LIGHT_SHAPES: Dict[str, str] = {
    '▷': 'REQUIRES',
    '△': 'DERIVES_FROM',
    '⬧': 'CRYSTALLIZES',
}
LIGHT_ORIENTATIONS: Dict[int, str] = {
    0: 'active',
    45: 'pending',
    90: 'deprecated',
    135: 'protected',
}
# 3x3 grid rows, per spec: "top=dependencies, mid=peers, bottom=outputs"
LIGHT_GRID_ROWS = ('dependencies', 'peers', 'outputs')

# Crystal Slime lifecycle order (see crystal_slime.py for the state machine).
CRYSTAL_SLIME_ORDER = ('A', 'B', 'C')  # AMORPHOUS -> ICE -> CRYSTAL


def get(wire_code: int) -> Optional[BlockType]:
    return BY_WIRE_CODE.get(wire_code)


def get_by_name(name: str) -> Optional[BlockType]:
    return BY_NAME.get(name.upper())


def executable_types(phase: Optional[int] = None) -> List[BlockType]:
    return [bt for bt in ALL_TYPES if bt.executable and (phase is None or bt.phase == phase)]


def pinned_types() -> List[BlockType]:
    return [bt for bt in ALL_TYPES if bt.pinned]
