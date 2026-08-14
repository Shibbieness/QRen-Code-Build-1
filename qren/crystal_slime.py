"""
Crystal Slime lifecycle: AMORPHOUS -> ICE -> CRYSTAL.

    AMORPHOUS (0x07)  ->  ICE (0x02)  ->  CRYSTAL (0x0D)
      Slime A               Slime B            Slime C
      still becoming        frozen identity    defined by connections
      living, mutable       crystallized       the gemstone, lattice node

Five crystallization triggers move a block from one state to the next.
Crystal Baby is the fusion of two ICE blocks into a new CRYSTAL with its
own identity — an ML-fusion operation, not a simple merge.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from qren.block_types import AMORPHOUS, ICE, CRYSTAL, BlockType


class SlimeState(Enum):
    AMORPHOUS = 'A'
    ICE = 'B'
    CRYSTAL = 'C'


_STATE_TO_BLOCK_TYPE = {
    SlimeState.AMORPHOUS: AMORPHOUS,
    SlimeState.ICE: ICE,
    SlimeState.CRYSTAL: CRYSTAL,
}

_NEXT_STATE = {
    SlimeState.AMORPHOUS: SlimeState.ICE,
    SlimeState.ICE: SlimeState.CRYSTAL,
    SlimeState.CRYSTAL: None,
}


class CrystallizationTrigger(Enum):
    DEPENDENCY_SATURATION = 'dependency_saturation'
    DIFF_COUNT = 'diff_count'
    STABILITY_RISK = 'stability_risk'
    MANUAL_DECLARATION = 'manual_declaration'
    EXPLICIT_FLAG = 'explicit_flag'


@dataclass
class TriggerEvent:
    trigger: CrystallizationTrigger
    detail: str
    fired_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SlimeTracker:
    """Tracks one block's position in the Crystal Slime lifecycle."""
    identity: str
    state: SlimeState = SlimeState.AMORPHOUS
    events: List[TriggerEvent] = field(default_factory=list)

    @property
    def block_type(self) -> BlockType:
        return _STATE_TO_BLOCK_TYPE[self.state]

    def record_trigger(self, trigger: CrystallizationTrigger, detail: str = ''):
        self.events.append(TriggerEvent(trigger, detail))

    def can_advance(self) -> bool:
        """Any recorded trigger since the last transition is sufficient (spec
        lists 5 trigger types without an AND/OR combination rule beyond
        'trigger fires the transition'; treated as OR — any one suffices)."""
        return _NEXT_STATE[self.state] is not None and len(self.events) > 0

    def advance(self) -> bool:
        """Attempt the next lifecycle transition. Returns True if it advanced."""
        next_state = _NEXT_STATE[self.state]
        if next_state is None or not self.can_advance():
            return False
        self.state = next_state
        self.events = []  # triggers consumed by the transition they caused
        return True


def crystal_baby_fusion(parent_a: SlimeTracker, parent_b: SlimeTracker) -> SlimeTracker:
    """
    "Crystal Baby: ML fusion of two ICE blocks -> new CRYSTAL with own
    identity." Both parents must be in ICE state; the child starts directly
    in CRYSTAL state with an identity derived from, but distinct from,
    both parents.
    """
    if parent_a.state != SlimeState.ICE or parent_b.state != SlimeState.ICE:
        raise ValueError(
            f"Crystal Baby fusion requires two ICE-state parents, got "
            f"{parent_a.state.name} and {parent_b.state.name}"
        )

    fused_seed = f"{parent_a.identity}+{parent_b.identity}"
    child_identity = 'crystal-baby-' + hashlib.sha256(fused_seed.encode('utf-8')).hexdigest()[:12]

    child = SlimeTracker(identity=child_identity, state=SlimeState.CRYSTAL)
    child.events.append(TriggerEvent(
        CrystallizationTrigger.EXPLICIT_FLAG,
        detail=f"Crystal Baby fusion of {parent_a.identity} + {parent_b.identity}",
    ))
    return child
