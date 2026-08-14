"""
The three pre-encoded Runic tokens: TB, EA, IF.

Defined in ml-filesystem-monolith's ECHO_D_ANALYSIS.md / sub-skill C. Each
is a natural-language concept compressed into a single symbol, with a
concrete wire-format encoding (block type + NADA flag + metadata).

Note on EA's state: the source doc declares EA state as EMBER "block
binding (IF#6) and API routing (IF#7) suspended" — but in this repo's
sovereign_py/ build, IF#6 (AgentBlockEnforcer.get_allowed_files) and IF#7
(EnhancedAgent._call_api) were both wired up. RESOLVED_IF_STATE below
reflects the real, current state of *this* build rather than restating
the doc's now-stale snapshot.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from qren.block_types import TREE, FLAME, VOID
from qren.wire_format import QRCFBlock

# Which integration failures are actually resolved in sovereign_py/ as built
# in this repo (see sovereign_py commit history — all 7 IFs applied).
RESOLVED_IF_STATE = {
    'IF#1': True, 'IF#2': True, 'IF#3': True, 'IF#4': True,
    'IF#5': True, 'IF#6': True, 'IF#7': True,
}


@dataclass(frozen=True)
class RunicToken:
    token: str                      # '⟨TB⟩', '⟨EA⟩', '⟨IF⟩'
    name: str
    wire_code: int
    compression_ratio: str
    nada_protected: bool
    full_concept: str
    requires: List[str]
    derived_from: List[str]
    resolves_to: Optional[str] = None

    def state(self) -> str:
        """Live state, not a frozen doc snapshot."""
        if self.token == '⟨EA⟩':
            if RESOLVED_IF_STATE.get('IF#6') and RESOLVED_IF_STATE.get('IF#7'):
                return 'active'
            return 'ember'
        if self.token == '⟨IF⟩':
            return 'pending-resolution'
        return 'active'

    def to_block(self, payload: bytes = b'', extra_metadata: Optional[Dict[str, Any]] = None) -> QRCFBlock:
        metadata = {
            'token': self.token,
            'name': self.name,
            'compression_ratio': self.compression_ratio,
            'state': self.state(),
            'requires': self.requires,
            'derived_from': self.derived_from,
        }
        if self.resolves_to:
            metadata['resolves_to'] = self.resolves_to
        if extra_metadata:
            metadata.update(extra_metadata)
        return QRCFBlock(
            block_type=self.wire_code,
            payload=payload,
            metadata=metadata,
            nada_protected=self.nada_protected,
            ember=(self.state() == 'ember'),
        )


TB = RunicToken(
    token='⟨TB⟩', name='Training Block', wire_code=TREE.wire_code,
    compression_ratio='15:1', nada_protected=True,
    full_concept=(
        "named, toggleable collection of files that an ML agent may access "
        "during inference, with enable/disable state, type (rote|process|hybrid), "
        "file associations, agent bindings, embedding index"
    ),
    requires=[], derived_from=[],
)

EA = RunicToken(
    token='⟨EA⟩', name='Enhanced Agent', wire_code=FLAME.wire_code,
    compression_ratio='13:1', nada_protected=True,
    full_concept=(
        "ML agent implementing four-layer separation (Data/Models/Agents/Functions), "
        "six reasoning profiles, five execution modes, training block binding, "
        "API connection routing"
    ),
    requires=['⟨TB⟩'],
    derived_from=['hybrid_agent Ghost BONE', 'ml_agents_v1 Ghost BONE'],
)

IF = RunicToken(
    token='⟨IF⟩', name='Integration Failure', wire_code=VOID.wire_code,
    compression_ratio='18:1', nada_protected=False,
    full_concept=(
        "location where code is complete but component connection was not made "
        "— equivalent to .saipkg install step not executed, resumable at exact "
        "suspension point"
    ),
    requires=[], derived_from=[], resolves_to='LIGHTNING',
)

ALL_TOKENS: Dict[str, RunicToken] = {t.token: t for t in (TB, EA, IF)}


def get(token: str) -> Optional[RunicToken]:
    return ALL_TOKENS.get(token)


def active_tokens() -> List[RunicToken]:
    return [t for t in ALL_TOKENS.values() if t.state() == 'active']


def ember_tokens() -> List[RunicToken]:
    return [t for t in ALL_TOKENS.values() if t.state() == 'ember']
