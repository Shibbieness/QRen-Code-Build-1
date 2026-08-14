"""
The Magic Circle — formal Runic ArCircle inference loop.

    ᚨ○  (  ᛟ○ inference ᛟ○0  )  ᚨ○0

Not a metaphor. Three ArGlyphs form the boundary; a pluggable inner
operation stands in for "the admathCircle" (the reasoning substrate / model
call). This mirrors sovereign_py/runic/runic_translation.py's RunicBoundary
design (ingress -> process -> egress, translate only at the boundary) —
this module specializes that same shape for QRCF block routing rather than
generic Rune translation.

    ○1 ≡ InputParser    -> mode detection, wraps/decodes input
    ○2 ≡ BlockRouter     -> routes by block/token type to a context
    ᛟ○ inference ᛟ○0    -> the pluggable inner operation
    ○3 ≡ OutputFormatter -> formats per mode

Three-mode I/O protocol:
    Mode 1  - Human <-> Circle, natural language both ways
    Mode 2  - Machine <-> Circle, QRCF native both ways
    Mode 3A - natural language in -> QRCF block out
    Mode 3B - QRCF block in -> natural language out
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union

from qren.block_types import AMORPHOUS
from qren.tokens import ALL_TOKENS
from qren.wire_format import QRCFBlock, QRCFDecodeError, has_qrcf_magic


class IOMode(Enum):
    MODE_1 = 'mode_1_natural_language'
    MODE_2 = 'mode_2_qrcf_native'
    MODE_3A = 'mode_3a_nl_to_qrcf'
    MODE_3B = 'mode_3b_qrcf_to_nl'


_TOKEN_CONTEXTS: Dict[str, str] = {
    '⟨TB⟩': 'training_block_context',
    '⟨EA⟩': 'agent_invocation_context',
    '⟨IF⟩': 'failure_query_context',
}


@dataclass
class OperationResult:
    """What an inner operation returns: text always; a block when the
    operation produced/read one worth surfacing (Mode 2/3A/3B)."""
    text: str
    block: Optional[QRCFBlock] = None


@dataclass
class MagicCircleResult:
    output: Union[str, bytes, Dict[str, Any]]
    io_mode: IOMode
    routed_context: str
    input_block: QRCFBlock


class InputParser:
    """ArGlyph ○1. Detects mode, wraps input. No inference."""

    @staticmethod
    def detect_mode(value: Any, force_mode3: Optional[str] = None) -> IOMode:
        if force_mode3 == '3A':
            return IOMode.MODE_3A
        if force_mode3 == '3B':
            return IOMode.MODE_3B
        if has_qrcf_magic(value if isinstance(value, (bytes, bytearray)) else b''):
            return IOMode.MODE_2
        return IOMode.MODE_1

    @staticmethod
    def parse(value: Any, mode: IOMode) -> QRCFBlock:
        if mode in (IOMode.MODE_2, IOMode.MODE_3B):
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(f"{mode} requires bytes input, got {type(value).__name__}")
            return QRCFBlock.decode(value)
        # Mode 1 / Mode 3A: "str wrapped in minimal AMORPHOUS block by InputParser"
        text = value if isinstance(value, str) else str(value)
        return QRCFBlock(block_type=AMORPHOUS.wire_code, payload=text.encode('utf-8'),
                          metadata={'raw_text': text})


class BlockRouter:
    """ArGlyph ○2. Routes by block_type/token to a handler context. Skipped in Mode 1."""

    @staticmethod
    def route(block: QRCFBlock) -> str:
        token = block.metadata.get('token')
        if token in _TOKEN_CONTEXTS:
            return _TOKEN_CONTEXTS[token]
        info = block.block_type_info
        return f"generic_{info.name.lower()}_context" if info else "unknown_context"


class OutputFormatter:
    """ArGlyph ○3. Formats per mode."""

    @staticmethod
    def format(result: OperationResult, mode: IOMode) -> Union[str, bytes, Dict[str, Any]]:
        if mode == IOMode.MODE_1:
            return result.text
        if mode == IOMode.MODE_2:
            if result.block is None:
                raise ValueError("Mode 2 requires the operation to produce a block")
            return result.block.encode()
        if mode == IOMode.MODE_3A:
            return {
                'text': result.text,
                'block_id': result.block.metadata.get('token') if result.block else None,
                'block': result.block.encode() if result.block else None,
            }
        if mode == IOMode.MODE_3B:
            return result.text
        raise ValueError(f"Unknown mode: {mode}")


def default_operation(block: QRCFBlock, context: str) -> OperationResult:
    """Identity/echo operation, used when no domain operation is supplied."""
    return OperationResult(text=f"[{context}] received: {block.metadata.get('raw_text', block.payload)}")


class MagicCircle:
    """
    ᚨ○ ( ᛟ○ inference ᛟ○0 ) ᚨ○0

    invoke() runs the full pipeline: InputParser -> BlockRouter -> inner
    operation (the admathCircle) -> OutputFormatter. `operation` is
    Callable[[QRCFBlock, str], OperationResult] — the pluggable reasoning
    substrate, kept out of this module deliberately (this module is the
    boundary, not the model).
    """

    def __init__(self, operation: Optional[Callable[[QRCFBlock, str], OperationResult]] = None):
        self.operation = operation or default_operation

    def invoke(self, value: Any, force_mode3: Optional[str] = None) -> MagicCircleResult:
        mode = InputParser.detect_mode(value, force_mode3=force_mode3)
        try:
            input_block = InputParser.parse(value, mode)
        except QRCFDecodeError as e:
            raise ValueError(f"Mode {mode} input failed to parse as QRCF: {e}")

        context = BlockRouter.route(input_block)  # computed regardless; meaningless in Mode 1
        result = self.operation(input_block, context)
        output = OutputFormatter.format(result, mode)

        return MagicCircleResult(output=output, io_mode=mode, routed_context=context, input_block=input_block)
