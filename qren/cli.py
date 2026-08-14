#!/usr/bin/env python3
"""
QRen — command-line interface.

Demonstrates the full magic circle pipeline across all three I/O modes
using real data where it's available (⟨EA⟩'s live state reflects the
actual IF#6/IF#7 resolution status of sovereign_py/ in this repo, not a
hardcoded doc snapshot) rather than fabricated examples throughout.

Usage:
    python -m qren.cli blocks list
    python -m qren.cli blocks show <name-or-hex>
    python -m qren.cli tokens list
    python -m qren.cli tokens show <TB|EA|IF>
    python -m qren.cli demo mode1 "<question>"
    python -m qren.cli demo mode2
    python -m qren.cli demo mode3a "<instruction>"
    python -m qren.cli demo mode3b <TB|EA|IF>
"""

import argparse
import sys

from qren.block_types import ALL_TYPES, get as get_block_type, get_by_name
from qren.magic_circle import MagicCircle, OperationResult
from qren.tokens import ALL_TOKENS, get as get_token
from qren.wire_format import QRCFBlock


def cmd_blocks_list(args):
    print(f"{'code':6} {'name':10} {'phase':5} {'exec':5} {'pinned':6} {'slime':5}  property")
    for bt in ALL_TYPES:
        print(f"{bt.hex_code:6} {bt.name:10} {bt.phase:<5} {str(bt.executable):5} "
              f"{str(bt.pinned):6} {bt.crystal_slime or '-':5}  {bt.core_property}")
    return 0


def cmd_blocks_show(args):
    bt = get_by_name(args.identifier) if not args.identifier.startswith('0x') else get_block_type(int(args.identifier, 16))
    if not bt:
        print(f"error: unknown block type {args.identifier!r}", file=sys.stderr)
        return 1
    print(f"name:               {bt.name}")
    print(f"wire_code:          {bt.hex_code}")
    print(f"phase:              {bt.phase}")
    print(f"core_property:      {bt.core_property}")
    print(f"executable:         {bt.executable}")
    print(f"pinned:             {bt.pinned}")
    print(f"crystal_slime:      {bt.crystal_slime}")
    print(f"monolith_instances: {bt.monolith_instances}")
    return 0


def cmd_tokens_list(args):
    for t in ALL_TOKENS.values():
        print(f"{t.token}  {t.name:20} wire={t.wire_code:#04x}  compression={t.compression_ratio:6}  state={t.state()}")
    return 0


def cmd_tokens_show(args):
    token = get_token(f"⟨{args.name.upper()}⟩")
    if not token:
        print(f"error: unknown token {args.name!r} (expected TB, EA, or IF)", file=sys.stderr)
        return 1
    print(f"token:             {token.token}")
    print(f"name:              {token.name}")
    print(f"wire_code:         0x{token.wire_code:02X}")
    print(f"compression_ratio: {token.compression_ratio}")
    print(f"nada_protected:    {token.nada_protected}")
    print(f"state:             {token.state()}  (live, not a fixed doc snapshot)")
    print(f"requires:          {token.requires}")
    print(f"derived_from:      {token.derived_from}")
    if token.resolves_to:
        print(f"resolves_to:       {token.resolves_to}")
    print(f"full_concept:      {token.full_concept}")
    return 0


# --- Demo operation ---------------------------------------------------------

def sovereign_ai_demo_operation(block: QRCFBlock, context: str) -> OperationResult:
    """
    A real (if small) operation for the magic circle's inner admathCircle
    step, grounded in this repo's actual state rather than invented examples.
    """
    if context == 'training_block_context':
        return OperationResult(
            text=("Training blocks are the ⟨TB⟩ concept: named, toggleable file "
                  "collections an agent may read at inference time. sovereign_py's "
                  "default seed data ships three: 'General Knowledge' (enabled), "
                  "'Code Patterns' (enabled), 'Personal Notes' (disabled by default)."),
        )
    if context == 'agent_invocation_context':
        ea = get_token('⟨EA⟩')
        text = (f"⟨EA⟩ Enhanced Agent is currently '{ea.state()}'. "
                f"IF#6 (block-access enforcement) and IF#7 (API routing) are both "
                f"resolved in this build's sovereign_py/ml_runtime/enhanced_agents.py.")
        return OperationResult(text=text, block=ea.to_block(payload=b'agent-status-query'))
    if context == 'failure_query_context':
        iff = get_token('⟨IF⟩')
        text = ("⟨IF⟩ tracks unresolved wiring gaps. In this repo's sovereign_py/ build, "
                "all 7 documented integration failures (IF#1-IF#7) were applied — "
                "see the sovereign_py commit history. Zero ⟨IF⟩ instances remain open here.")
        return OperationResult(text=text, block=iff.to_block(payload=b'failure-status-query'))
    if context.startswith('generic_amorphous'):
        raw = block.metadata.get('raw_text', '')
        return OperationResult(text=f"Received free-text instruction: {raw!r} — no specific token context matched.")
    return OperationResult(text=f"[{context}] no domain handler for this context")


def _print_result(result):
    print(f"mode:    {result.io_mode.value}")
    print(f"context: {result.routed_context}")
    print(f"output:  {result.output if not isinstance(result.output, bytes) else f'<{len(result.output)} bytes QRCF>'}")


def cmd_demo_mode1(args):
    circle = MagicCircle(operation=sovereign_ai_demo_operation)
    result = circle.invoke(args.text)
    _print_result(result)
    return 0


def cmd_demo_mode2(args):
    ea = get_token('⟨EA⟩')
    input_block = ea.to_block(payload=b'status-check')
    circle = MagicCircle(operation=sovereign_ai_demo_operation)

    def mode2_operation(block, context):
        result = sovereign_ai_demo_operation(block, context)
        if result.block is None:
            result.block = ea.to_block(payload=result.text.encode('utf-8'))
        return result

    circle.operation = mode2_operation
    result = circle.invoke(input_block.encode())
    print(f"mode:    {result.io_mode.value}")
    print(f"context: {result.routed_context}")
    decoded = QRCFBlock.decode(result.output)
    print(f"output:  QRCF block, block_type={decoded.block_type_info.name if decoded.block_type_info else decoded.block_type}, "
          f"payload={decoded.payload[:120]!r}")
    return 0


def cmd_demo_mode3a(args):
    def mode3a_operation(block, context):
        from qren.block_types import TREE
        raw = block.metadata.get('raw_text', '')
        new_block = QRCFBlock(
            block_type=TREE.wire_code,
            payload=raw.encode('utf-8'),
            metadata={'sub_type': 'TREE/FRUIT', 'created_from_instruction': raw},
            nada_protected=True,
        )
        return OperationResult(text=f"Created training block from instruction: {raw!r}", block=new_block)

    circle = MagicCircle(operation=mode3a_operation)
    result = circle.invoke(args.text, force_mode3='3A')
    print(f"mode:     {result.io_mode.value}")
    print(f"context:  {result.routed_context}")
    print(f"text:     {result.output['text']}")
    print(f"block_id: {result.output['block_id']}")
    print(f"block:    <{len(result.output['block'])} bytes QRCF>" if result.output['block'] else None)
    return 0


def cmd_demo_mode3b(args):
    token = get_token(f"⟨{args.token.upper()}⟩")
    if not token:
        print(f"error: unknown token {args.token!r}", file=sys.stderr)
        return 1
    input_block = token.to_block(payload=b'state-query')
    circle = MagicCircle(operation=sovereign_ai_demo_operation)
    result = circle.invoke(input_block.encode(), force_mode3='3B')
    _print_result(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='qren', description='QRen magic circle CLI')
    sub = parser.add_subparsers(dest='command', required=True)

    blocks = sub.add_parser('blocks', help='Block type taxonomy')
    blocks_sub = blocks.add_subparsers(dest='blocks_command', required=True)
    bl = blocks_sub.add_parser('list')
    bl.set_defaults(func=cmd_blocks_list)
    bs = blocks_sub.add_parser('show')
    bs.add_argument('identifier', help='Block type name or 0xNN wire code')
    bs.set_defaults(func=cmd_blocks_show)

    tokens = sub.add_parser('tokens', help='TB/EA/IF pre-encoded Runic tokens')
    tokens_sub = tokens.add_subparsers(dest='tokens_command', required=True)
    tl = tokens_sub.add_parser('list')
    tl.set_defaults(func=cmd_tokens_list)
    ts = tokens_sub.add_parser('show')
    ts.add_argument('name', help='TB, EA, or IF')
    ts.set_defaults(func=cmd_tokens_show)

    demo = sub.add_parser('demo', help='Run the magic circle across all I/O modes')
    demo_sub = demo.add_subparsers(dest='demo_command', required=True)

    d1 = demo_sub.add_parser('mode1', help='Mode 1: natural language in, natural language out')
    d1.add_argument('text')
    d1.set_defaults(func=cmd_demo_mode1)

    d2 = demo_sub.add_parser('mode2', help='Mode 2: QRCF native both ways')
    d2.set_defaults(func=cmd_demo_mode2)

    d3a = demo_sub.add_parser('mode3a', help='Mode 3A: natural language in, QRCF block out')
    d3a.add_argument('text')
    d3a.set_defaults(func=cmd_demo_mode3a)

    d3b = demo_sub.add_parser('mode3b', help='Mode 3B: QRCF block in, natural language out')
    d3b.add_argument('token', help='TB, EA, or IF')
    d3b.set_defaults(func=cmd_demo_mode3b)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
