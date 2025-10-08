import os
import json
from typing import List, Dict, Any

# EVM操作码表（部分，常用）
EVM_OPCODES = {
    0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV',
    0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD',
    0x0a: 'EXP', 0x0b: 'SIGNEXTEND',
    0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO',
    0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT', 0x1a: 'BYTE',
    0x20: 'SHA3',
    0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER', 0x34: 'CALLVALUE',
    0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY', 0x38: 'CODESIZE',
    0x39: 'CODECOPY', 0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY',
    0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
    0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER', 0x44: 'DIFFICULTY', 0x45: 'GASLIMIT',
    0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE',
    0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
    0x60: 'PUSH1', 0x61: 'PUSH2', 0x62: 'PUSH3', 0x63: 'PUSH4', 0x64: 'PUSH5', 0x65: 'PUSH6', 0x66: 'PUSH7', 0x67: 'PUSH8',
    0x68: 'PUSH9', 0x69: 'PUSH10', 0x6a: 'PUSH11', 0x6b: 'PUSH12', 0x6c: 'PUSH13', 0x6d: 'PUSH14', 0x6e: 'PUSH15', 0x6f: 'PUSH16',
    0x70: 'PUSH17', 0x71: 'PUSH18', 0x72: 'PUSH19', 0x73: 'PUSH20', 0x74: 'PUSH21', 0x75: 'PUSH22', 0x76: 'PUSH23', 0x77: 'PUSH24',
    0x78: 'PUSH25', 0x79: 'PUSH26', 0x7a: 'PUSH27', 0x7b: 'PUSH28', 0x7c: 'PUSH29', 0x7d: 'PUSH30', 0x7e: 'PUSH31', 0x7f: 'PUSH32',
    0x80: 'DUP1', 0x81: 'DUP2', 0x82: 'DUP3', 0x83: 'DUP4', 0x84: 'DUP5', 0x85: 'DUP6', 0x86: 'DUP7', 0x87: 'DUP8',
    0x88: 'DUP9', 0x89: 'DUP10', 0x8a: 'DUP11', 0x8b: 'DUP12', 0x8c: 'DUP13', 0x8d: 'DUP14', 0x8e: 'DUP15', 0x8f: 'DUP16',
    0x90: 'SWAP1', 0x91: 'SWAP2', 0x92: 'SWAP3', 0x93: 'SWAP4', 0x94: 'SWAP5', 0x95: 'SWAP6', 0x96: 'SWAP7', 0x97: 'SWAP8',
    0x98: 'SWAP9', 0x99: 'SWAP10', 0x9a: 'SWAP11', 0x9b: 'SWAP12', 0x9c: 'SWAP13', 0x9d: 'SWAP14', 0x9e: 'SWAP15', 0x9f: 'SWAP16',
    0xa0: 'LOG0', 0xa1: 'LOG1', 0xa2: 'LOG2', 0xa3: 'LOG3', 0xa4: 'LOG4',
    0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL', 0xf5: 'CREATE2',
    0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT',
}

class BytecodeAnalyzer:
    def __init__(self, bytecode_path: str, key_variables: List[str]):
        self.bytecode_path = bytecode_path
        self.key_variables = key_variables
        self.bytecode = self._load_bytecode()
        self.cfg = None
        self.basic_blocks = None
        self.var_storage_map = {}

    def _load_bytecode(self) -> str:
        with open(self.bytecode_path, 'r') as f:
            return f.read().strip()

    def disassemble(self) -> List[Dict[str, Any]]:
        code = self.bytecode
        if code.startswith('0x'):
            code = code[2:]
        code_bytes = bytes.fromhex(code)
        i = 0
        instructions = []
        while i < len(code_bytes):
            opcode = code_bytes[i]
            op = EVM_OPCODES.get(opcode, f'UNKNOWN_{opcode:02x}')
            instr = {'offset': i, 'opcode': opcode, 'op': op}
            if 0x60 <= opcode <= 0x7f:  # PUSH1-PUSH32
                push_len = opcode - 0x5f
                instr['push_data'] = code_bytes[i+1:i+1+push_len].hex()
                i += push_len
            instructions.append(instr)
            i += 1
        return instructions

    def analyze_cfg(self):
        instructions = self.disassemble()
        # 1. 识别所有JUMPDEST，作为基本块的起点
        jumpdests = set(instr['offset'] for instr in instructions if instr['op'] == 'JUMPDEST')
        block_starts = set([0]) | jumpdests
        # 2. 识别所有跳转指令的下一个指令（fallthrough）
        for idx, instr in enumerate(instructions):
            if instr['op'] in ('JUMP', 'JUMPI') and idx+1 < len(instructions):
                block_starts.add(instructions[idx+1]['offset'])
        block_starts = sorted(block_starts)
        # 3. 分割基本块
        blocks = []
        for i, start in enumerate(block_starts):
            end = block_starts[i+1] if i+1 < len(block_starts) else len(self.bytecode)//2
            block_instrs = [instr for instr in instructions if start <= instr['offset'] < end]
            blocks.append({'start': start, 'end': end, 'instructions': block_instrs})
        self.basic_blocks = blocks
        # 4. 构建CFG（邻接表）
        cfg = {b['start']: set() for b in blocks}
        offset_to_block = {b['start']: b for b in blocks}
        for b in blocks:
            if not b['instructions']:
                continue
            last = b['instructions'][-1]
            if last['op'] == 'JUMP':
                # 静态分析无法确定目标，理论上可分析PUSH+JUMP
                pass
            elif last['op'] == 'JUMPI':
                # 条件跳转，可能到下一个块，也可能到目标
                # 简单处理：加上fallthrough
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
            elif last['op'] not in ('RETURN', 'STOP', 'SELFDESTRUCT', 'REVERT', 'INVALID'):
                # 顺序流向下一个块
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
        self.cfg = {k: list(v) for k, v in cfg.items()}

    def match_key_vars_to_storage(self):
        # 这里可以用solc的--storage-layout或slither等工具辅助
        # 假设有一个变量布局文件key_var_layout.json
        if os.path.exists("key_var_layout.json"):
            with open("key_var_layout.json", "r") as f:
                layout = json.load(f)
            for var in self.key_variables:
                if var in layout:
                    self.var_storage_map[var] = layout[var]
        else:
            # 简单演示：假设变量顺序与slot一一对应
            for idx, var in enumerate(self.key_variables):
                self.var_storage_map[var] = {"slot": idx}

    def analyze(self):
        print("分析CFG和基本块...")
        self.analyze_cfg()
        print("基本块:")
        for b in self.basic_blocks:
            print(f"Block {b['start']} - {b['end']}: {[i['op'] for i in b['instructions']]}")
        print("CFG:")
        print(json.dumps(self.cfg, indent=2))
        print("同步关键变量存储位置...")
        self.match_key_vars_to_storage()
        print("分析完成。关键变量与存储位置映射：")
        print(json.dumps(self.var_storage_map, indent=2))

if __name__ == "__main__":
    # 假设关键变量已由前一阶段获得
    key_vars = ["owner", "balance", "withdrawLimit"]
    analyzer = BytecodeAnalyzer("/Users/almightyfish/Desktop/AChecker/AC/bytecode_analysis/bytecode/contract_1.code", key_vars)
    analyzer.analyze() 