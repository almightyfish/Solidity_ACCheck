#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
字节码分析模块
"""

import json
import os
from typing import List, Dict
from utils.colors import Colors
from utils.constants import EVM_OPCODES


class BytecodeAnalyzer:
    """字节码分析器"""
    
    def __init__(self, bytecode: str, key_variables: List[str], output_dir: str):
        self.bytecode = bytecode
        self.key_variables = key_variables
        self.output_dir = output_dir
        self.instructions = []
        self.basic_blocks = []
        self.cfg = {}
        self.var_storage_map = {}
    
    def analyze(self) -> bool:
        """执行完整分析"""
        print(f"\n{Colors.HEADER}【步骤3】字节码分析{Colors.ENDC}")
        print("-" * 80)
        
        # 反汇编
        self.instructions = self.disassemble()
        print(f"✓ 反汇编完成: {len(self.instructions)} 条指令")
        
        # 构建CFG
        self.analyze_cfg()
        print(f"✓ CFG分析完成: {len(self.basic_blocks)} 个基本块")
        
        # 映射变量到存储
        self.match_key_vars_to_storage()
        print(f"✓ 变量存储映射:")
        for var, info in self.var_storage_map.items():
            print(f"    {var} → slot {info.get('slot')}")
        
        # 保存中间结果
        self._save_analysis_results()
        
        return True
    
    def disassemble(self) -> List[Dict]:
        """反汇编字节码"""
        code = self.bytecode
        if code.startswith('0x'):
            code = code[2:]
        code_bytes = bytes.fromhex(code)
        
        instructions = []
        i = 0
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
        """分析控制流图"""
        # 识别基本块起始点
        jumpdests = set(instr['offset'] for instr in self.instructions if instr['op'] == 'JUMPDEST')
        block_starts = set([0]) | jumpdests
        
        for idx, instr in enumerate(self.instructions):
            if instr['op'] in ('JUMP', 'JUMPI') and idx+1 < len(self.instructions):
                block_starts.add(self.instructions[idx+1]['offset'])
        
        block_starts = sorted(block_starts)
        
        # 分割基本块
        blocks = []
        for i, start in enumerate(block_starts):
            end = block_starts[i+1] if i+1 < len(block_starts) else len(self.bytecode)//2
            block_instrs = [instr for instr in self.instructions if start <= instr['offset'] < end]
            blocks.append({'start': start, 'end': end, 'instructions': block_instrs})
        
        self.basic_blocks = blocks
        
        # 构建CFG
        cfg = {b['start']: set() for b in blocks}
        for b in blocks:
            if not b['instructions']:
                continue
            last = b['instructions'][-1]
            
            if last['op'] not in ('RETURN', 'STOP', 'SELFDESTRUCT', 'REVERT', 'INVALID', 'JUMP'):
                # 顺序流
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
            
            if last['op'] == 'JUMPI':
                # 条件跳转的fallthrough
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
        
        self.cfg = {k: list(v) for k, v in cfg.items()}
    
    def match_key_vars_to_storage(self):
        """映射变量到存储槽位"""
        for idx, var in enumerate(self.key_variables):
            self.var_storage_map[var] = {"slot": idx}
    
    def _save_analysis_results(self):
        """保存分析结果"""
        output_file = os.path.join(self.output_dir, "intermediate", "bytecode_analysis.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        result = {
            'instructions_count': len(self.instructions),
            'basic_blocks_count': len(self.basic_blocks),
            'cfg': self.cfg,
            'variable_storage_map': self.var_storage_map,
            'instructions_sample': self.instructions[:20]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"  → 字节码分析结果: {output_file}")

