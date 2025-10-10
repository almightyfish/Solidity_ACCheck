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
        self.sensitive_operations = []  # 🔧 新增：存储敏感操作
    
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
        
        # 🔧 新增：检测敏感操作
        sensitive_ops = self.detect_sensitive_opcodes()
        if sensitive_ops:
            print(f"✓ 检测到 {len(sensitive_ops)} 个敏感操作（字节码层面）:")
            for op in sensitive_ops:
                severity_color = Colors.RED if op['severity'] == 'critical' else Colors.YELLOW
                print(f"    {severity_color}[{op['severity'].upper()}]{Colors.ENDC} 偏移 {op['offset']}: {op['opcode']} - {op['description']}")
        
        self.sensitive_operations = sensitive_ops  # 保存到实例变量
        
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
        """分析控制流图（增强版：正确处理JUMPI双分支和动态跳转）"""
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
        
        # 🔧 改进：构建增强的CFG
        cfg = {b['start']: set() for b in blocks}
        for b in blocks:
            if not b['instructions']:
                continue
            last = b['instructions'][-1]
            
            # 🔧 改进1：处理JUMP指令（无条件跳转）
            if last['op'] == 'JUMP':
                # 尝试识别静态跳转目标
                jump_target = self._find_jump_target(b['instructions'], len(b['instructions']) - 1)
                if jump_target is not None and jump_target in block_starts:
                    cfg[b['start']].add(jump_target)
                # 如果是动态跳转，标记为未知目标
                elif jump_target is None:
                    # 保守策略：连接到所有JUMPDEST（可能过度连接）
                    for dest in jumpdests:
                        cfg[b['start']].add(dest)
            
            # 🔧 改进2：正确处理JUMPI指令（条件跳转的两个分支）
            elif last['op'] == 'JUMPI':
                # 分支1：条件为真，跳转到目标
                jump_target = self._find_jump_target(b['instructions'], len(b['instructions']) - 1)
                if jump_target is not None and jump_target in block_starts:
                    cfg[b['start']].add(jump_target)
                elif jump_target is None:
                    # 动态跳转：保守连接到所有JUMPDEST
                    for dest in jumpdests:
                        cfg[b['start']].add(dest)
                
                # 分支2：条件为假，fallthrough到下一个块
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
            
            # 处理其他指令（顺序流）
            elif last['op'] not in ('RETURN', 'STOP', 'SELFDESTRUCT', 'REVERT', 'INVALID'):
                # 顺序流：继续到下一个基本块
                next_block = None
                for s in block_starts:
                    if s > b['start']:
                        next_block = s
                        break
                if next_block:
                    cfg[b['start']].add(next_block)
        
        self.cfg = {k: list(v) for k, v in cfg.items()}
    
    def _find_jump_target(self, instructions, jump_idx):
        """
        🔧 新增：识别跳转目标（支持静态和动态跳转）
        
        Args:
            instructions: 指令列表
            jump_idx: JUMP/JUMPI指令的索引
        
        Returns:
            跳转目标偏移量，如果无法确定则返回None
        """
        # 向前回溯，查找PUSH指令（静态跳转目标）
        # 典型模式：PUSH <target> ... JUMP/JUMPI
        
        # 从JUMP/JUMPI向前看最多10条指令
        for lookback in range(1, min(11, jump_idx + 1)):
            idx = jump_idx - lookback
            instr = instructions[idx]
            
            # 找到PUSH指令
            if instr['op'].startswith('PUSH'):
                try:
                    # 提取PUSH的数据作为跳转目标
                    target = int(instr.get('push_data', '0'), 16)
                    
                    # 验证：目标应该是合理的偏移量
                    if 0 <= target < len(self.bytecode) // 2:
                        # 进一步验证：目标位置应该是JUMPDEST
                        target_instr = next((i for i in self.instructions if i['offset'] == target), None)
                        if target_instr and target_instr['op'] == 'JUMPDEST':
                            return target
                except:
                    continue
            
            # 如果遇到其他可能修改栈的指令，可能无法确定
            # 例如：DUP、SWAP不影响，但ADD、SUB等会修改
            if instr['op'] in ('ADD', 'SUB', 'MUL', 'DIV', 'MLOAD', 'SLOAD', 'CALLDATALOAD'):
                # 动态计算的跳转目标
                return None
        
        # 无法确定跳转目标
        return None
    
    def match_key_vars_to_storage(self):
        """映射变量到存储槽位"""
        for idx, var in enumerate(self.key_variables):
            self.var_storage_map[var] = {"slot": idx}
    
    def detect_sensitive_opcodes(self) -> List[Dict]:
        """
        🔧 新增：检测字节码中的敏感操作
        
        返回包含敏感指令位置的列表
        """
        sensitive_opcodes = {
            'SELFDESTRUCT': {'severity': 'critical', 'description': '合约自毁'},
            'DELEGATECALL': {'severity': 'high', 'description': '委托调用（可改变合约状态）'},
            'CALLCODE': {'severity': 'high', 'description': '代码调用（已弃用）'},
            'CREATE': {'severity': 'medium', 'description': '创建新合约'},
            'CREATE2': {'severity': 'medium', 'description': '确定性创建合约'},
        }
        
        detected = []
        
        for instr in self.instructions:
            op = instr['op']
            if op in sensitive_opcodes:
                info = sensitive_opcodes[op]
                detected.append({
                    'offset': instr['offset'],
                    'opcode': op,
                    'severity': info['severity'],
                    'description': info['description'],
                    'basic_block': self._find_block_for_offset(instr['offset'])
                })
        
        return detected
    
    def _find_block_for_offset(self, offset: int) -> int:
        """找到包含指定偏移量的基本块"""
        for block in self.basic_blocks:
            if any(instr['offset'] == offset for instr in block['instructions']):
                return block['start']
        return -1
    
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

