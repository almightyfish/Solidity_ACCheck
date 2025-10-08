#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一体化智能合约污点分析工具
集成：编译 → 字节码分析 → 污点分析 → 源码映射 → 报告生成

使用方法：
    只需配置以下3个参数即可运行：
    - SOLC_VERSION: solc版本（如 "0.4.25", "0.8.0"）
    - KEY_VARIABLES: 关键变量列表
    - CONTRACT_PATH: Solidity源码路径
"""

import json
import os
import sys
import re
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


# ============================================================================
# 配置区域 - 只需修改这里！
# ============================================================================

SOLC_VERSION = "0.4.25"  # Solidity编译器版本
KEY_VARIABLES = ["totalSupply", "balances", "rate"]  # 要分析的关键变量
CONTRACT_PATH = "/Users/almightyfish/Desktop/AChecker/AC/undependency/0xf41624c6465e57a0dca498ef0b62f07cbaab09ca.sol"  # Solidity源码文件路径

# 可选配置
OUTPUT_DIR = "analysis_output_4"  # 输出目录
KEEP_TEMP_FILES = True  # 是否保留中间文件

# ============================================================================


class Colors:
    """终端颜色"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# 第1部分：Solc版本管理和编译
# ============================================================================

class SolcManager:
    """Solc版本管理器"""
    
    def __init__(self, version: str):
        self.version = version
        self.solc_path = None
    
    def check_and_switch_version(self) -> bool:
        """检查并切换到指定的solc版本"""
        print(f"\n{Colors.HEADER}【步骤1】检查和切换Solc版本{Colors.ENDC}")
        print("-" * 80)
        
        # 检查是否安装了solc-select
        try:
            result = subprocess.run(['solc-select', 'versions'], 
                                  capture_output=True, text=True, timeout=10)
            has_solc_select = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            has_solc_select = False
        
        if has_solc_select:
            print(f"✓ 检测到 solc-select")
            return self._use_solc_select()
        else:
            print(f"⚠️  未检测到 solc-select，尝试使用系统solc")
            return self._use_system_solc()
    
    def _use_solc_select(self) -> bool:
        """使用solc-select切换版本"""
        try:
            # 检查是否已安装所需版本
            result = subprocess.run(['solc-select', 'versions'], 
                                  capture_output=True, text=True)
            installed_versions = result.stdout
            
            if self.version not in installed_versions:
                print(f"📦 安装 solc {self.version}...")
                subprocess.run(['solc-select', 'install', self.version], 
                             check=True, capture_output=True)
                print(f"✓ 安装完成")
            
            # 切换版本
            print(f"🔄 切换到 solc {self.version}...")
            subprocess.run(['solc-select', 'use', self.version], 
                         check=True, capture_output=True)
            
            self.solc_path = 'solc'
            
            # 验证版本
            result = subprocess.run(['solc', '--version'], 
                                  capture_output=True, text=True)
            print(f"✓ 当前版本: {result.stdout.split('Version:')[1].split()[0]}")
            return True
            
        except Exception as e:
            print(f"❌ solc-select切换失败: {e}")
            return False
    
    def _use_system_solc(self) -> bool:
        """使用系统默认solc"""
        try:
            result = subprocess.run(['solc', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                version_info = result.stdout
                print(f"✓ 找到系统solc")
                print(f"  版本信息: {version_info.split('Version:')[1].split()[0] if 'Version:' in version_info else 'Unknown'}")
                self.solc_path = 'solc'
                return True
            return False
        except FileNotFoundError:
            print(f"❌ 未找到solc编译器")
            print(f"\n安装建议:")
            print(f"  1. 使用 solc-select (推荐):")
            print(f"     pip install solc-select")
            print(f"     solc-select install {self.version}")
            print(f"     solc-select use {self.version}")
            print(f"  2. 或安装系统solc:")
            print(f"     macOS: brew install solidity")
            print(f"     Linux: apt-get install solc")
            return False


class ContractCompiler:
    """合约编译器"""
    
    def __init__(self, solc_path: str, output_dir: str):
        self.solc_path = solc_path
        self.output_dir = output_dir
        self.bytecode = None
        self.runtime_bytecode = None
        self.asm = None
        self.srcmap = None
        self.srcmap_runtime = None
    
    def compile(self, contract_path: str) -> bool:
        """编译合约"""
        print(f"\n{Colors.HEADER}【步骤2】编译合约{Colors.ENDC}")
        print("-" * 80)
        print(f"源文件: {contract_path}")
        
        try:
            # 编译命令（兼容不同版本）
            cmd = [
                self.solc_path,
                '--bin', '--bin-runtime', '--asm',
                '--overwrite',
                '-o', self.output_dir,
                contract_path
            ]
            
            print(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"{Colors.RED}❌ 编译失败:{Colors.ENDC}")
                print(result.stderr)
                return False
            
            # 读取编译产物
            contract_name = self._extract_contract_name(contract_path)
            self._load_artifacts(contract_name)
            
            print(f"{Colors.GREEN}✓ 编译成功{Colors.ENDC}")
            print(f"  - Runtime bytecode: {len(self.runtime_bytecode)} 字符")
            print(f"  - Bytecode: {len(self.bytecode)} 字符")
            
            # 保存中间结果
            self._save_intermediate_files()
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}❌ 编译超时{Colors.ENDC}")
            return False
        except Exception as e:
            print(f"{Colors.RED}❌ 编译错误: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            return False
    
    def _extract_contract_name(self, contract_path: str) -> str:
        """提取合约名称"""
        with open(contract_path, 'r') as f:
            content = f.read()
        match = re.search(r'contract\s+(\w+)', content)
        return match.group(1) if match else Path(contract_path).stem
    
    def _load_artifacts(self, contract_name: str):
        """加载编译产物"""
        base_path = os.path.join(self.output_dir, contract_name)
        
        # 读取各种编译产物（兼容不同solc版本）
        files = {
            'bin': 'bytecode',
            'bin-runtime': 'runtime_bytecode',
            'asm': 'asm'
        }
        
        for ext, attr in files.items():
            file_path = f"{base_path}.{ext}"
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    setattr(self, attr, f.read().strip())
    
    def _save_intermediate_files(self):
        """保存中间文件"""
        intermediate_dir = os.path.join(self.output_dir, "intermediate")
        os.makedirs(intermediate_dir, exist_ok=True)
        
        # 保存runtime bytecode
        with open(os.path.join(intermediate_dir, "runtime_bytecode.hex"), 'w') as f:
            f.write(self.runtime_bytecode)
        
        print(f"  → 中间文件已保存到: {intermediate_dir}/")


# ============================================================================
# 第2部分：字节码分析
# ============================================================================

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
    0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER', 
    0x44: 'DIFFICULTY', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE',
    0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE',
    0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
    0x60: 'PUSH1', 0x61: 'PUSH2', 0x62: 'PUSH3', 0x63: 'PUSH4', 0x64: 'PUSH5', 
    0x65: 'PUSH6', 0x66: 'PUSH7', 0x67: 'PUSH8', 0x68: 'PUSH9', 0x69: 'PUSH10', 
    0x6a: 'PUSH11', 0x6b: 'PUSH12', 0x6c: 'PUSH13', 0x6d: 'PUSH14', 0x6e: 'PUSH15', 
    0x6f: 'PUSH16', 0x70: 'PUSH17', 0x71: 'PUSH18', 0x72: 'PUSH19', 0x73: 'PUSH20', 
    0x74: 'PUSH21', 0x75: 'PUSH22', 0x76: 'PUSH23', 0x77: 'PUSH24', 0x78: 'PUSH25', 
    0x79: 'PUSH26', 0x7a: 'PUSH27', 0x7b: 'PUSH28', 0x7c: 'PUSH29', 0x7d: 'PUSH30', 
    0x7e: 'PUSH31', 0x7f: 'PUSH32',
    0x80: 'DUP1', 0x81: 'DUP2', 0x82: 'DUP3', 0x83: 'DUP4', 0x84: 'DUP5', 
    0x85: 'DUP6', 0x86: 'DUP7', 0x87: 'DUP8', 0x88: 'DUP9', 0x89: 'DUP10', 
    0x8a: 'DUP11', 0x8b: 'DUP12', 0x8c: 'DUP13', 0x8d: 'DUP14', 0x8e: 'DUP15', 0x8f: 'DUP16',
    0x90: 'SWAP1', 0x91: 'SWAP2', 0x92: 'SWAP3', 0x93: 'SWAP4', 0x94: 'SWAP5', 
    0x95: 'SWAP6', 0x96: 'SWAP7', 0x97: 'SWAP8', 0x98: 'SWAP9', 0x99: 'SWAP10', 
    0x9a: 'SWAP11', 0x9b: 'SWAP12', 0x9c: 'SWAP13', 0x9d: 'SWAP14', 0x9e: 'SWAP15', 0x9f: 'SWAP16',
    0xa0: 'LOG0', 0xa1: 'LOG1', 0xa2: 'LOG2', 0xa3: 'LOG3', 0xa4: 'LOG4',
    0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL', 
    0xf5: 'CREATE2', 0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT',
}


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


# ============================================================================
# 第3部分：污点分析
# ============================================================================

class TaintAnalyzer:
    """污点分析器"""
    
    def __init__(self, bytecode_analyzer: BytecodeAnalyzer, output_dir: str):
        self.bytecode_analyzer = bytecode_analyzer
        self.output_dir = output_dir
        self.taint_results = []
    
    def analyze(self) -> bool:
        """执行污点分析"""
        print(f"\n{Colors.HEADER}【步骤4】污点分析{Colors.ENDC}")
        print("-" * 80)
        
        bb = self.bytecode_analyzer.basic_blocks
        cfg = self.bytecode_analyzer.cfg
        var_storage_map = self.bytecode_analyzer.var_storage_map
        
        # 1. 找到污点源
        taint_sources = set()
        for b in bb:
            for instr in b['instructions']:
                if instr['op'] in ('CALLDATALOAD', 'CALLDATACOPY', 'CALLER', 'ORIGIN'):
                    taint_sources.add(b['start'])
        
        print(f"✓ 识别到 {len(taint_sources)} 个污点源基本块")
        
        # 2. 为每个变量追踪污点
        results = []
        for var, info in var_storage_map.items():
            slot = info.get('slot')
            
            # 找到操作该slot的SSTORE/SLOAD
            sink_bbs = set()
            for b in bb:
                for idx, instr in enumerate(b['instructions']):
                    if instr['op'] in ('SSTORE', 'SLOAD'):
                        if self._find_slot_in_stack(b['instructions'], idx, slot):
                            sink_bbs.add(b['start'])
            
            # 污点传播（BFS）
            all_paths = []
            queue = [(src, [src]) for src in taint_sources]
            visited = set()
            
            while queue:
                curr, path = queue.pop(0)
                if curr in sink_bbs:
                    all_paths.append(path)
                    continue
                
                for succ in cfg.get(curr, []):
                    if (curr, succ) not in visited:
                        queue.append((succ, path + [succ]))
                        visited.add((curr, succ))
            
            # 汇总
            taint_bb_set = set()
            for p in all_paths:
                taint_bb_set.update(p)
            
            # 3. 检测路径上的条件判断（新增）
            paths_with_conditions = []
            for path in all_paths:
                has_condition = self._check_path_has_condition(path, bb)
                paths_with_conditions.append({
                    'path': path,
                    'has_condition': has_condition
                })
            
            result = {
                "name": var,
                "offset": slot,
                "taint_bb": sorted(list(taint_bb_set)),
                "taint_cfg": all_paths,
                "paths_with_conditions": paths_with_conditions  # 新增
            }
            results.append(result)
        
        self.taint_results = results
        
        # 统计
        vulnerable_count = sum(1 for r in results if r['taint_bb'])
        print(f"{Colors.GREEN}✓ 污点分析完成{Colors.ENDC}")
        print(f"  - 分析变量: {len(results)} 个")
        print(f"  - 检测到污点: {vulnerable_count} 个")
        
        # 保存结果
        self._save_taint_results()
        
        return True
    
    def _find_slot_in_stack(self, instructions, idx, target_slot):
        """查找栈中的slot"""
        for back in range(1, 6):
            i = idx - back
            if i < 0:
                break
            instr = instructions[i]
            if instr['op'].startswith('PUSH'):
                try:
                    pushed = int(instr.get('push_data', '0'), 16)
                    if pushed == target_slot:
                        return True
                except:
                    continue
            elif instr['op'].startswith(('DUP', 'SWAP')):
                continue
            else:
                break
        return False
    
    def _check_path_has_condition(self, path: List[int], basic_blocks: List[Dict]) -> bool:
        """
        检查污点路径上是否存在条件判断语句
        
        条件判断的字节码特征：
        - JUMPI: 条件跳转
        - EQ, LT, GT, SLT, SGT: 比较操作
        - ISZERO: 零值检查
        - REVERT: 回滚（通常在require失败后）
        
        返回: True表示路径上有条件判断（可能是安全的），False表示无条件判断（危险）
        """
        condition_opcodes = {
            'JUMPI',      # 条件跳转（if/require的核心）
            'EQ', 'LT', 'GT', 'SLT', 'SGT',  # 比较操作
            'ISZERO',     # 零值检查
            'REVERT'      # 回滚（require失败）
        }
        
        # 遍历路径上的所有基本块
        for bb_start in path:
            # 找到对应的基本块
            block = next((b for b in basic_blocks if b['start'] == bb_start), None)
            if not block:
                continue
            
            # 检查基本块中的指令
            for instr in block['instructions']:
                if instr['op'] in condition_opcodes:
                    return True
        
        return False
    
    def _save_taint_results(self):
        """保存污点分析结果"""
        output_file = os.path.join(self.output_dir, "intermediate", "taint_analysis.jsonl")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in self.taint_results:
                f.write(json.dumps(result, ensure_ascii=False) + '\n')
        
        print(f"  → 污点分析结果: {output_file}")


# ============================================================================
# 第4部分：源码映射
# ============================================================================

class SourceMapper:
    """源码映射器"""
    
    def __init__(self, source_file: str, output_dir: str):
        self.source_file = source_file
        self.output_dir = output_dir
        self.source_lines = []
        self.function_map = {}
        self._load_and_parse_source()
    
    def _load_and_parse_source(self):
        """加载并解析源码"""
        with open(self.source_file, 'r', encoding='utf-8') as f:
            self.source_lines = f.readlines()
        
        # 两阶段解析：先找所有函数定义，再分配行号
        function_starts = []  # [(line_num, func_name), ...]
        
        # 阶段1：找到所有函数定义（排除注释）
        for line_num, line in enumerate(self.source_lines, 1):
            # 移除注释后再匹配
            code_part = line.split('//')[0]  # 移除单行注释
            func_match = re.search(r'function\s+(\w+|\(\))', code_part)  # 支持 function() 形式
            if func_match:
                func_name_match = func_match.group(1)
                # 如果是 () 则使用特殊名称
                func_name = 'fallback' if func_name_match == '()' else func_name_match
                function_starts.append((line_num, func_name))
        
        # 阶段2：为每个函数分配行号范围
        for i, (start_line, func_name) in enumerate(function_starts):
            # 函数结束位置：下一个函数开始的前一行，或文件结束
            if i + 1 < len(function_starts):
                end_line = function_starts[i + 1][0] - 1
            else:
                end_line = len(self.source_lines)
            
            # 使用大括号计数+缩进判断精确确定函数结束位置
            brace_count = 0
            actual_end = end_line
            found_opening_brace = False
            
            # 获取函数定义行的缩进级别
            func_def_line = self.source_lines[start_line - 1]
            func_indent = len(func_def_line) - len(func_def_line.lstrip())
            
            for line_num in range(start_line, min(end_line + 1, len(self.source_lines) + 1)):
                line = self.source_lines[line_num - 1]
                
                # 检查是否有左大括号（函数体开始）
                if '{' in line:
                    found_opening_brace = True
                
                brace_count += line.count('{') - line.count('}')
                
                # 函数体完全闭合的条件（关键改进：使用缩进判断）：
                # 1. 已经找到过左大括号（函数体已开始）
                # 2. 当前brace_count==0（大括号已经全部配对）
                # 3. 当前行包含右大括号
                # 4. 当前行的缩进 <= 函数定义行的缩进（同级或更外层，说明是函数级别的}）
                if found_opening_brace and brace_count == 0 and '}' in line and line_num > start_line:
                    line_indent = len(line) - len(line.lstrip())
                    stripped = line.strip()
                    
                    # 是函数级别的} （缩进与函数定义同级或更外层）
                    if (stripped == '}' or stripped.startswith('}')) and line_indent <= func_indent:
                        actual_end = line_num
                        break
            
            self.function_map[func_name] = {
                'start_line': start_line,
                'end_line': actual_end,
                'lines': list(range(start_line, actual_end + 1)),
                'variables_used': []
            }
    
    def map_to_source(self, taint_results: List[Dict], 
                      bytecode_analyzer: BytecodeAnalyzer) -> List[Dict]:
        """将污点结果映射到源码"""
        print(f"\n{Colors.HEADER}【步骤5】源码映射{Colors.ENDC}")
        print("-" * 80)
        
        mapped_results = []
        
        for taint_result in taint_results:
            var_name = taint_result['name']
            has_taint = len(taint_result['taint_bb']) > 0
            
            # 查找变量在源码中的使用
            usages = self._find_variable_usage(var_name)
            
            # 分析路径类型（新增）
            dangerous_paths = []  # 无条件判断的危险路径
            suspicious_paths = []  # 有条件判断的可疑路径
            
            if has_taint and 'paths_with_conditions' in taint_result:
                for path_info in taint_result['paths_with_conditions']:
                    if path_info['has_condition']:
                        suspicious_paths.append(path_info['path'])
                    else:
                        dangerous_paths.append(path_info['path'])
            
            # 标记风险位置（区分危险和可疑）
            # 关键改进：只检查写入操作，排除读取操作（如条件判断中的变量）
            dangerous_locations = []
            suspicious_locations = []
            
            # 改进1: 基于污点分析的检测（原有逻辑）
            if has_taint:
                for usage in usages:
                    # 核心修复：只有写入操作才可能是风险位置
                    if usage['operation'] == 'write':
                        # 检查该位置对应的源码是否有条件判断
                        has_condition_in_source = self._check_source_has_condition(usage)
                        
                        location_info = usage.copy()
                        location_info['has_source_condition'] = has_condition_in_source
                        location_info['detection_method'] = 'taint_analysis'
                        
                        # 修复后的逻辑：源码有条件保护 → 可疑，否则 → 危险
                        if has_condition_in_source:
                            # 源码明确有条件保护（require/if/modifier）
                            suspicious_locations.append(location_info)
                        else:
                            # 源码无明确条件保护
                            dangerous_locations.append(location_info)
                    # 读取操作（如 if (keyHash == 0x0)）不会被标记为风险
            
            # 改进2: 补充检测 - public函数写入关键变量但无访问控制（新增）
            # 即使污点分析失败，也能通过此机制检测到漏洞
            for usage in usages:
                if usage['operation'] == 'write':
                    func_name = usage.get('function')
                    if func_name:
                        # 检查是否是public函数且无访问控制
                        has_ac, reason = self._check_public_function_has_access_control(func_name)
                        
                        if not has_ac:  # public函数无访问控制
                            # 检查是否已经被标记（避免重复）
                            already_flagged = any(
                                loc['line'] == usage['line'] and loc['function'] == func_name
                                for loc in dangerous_locations + suspicious_locations
                            )
                            
                            if not already_flagged:
                                location_info = usage.copy()
                                location_info['has_source_condition'] = False
                                location_info['detection_method'] = 'public_function_check'
                                location_info['warning'] = f"⚠️ {reason}"
                                dangerous_locations.append(location_info)
            
            # 重新计算：如果补充检测发现了危险位置，也应标记为有漏洞
            has_vulnerability = has_taint or len(dangerous_locations) > 0 or len(suspicious_locations) > 0
            
            mapped = {
                'variable': var_name,
                'storage_slot': taint_result['offset'],
                'has_taint': has_taint,
                'has_vulnerability': has_vulnerability,  # 新增：综合判断
                'taint_paths_count': len(taint_result['taint_cfg']),
                'dangerous_paths_count': len(dangerous_paths),  # 新增
                'suspicious_paths_count': len(suspicious_paths),  # 新增
                'affected_basic_blocks': taint_result['taint_bb'],
                'source_usages': usages,
                'dangerous_locations': dangerous_locations,  # 新增：危险位置（无保护）
                'suspicious_locations': suspicious_locations,  # 新增：可疑位置（有保护）
                'risk_locations': dangerous_locations + suspicious_locations  # 保持兼容性
            }
            
            mapped_results.append(mapped)
        
        print(f"{Colors.GREEN}✓ 源码映射完成{Colors.ENDC}")
        print(f"  - 映射变量: {len(mapped_results)} 个")
        
        # 保存结果
        self._save_mapped_results(mapped_results)
        
        return mapped_results
    
    def _find_variable_usage(self, var_name: str) -> List[Dict]:
        """查找变量使用位置"""
        usages = []
        
        for line_num, line in enumerate(self.source_lines, 1):
            if re.search(rf'\b{var_name}\b', line):
                usage_type = 'declaration' if any(kw in line for kw in 
                    ['uint', 'address', 'bool', 'mapping', 'string']) else 'usage'
                
                # 改进的操作类型识别
                operation = self._determine_operation_type(line, var_name)
                
                usages.append({
                    'line': line_num,
                    'code': line.strip(),
                    'type': usage_type,
                    'operation': operation,
                    'function': self._find_function_for_line(line_num)
                })
        
        return usages
    
    def _determine_operation_type(self, line: str, var_name: str) -> str:
        """
        准确判断变量操作类型
        
        写入操作特征：
        - varName = value (赋值)
        - varName += value (复合赋值)
        - varName++ / ++varName (自增)
        
        读取操作特征（不应标记为风险）：
        - if (varName == ...) (条件判断)
        - require(varName != ...) (条件检查)
        - return varName (返回值)
        - function(varName) (函数参数)
        """
        # 移除注释
        code_part = line.split('//')[0].strip()
        
        # 优先级1: 检查写入操作（赋值）- 必须先检查，因为赋值是最明确的写入
        # 匹配 varName = value 或 varName += value 等
        # 注意：要排除比较操作 (==, !=, >=, <=)
        assignment_pattern = rf'\b{re.escape(var_name)}\b\s*(=|[\+\-\*/%&|\^]=|<<=|>>=)\s*'
        if re.search(assignment_pattern, code_part):
            # 再次确认不是比较操作 (==, !=, >=, <=)
            comparison_pattern = rf'\b{re.escape(var_name)}\b\s*(==|!=|>=|<=)\s*'
            if not re.search(comparison_pattern, code_part):
                # 确认是赋值操作（写入）
                return 'write'
        
        # 优先级2: 检查自增/自减操作（写入）
        if re.search(rf'(\+\+{re.escape(var_name)}|{re.escape(var_name)}\+\+|--{re.escape(var_name)}|{re.escape(var_name)}--)', code_part):
            return 'write'
        
        # 优先级3: 检查是否在条件判断中（读取操作）
        if any(keyword in code_part for keyword in [
            'if (', 'if(', 
            'require(', 'require (', 
            'assert(', 'assert (',
            'return ', 'return(',
        ]):
            # 在条件判断/返回语句中的使用都是读取
            return 'read'
        
        # 优先级4: 检查是否是比较操作（读取操作）
        # 匹配 varName == / != / > / < / >= / <= 等比较操作
        comparison_pattern = rf'\b{re.escape(var_name)}\b\s*(==|!=|>|<|>=|<=)\s*'
        if re.search(comparison_pattern, code_part):
            return 'read'
        
        # 优先级5: 检查函数调用中作为参数（读取）
        # 例如: someFunction(varName)
        func_call_pattern = rf'\w+\([^)]*\b{re.escape(var_name)}\b[^)]*\)'
        if re.search(func_call_pattern, code_part):
            return 'read'
        
        # 优先级6: 检查是否在等号右边（读取操作）
        # 例如: otherVar = varName + 1
        if '=' in code_part:
            parts = code_part.split('=')
            if len(parts) >= 2:
                left_side = parts[0]
                right_side = '='.join(parts[1:])
                
                # 变量只在右边出现（读取）
                if var_name not in left_side and var_name in right_side:
                    return 'read'
        
        # 默认为读取（保守策略，避免误报）
        return 'read'
    
    def _find_function_for_line(self, line_num: int) -> Optional[str]:
        """找到行所属的函数"""
        for func_name, func_info in self.function_map.items():
            if line_num in func_info['lines']:
                return func_name
        return None
    
    def _check_public_function_has_access_control(self, func_name: str):
        """
        检查public函数是否有访问控制（新增功能）
        
        返回: (has_control, reason)
        - has_control: True表示有访问控制，False表示无保护
        - reason: 说明原因
        """
        if not func_name:
            return False, "未知函数"
        
        # 检查函数定义
        for line in self.source_lines:
            if f'function {func_name}' in line:
                # 检查是否是public/external函数
                if 'public' not in line and 'external' not in line:
                    return True, "非public函数"
                
                # 检查是否有访问控制modifier
                if any(modifier in line for modifier in [
                    'onlyOwner', 'onlyAdmin', 'only', 'ownerOnly',
                    'whenNotPaused', 'nonReentrant'
                ]):
                    return True, f"有访问控制modifier"
        
        # 检查函数体内是否有访问控制
        func_lines = self.function_map.get(func_name, {}).get('lines', [])
        access_control_patterns = ['msg.sender', 'tx.origin', 'owner', 'admin']
        
        for func_line_num in func_lines:
            if 0 <= func_line_num - 1 < len(self.source_lines):
                line = self.source_lines[func_line_num - 1]
                
                if any(keyword in line for keyword in ['require(', 'require ', 'assert(']):
                    if any(pattern in line for pattern in access_control_patterns):
                        return True, f"有require访问控制"
        
        return False, "public函数无访问控制"
    
    def _check_source_has_condition(self, usage: Dict) -> bool:
        """
        检查源码位置是否有**访问控制**条件（而非普通状态检查）
        
        关键改进：区分访问控制 vs 状态检查
        
        ✅ 访问控制（返回True）：
        - require(msg.sender == owner): 检查调用者身份
        - modifier onlyOwner: 访问控制修饰器
        - if (msg.sender == ...): 调用者检查
        
        ❌ 状态检查（返回False，不是真正的保护）：
        - if (keyHash == 0x0): 只是检查变量值
        - if (balance > 0): 只是状态判断
        
        返回: True表示有访问控制保护，False表示无保护
        """
        line_num = usage['line']
        func_name = usage.get('function')
        
        # 优先级1: 检查函数是否有访问控制modifier
        if func_name:
            for line in self.source_lines:
                if f'function {func_name}' in line:
                    # 检查常见的访问控制modifier
                    if any(modifier in line for modifier in [
                        'onlyOwner', 'onlyAdmin', 'only',
                        'whenNotPaused', 'whenPaused',
                        'nonReentrant', 'ownerOnly'
                    ]):
                        return True
        
        # 优先级2: 检查函数内是否有访问控制相关的条件判断
        # 关键：必须检查 msg.sender 或 tx.origin
        access_control_patterns = [
            'msg.sender',   # 调用者检查
            'tx.origin',    # 原始调用者检查
            'owner',        # 所有者检查（通常与msg.sender配合）
            'admin',        # 管理员检查
            'authorized',   # 授权检查
        ]
        
        if func_name:
            func_lines = self.function_map.get(func_name, {}).get('lines', [])
            if func_lines:
                for func_line_num in func_lines:
                    # 只检查当前写入行之前的行（条件保护应该在赋值之前）
                    if func_line_num >= line_num:
                        continue
                    
                    if 0 <= func_line_num - 1 < len(self.source_lines):
                        line = self.source_lines[func_line_num - 1]
                        
                        # 检查是否是访问控制相关的条件
                        if any(keyword in line for keyword in [
                            'require(', 'require (', 
                            'assert(', 'assert (',
                            'revert(', 'revert ('
                        ]):
                            # 进一步检查是否包含访问控制模式
                            if any(pattern in line for pattern in access_control_patterns):
                                return True
                        
                        # 检查 if 语句是否包含访问控制
                        if 'if (' in line or 'if(' in line:
                            if any(pattern in line for pattern in access_control_patterns):
                                return True
        
        # 优先级3: 检查当前行前几行是否有访问控制
        check_range = 5  # 只检查前5行（条件保护应该紧邻赋值语句）
        
        for i in range(max(0, line_num - 1 - check_range), line_num - 1):
            if i < len(self.source_lines):
                line = self.source_lines[i]
                
                # 只检查访问控制相关的条件
                if any(keyword in line for keyword in [
                    'require(', 'require (', 
                    'assert(', 'assert ('
                ]):
                    if any(pattern in line for pattern in access_control_patterns):
                        return True
        
        return False
    
    def _save_mapped_results(self, results: List[Dict]):
        """保存映射结果"""
        output_file = os.path.join(self.output_dir, "intermediate", "source_mapping.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"  → 源码映射结果: {output_file}")


# ============================================================================
# 第5部分：报告生成
# ============================================================================

class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, output_dir: str, source_file: str):
        self.output_dir = output_dir
        self.source_file = source_file
        self.source_lines = []
        
        with open(source_file, 'r', encoding='utf-8') as f:
            self.source_lines = f.readlines()
    
    def generate(self, mapped_results: List[Dict]) -> Dict:
        """生成完整报告"""
        print(f"\n{Colors.HEADER}【步骤6】生成报告{Colors.ENDC}")
        print("=" * 80)
        
        # 使用 has_vulnerability 而不是只看 has_taint
        vulnerable_count = sum(1 for r in mapped_results if r.get('has_vulnerability', r['has_taint']))
        
        # 终端报告
        self._print_terminal_report(mapped_results, vulnerable_count)
        
        # JSON报告
        report = {
            'analysis_time': datetime.now().isoformat(),
            'source_file': self.source_file,
            'summary': {
                'total_variables': len(mapped_results),
                'vulnerable_variables': vulnerable_count,
                'safe_variables': len(mapped_results) - vulnerable_count
            },
            'results': mapped_results
        }
        
        # 保存最终报告
        final_report_path = os.path.join(self.output_dir, "final_report.json")
        with open(final_report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Colors.BLUE}💾 最终报告已保存:{Colors.ENDC}")
        print(f"   {final_report_path}")
        
        # 生成HTML报告（可选）
        html_report_path = os.path.join(self.output_dir, "final_report.html")
        self._generate_html_report(report, html_report_path)
        print(f"   {html_report_path}")
        
        return report
    
    def _print_terminal_report(self, results: List[Dict], vulnerable_count: int):
        """打印终端报告"""
        print(f"\n{Colors.BOLD}分析概要:{Colors.ENDC}")
        print(f"  总变量数: {len(results)}")
        print(f"  检测到漏洞: {Colors.RED}{vulnerable_count}{Colors.ENDC}")
        print(f"  安全变量: {Colors.GREEN}{len(results) - vulnerable_count}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}详细结果:{Colors.ENDC}")
        print("=" * 80)
        
        for idx, result in enumerate(results, 1):
            var_name = result['variable']
            has_taint = result['has_taint']
            has_vulnerability = result.get('has_vulnerability', has_taint)
            
            status_color = Colors.RED if has_vulnerability else Colors.GREEN
            status_icon = "⚠️ " if has_vulnerability else "✅"
            
            # 显示检测方法
            if has_vulnerability:
                if has_taint:
                    status_text = "检测到污点传播"
                else:
                    status_text = "检测到访问控制漏洞（补充检测）"
            else:
                status_text = "未检测到漏洞"
            
            print(f"\n{Colors.BOLD}[{idx}] 变量: {var_name}{Colors.ENDC}")
            print(f"    状态: {status_color}{status_icon}{status_text}{Colors.ENDC}")
            print(f"    存储槽位: {result['storage_slot']}")
            
            if has_taint:
                print(f"    污点路径数: {result['taint_paths_count']}")
                
                # 显示路径类型统计（新增）
                if 'dangerous_paths_count' in result and 'suspicious_paths_count' in result:
                    dangerous_count = result['dangerous_paths_count']
                    suspicious_count = result['suspicious_paths_count']
                    print(f"      ├─ {Colors.RED}危险路径: {dangerous_count} 条{Colors.ENDC} (无条件保护)")
                    print(f"      └─ {Colors.YELLOW}可疑路径: {suspicious_count} 条{Colors.ENDC} (有条件判断)")
                
                print(f"    受影响的基本块: {result['affected_basic_blocks']}")
            
            # 源码使用位置（区分读写操作）
            if result['source_usages']:
                write_usages = [u for u in result['source_usages'] if u['operation'] == 'write']
                read_usages = [u for u in result['source_usages'] if u['operation'] == 'read']
                
                print(f"\n    {Colors.CYAN}📄 源码中的使用位置:{Colors.ENDC}")
                print(f"       总计: {len(result['source_usages'])} 处 (✏️  写入: {len(write_usages)}, 👁️  读取: {len(read_usages)})")
                
                # 优先显示写入操作（更重要）
                if write_usages:
                    print(f"\n       {Colors.YELLOW}写入操作:{Colors.ENDC}")
                    for usage in write_usages[:3]:
                        func_info = f" (在函数 {usage['function']})" if usage['function'] else ""
                        print(f"       ✏️  行 {usage['line']:3d}: {usage['code']}{func_info}")
                    if len(write_usages) > 3:
                        print(f"       ... 还有 {len(write_usages) - 3} 个写入位置")
                
                # 然后显示读取操作（参考信息）
                if read_usages:
                    print(f"\n       {Colors.CYAN}读取操作 (不是风险点):{Colors.ENDC}")
                    for usage in read_usages[:2]:
                        func_info = f" (在函数 {usage['function']})" if usage['function'] else ""
                        print(f"       👁️  行 {usage['line']:3d}: {usage['code']}{func_info}")
                    if len(read_usages) > 2:
                        print(f"       ... 还有 {len(read_usages) - 2} 个读取位置")
            
            # 危险位置（新增，重点标记）
            if result.get('dangerous_locations'):
                print(f"\n    {Colors.RED}🔥 危险位置（无条件保护，需立即修复）:{Colors.ENDC}")
                for risk in result['dangerous_locations']:
                    func_name = risk['function'] or '未知函数'
                    detection_method = risk.get('detection_method', 'taint_analysis')
                    warning = risk.get('warning', '')
                    
                    print(f"       {Colors.RED}⛔ 行 {risk['line']:3d} ({func_name}): {risk['code']}{Colors.ENDC}")
                    
                    # 显示检测方法
                    if detection_method == 'public_function_check':
                        print(f"          {Colors.YELLOW}🔍 检测方式: 补充检测（public函数无访问控制）{Colors.ENDC}")
                    else:
                        print(f"          🔍 检测方式: 污点分析")
                    
                    # 显示警告信息
                    if warning:
                        print(f"          {warning}")
                    
                    # 上下文
                    line_idx = risk['line'] - 1
                    if line_idx > 0:
                        print(f"          上文: {self.source_lines[line_idx - 1].strip()}")
                    if line_idx < len(self.source_lines) - 1:
                        print(f"          下文: {self.source_lines[line_idx + 1].strip()}")
            
            # 可疑位置（新增，需要人工审查）
            if result.get('suspicious_locations'):
                print(f"\n    {Colors.YELLOW}⚠️  可疑位置（检测到条件判断，建议人工审查）:{Colors.ENDC}")
                for risk in result['suspicious_locations']:
                    func_name = risk['function'] or '未知函数'
                    has_condition = risk.get('has_source_condition', False)
                    condition_mark = " ✓" if has_condition else ""
                    print(f"       {Colors.YELLOW}⚡ 行 {risk['line']:3d} ({func_name}): {risk['code']}{condition_mark}{Colors.ENDC}")
                    
                    if has_condition:
                        print(f"          {Colors.GREEN}↳ 检测到条件保护（require/if/modifier）{Colors.ENDC}")
                    
                    # 上下文
                    line_idx = risk['line'] - 1
                    if line_idx > 0:
                        print(f"          上文: {self.source_lines[line_idx - 1].strip()}")
                    if line_idx < len(self.source_lines) - 1:
                        print(f"          下文: {self.source_lines[line_idx + 1].strip()}")
        
        print("\n" + "=" * 80)
        
        # 安全建议
        self._print_security_advice(results)
    
    def _print_security_advice(self, results: List[Dict]):
        """打印安全建议"""
        vulnerable = [r for r in results if r['has_taint']]
        
        if not vulnerable:
            print(f"\n{Colors.GREEN}✅ 安全评估:{Colors.ENDC}")
            print("   未检测到明显的污点传播风险")
            print("   注意：仍建议进行全面的安全审计")
            return
        
        # 分类统计（新增）
        dangerous_vars = [r for r in vulnerable if r.get('dangerous_locations')]
        suspicious_vars = [r for r in vulnerable if r.get('suspicious_locations') and not r.get('dangerous_locations')]
        
        print(f"\n{Colors.YELLOW}⚠️  安全建议:{Colors.ENDC}")
        print("-" * 80)
        
        # 优先显示危险变量
        if dangerous_vars:
            print(f"\n{Colors.RED}{Colors.BOLD}🔥 高危险变量（需立即修复）:{Colors.ENDC}")
            for result in dangerous_vars:
                var_name = result['variable']
                dangerous_count = len(result.get('dangerous_locations', []))
                print(f"\n{Colors.BOLD}变量 '{var_name}' ({dangerous_count} 个危险位置):{Colors.ENDC}")
                self._print_variable_advice(var_name, is_dangerous=True)
        
        # 然后显示可疑变量
        if suspicious_vars:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  可疑变量（建议人工审查）:{Colors.ENDC}")
            for result in suspicious_vars:
                var_name = result['variable']
                suspicious_count = len(result.get('suspicious_locations', []))
                print(f"\n{Colors.BOLD}变量 '{var_name}' ({suspicious_count} 个可疑位置):{Colors.ENDC}")
                self._print_variable_advice(var_name, is_dangerous=False)
    
    def _print_variable_advice(self, var_name: str, is_dangerous: bool):
        """打印变量的具体建议"""
        if is_dangerous:
            priority = f"{Colors.RED}【紧急修复】{Colors.ENDC}"
            urgency_note = f"  {Colors.RED}⚠️  此变量无条件保护，存在直接利用风险！{Colors.ENDC}\n"
        else:
            priority = f"{Colors.YELLOW}【人工审查】{Colors.ENDC}"
            urgency_note = f"  {Colors.GREEN}✓ 已检测到条件判断，但仍需确认保护是否充分{Colors.ENDC}\n"
        
        print(f"  {priority}")
        print(urgency_note)
        
        var_name_lower = var_name.lower()
        
        if 'owner' in var_name_lower:
            print("  这是权限控制变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：任何人都可以修改此变量！{Colors.ENDC}")
            print("  1. 使用 modifier onlyOwner 保护所有修改owner的函数")
            print("  2. 考虑实现两步转移机制（transferOwnership + acceptOwnership）")
            print("  3. 为权限变更添加事件日志")
            print("\n  示例代码:")
            print("    modifier onlyOwner() { require(msg.sender == owner); _; }")
            print("    function changeOwner(address newOwner) public onlyOwner { ... }")
        
        elif 'balance' in var_name_lower or 'supply' in var_name_lower:
            print("  这是资金相关变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：资金可能被任意操控！{Colors.ENDC}")
            print("  1. 使用 Checks-Effects-Interactions 模式")
            print("  2. 在外部调用前更新状态")
            print("  3. 考虑使用 SafeMath 防止溢出")
            print("  4. 添加提现限额和冷却期")
        
        elif any(kw in var_name_lower for kw in ['auth', 'admin', 'pause']):
            print("  这是控制变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：合约控制权可能被夺取！{Colors.ENDC}")
            print("  1. 添加适当的访问控制")
            print("  2. 使用 OpenZeppelin 的 Ownable/AccessControl")
            print("  3. 为状态变更添加事件")
        
        else:
            print("  通用建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：变量可被任意修改！{Colors.ENDC}")
            print("  1. 检查所有修改此变量的函数是否有访问控制")
            print("  2. 验证所有外部输入")
            print("  3. 添加必要的 require 检查")
        
        if not is_dangerous:
            print(f"\n  {Colors.CYAN}提示：虽然检测到条件判断，但请确认：{Colors.ENDC}")
            print("    • 条件检查是否充分（不存在绕过方法）")
            print("    • 是否覆盖所有可能的攻击路径")
            print("    • 是否正确使用了 msg.sender 而不是 tx.origin")
    
    def _generate_html_report(self, report: Dict, output_path: str):
        """生成HTML报告"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>智能合约污点分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vulnerable {{ color: #f44336; font-weight: bold; }}
        .safe {{ color: #4CAF50; font-weight: bold; }}
        .variable {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .risk {{ background: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }}
        .code {{ background: #f5f5f5; padding: 10px; font-family: monospace; margin: 5px 0; border-radius: 3px; }}
        .timestamp {{ color: #999; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 智能合约污点分析报告</h1>
        <p class="timestamp">生成时间: {report['analysis_time']}</p>
        <p>源文件: <code>{report['source_file']}</code></p>
        
        <div class="summary">
            <h2>📊 分析概要</h2>
            <p>总变量数: {report['summary']['total_variables']}</p>
            <p class="vulnerable">受污点影响: {report['summary']['vulnerable_variables']}</p>
            <p class="safe">安全变量: {report['summary']['safe_variables']}</p>
        </div>
        
        <h2>📝 详细结果</h2>
"""
        
        for idx, result in enumerate(report['results'], 1):
            status_class = 'vulnerable' if result['has_taint'] else 'safe'
            status_text = '⚠️ 检测到污点' if result['has_taint'] else '✅ 安全'
            
            html_content += f"""
        <div class="variable">
            <h3>[{idx}] 变量: {result['variable']}</h3>
            <p class="{status_class}">状态: {status_text}</p>
            <p>存储槽位: {result['storage_slot']}</p>
"""
            
            if result['has_taint']:
                html_content += f"<p>污点路径数: {result['taint_paths_count']}</p>"
            
            if result['risk_locations']:
                html_content += "<h4>⚠️ 风险位置:</h4>"
                for risk in result['risk_locations']:
                    html_content += f"""
                <div class="risk">
                    <p>行 {risk['line']} (函数: {risk['function'] or '未知'})</p>
                    <div class="code">{risk['code']}</div>
                </div>
"""
            
            html_content += "</div>"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)


# ============================================================================
# 主流程
# ============================================================================

class AllInOneAnalyzer:
    """一体化分析器"""
    
    def __init__(self, solc_version: str, key_variables: List[str], 
                 contract_path: str, output_dir: str = "analysis_output"):
        self.solc_version = solc_version
        self.key_variables = key_variables
        self.contract_path = contract_path
        self.output_dir = output_dir
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "intermediate"), exist_ok=True)
    
    def run(self) -> Dict:
        """运行完整分析流程"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * 80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}智能合约一体化污点分析工具{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'=' * 80}{Colors.ENDC}")
        print(f"\n配置:")
        print(f"  Solc版本: {self.solc_version}")
        print(f"  合约路径: {self.contract_path}")
        print(f"  关键变量: {', '.join(self.key_variables)}")
        print(f"  输出目录: {self.output_dir}")
        
        try:
            # 步骤1: 检查和切换Solc版本
            solc_manager = SolcManager(self.solc_version)
            if not solc_manager.check_and_switch_version():
                return None
            
            # 步骤2: 编译合约
            compiler = ContractCompiler(solc_manager.solc_path, self.output_dir)
            if not compiler.compile(self.contract_path):
                return None
            
            # 步骤3: 字节码分析
            bytecode_analyzer = BytecodeAnalyzer(
                compiler.runtime_bytecode,
                self.key_variables,
                self.output_dir
            )
            if not bytecode_analyzer.analyze():
                return None
            
            # 步骤4: 污点分析
            taint_analyzer = TaintAnalyzer(bytecode_analyzer, self.output_dir)
            if not taint_analyzer.analyze():
                return None
            
            # 步骤5: 源码映射
            source_mapper = SourceMapper(self.contract_path, self.output_dir)
            mapped_results = source_mapper.map_to_source(
                taint_analyzer.taint_results,
                bytecode_analyzer
            )
            
            # 步骤6: 生成报告
            report_generator = ReportGenerator(self.output_dir, self.contract_path)
            final_report = report_generator.generate(mapped_results)
            
            # 完成
            print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.GREEN}✅ 分析完成！{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.ENDC}")
            print(f"\n所有结果已保存到: {Colors.CYAN}{self.output_dir}/{Colors.ENDC}")
            print(f"  - 最终报告: final_report.json")
            print(f"  - HTML报告: final_report.html")
            print(f"  - 中间结果: intermediate/")
            
            return final_report
            
        except Exception as e:
            print(f"\n{Colors.RED}❌ 分析过程中发生错误: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            return None


# ============================================================================
# 程序入口
# ============================================================================

def main():
    """主函数"""
    
    # 使用配置区域的参数运行分析
    analyzer = AllInOneAnalyzer(
        solc_version=SOLC_VERSION,
        key_variables=KEY_VARIABLES,
        contract_path=CONTRACT_PATH,
        output_dir=OUTPUT_DIR
    )
    
    result = analyzer.run()
    
    if result:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

