#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
污点分析模块
"""

import json
import os
from typing import List, Dict
from utils.colors import Colors


class TaintAnalyzer:
    """污点分析器"""
    
    def __init__(self, bytecode_analyzer, output_dir: str):
        self.bytecode_analyzer = bytecode_analyzer
        self.output_dir = output_dir
        self.taint_results = []
    
    def analyze(self) -> bool:
        """执行污点分析（增强版：利用改进的CFG）"""
        print(f"\n{Colors.HEADER}【步骤4】污点分析{Colors.ENDC}")
        print("-" * 80)
        
        bb = self.bytecode_analyzer.basic_blocks
        cfg = self.bytecode_analyzer.cfg
        var_storage_map = self.bytecode_analyzer.var_storage_map
        
        # 1. 找到污点源（扩展污点源类型）
        taint_sources = set()
        for b in bb:
            for instr in b['instructions']:
                if instr['op'] in ('CALLDATALOAD', 'CALLDATACOPY', 'CALLER', 'ORIGIN', 
                                   'CALLVALUE', 'GASPRICE', 'COINBASE', 'TIMESTAMP', 
                                   'NUMBER', 'DIFFICULTY', 'GASLIMIT'):
                    taint_sources.add(b['start'])
        
        print(f"✓ 识别到 {len(taint_sources)} 个污点源基本块")
        
        # 🔧 新增：统计CFG信息
        total_edges = sum(len(edges) for edges in cfg.values())
        print(f"✓ CFG边数: {total_edges} 条（改进的双分支处理）")
        
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
            
            # 🔧 改进：污点传播（BFS，支持更复杂的CFG）
            all_paths = []
            queue = [(src, [src]) for src in taint_sources]
            visited = set()
            
            # 🔧 新增：限制路径长度防止过度搜索
            MAX_PATH_LENGTH = 50
            
            while queue:
                curr, path = queue.pop(0)
                
                # 🔧 新增：路径长度限制
                if len(path) > MAX_PATH_LENGTH:
                    continue
                
                if curr in sink_bbs:
                    all_paths.append(path)
                    continue
                
                for succ in cfg.get(curr, []):
                    # 🔧 改进：防止简单循环（允许有限次重访）
                    if (curr, succ) not in visited:
                        # 🔧 新增：检测路径中的循环
                        if path.count(succ) < 2:  # 允许访问同一个块最多2次
                            queue.append((succ, path + [succ]))
                            visited.add((curr, succ))
            
            # 汇总
            taint_bb_set = set()
            for p in all_paths:
                taint_bb_set.update(p)
            
            # 3. 🔧 改进：检测路径上的条件判断（更精确的检测）
            paths_with_conditions = []
            for path in all_paths:
                condition_info = self._check_path_has_condition_enhanced(path, bb)
                paths_with_conditions.append({
                    'path': path,
                    'has_condition': condition_info['has_condition'],
                    'condition_types': condition_info['condition_types'],  # 🔧 新增：条件类型
                    'condition_count': condition_info['condition_count']   # 🔧 新增：条件数量
                })
            
            result = {
                "name": var,
                "offset": slot,
                "taint_bb": sorted(list(taint_bb_set)),
                "taint_cfg": all_paths,
                "paths_with_conditions": paths_with_conditions  # 增强的条件信息
            }
            results.append(result)
        
        self.taint_results = results
        
        # 统计
        vulnerable_count = sum(1 for r in results if r['taint_bb'])
        print(f"{Colors.GREEN}✓ 污点分析完成{Colors.ENDC}")
        print(f"  - 分析变量: {len(results)} 个")
        print(f"  - 检测到污点: {vulnerable_count} 个")
        
        # 🔧 新增：详细统计
        for r in results:
            if r['taint_bb']:
                paths_with_cond = sum(1 for p in r['paths_with_conditions'] if p['has_condition'])
                total_paths = len(r['paths_with_conditions'])
                print(f"    • {r['name']}: {total_paths} 条路径, {paths_with_cond} 条有条件保护")
        
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
        检查污点路径上是否存在条件判断语句（保留原版本兼容性）
        
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
    
    def _check_path_has_condition_enhanced(self, path: List[int], basic_blocks: List[Dict]) -> Dict:
        """
        🔧 新增：增强的条件检测（返回更详细的信息）
        
        检测内容：
        1. 条件跳转（JUMPI）
        2. 比较操作（EQ、LT、GT等）
        3. 访问控制特征（CALLER + EQ）
        4. 回滚保护（REVERT）
        
        返回: {
            'has_condition': bool,
            'condition_types': List[str],  # 条件类型列表
            'condition_count': int          # 条件数量
        }
        """
        condition_types = []
        condition_count = 0
        
        # 定义不同类型的条件指令
        jump_opcodes = {'JUMPI'}
        compare_opcodes = {'EQ', 'LT', 'GT', 'SLT', 'SGT', 'ISZERO'}
        revert_opcodes = {'REVERT'}
        caller_opcodes = {'CALLER', 'ORIGIN'}
        
        # 遍历路径上的所有基本块
        has_caller = False
        has_compare = False
        
        for bb_start in path:
            block = next((b for b in basic_blocks if b['start'] == bb_start), None)
            if not block:
                continue
            
            # 检查基本块中的指令
            for instr in block['instructions']:
                op = instr['op']
                
                # 检测条件跳转
                if op in jump_opcodes:
                    if 'conditional_jump' not in condition_types:
                        condition_types.append('conditional_jump')
                    condition_count += 1
                
                # 检测比较操作
                if op in compare_opcodes:
                    has_compare = True
                    if 'comparison' not in condition_types:
                        condition_types.append('comparison')
                    condition_count += 1
                
                # 检测回滚保护
                if op in revert_opcodes:
                    if 'revert' not in condition_types:
                        condition_types.append('revert')
                    condition_count += 1
                
                # 检测调用者检查
                if op in caller_opcodes:
                    has_caller = True
        
        # 🔧 智能判断：CALLER + 比较操作 = 访问控制
        if has_caller and has_compare:
            if 'access_control' not in condition_types:
                condition_types.append('access_control')
        
        return {
            'has_condition': len(condition_types) > 0,
            'condition_types': condition_types,
            'condition_count': condition_count
        }
    
    def _save_taint_results(self):
        """保存污点分析结果"""
        output_file = os.path.join(self.output_dir, "intermediate", "taint_analysis.jsonl")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in self.taint_results:
                f.write(json.dumps(result, ensure_ascii=False) + '\n')
        
        print(f"  → 污点分析结果: {output_file}")

