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

