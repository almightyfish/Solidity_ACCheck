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
        self.taint_to_sensitive_flows = []  # 🔧 新增：污点到敏感函数的流
    
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
            
            # 找到操作该slot的SSTORE（只检查写入操作，不检查读取）
            # 🔧 修复：SLOAD只是读取，不会修改变量，不应作为污点汇
            sink_bbs = set()
            for b in bb:
                for idx, instr in enumerate(b['instructions']):
                    if instr['op'] == 'SSTORE':  # 只检查写入操作
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
        
        # 🔧 新增：检测污点是否到达敏感操作
        self._check_taint_to_sensitive_flows()
        
        return True
    
    def _find_slot_in_stack(self, instructions, idx, target_slot):
        """
        查找栈中的slot（增强版：支持 mapping 和动态数组）
        
        检测两种模式：
        1. 直接访问：PUSH slot → SLOAD/SSTORE
        2. mapping/数组访问：PUSH slot → ... → SHA3 → SLOAD/SSTORE
        
        Args:
            instructions: 指令列表
            idx: SLOAD/SSTORE 指令的索引
            target_slot: 目标槽位
        
        Returns:
            True: 找到目标槽位的访问
            False: 未找到
        """
        # 🔧 改进1：检查直接访问（原有逻辑）
        for back in range(1, 6):
            i = idx - back
            if i < 0:
                break
            instr = instructions[i]
            if instr['op'].startswith('PUSH'):
                try:
                    pushed = int(instr.get('push_data', '0'), 16)
                    if pushed == target_slot:
                        return True  # 直接访问
                except:
                    continue
            elif instr['op'].startswith(('DUP', 'SWAP')):
                continue
            else:
                break
        
        # 🔧 改进2：检查 mapping/动态数组访问模式
        # 模式：PUSH slot → ... → SHA3/KECCAK256 → SLOAD/SSTORE
        # 向前回溯更多指令（最多20条）
        has_sha3 = False
        sha3_idx = -1
        
        for back in range(1, min(21, idx + 1)):
            i = idx - back
            if i < 0:
                break
            instr = instructions[i]
            
            # 找到 SHA3 指令
            if instr['op'] == 'SHA3':
                has_sha3 = True
                sha3_idx = i
                break
        
        # 如果找到了 SHA3，继续向前查找 PUSH slot
        if has_sha3 and sha3_idx >= 0:
            # 从 SHA3 之前继续向前回溯，查找目标槽位
            for back in range(1, min(16, sha3_idx + 1)):
                i = sha3_idx - back
                if i < 0:
                    break
                instr = instructions[i]
                
                if instr['op'].startswith('PUSH'):
                    try:
                        pushed = int(instr.get('push_data', '0'), 16)
                        if pushed == target_slot:
                            return True  # mapping/动态数组访问
                    except:
                        continue
        
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
    
    def _check_taint_to_sensitive_flows(self):
        """
        🔧 新增：检测污点路径是否到达敏感操作（增强版：检查参数依赖）
        
        这是一个复合风险检测：
        - 污点传播（用户可控数据）
        - 敏感函数调用（selfdestruct, delegatecall等）
        - 两者结合 = 高危漏洞
        
        改进：不仅检查路径，还检查敏感操作的参数是否受污点影响
        """
        # 获取敏感操作（从字节码分析器）
        sensitive_ops = getattr(self.bytecode_analyzer, 'sensitive_operations', [])
        
        if not sensitive_ops:
            print(f"\n{Colors.GREEN}✓ 未检测到敏感操作，跳过污点-敏感函数关联分析{Colors.ENDC}")
            return
        
        print(f"\n{Colors.HEADER}【额外检测】污点传播到敏感函数分析（增强版）{Colors.ENDC}")
        print("-" * 80)
        
        # 提取敏感操作所在的基本块
        sensitive_blocks = {}  # {basic_block: [sensitive_ops]}
        for op in sensitive_ops:
            bb = op.get('basic_block', -1)
            if bb not in sensitive_blocks:
                sensitive_blocks[bb] = []
            sensitive_blocks[bb].append(op)
        
        print(f"✓ 敏感操作分布在 {len(sensitive_blocks)} 个基本块中")
        
        # 获取污点变量的存储槽位信息
        var_storage_map = self.bytecode_analyzer.var_storage_map
        basic_blocks = self.bytecode_analyzer.basic_blocks
        
        # 检查每个变量的污点路径是否到达敏感操作
        flows_found = []
        
        for taint_result in self.taint_results:
            var_name = taint_result['name']
            taint_paths = taint_result['taint_cfg']
            var_slot = var_storage_map.get(var_name, {}).get('slot', -1)
            
            if not taint_paths:
                continue
            
            # 检查每条污点路径
            for path in taint_paths:
                # 查找路径中是否包含敏感操作所在的基本块
                sensitive_blocks_in_path = []
                for bb in path:
                    if bb in sensitive_blocks:
                        # 🔧 关键改进：检查敏感操作的参数是否受污点影响
                        for op in sensitive_blocks[bb]:
                            param_tainted = self._check_sensitive_op_param_tainted(
                                bb, op, var_slot, basic_blocks, path
                            )
                            
                            sensitive_blocks_in_path.append({
                                'basic_block': bb,
                                'operation': op,
                                'param_tainted': param_tainted,  # 🔧 新增：参数是否受污点影响
                                'confidence': param_tainted['confidence']  # 🔧 新增：置信度
                            })
                
                # 🔧 改进：只有当参数确实受污点影响时才报告
                real_risks = [sb for sb in sensitive_blocks_in_path if sb['param_tainted']['is_tainted']]
                
                if real_risks:
                    # 🔧 新增：检查从污点汇到敏感操作之间的路径条件
                    # 找到路径中最后一个 SSTORE（污点汇）的位置
                    last_sstore_idx = self._find_last_sstore_in_path(
                        path, var_slot, basic_blocks
                    )
                    
                    # 提取从污点汇到敏感操作的子路径
                    if last_sstore_idx >= 0 and last_sstore_idx < len(path):
                        sub_path_to_sensitive = path[last_sstore_idx:]
                        
                        # 检查这段子路径上是否有条件判断
                        path_to_sensitive_condition = self._check_path_has_condition_enhanced(
                            sub_path_to_sensitive, basic_blocks
                        )
                    else:
                        # 无法确定子路径，保守判断
                        path_to_sensitive_condition = {
                            'has_condition': False,
                            'condition_types': [],
                            'condition_count': 0
                        }
                    
                    flows_found.append({
                        'variable': var_name,
                        'path': path,
                        'path_length': len(path),
                        'sensitive_blocks': real_risks,
                        'sensitive_count': len(real_risks),
                        'risk_level': 'critical',  # 污点+敏感函数 = 严重风险
                        'detection_method': 'enhanced_taint_analysis',  # 🔧 新增：检测方法
                        'path_to_sensitive_condition': path_to_sensitive_condition,  # 🔧 新增：子路径条件
                        'has_guard_before_sensitive': path_to_sensitive_condition['has_condition']  # 🔧 新增：简化标记
                    })
        
        # 保存结果
        self.taint_to_sensitive_flows = flows_found
        
        # 输出统计（增强版：显示置信度）
        if flows_found:
            print(f"{Colors.RED}⚠️  发现 {len(flows_found)} 条污点传播到敏感函数的路径！{Colors.ENDC}")
            
            # 按变量分组统计
            var_flows = {}
            for flow in flows_found:
                var = flow['variable']
                if var not in var_flows:
                    var_flows[var] = []
                var_flows[var].append(flow)
            
            for var, flows in var_flows.items():
                ops_types = set()
                confidence_levels = {'high': 0, 'medium': 0, 'low': 0}
                
                for flow in flows:
                    for sb in flow['sensitive_blocks']:
                        # 收集操作类型
                        op = sb['operation']
                        ops_types.add(op['opcode'])
                        
                        # 统计置信度
                        conf = sb.get('confidence', 'low')
                        if conf in confidence_levels:
                            confidence_levels[conf] += 1
                
                # 显示统计信息
                high_conf = confidence_levels['high']
                medium_conf = confidence_levels['medium']
                low_conf = confidence_levels['low']
                
                confidence_str = []
                if high_conf > 0:
                    confidence_str.append(f"{high_conf} 高置信度")
                if medium_conf > 0:
                    confidence_str.append(f"{medium_conf} 中置信度")
                if low_conf > 0:
                    confidence_str.append(f"{low_conf} 低置信度")
                
                print(f"  {Colors.RED}❌ 变量 '{var}': {len(flows)} 条路径到达敏感操作 {list(ops_types)}{Colors.ENDC}")
                print(f"     置信度分布: {', '.join(confidence_str)}")
                
                # 🔧 新增：显示路径保护信息
                flows_with_guard = sum(1 for f in flows if f.get('has_guard_before_sensitive'))
                flows_without_guard = len(flows) - flows_with_guard
                
                if flows_without_guard > 0:
                    print(f"     {Colors.RED}⚠️  无保护路径: {flows_without_guard} 条（污点汇→敏感操作无条件判断）{Colors.ENDC}")
                if flows_with_guard > 0:
                    print(f"     {Colors.YELLOW}🛡️  有保护路径: {flows_with_guard} 条（污点汇→敏感操作有条件判断）{Colors.ENDC}")
                
                # 显示高置信度的详细信息
                for flow in flows:
                    for sb in flow['sensitive_blocks']:
                        if sb.get('confidence') == 'high':
                            param_info = sb['param_tainted']
                            has_guard = flow.get('has_guard_before_sensitive', False)
                            guard_mark = " [有条件保护]" if has_guard else " [无保护⚠️]"
                            print(f"     {Colors.RED}🔥 高置信度: {param_info['reason']}{guard_mark}{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}✓ 未发现污点传播到敏感函数的直接路径{Colors.ENDC}")
        
        # 保存详细结果
        self._save_taint_to_sensitive_flows()
    
    def _find_last_sstore_in_path(self, path: List[int], var_slot: int, 
                                  basic_blocks: List[Dict]) -> int:
        """
        🔧 新增：在路径中找到最后一个写入变量的 SSTORE 的位置
        
        这个方法找到污点汇（SSTORE）在路径中的索引，
        用于分割路径为两段：
        1. 污点源 → 污点汇
        2. 污点汇 → 敏感操作
        
        Args:
            path: 完整的污点路径
            var_slot: 变量的存储槽位
            basic_blocks: 所有基本块
        
        Returns:
            污点汇在路径中的索引，未找到返回 -1
        """
        last_sstore_idx = -1
        
        for idx, bb_start in enumerate(path):
            # 找到对应的基本块
            block = next((b for b in basic_blocks if b['start'] == bb_start), None)
            if not block:
                continue
            
            # 检查基本块中是否有 SSTORE var_slot
            for instr_idx, instr in enumerate(block['instructions']):
                if instr['op'] == 'SSTORE':
                    # 检查是否是我们追踪的变量
                    if self._find_slot_in_stack(block['instructions'], instr_idx, var_slot):
                        last_sstore_idx = idx  # 记录位置
        
        return last_sstore_idx
    
    def _check_sensitive_op_param_tainted(self, bb_start: int, sensitive_op: Dict, 
                                          var_slot: int, basic_blocks: List[Dict],
                                          taint_path: List[int]) -> Dict:
        """
        🔧 新增：检查敏感操作的参数是否受污点影响
        
        通过向前回溯指令，检查参数来源：
        1. SLOAD var_slot：直接读取污点变量
        2. CALLER/CALLDATALOAD：来自其他污点源
        3. PUSH 常量：不受污点影响
        
        Args:
            bb_start: 基本块起始位置
            sensitive_op: 敏感操作信息
            var_slot: 污点变量的存储槽位
            basic_blocks: 所有基本块
            taint_path: 污点传播路径
        
        Returns:
            {
                'is_tainted': bool,  # 参数是否受污点影响
                'confidence': str,   # 置信度：high/medium/low
                'reason': str,       # 检测原因
                'param_source': str  # 参数来源
            }
        """
        # 找到包含敏感操作的基本块
        block = next((b for b in basic_blocks if b['start'] == bb_start), None)
        if not block:
            return {'is_tainted': False, 'confidence': 'low', 'reason': '未找到基本块', 'param_source': 'unknown'}
        
        # 找到敏感操作在基本块中的位置
        sensitive_offset = sensitive_op.get('offset', -1)
        instructions = block['instructions']
        sensitive_idx = None
        
        for idx, instr in enumerate(instructions):
            if instr.get('offset') == sensitive_offset:
                sensitive_idx = idx
                break
        
        if sensitive_idx is None:
            return {'is_tainted': False, 'confidence': 'low', 'reason': '未找到敏感操作', 'param_source': 'unknown'}
        
        # 🔧 关键：向前回溯，分析参数来源
        # 敏感操作的参数通常在栈顶（由前面的指令压入）
        
        # 回溯范围：最多检查前20条指令
        lookback_range = min(20, sensitive_idx)
        
        for back in range(1, lookback_range + 1):
            idx = sensitive_idx - back
            if idx < 0:
                break
            
            instr = instructions[idx]
            op = instr.get('op', '')
            
            # 🔧 检测1：SLOAD var_slot（直接读取污点变量）
            if op == 'SLOAD':
                # 检查 SLOAD 的槽位是否是我们追踪的变量
                if self._find_slot_in_stack(instructions, idx, var_slot):
                    return {
                        'is_tainted': True,
                        'confidence': 'high',
                        'reason': f'参数来自 SLOAD slot_{var_slot}（污点变量）',
                        'param_source': 'storage_read'
                    }
            
            # 🔧 检测2：来自其他污点源
            if op in ('CALLER', 'ORIGIN', 'CALLDATALOAD', 'CALLDATACOPY', 'CALLVALUE'):
                return {
                    'is_tainted': True,
                    'confidence': 'high',
                    'reason': f'参数来自污点源 {op}',
                    'param_source': op.lower()
                }
            
            # 🔧 检测3：PUSH 常量（不受污点影响）
            if op.startswith('PUSH'):
                # 如果最近的参数是常量，可能不受污点影响
                # 但需要考虑可能有多个参数，继续检查
                push_data = instr.get('push_data', '')
                if back <= 3:  # 如果是最近的几条指令
                    # 这可能是参数，但不一定是唯一参数
                    # 继续检查，但降低置信度
                    pass
        
        # 🔧 检测4：检查路径上是否有 SLOAD 操作
        # 即使在当前基本块没找到，也可能在前面的基本块中加载了
        path_idx = taint_path.index(bb_start) if bb_start in taint_path else -1
        if path_idx > 0:
            # 检查路径中前面的基本块
            for prev_bb_start in taint_path[:path_idx]:
                prev_block = next((b for b in basic_blocks if b['start'] == prev_bb_start), None)
                if prev_block:
                    for instr in prev_block['instructions']:
                        if instr.get('op') == 'SLOAD':
                            if self._find_slot_in_stack(prev_block['instructions'], 
                                                       prev_block['instructions'].index(instr), 
                                                       var_slot):
                                return {
                                    'is_tainted': True,
                                    'confidence': 'medium',
                                    'reason': f'路径上存在 SLOAD slot_{var_slot}（可能影响参数）',
                                    'param_source': 'storage_read_in_path'
                                }
        
        # 默认：无法确定污点影响（保守策略：标记为可能受影响）
        return {
            'is_tainted': True,
            'confidence': 'low',
            'reason': '无法确定参数来源，污点路径经过此处（保守判断）',
            'param_source': 'uncertain'
        }
    
    def _save_taint_to_sensitive_flows(self):
        """保存污点到敏感函数的流分析结果"""
        if not self.taint_to_sensitive_flows:
            return
        
        output_file = os.path.join(self.output_dir, "intermediate", "taint_to_sensitive_flows.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'flow_count': len(self.taint_to_sensitive_flows),
                'flows': self.taint_to_sensitive_flows
            }, f, indent=2, ensure_ascii=False)
        
        print(f"  → 污点-敏感函数流分析: {output_file}")
    
    def _save_taint_results(self):
        """保存污点分析结果"""
        output_file = os.path.join(self.output_dir, "intermediate", "taint_analysis.jsonl")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in self.taint_results:
                f.write(json.dumps(result, ensure_ascii=False) + '\n')
        
        print(f"  → 污点分析结果: {output_file}")

