#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
源码映射模块
"""

import json
import os
import re
from typing import List, Dict, Optional
from utils.colors import Colors


class SourceMapper:
    """源码映射器（使用solc srcmap）"""
    
    def __init__(self, source_file: str, output_dir: str, 
                 srcmap_runtime: str = None, runtime_bytecode: str = None):
        self.source_file = source_file
        self.output_dir = output_dir
        self.srcmap_runtime = srcmap_runtime
        self.runtime_bytecode = runtime_bytecode
        self.source_lines = []
        self.function_map = {}
        self.srcmap_entries = []  # 🔧 新增：解析后的srcmap条目
        self._load_and_parse_source()
        
        # 🔧 新增：如果有srcmap，则解析它
        if self.srcmap_runtime:
            self._parse_srcmap()
    
    def _load_and_parse_source(self):
        """加载并解析源码"""
        with open(self.source_file, 'r', encoding='utf-8') as f:
            self.source_lines = f.readlines()
        
        # 提取合约名称（用于识别构造函数）
        self.contract_names = self._extract_contract_name()  # 改为复数，返回列表
        
        # 两阶段解析：先找所有函数/modifier定义，再分配行号
        function_starts = []  # [(line_num, func_name, is_constructor, is_modifier), ...]
        
        # 阶段1：找到所有函数/modifier定义（排除注释）
        for line_num, line in enumerate(self.source_lines, 1):
            # 移除注释后再匹配
            code_part = line.split('//')[0]  # 移除单行注释
            
            # 🔧 新增：检查是否是 modifier
            modifier_match = re.search(r'\bmodifier\s+(\w+)', code_part)
            if modifier_match:
                modifier_name = modifier_match.group(1)
                function_starts.append((line_num, modifier_name, False, True))
                continue
            
            # 检查是否是构造函数 (Solidity 0.5.0+)
            constructor_match = re.search(r'\bconstructor\s*\(', code_part)
            if constructor_match:
                function_starts.append((line_num, 'constructor', True, False))
                continue
            
            # 检查是否是老式构造函数 (Solidity 0.4.x: function ContractName)
            # 🔧 修复：检查是否匹配任何一个合约名
            is_old_constructor = False
            if self.contract_names:
                for contract_name in self.contract_names:
                    old_constructor_match = re.search(rf'\bfunction\s+{re.escape(contract_name)}\s*\(', code_part)
                    if old_constructor_match:
                        function_starts.append((line_num, 'constructor', True, False))
                        is_old_constructor = True
                        break
            
            if is_old_constructor:
                continue
            
            # 🔧 检查是否是fallback函数（匿名函数）
            # Solidity 0.4.x: function() payable public
            # Solidity 0.6.0+: fallback() / receive()
            fallback_match = re.search(r'\bfunction\s*\(\s*\)', code_part)
            if fallback_match:
                # 检查是否是payable（通常fallback都是payable）
                is_fallback = True
                function_starts.append((line_num, 'fallback', False, False, is_fallback))
                continue
            
            # 检查新式fallback/receive
            if 'fallback()' in code_part or 'receive()' in code_part:
                func_type = 'receive' if 'receive()' in code_part else 'fallback'
                function_starts.append((line_num, func_type, False, False, True))
                continue
            
            # 普通函数
            func_match = re.search(r'function\s+(\w+)', code_part)
            if func_match:
                func_name = func_match.group(1)
                function_starts.append((line_num, func_name, False, False, False))
        
        # 阶段2：为每个函数/modifier分配行号范围
        for i, func_info_tuple in enumerate(function_starts):
            # 🔧 兼容新旧格式
            if len(func_info_tuple) == 5:
                start_line, func_name, is_constructor, is_modifier, is_fallback = func_info_tuple
            else:
                start_line, func_name, is_constructor, is_modifier = func_info_tuple
                is_fallback = False
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
                'variables_used': [],
                'is_constructor': is_constructor,  # 标记是否是构造函数
                'is_modifier': is_modifier,  # 标记是否是modifier
                'is_fallback': is_fallback  # 🔧 新增：标记是否是fallback/receive函数
            }
    
    def _extract_contract_name(self) -> List[str]:
        """提取所有合约名称（用于识别老式构造函数）
        
        注意：一个文件可能包含多个合约定义
        """
        contract_names = []
        for line in self.source_lines:
            # 匹配 contract ContractName { 或 contract ContractName is ...
            match = re.search(r'\bcontract\s+(\w+)', line)
            if match:
                contract_names.append(match.group(1))
        return contract_names
    
    def _parse_srcmap(self):
        """
        🔧 新增：解析Solidity源码映射（srcmap）
        
        srcmap格式：s:l:f:j[;s:l:f:j...]
        - s: 起始字节偏移（在源文件中的位置）
        - l: 长度（字节数）
        - f: 文件索引（通常是0）
        - j: 跳转类型（i=跳入, o=跳出, -=常规）
        
        压缩格式：可以省略与前一个相同的值，用空值表示
        例如: "0:10:0;:5;;;" 表示第二个条目从偏移10开始，长度5
        """
        if not self.srcmap_runtime:
            return
        
        entries = self.srcmap_runtime.split(';')
        prev_values = [0, 0, 0, '-']  # s, l, f, j
        
        for entry in entries:
            parts = entry.split(':')
            current_values = prev_values.copy()
            
            # 解析每个部分，空值表示使用前一个值
            for i, part in enumerate(parts):
                if part:  # 非空才更新
                    if i < 3:  # s, l, f 是数字
                        current_values[i] = int(part)
                    else:  # j 是字符
                        current_values[i] = part
            
            # 计算行号和列号
            line_num, col_num = self._offset_to_line_col(current_values[0])
            
            self.srcmap_entries.append({
                'offset': current_values[0],  # 字节偏移
                'length': current_values[1],  # 长度
                'file_index': current_values[2],  # 文件索引
                'jump_type': current_values[3],  # 跳转类型
                'line': line_num,  # 源码行号
                'column': col_num  # 源码列号
            })
            
            prev_values = current_values
        
        print(f"  ✓ 解析 srcmap: {len(self.srcmap_entries)} 个条目")
    
    def _offset_to_line_col(self, byte_offset: int) -> tuple:
        """
        将字节偏移转换为行号和列号
        
        Args:
            byte_offset: 源文件中的字节偏移
        
        Returns:
            (line_num, col_num): 行号（从1开始）和列号（从0开始）
        """
        current_offset = 0
        
        for line_num, line in enumerate(self.source_lines, 1):
            line_length = len(line.encode('utf-8'))
            
            if current_offset + line_length > byte_offset:
                # 找到了对应的行
                col_num = byte_offset - current_offset
                return (line_num, col_num)
            
            current_offset += line_length
        
        # 如果超出范围，返回最后一行
        return (len(self.source_lines), 0)
    
    def get_source_location_for_pc(self, pc: int, bytecode_instructions: List) -> Dict:
        """
        🔧 新增：根据程序计数器（PC）获取源码位置
        
        Args:
            pc: EVM程序计数器值
            bytecode_instructions: 反汇编的指令列表
        
        Returns:
            包含行号、列号、代码片段的字典
        """
        if not self.srcmap_entries or not bytecode_instructions:
            return None
        
        # 找到PC对应的指令索引
        instr_index = None
        for idx, instr in enumerate(bytecode_instructions):
            if instr.get('pc') == pc:
                instr_index = idx
                break
        
        if instr_index is None or instr_index >= len(self.srcmap_entries):
            return None
        
        srcmap_entry = self.srcmap_entries[instr_index]
        line_num = srcmap_entry['line']
        
        if line_num < 1 or line_num > len(self.source_lines):
            return None
        
        return {
            'line': line_num,
            'column': srcmap_entry['column'],
            'code': self.source_lines[line_num - 1].strip(),
            'function': self._find_function_for_line(line_num),
            'offset': srcmap_entry['offset'],
            'length': srcmap_entry['length']
        }
    
    def map_to_source(self, taint_results: List[Dict], bytecode_analyzer) -> List[Dict]:
        """将污点结果映射到源码"""
        print(f"\n{Colors.HEADER}【步骤5】源码映射{Colors.ENDC}")
        print("-" * 80)
        
        # 🔧 保存字节码分析器的指令信息（用于敏感函数映射）
        if hasattr(bytecode_analyzer, 'instructions'):
            self.instructions = bytecode_analyzer.instructions
        
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
            
            # 改进1: 基于污点分析的检测（使用字节码层面的条件信息）
            # 🔧 关键改进：利用字节码分析得到的路径条件信息，而非源码模式匹配
            if has_taint:
                # 构建写入操作到污点路径的映射
                # 通过检查写入操作所在的基本块是否在有条件的污点路径上
                for usage in usages:
                    # 核心修复：只有写入操作才可能是风险位置
                    if usage['operation'] == 'write':
                        # 🔧 关键修复1：跳过变量声明（不是运行时风险）
                        if usage.get('type') == 'declaration':
                            # 变量声明（如 uint256 constant BET = 100）不是运行时操作
                            # 不应该被标记为风险
                            continue
                        
                        func_name = usage.get('function')
                        
                        # 🔧 关键修复2：跳过构造函数、fallback和view/pure函数中的操作
                        if func_name:
                            func_info = self.function_map.get(func_name, {})
                            if func_info.get('is_constructor', False):
                                # 构造函数中的操作，直接跳过，不标记为危险
                                continue
                            if func_info.get('is_fallback', False):
                                # 🔧 新增：fallback/receive函数是接收以太币的，不是漏洞
                                # 例如：捐赠合约的fallback函数接收捐款并更新totalReceive
                                continue
                            
                            # 🔧 新增：跳过view/pure函数中的操作
                            if self._is_view_or_pure_function(func_name):
                                # view/pure函数不能修改状态，里面的赋值是给返回值赋值
                                # 例如：function getPet(...) view returns (uint256 genes) { genes = pet.genes; }
                                continue
                        
                        # 🔧 新方法：利用字节码分析的路径条件信息（增强版）
                        # 检查是否所有包含此写入的污点路径都有条件判断
                        has_path_condition = False
                        has_path_without_condition = False
                        bytecode_condition_types = []  # 🔧 新增：记录字节码发现的条件类型
                        bytecode_condition_details = []  # 🔧 新增：详细的条件信息
                        
                        if 'paths_with_conditions' in taint_result:
                            for path_info in taint_result['paths_with_conditions']:
                                if path_info['has_condition']:
                                    has_path_condition = True
                                    # 🔧 新增：收集条件类型
                                    if 'condition_types' in path_info:
                                        bytecode_condition_types.extend(path_info['condition_types'])
                                        bytecode_condition_details.append({
                                            'types': path_info['condition_types'],
                                            'count': path_info.get('condition_count', 0)
                                        })
                                else:
                                    has_path_without_condition = True
                        
                        # 去重条件类型
                        bytecode_condition_types = list(set(bytecode_condition_types))
                        
                        # 同时检查源码级别的访问控制（作为补充）
                        has_source_condition = self._check_source_has_condition(usage)
                        
                        # 🔧 改进：综合判断（双重验证机制）
                        has_protection = has_path_condition or has_source_condition
                        
                        # 🔧 新增：置信度评估
                        confidence = self._calculate_confidence(
                            has_path_condition, 
                            has_source_condition,
                            bytecode_condition_types
                        )
                        
                        location_info = usage.copy()
                        location_info['has_bytecode_condition'] = has_path_condition  # 字节码层面的条件
                        location_info['has_source_condition'] = has_source_condition  # 源码层面的条件
                        location_info['bytecode_condition_types'] = bytecode_condition_types  # 🔧 新增
                        location_info['bytecode_condition_details'] = bytecode_condition_details  # 🔧 新增
                        location_info['protection_confidence'] = confidence  # 🔧 新增：保护强度置信度
                        location_info['detection_method'] = 'taint_analysis'
                        
                        # 🔧 改进后的逻辑：
                        # 1. 如果字节码路径或源码都有保护 → 可疑（需人工审查）
                        # 2. 如果完全没有保护 → 危险（需立即修复）
                        if has_protection:
                            suspicious_locations.append(location_info)
                        else:
                            dangerous_locations.append(location_info)
                    # 读取操作（如 if (keyHash == 0x0)）不会被标记为风险
            
            # 改进2: 补充检测 - public函数写入关键变量但无访问控制（新增）
            # 即使污点分析失败，也能通过此机制检测到漏洞
            for usage in usages:
                if usage['operation'] == 'write':
                    # 🔧 关键修复1：跳过变量声明（不是运行时风险）
                    if usage.get('type') == 'declaration':
                        # 变量声明不是运行时操作，跳过
                        continue
                    
                    func_name = usage.get('function')
                    if func_name:
                        # 🔧 关键修复2：先检查是否是构造函数或fallback
                        func_info = self.function_map.get(func_name, {})
                        if func_info.get('is_constructor', False):
                            # 构造函数中的操作，跳过
                            continue
                        if func_info.get('is_fallback', False):
                            # 🔧 新增：fallback/receive函数，跳过
                            continue
                        
                        # 🔧 新增：跳过view/pure函数
                        if self._is_view_or_pure_function(func_name):
                            # view/pure函数不修改状态
                            continue
                        
                        # 检查是否是public函数且无访问控制
                        has_ac, reason = self._check_public_function_has_access_control(func_name)
                        
                        if not has_ac:  # public函数无访问控制
                            # 检查是否已经被标记（避免重复）
                            already_flagged = any(
                                loc['line'] == usage['line'] and loc['function'] == func_name
                                for loc in dangerous_locations + suspicious_locations
                            )
                            
                            if not already_flagged:
                                # 🔧 关键修复：即使无访问控制，也要检查是否有条件判断
                                has_source_condition = self._check_source_has_condition(usage)
                                
                                location_info = usage.copy()
                                location_info['has_source_condition'] = has_source_condition
                                location_info['detection_method'] = 'public_function_check'
                                location_info['warning'] = f"⚠️ {reason}"
                                
                                # 🔧 根据条件判断决定是危险还是可疑
                                if has_source_condition:
                                    # 有条件判断（require/if等） → 可疑
                                    suspicious_locations.append(location_info)
                                else:
                                    # 完全没有条件保护 → 危险
                                    dangerous_locations.append(location_info)
            
            # 重新计算：如果补充检测发现了危险位置，也应标记为有漏洞
            has_vulnerability = has_taint or len(dangerous_locations) > 0 or len(suspicious_locations) > 0
            
            # 🔧 重新计算路径统计：基于实际的危险和可疑位置
            # 而不是使用污点分析阶段的路径统计（那时候还包含构造函数）
            actual_dangerous_count = len(dangerous_locations)
            actual_suspicious_count = len(suspicious_locations)
            
            mapped = {
                'variable': var_name,
                'storage_slot': taint_result['offset'],
                'has_taint': has_taint,
                'has_vulnerability': has_vulnerability,  # 新增：综合判断
                'taint_paths_count': len(taint_result['taint_cfg']),
                'dangerous_paths_count': actual_dangerous_count,  # 🔧 修复：使用实际的危险位置数量
                'suspicious_paths_count': actual_suspicious_count,  # 🔧 修复：使用实际的可疑位置数量
                'affected_basic_blocks': taint_result['taint_bb'],
                'source_usages': usages,
                'dangerous_locations': dangerous_locations,  # 新增：危险位置（无保护）
                'suspicious_locations': suspicious_locations,  # 新增：可疑位置（有保护）
                'risk_locations': dangerous_locations + suspicious_locations  # 保持兼容性
            }
            
            mapped_results.append(mapped)
        
        # 🔧 改进：检测敏感函数（双重检测：字节码 + 源码）
        print(f"\n{Colors.HEADER}【额外检测】敏感函数分析（双重检测）{Colors.ENDC}")
        print("-" * 80)
        
        # 1️⃣ 字节码层面检测
        bytecode_sensitive = []
        if hasattr(bytecode_analyzer, 'sensitive_operations'):
            bytecode_sensitive = bytecode_analyzer.sensitive_operations
            if bytecode_sensitive:
                print(f"🔍 字节码检测: 发现 {len(bytecode_sensitive)} 个敏感操作")
        
        # 2️⃣ 源码层面检测
        source_sensitive = self._check_sensitive_functions()
        if source_sensitive:
            print(f"🔍 源码检测: 发现 {len(source_sensitive)} 个敏感函数调用")
        
        # 3️⃣ 综合结果（双重验证）
        sensitive_functions = self._merge_sensitive_detections(
            bytecode_sensitive, 
            source_sensitive
        )
        
        if sensitive_functions:
            print(f"\n{Colors.YELLOW}⚠️  综合结果: {len(sensitive_functions)} 个敏感操作{Colors.ENDC}")
            for sf in sensitive_functions:
                risk_color = Colors.GREEN if sf['has_access_control'] else Colors.RED
                risk_icon = "✅" if sf['has_access_control'] else "❌"
                detection_source = sf.get('detection_source', 'source')
                detection_badge = {
                    'both': '🔴🔵 双重检测',
                    'bytecode': '🔴 字节码',
                    'source': '🔵 源码'
                }.get(detection_source, detection_source)
                
                print(f"  {risk_icon} 行 {sf['line']:4d}: {sf['keyword']} - {sf['description']}")
                print(f"     检测来源: {detection_badge}")
                print(f"     函数: {sf['function']}, 访问控制: {sf['control_reason']}")
        else:
            print(f"{Colors.GREEN}✓ 未发现敏感函数调用{Colors.ENDC}")
        
        print(f"\n{Colors.GREEN}✓ 源码映射完成{Colors.ENDC}")
        print(f"  - 映射变量: {len(mapped_results)} 个")
        print(f"  - 敏感函数: {len(sensitive_functions)} 个")
        
        # 保存结果（包含敏感函数信息）
        self._save_mapped_results(mapped_results, sensitive_functions)
        
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
    
    def _is_view_or_pure_function(self, func_name: str) -> bool:
        """🔧 新增：检查函数是否是view或pure函数"""
        if not func_name:
            return False
        
        # 在源码中查找函数定义
        for line in self.source_lines:
            if f'function {func_name}' in line:
                # 检查是否包含 view 或 pure 关键字
                if 'view' in line or 'pure' in line:
                    return True
                break
        
        return False
    
    def _check_public_function_has_access_control(self, func_name: str):
        """
        检查public函数是否有访问控制（新增功能）
        
        返回: (has_control, reason)
        - has_control: True表示有访问控制，False表示无保护
        - reason: 说明原因
        """
        if not func_name:
            return False, "未知函数"
        
        # 🔧 新增：检查是否是构造函数
        func_info = self.function_map.get(func_name, {})
        if func_info.get('is_constructor', False):
            return True, "构造函数（仅部署时执行一次，安全）"
        
        # 🔧 新增：检查是否是modifier
        if func_info.get('is_modifier', False):
            return True, "modifier（由其他函数调用，本身不是漏洞点）"
        
        # 🔧 新增：检查是否是fallback/receive函数
        if func_info.get('is_fallback', False):
            return True, "fallback/receive函数（接收以太币的函数，任何人都应该能调用）"
        
        # 🔧 新增：检查是否是view/pure函数
        if self._is_view_or_pure_function(func_name):
            return True, "view/pure函数（只读函数，不修改状态，无需访问控制）"
        
        # 检查函数定义
        for line in self.source_lines:
            # 匹配构造函数（Solidity 0.5.0+）
            if 'constructor' in line and func_name == 'constructor':
                return True, "构造函数（仅部署时执行一次，安全）"
            
            # 匹配普通函数
            if f'function {func_name}' in line:
                # 检查是否是public/external函数
                if 'public' not in line and 'external' not in line:
                    return True, "非public函数"
                
                # 检查是否有访问控制modifier
                # 🔧 改进：使用更灵活的模式匹配
                access_control_patterns = [
                    'onlyOwner', 'onlyAdmin', 'only', 'ownerOnly',
                    'isOwner', 'isAdmin', 'is',  # 🔧 新增：isOwner(), isAdmin()等
                    'whenNotPaused', 'whenPaused',
                    'nonReentrant', 'senderIsOwner'
                ]
                if any(modifier in line for modifier in access_control_patterns):
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
    
    def _check_sensitive_functions(self) -> List[Dict]:
        """
        🔧 源码层面：检测敏感函数（selfdestruct, delegatecall等）是否有访问控制
        
        返回包含敏感函数位置和风险级别的列表
        """
        sensitive_functions = []
        
        # 定义敏感函数关键词
        sensitive_keywords = {
            'selfdestruct': '合约自毁',
            'suicide': '合约自毁（已弃用）',
            'delegatecall': '委托调用（可能改变合约状态）',
            'callcode': '代码调用（已弃用）',
        }
        
        for line_num, line in enumerate(self.source_lines, 1):
            # 🔧 改进：跳过注释行（减少误报）
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            
            for keyword, description in sensitive_keywords.items():
                if keyword in line.lower():
                    # 🔧 改进：检查是否在字符串中（简单检测）
                    if line.count('"') >= 2 and keyword in line.split('"')[1::2]:
                        continue  # 在字符串字面量中，跳过
                    
                    # 找到敏感函数所在的函数
                    func_name = self._find_function_for_line(line_num)
                    
                    if not func_name:
                        continue
                    
                    # 检查该函数是否有访问控制
                    has_control, reason = self._check_public_function_has_access_control(func_name)
                    
                    sensitive_functions.append({
                        'line': line_num,
                        'code': line.strip(),
                        'keyword': keyword,
                        'description': description,
                        'function': func_name,
                        'has_access_control': has_control,
                        'control_reason': reason,
                        'risk_level': 'low' if has_control else 'high',
                        'detection_source': 'source'  # 🔧 新增：标记来源
                    })
        
        return sensitive_functions
    
    def _merge_sensitive_detections(self, bytecode_ops: List[Dict], 
                                   source_funcs: List[Dict]) -> List[Dict]:
        """
        🔧 新增：合并字节码和源码的敏感函数检测结果
        
        策略：
        1. 字节码检测到但源码没检测到 → 使用字节码结果（可能源码被混淆）
        2. 源码检测到但字节码没检测到 → 使用源码结果（可能是条件调用）
        3. 两者都检测到 → 合并信息，标记为双重验证
        
        Args:
            bytecode_ops: 字节码层面检测的敏感操作
            source_funcs: 源码层面检测的敏感函数
        
        Returns:
            合并后的敏感函数列表
        """
        merged = []
        
        # 🔧 新增：使用srcmap将字节码操作映射到源码行
        bytecode_mapped = []
        if self.srcmap_entries and bytecode_ops:
            for op in bytecode_ops:
                # 尝试找到对应的源码位置
                # 简化版：通过基本块找到大致位置
                line = self._estimate_line_for_bytecode_op(op)
                if line:
                    bytecode_mapped.append({
                        'line': line,
                        'code': self.source_lines[line - 1].strip() if line <= len(self.source_lines) else '',
                        'keyword': op['opcode'].lower(),
                        'description': op['description'],
                        'function': self._find_function_for_line(line),
                        'has_access_control': False,  # 默认假设无保护，后续检查
                        'control_reason': '需要源码验证',
                        'risk_level': op['severity'],
                        'detection_source': 'bytecode'
                    })
        
        # 合并策略：基于行号匹配
        source_lines_set = {sf['line'] for sf in source_funcs}
        bytecode_lines_set = {bf['line'] for bf in bytecode_mapped}
        
        # 1. 源码检测到的（包括双重检测的）
        for sf in source_funcs:
            # 检查是否也被字节码检测到（双重验证）
            if sf['line'] in bytecode_lines_set:
                sf_copy = sf.copy()
                sf_copy['detection_source'] = 'both'  # 双重验证
                merged.append(sf_copy)
            else:
                merged.append(sf)
        
        # 2. 仅字节码检测到的（源码可能被混淆或优化）
        for bf in bytecode_mapped:
            if bf['line'] not in source_lines_set:
                # 检查访问控制（通过源码）
                if bf['function']:
                    has_control, reason = self._check_public_function_has_access_control(bf['function'])
                    bf['has_access_control'] = has_control
                    bf['control_reason'] = reason
                    bf['risk_level'] = 'low' if has_control else bf['risk_level']
                merged.append(bf)
        
        return merged
    
    def _estimate_line_for_bytecode_op(self, bytecode_op: Dict) -> Optional[int]:
        """
        🔧 新增：估算字节码操作对应的源码行号
        
        通过srcmap或基本块位置估算
        """
        if not self.srcmap_entries:
            return None
        
        offset = bytecode_op['offset']
        
        # 方法1：直接通过srcmap条目查找
        for idx, instr in enumerate(self.instructions if hasattr(self, 'instructions') else []):
            if instr.get('offset') == offset and idx < len(self.srcmap_entries):
                return self.srcmap_entries[idx]['line']
        
        # 方法2：通过基本块查找（如果有）
        bb_start = bytecode_op.get('basic_block', -1)
        if bb_start >= 0:
            # 查找该基本块的第一条指令对应的源码行
            for idx, instr in enumerate(self.instructions if hasattr(self, 'instructions') else []):
                if instr.get('offset') >= bb_start and idx < len(self.srcmap_entries):
                    return self.srcmap_entries[idx]['line']
        
        return None
    
    def _check_source_has_condition(self, usage: Dict) -> bool:
        """
        🔧 修复：检查源码位置是否有**任何**条件判断
        
        改进思路：
        - 任何require/assert/if语句都视为有条件保护
        - 不区分访问控制 vs 状态检查（都是条件）
        - 让字节码分析和人工审查来判断条件的有效性
        
        ✅ 有条件（返回True）：
        - require(...): 任何require语句
        - assert(...): 任何assert语句  
        - if (...): 任何if条件判断
        - modifier: 任何modifier
        
        返回: True表示有条件保护（需人工审查），False表示完全无保护（高危）
        """
        line_num = usage['line']
        func_name = usage.get('function')
        
        # 优先级1: 检查函数是否有访问控制modifier
        if func_name:
            for line in self.source_lines:
                if f'function {func_name}' in line:
                    # 🔧 改进：检查常见的访问控制modifier
                    access_control_patterns = [
                        'onlyOwner', 'onlyAdmin', 'only', 'ownerOnly',
                        'isOwner', 'isAdmin', 'is',  # 🔧 新增：isOwner(), isAdmin()等
                        'whenNotPaused', 'whenPaused',
                        'nonReentrant', 'senderIsOwner'
                    ]
                    if any(modifier in line for modifier in access_control_patterns):
                        return True
        
        # 🔧 优先级2: 检查函数内是否有**任何**条件判断（不仅限于访问控制）
        if func_name:
            func_lines = self.function_map.get(func_name, {}).get('lines', [])
            if func_lines:
                for func_line_num in func_lines:
                    # 只检查当前写入行之前的行（条件保护应该在赋值之前）
                    if func_line_num >= line_num:
                        continue
                    
                    if 0 <= func_line_num - 1 < len(self.source_lines):
                        line = self.source_lines[func_line_num - 1]
                        
                        # 🔧 关键修复：检查任何require/assert/if语句
                        if any(keyword in line for keyword in [
                            'require(', 'require (', 
                            'assert(', 'assert (',
                            'revert(', 'revert (',
                            'if (', 'if(',
                            'throw', 'throw;'  # Solidity 0.4.x
                        ]):
                            return True  # 🔧 有任何条件就返回True
                
                # ✅ 如果函数已识别，优先使用函数内检测，直接返回False（无条件）
                return False
        
        # 🔧 优先级3: 仅当函数未识别时，检查当前行前几行（限定范围，避免跨函数）
        # ⚠️ 重要：只检查同一作用域内的行，避免误把其他函数的条件当成保护
        check_range = 5  # 🔧 缩小范围到5行（从10改为5）
        
        for i in range(max(0, line_num - 1 - check_range), line_num - 1):
            if i < len(self.source_lines):
                line = self.source_lines[i]
                
                # 🔧 跳过函数声明行（避免跨函数检测）
                if 'function ' in line or '}' in line.strip():
                    continue
                
                # 🔧 检查任何条件语句
                if any(keyword in line for keyword in [
                    'require(', 'require (', 
                    'assert(', 'assert (',
                    'if (', 'if(',
                    'throw', 'throw;'
                ]):
                    # 🔧 额外验证：不是注释
                    stripped = line.strip()
                    if not stripped.startswith('//') and not stripped.startswith('*'):
                        return True
        
        return False
    
    def _calculate_confidence(self, has_bytecode_condition: bool, has_source_condition: bool, 
                             bytecode_condition_types: List[str]) -> str:
        """
        🔧 新增：计算保护强度的置信度
        
        置信度级别：
        - high: 字节码和源码都检测到条件，且包含访问控制
        - medium: 只有一方检测到，或者没有明确的访问控制
        - low: 两者都没检测到
        
        Args:
            has_bytecode_condition: 字节码是否检测到条件
            has_source_condition: 源码是否检测到条件
            bytecode_condition_types: 字节码检测到的条件类型列表
        
        Returns:
            'high', 'medium', 或 'low'
        """
        # 完全没有保护
        if not has_bytecode_condition and not has_source_condition:
            return 'low'
        
        # 双重验证：字节码和源码都检测到
        if has_bytecode_condition and has_source_condition:
            # 进一步检查：是否包含访问控制
            if 'access_control' in bytecode_condition_types:
                return 'high'  # 有明确的访问控制
            else:
                return 'medium'  # 有条件但不确定是否是访问控制
        
        # 单一验证：只有一方检测到
        if has_bytecode_condition:
            # 字节码检测到，检查条件类型
            if 'access_control' in bytecode_condition_types:
                return 'medium'  # 有访问控制特征
            elif 'revert' in bytecode_condition_types:
                return 'medium'  # 有回滚保护
            else:
                return 'low'  # 只有简单条件
        
        if has_source_condition:
            return 'medium'  # 源码检测到modifier或require
        
        return 'low'
    
    def _save_mapped_results(self, results: List[Dict], sensitive_functions: List[Dict] = None):
        """保存映射结果（包含敏感函数信息）"""
        output_file = os.path.join(self.output_dir, "intermediate", "source_mapping.json")
        
        # 🔧 新增：将敏感函数信息一起保存
        data_to_save = {
            'mapped_results': results,
            'sensitive_functions': sensitive_functions or []
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        
        print(f"  → 源码映射结果: {output_file}")

