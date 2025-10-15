#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
源码映射器 - 将字节码位置映射回Solidity源码
"""

import json
import re
from typing import Dict, List, Tuple, Optional


class SourceMapper:
    """将字节码分析结果映射回源码"""
    
    def __init__(self, source_file: str = None, source_map: str = None, 
                 combined_json: str = None, bytecode_offset_map: Dict = None):
        """
        初始化源码映射器
        
        参数：
            source_file: Solidity源码文件路径
            source_map: solc生成的source map字符串
            combined_json: solc --combined-json的输出文件
            bytecode_offset_map: 自定义的字节码偏移映射
        """
        self.source_file = source_file
        self.source_map = source_map
        self.combined_json_path = combined_json
        self.source_code = None
        self.source_lines = []
        self.pc_to_source_map = {}
        self.bytecode_offset_map = bytecode_offset_map or {}
        
        # 加载源码
        if source_file:
            self._load_source_code()
        
        # 解析source map
        if combined_json:
            self._load_from_combined_json()
        elif source_map:
            self._parse_source_map()
    
    def _load_source_code(self):
        """加载Solidity源码"""
        try:
            with open(self.source_file, 'r', encoding='utf-8') as f:
                self.source_code = f.read()
                self.source_lines = self.source_code.split('\n')
        except Exception as e:
            print(f"警告: 无法加载源码文件 {self.source_file}: {e}")
    
    def _load_from_combined_json(self):
        """从solc的combined-json输出加载映射信息"""
        try:
            with open(self.combined_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # 获取第一个合约的信息
            if 'contracts' in data:
                for contract_name, contract_data in data['contracts'].items():
                    # 获取source map
                    if 'srcmap-runtime' in contract_data:
                        self.source_map = contract_data['srcmap-runtime']
                    
                    # 获取源码
                    if 'source' in contract_data:
                        self.source_code = contract_data['source']
                        self.source_lines = self.source_code.split('\n')
                    
                    break  # 只处理第一个合约
            
            # 解析source map
            if self.source_map:
                self._parse_source_map()
                
        except Exception as e:
            print(f"警告: 无法加载combined-json文件: {e}")
    
    def _parse_source_map(self):
        """
        解析Solidity的source map格式
        格式: s:l:f:j 其中
        s = 源码起始位置
        l = 长度
        f = 文件索引
        j = 跳转类型
        """
        if not self.source_map:
            return
        
        entries = self.source_map.split(';')
        pc = 0
        last_mapping = {'s': 0, 'l': 0, 'f': 0, 'j': ''}
        
        for entry in entries:
            if entry:
                parts = entry.split(':')
                
                # 解析当前条目（可能省略某些字段）
                if len(parts) > 0 and parts[0]:
                    last_mapping['s'] = int(parts[0])
                if len(parts) > 1 and parts[1]:
                    last_mapping['l'] = int(parts[1])
                if len(parts) > 2 and parts[2]:
                    last_mapping['f'] = int(parts[2])
                if len(parts) > 3 and parts[3]:
                    last_mapping['j'] = parts[3]
            
            # 存储映射
            self.pc_to_source_map[pc] = dict(last_mapping)
            pc += 1
    
    def get_source_location(self, bytecode_offset: int) -> Optional[Dict]:
        """
        获取字节码偏移对应的源码位置
        
        返回: {
            'start': 源码起始位置,
            'length': 源码长度,
            'line': 行号,
            'column': 列号,
            'code_snippet': 代码片段
        }
        """
        if bytecode_offset not in self.pc_to_source_map:
            return None
        
        mapping = self.pc_to_source_map[bytecode_offset]
        start = mapping['s']
        length = mapping['l']
        
        if not self.source_code:
            return {
                'start': start,
                'length': length,
                'line': None,
                'column': None,
                'code_snippet': None
            }
        
        # 计算行号和列号
        line, column = self._offset_to_line_column(start)
        
        # 提取代码片段
        end = start + length
        snippet = self.source_code[start:end]
        
        # 获取完整的行内容
        full_line = self.source_lines[line - 1] if line > 0 else ""
        
        return {
            'start': start,
            'length': length,
            'line': line,
            'column': column,
            'code_snippet': snippet,
            'full_line': full_line.strip()
        }
    
    def _offset_to_line_column(self, offset: int) -> Tuple[int, int]:
        """将字符偏移转换为行号和列号"""
        if not self.source_code:
            return (0, 0)
        
        line = 1
        column = 1
        
        for i, char in enumerate(self.source_code):
            if i >= offset:
                break
            if char == '\n':
                line += 1
                column = 1
            else:
                column += 1
        
        return (line, column)
    
    def map_taint_path_to_source(self, taint_result: Dict, 
                                  basic_blocks: List[Dict]) -> Dict:
        """
        将污点分析结果映射到源码
        
        参数:
            taint_result: TaintAnalyzer返回的单个变量分析结果
            basic_blocks: BytecodeAnalyzer的基本块列表
        
        返回:
            包含源码映射信息的结果
        """
        result = {
            'variable': taint_result['name'],
            'storage_slot': taint_result['offset'],
            'has_taint': len(taint_result['taint_bb']) > 0,
            'taint_paths': [],
            'affected_source_locations': []
        }
        
        # 为每条污点路径创建源码映射
        for path in taint_result['taint_cfg']:
            path_mapping = {
                'basic_blocks': path,
                'source_locations': []
            }
            
            for bb_start in path:
                # 找到对应的基本块
                block = next((b for b in basic_blocks if b['start'] == bb_start), None)
                if not block:
                    continue
                
                # 获取该基本块中关键指令的源码位置
                for instr in block['instructions']:
                    offset = instr['offset']
                    
                    # 只关注关键指令
                    if instr['op'] in ['SSTORE', 'SLOAD', 'CALLER', 'ORIGIN', 
                                       'CALLDATALOAD', 'CALLDATACOPY']:
                        source_loc = self.get_source_location(offset)
                        if source_loc:
                            path_mapping['source_locations'].append({
                                'bytecode_offset': offset,
                                'opcode': instr['op'],
                                'source': source_loc
                            })
            
            result['taint_paths'].append(path_mapping)
        
        # 收集所有受影响的源码位置（去重）
        all_locations = {}
        for path in result['taint_paths']:
            for loc in path['source_locations']:
                if loc['source']['line']:
                    line_num = loc['source']['line']
                    if line_num not in all_locations:
                        all_locations[line_num] = {
                            'line': line_num,
                            'code': loc['source']['full_line'],
                            'opcodes': []
                        }
                    all_locations[line_num]['opcodes'].append(loc['opcode'])
        
        result['affected_source_locations'] = sorted(
            all_locations.values(), 
            key=lambda x: x['line']
        )
        
        return result
    
    def create_manual_mapping(self, source_file: str, 
                              function_annotations: Dict[str, List[int]]) -> Dict:
        """
        创建手动映射（当没有source map时的备选方案）
        
        参数:
            source_file: Solidity源码文件
            function_annotations: 函数名到基本块的映射
                例如: {'transferOwnership': [100, 200], 'withdraw': [300, 400]}
        
        返回:
            手动创建的映射字典
        """
        mapping = {}
        
        if not self.source_code:
            self._load_source_code()
        
        for line_num, line in enumerate(self.source_lines, 1):
            # 检测函数声明
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                func_name = func_match.group(1)
                if func_name in function_annotations:
                    for bb in function_annotations[func_name]:
                        mapping[bb] = {
                            'line': line_num,
                            'code': line.strip(),
                            'function': func_name
                        }
            
            # 检测关键操作
            if 'owner' in line.lower():
                mapping[line_num * 10] = {  # 简单的假设映射
                    'line': line_num,
                    'code': line.strip()
                }
        
        return mapping


def generate_source_mapped_report(taint_results: List[Dict], 
                                   basic_blocks: List[Dict],
                                   source_mapper: SourceMapper) -> Dict:
    """
    生成包含源码映射的完整报告
    
    参数:
        taint_results: TaintAnalyzer的分析结果列表
        basic_blocks: BytecodeAnalyzer的基本块列表
        source_mapper: 源码映射器实例
    
    返回:
        完整的映射报告
    """
    report = {
        'summary': {
            'total_variables': len(taint_results),
            'vulnerable_variables': sum(1 for r in taint_results if r['taint_bb']),
        },
        'results': []
    }
    
    for taint_result in taint_results:
        mapped_result = source_mapper.map_taint_path_to_source(
            taint_result, 
            basic_blocks
        )
        report['results'].append(mapped_result)
    
    return report


if __name__ == "__main__":
    # 示例用法
    print("源码映射器使用示例:")
    print("\n1. 使用solc生成combined-json:")
    print("   solc --combined-json bin-runtime,srcmap-runtime,source Contract.sol > combined.json")
    
    print("\n2. 在Python中使用:")
    print("""
    from SourceMapper import SourceMapper, generate_source_mapped_report
    from BytecodeAnalyzer import BytecodeAnalyzer
    from TaintAnalyzer import TaintAnalyzer
    
    # 执行污点分析
    analyzer = TaintAnalyzer('contract.code', ['owner', 'balance'])
    taint_results = analyzer.analyze()
    basic_blocks = analyzer.bytecode_analyzer.basic_blocks
    
    # 创建源码映射器
    mapper = SourceMapper(
        source_file='Contract.sol',
        combined_json='combined.json'
    )
    
    # 生成映射报告
    report = generate_source_mapped_report(taint_results, basic_blocks, mapper)
    
    # 查看结果
    for result in report['results']:
        print(f"变量: {result['variable']}")
        for loc in result['affected_source_locations']:
            print(f"  行 {loc['line']}: {loc['code']}")
    """)


