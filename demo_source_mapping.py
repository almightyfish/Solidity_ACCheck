#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
源码映射演示 - 使用启发式方法将污点路径映射到源码
"""

import json
import re
from TaintAnalyzer import TaintAnalyzer
from BytecodeAnalyzer import BytecodeAnalyzer


class SimpleSourceMapper:
    """简单的源码映射器（启发式方法）"""
    
    def __init__(self, source_file: str):
        self.source_file = source_file
        self.source_lines = []
        self.function_map = {}
        self._load_and_parse_source()
    
    def _load_and_parse_source(self):
        """加载并解析源码"""
        with open(self.source_file, 'r', encoding='utf-8') as f:
            self.source_lines = f.readlines()
        
        # 解析函数和变量位置
        current_function = None
        for line_num, line in enumerate(self.source_lines, 1):
            # 检测函数声明
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                func_name = func_match.group(1)
                current_function = func_name
                self.function_map[func_name] = {
                    'start_line': line_num,
                    'lines': [],
                    'variables_used': []
                }
            
            # 记录函数体
            if current_function:
                self.function_map[current_function]['lines'].append(line_num)
                
                # 检测函数结束
                if line.strip() == '}' and len([c for c in line if c == '}']) == 1:
                    # 简单判断：单独的}可能是函数结束
                    pass
    
    def find_variable_usage(self, var_name: str):
        """查找变量在源码中的使用位置"""
        usages = []
        
        for line_num, line in enumerate(self.source_lines, 1):
            # 查找变量声明
            if re.search(rf'\b{var_name}\b.*?;', line):
                usage_type = 'declaration' if any(kw in line for kw in 
                    ['uint', 'address', 'bool', 'mapping', 'string']) else 'usage'
                
                # 判断是读还是写
                if '=' in line and var_name in line.split('=')[0]:
                    operation = 'write'
                elif var_name in line:
                    operation = 'read'
                else:
                    operation = 'unknown'
                
                usages.append({
                    'line': line_num,
                    'code': line.strip(),
                    'type': usage_type,
                    'operation': operation,
                    'function': self._find_function_for_line(line_num)
                })
        
        return usages
    
    def _find_function_for_line(self, line_num: int):
        """找到某行代码所属的函数"""
        for func_name, func_info in self.function_map.items():
            if line_num in func_info['lines']:
                return func_name
        return None
    
    def map_taint_to_source(self, taint_result: dict, bytecode_analyzer: BytecodeAnalyzer):
        """将污点分析结果映射到源码"""
        var_name = taint_result['name']
        has_taint = len(taint_result['taint_bb']) > 0
        
        # 查找变量在源码中的使用
        usages = self.find_variable_usage(var_name)
        
        # 如果检测到污点，标记写操作为潜在风险点
        risk_locations = []
        if has_taint:
            for usage in usages:
                if usage['operation'] == 'write':
                    risk_locations.append(usage)
        
        result = {
            'variable': var_name,
            'storage_slot': taint_result['offset'],
            'has_taint': has_taint,
            'taint_paths_count': len(taint_result['taint_cfg']),
            'affected_basic_blocks': taint_result['taint_bb'],
            'source_usages': usages,
            'risk_locations': risk_locations
        }
        
        return result


def analyze_and_map_to_source(bytecode_file: str, source_file: str, 
                               key_variables: list, output_file: str = None):
    """
    完整的分析流程：污点分析 + 源码映射
    
    参数:
        bytecode_file: runtime bytecode文件
        source_file: Solidity源码文件
        key_variables: 关键变量列表
        output_file: 输出文件（可选）
    """
    
    print("\n" + "=" * 80)
    print("智能合约污点分析与源码映射")
    print("=" * 80)
    print(f"Bytecode文件: {bytecode_file}")
    print(f"源码文件: {source_file}")
    print(f"分析变量: {', '.join(key_variables)}")
    
    # 步骤1: 污点分析
    print("\n【步骤1】字节码污点分析")
    print("-" * 80)
    
    taint_analyzer = TaintAnalyzer(bytecode_file, key_variables)
    taint_results = taint_analyzer.analyze()
    
    vulnerable_count = sum(1 for r in taint_results if r['taint_bb'])
    print(f"✓ 污点分析完成")
    print(f"  - 分析变量: {len(taint_results)} 个")
    print(f"  - 检测到污点: {vulnerable_count} 个")
    
    # 步骤2: 源码映射
    print("\n【步骤2】映射到源码")
    print("-" * 80)
    
    mapper = SimpleSourceMapper(source_file)
    mapped_results = []
    
    for taint_result in taint_results:
        mapped = mapper.map_taint_to_source(taint_result, taint_analyzer.bytecode_analyzer)
        mapped_results.append(mapped)
    
    print(f"✓ 源码映射完成")
    
    # 步骤3: 生成报告
    print("\n【步骤3】分析报告")
    print("=" * 80)
    
    for idx, result in enumerate(mapped_results, 1):
        var_name = result['variable']
        has_taint = result['has_taint']
        
        status_icon = "⚠️" if has_taint else "✅"
        status_text = "检测到污点" if has_taint else "未检测到污点"
        
        print(f"\n[{idx}] 变量: {var_name}")
        print(f"    状态: {status_icon} {status_text}")
        print(f"    存储槽位: {result['storage_slot']}")
        
        if has_taint:
            print(f"    污点路径数: {result['taint_paths_count']}")
            print(f"    受影响的基本块: {result['affected_basic_blocks']}")
        
        # 显示源码使用情况
        if result['source_usages']:
            print(f"\n    📄 源码中的使用位置:")
            for usage in result['source_usages']:
                op_icon = "✏️" if usage['operation'] == 'write' else "👁️"
                func_info = f" (在函数 {usage['function']})" if usage['function'] else ""
                print(f"       {op_icon} 行 {usage['line']:3d}: {usage['code']}{func_info}")
        
        # 显示风险位置
        if result['risk_locations']:
            print(f"\n    ⚠️  风险位置（可能受污点影响的写操作）:")
            for risk in result['risk_locations']:
                func_name = risk['function'] or '未知函数'
                print(f"       ⛔ 行 {risk['line']:3d} ({func_name}): {risk['code']}")
                
                # 读取前后几行代码提供上下文
                line_idx = risk['line'] - 1
                if line_idx > 0:
                    context_before = mapper.source_lines[line_idx - 1].strip()
                    print(f"          上文: {context_before}")
                if line_idx < len(mapper.source_lines) - 1:
                    context_after = mapper.source_lines[line_idx + 1].strip()
                    print(f"          下文: {context_after}")
    
    print("\n" + "=" * 80)
    
    # 安全建议
    _print_security_advice(mapped_results)
    
    # 保存结果
    if output_file:
        report = {
            'bytecode_file': bytecode_file,
            'source_file': source_file,
            'summary': {
                'total_variables': len(mapped_results),
                'vulnerable_variables': vulnerable_count
            },
            'results': mapped_results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 详细报告已保存到: {output_file}")
    
    return mapped_results


def _print_security_advice(results: list):
    """打印安全建议"""
    vulnerable = [r for r in results if r['has_taint']]
    
    if not vulnerable:
        print("\n✅ 安全评估: 未检测到明显的污点传播风险")
        print("   注意: 仍建议进行全面的安全审计")
        return
    
    print("\n⚠️  安全建议:")
    print("-" * 80)
    
    for result in vulnerable:
        var_name = result['variable']
        
        print(f"\n变量 '{var_name}' 的安全建议:")
        
        if 'owner' in var_name.lower():
            print("  这是权限控制变量，建议:")
            print("  1. 使用 modifier onlyOwner 保护所有修改owner的函数")
            print("  2. 考虑实现两步转移机制（transferOwnership + acceptOwnership）")
            print("  3. 为权限变更添加事件日志")
            print("\n  示例代码:")
            print("    modifier onlyOwner() {")
            print("        require(msg.sender == owner, 'Not owner');")
            print("        _;")
            print("    }")
            print("    function changeOwner(address newOwner) public onlyOwner { ... }")
        
        elif 'balance' in var_name.lower():
            print("  这是资金相关变量，建议:")
            print("  1. 使用 Checks-Effects-Interactions 模式")
            print("  2. 在外部调用前更新状态")
            print("  3. 使用 transfer/send 而不是 call.value")
            print("  4. 考虑添加提现限额和冷却期")
        
        elif any(kw in var_name.lower() for kw in ['auth', 'admin', 'pause']):
            print("  这是控制变量，建议:")
            print("  1. 添加适当的访问控制")
            print("  2. 使用 OpenZeppelin 的 Ownable/AccessControl")
            print("  3. 为状态变更添加事件")
        
        else:
            print("  通用建议:")
            print("  1. 检查所有修改此变量的函数是否有访问控制")
            print("  2. 验证所有外部输入")
            print("  3. 添加必要的 require 检查")


if __name__ == "__main__":
    # 演示：分析已有的合约
    print("\n" + "=" * 80)
    print("演示：使用启发式方法进行源码映射")
    print("=" * 80)
    
    # 使用已有的bytecode文件
    bytecode_file = "bytecode/contract.code"
    
    # 需要对应的源码文件（这里我们创建一个简化版本）
    # 如果没有对应的源码，会尽可能从字节码分析中推断
    
    key_vars = ["owner", "balance", "withdrawLimit"]
    
    import os
    if os.path.exists(bytecode_file):
        # 创建一个示例源码文件用于演示
        demo_source = """pragma solidity ^0.4.25;

contract SimpleWallet {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public withdrawLimit;
    
    constructor() public {
        owner = msg.sender;
        withdrawLimit = 1 ether;
    }
    
    function changeOwner(address newOwner) public {
        owner = newOwner;  // 危险：没有访问控制！
    }
    
    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
    
    function setLimit(uint256 newLimit) public {
        require(msg.sender == owner);
        withdrawLimit = newLimit;
    }
}
"""
        
        # 保存演示源码
        demo_source_file = "demo_contract.sol"
        with open(demo_source_file, 'w') as f:
            f.write(demo_source)
        
        print(f"\n已创建演示源码文件: {demo_source_file}")
        
        # 执行分析
        results = analyze_and_map_to_source(
            bytecode_file=bytecode_file,
            source_file=demo_source_file,
            key_variables=key_vars,
            output_file="source_mapped_analysis.json"
        )
        
        print("\n" + "=" * 80)
        print("✅ 演示完成！")
        print("=" * 80)
        print("\n使用方法:")
        print("  python demo_source_mapping.py")
        print("\n或在代码中调用:")
        print("  from demo_source_mapping import analyze_and_map_to_source")
        print("  results = analyze_and_map_to_source('your.code', 'your.sol', ['owner'])")
        
    else:
        print(f"\n❌ 找不到bytecode文件: {bytecode_file}")
        print("请确保文件存在或修改脚本中的路径")

