#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能合约字节码污点分析示例
此脚本演示如何使用BytecodeAnalyzer和TaintAnalyzer对智能合约进行污点分析
"""

import json
import sys
import os

# 添加路径以便导入模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bytecode_analysis.BytecodeAnalyzer import BytecodeAnalyzer
from bytecode_analysis.TaintAnalyzer import TaintAnalyzer


def analyze_contract_bytecode(bytecode_path: str, key_variables: list, output_file: str = None):
    """
    对智能合约的runtime bytecode进行完整的污点分析
    
    参数:
        bytecode_path: runtime bytecode文件路径
        key_variables: 需要分析的关键变量列表（例如: ["owner", "balance", "withdrawLimit"]）
        output_file: 结果输出文件路径（可选）
    
    返回:
        污点分析结果列表
    """
    
    print("=" * 70)
    print("开始智能合约字节码污点分析")
    print("=" * 70)
    
    # 第一步：字节码分析
    print("\n【第1步】字节码反汇编和控制流分析")
    print("-" * 70)
    bytecode_analyzer = BytecodeAnalyzer(bytecode_path, key_variables)
    
    # 反汇编字节码
    instructions = bytecode_analyzer.disassemble()
    print(f"✓ 反汇编完成，共 {len(instructions)} 条指令")
    
    # 显示前10条指令
    print("\n前10条指令:")
    for i, instr in enumerate(instructions[:10]):
        push_info = f" [{instr.get('push_data', '')}]" if 'push_data' in instr else ""
        print(f"  {i:3d}. offset={instr['offset']:4d} | {instr['op']}{push_info}")
    
    # 分析控制流图
    bytecode_analyzer.analyze_cfg()
    print(f"\n✓ CFG分析完成，共 {len(bytecode_analyzer.basic_blocks)} 个基本块")
    
    # 显示基本块信息
    print("\n基本块摘要:")
    for idx, block in enumerate(bytecode_analyzer.basic_blocks[:5]):  # 只显示前5个
        ops = [instr['op'] for instr in block['instructions'][:5]]
        print(f"  Block {idx}: offset={block['start']}, {len(block['instructions'])} instrs, "
              f"ops={ops}{'...' if len(block['instructions']) > 5 else ''}")
    if len(bytecode_analyzer.basic_blocks) > 5:
        print(f"  ... 还有 {len(bytecode_analyzer.basic_blocks) - 5} 个基本块")
    
    # 映射变量到存储槽位
    bytecode_analyzer.match_key_vars_to_storage()
    print(f"\n✓ 关键变量存储映射:")
    for var, info in bytecode_analyzer.var_storage_map.items():
        print(f"  {var} -> slot {info.get('slot')}")
    
    # 第二步：污点分析
    print("\n【第2步】污点分析")
    print("-" * 70)
    taint_analyzer = TaintAnalyzer(bytecode_path, key_variables)
    taint_results = taint_analyzer.analyze()
    
    print(f"✓ 污点分析完成，分析了 {len(taint_results)} 个关键变量")
    
    # 显示详细结果
    print("\n污点分析结果:")
    for idx, result in enumerate(taint_results, 1):
        var_name = result['name']
        slot = result['offset']
        taint_bbs = result['taint_bb']
        taint_paths = result['taint_cfg']
        
        print(f"\n  [{idx}] 变量: {var_name} (存储槽位: {slot})")
        
        if taint_bbs:
            print(f"      ⚠️  检测到污点传播！")
            print(f"      受污点影响的基本块: {taint_bbs}")
            print(f"      发现 {len(taint_paths)} 条污点传播路径")
            
            # 显示路径详情
            if taint_paths:
                print(f"      污点路径示例:")
                for path_idx, path in enumerate(taint_paths[:3], 1):  # 只显示前3条路径
                    print(f"        路径 {path_idx}: {' -> '.join(map(str, path))}")
                if len(taint_paths) > 3:
                    print(f"        ... 还有 {len(taint_paths) - 3} 条路径")
        else:
            print(f"      ✓ 未检测到污点传播，该变量安全")
    
    # 第三步：保存结果
    if output_file:
        print(f"\n【第3步】保存结果到文件")
        print("-" * 70)
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in taint_results:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(f"✓ 结果已保存到: {output_file}")
    
    # 生成总结报告
    print("\n" + "=" * 70)
    print("分析总结")
    print("=" * 70)
    
    vulnerable_vars = [r for r in taint_results if r['taint_bb']]
    safe_vars = [r for r in taint_results if not r['taint_bb']]
    
    print(f"总共分析的关键变量: {len(taint_results)}")
    print(f"受污点影响的变量: {len(vulnerable_vars)}")
    print(f"安全的变量: {len(safe_vars)}")
    
    if vulnerable_vars:
        print(f"\n⚠️  风险提示: 以下变量可能受到用户输入或外部调用的影响:")
        for result in vulnerable_vars:
            print(f"  - {result['name']} (发现 {len(result['taint_cfg'])} 条污点路径)")
    else:
        print(f"\n✓ 所有关键变量未检测到明显的污点传播风险")
    
    print("=" * 70)
    
    return taint_results


def analyze_with_custom_sources_sinks(bytecode_path: str, key_variables: list):
    """
    高级用法：自定义污点源和污点汇
    """
    print("\n高级分析：自定义污点源和污点汇")
    print("-" * 70)
    
    # 这里可以扩展TaintAnalyzer类来支持自定义污点源
    # 默认的污点源包括：CALLDATALOAD, CALLDATACOPY, CALLER, ORIGIN
    # 默认的污点汇包括：SSTORE, SLOAD
    
    taint_sources = {
        'CALLDATALOAD': '用户输入数据',
        'CALLDATACOPY': '用户输入数据复制',
        'CALLER': '调用者地址',
        'ORIGIN': '交易发起者地址',
        'CALLVALUE': 'ETH转账金额',
        'BALANCE': '账户余额',
    }
    
    print("当前污点源定义:")
    for source, desc in taint_sources.items():
        print(f"  - {source}: {desc}")
    
    print("\n当前污点汇定义:")
    print("  - SSTORE: 写入存储槽位（状态变量修改）")
    print("  - SLOAD: 读取存储槽位（状态变量读取）")


if __name__ == "__main__":
    # 示例1: 分析示例合约
    print("\n" + "=" * 70)
    print("示例1: 分析 contract.code")
    print("=" * 70)
    
    bytecode_file = "bytecode/contract.code"
    key_vars = ["owner", "balance", "withdrawLimit"]
    
    if os.path.exists(bytecode_file):
        results = analyze_contract_bytecode(
            bytecode_path=bytecode_file,
            key_variables=key_vars,
            output_file="taint_analysis_results.jsonl"
        )
    else:
        print(f"❌ 错误: 文件不存在 {bytecode_file}")
        print(f"请确保bytecode文件位于正确路径")
    
    # 示例2: 显示高级用法
    print("\n" + "=" * 70)
    print("示例2: 高级用法说明")
    print("=" * 70)
    analyze_with_custom_sources_sinks(bytecode_file, key_vars)
    
    # 使用说明
    print("\n" + "=" * 70)
    print("使用说明")
    print("=" * 70)
    print("""
如何使用此工具分析您自己的合约:

1. 准备runtime bytecode文件:
   - 使用 solc 编译: solc --bin-runtime YourContract.sol
   - 或从区块链浏览器获取已部署合约的runtime bytecode
   - 将bytecode保存到 .code 文件中

2. 确定关键变量:
   - 识别合约中需要保护的状态变量
   - 例如: owner, balance, authorized, paused 等

3. 运行分析:
   ```python
   from bytecode_analysis.TaintAnalyzer import TaintAnalyzer
   
   key_variables = ["owner", "balance", "isAuthorized"]
   analyzer = TaintAnalyzer("your_contract.code", key_variables)
   results = analyzer.analyze()
   ```

4. 解读结果:
   - taint_bb: 受污点影响的基本块编号
   - taint_cfg: 污点传播的具体路径
   - 如果 taint_bb 非空，说明该变量可能被外部输入影响

5. 安全建议:
   - 对受污点影响的变量添加访问控制检查
   - 验证所有外部输入
   - 使用 modifier 保护敏感函数
""")


