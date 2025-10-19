#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试存储布局检测功能

演示如何使用改进后的 BytecodeAnalyzer 来准确获取变量的存储槽位
"""

import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from core.analyzer import AllInOneAnalyzer


def test_storage_layout():
    """测试存储布局检测"""
    
    print("\n" + "=" * 80)
    print("测试：使用 solc --storage-layout 获取准确的存储槽位")
    print("=" * 80)
    
    # 配置
    contract_path = os.path.join(os.path.dirname(__file__), "test_storage_layout.sol")
    output_dir = "test_storage_output"
    
    # 关键变量（包含不同类型）
    key_variables = [
        "owner",         # 简单类型 - slot 0
        "balance",       # 简单类型 - slot 1
        "isActive",      # 简单类型 - slot 2
        "balances",      # mapping - slot 3 (基础槽位)
        "users",         # 动态数组 - slot 4
        "fixedArray",    # 固定数组 - slot 5
        "userInfo",      # mapping(struct) - slot 8
        "allowances",    # 嵌套mapping - slot 9
    ]
    
    # 创建分析器
    analyzer = AllInOneAnalyzer(
        solc_version="0.8.0",
        key_variables=key_variables,
        contract_path=contract_path,
        output_dir=output_dir
    )
    
    # 运行分析
    result = analyzer.run()
    
    if result:
        print("\n" + "=" * 80)
        print("✅ 测试成功！")
        print("=" * 80)
        print(f"\n请查看输出目录: {output_dir}")
        print(f"  - intermediate/bytecode_analysis.json 包含详细的存储布局信息")
        
        # 显示存储布局摘要
        print("\n存储布局摘要:")
        bytecode_analysis_file = os.path.join(output_dir, "intermediate", "bytecode_analysis.json")
        if os.path.exists(bytecode_analysis_file):
            import json
            with open(bytecode_analysis_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                var_map = data.get('variable_storage_map', {})
                
                print("\n变量名".ljust(20) + "槽位".ljust(10) + "类型".ljust(30) + "备注")
                print("-" * 100)
                for var_name, info in var_map.items():
                    slot = info.get('slot', 'N/A')
                    var_type = info.get('type', 'unknown')
                    note = info.get('note', '')
                    print(f"{var_name.ljust(20)}{str(slot).ljust(10)}{var_type.ljust(30)}{note}")
    else:
        print("\n" + "=" * 80)
        print("❌ 测试失败")
        print("=" * 80)


def test_comparison():
    """对比测试：旧方法 vs 新方法"""
    
    print("\n" + "=" * 80)
    print("对比测试：简单索引映射 vs solc --storage-layout")
    print("=" * 80)
    
    # 模拟旧方法（简单索引）
    print("\n【旧方法】简单索引映射:")
    old_mapping = {
        "owner": {"slot": 0, "type": "unknown"},
        "balance": {"slot": 1, "type": "unknown"},
        "isActive": {"slot": 2, "type": "unknown"},
        "balances": {"slot": 3, "type": "unknown"},  # ❌ 不知道是 mapping
        "users": {"slot": 4, "type": "unknown"},     # ❌ 不知道是动态数组
        "fixedArray": {"slot": 5, "type": "unknown"}, # ❌ 不知道占3个槽位
    }
    
    for var, info in old_mapping.items():
        print(f"  {var} → slot {info['slot']} [{info['type']}]")
    
    print("\n⚠️  问题：")
    print("  1. 无法识别 mapping 类型，可能导致误判")
    print("  2. 无法识别动态数组，不知道需要计算实际槽位")
    print("  3. 无法知道固定数组的大小，可能跨多个槽位")
    
    print("\n【新方法】使用 solc --storage-layout:")
    print("  ✅ 准确获取每个变量的槽位")
    print("  ✅ 识别变量类型（mapping、array、struct等）")
    print("  ✅ 提供槽位计算说明（mapping需要keccak256）")
    print("  ✅ 支持复杂类型（嵌套mapping、结构体等）")


if __name__ == "__main__":
    # 检查 solc 是否安装
    import subprocess
    try:
        result = subprocess.run(['solc', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print("❌ 未找到 solc 编译器，请先安装")
            print("\n安装方法:")
            print("  pip install solc-select")
            print("  solc-select install 0.8.0")
            print("  solc-select use 0.8.0")
            sys.exit(1)
    except FileNotFoundError:
        print("❌ 未找到 solc 编译器，请先安装")
        sys.exit(1)
    
    # 运行对比测试
    test_comparison()
    
    # 运行实际测试
    print("\n" + "=" * 80)
    input("按 Enter 继续运行实际测试...")
    test_storage_layout()



