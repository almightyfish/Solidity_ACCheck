#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 mapping 类型检测功能
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.bytecode import BytecodeAnalyzer


def test_mapping_metadata():
    """测试 mapping 类型元数据的正确性"""
    
    print("=" * 80)
    print("测试 Mapping 类型检测功能")
    print("=" * 80)
    
    # 模拟存储布局数据（来自 solc --storage-layout）
    mock_storage_layout = {
        'storage': [
            {
                'label': 'balance',
                'slot': 0,
                'offset': 0,
                'type': 't_uint256'
            },
            {
                'label': 'balances',
                'slot': 1,
                'offset': 0,
                'type': 't_mapping(t_address,t_uint256)'
            },
            {
                'label': 'admins',
                'slot': 2,
                'offset': 0,
                'type': 't_array(t_address)dyn_storage'
            }
        ],
        'types': {
            't_uint256': {
                'label': 'uint256',
                'encoding': 'inplace'
            },
            't_address': {
                'label': 'address',
                'encoding': 'inplace'
            },
            't_mapping(t_address,t_uint256)': {
                'label': 'mapping(address => uint256)',
                'encoding': 'mapping',
                'key': 't_address',
                'value': 't_uint256'
            },
            't_array(t_address)dyn_storage': {
                'label': 'address[]',
                'encoding': 'dynamic_array'
            }
        }
    }
    
    # 创建 BytecodeAnalyzer 实例
    analyzer = BytecodeAnalyzer(
        bytecode="0x608060405234801561001057600080fd5b50",  # 简化的字节码
        key_variables=['balance', 'balances', 'admins'],
        output_dir="/tmp/test_mapping_output"
    )
    
    # 直接调用映射方法
    analyzer._map_variables_from_layout(mock_storage_layout)
    
    print("\n[测试1] 普通变量检测")
    print("-" * 40)
    balance_info = analyzer.var_storage_map.get('balance', {})
    print(f"  变量: balance")
    print(f"  槽位: {balance_info.get('slot')}")
    print(f"  类型: {balance_info.get('type')}")
    print(f"  是否为 mapping: {balance_info.get('is_mapping', False)}")
    print(f"  是否为动态数组: {balance_info.get('is_dynamic_array', False)}")
    
    assert balance_info.get('slot') == 0
    assert balance_info.get('is_mapping') == False
    assert balance_info.get('is_dynamic_array') == False
    print("  ✅ 测试通过")
    
    print("\n[测试2] Mapping 类型检测")
    print("-" * 40)
    balances_info = analyzer.var_storage_map.get('balances', {})
    print(f"  变量: balances")
    print(f"  槽位: {balances_info.get('slot')}")
    print(f"  类型: {balances_info.get('type')}")
    print(f"  是否为 mapping: {balances_info.get('is_mapping', False)}")
    print(f"  是否为动态数组: {balances_info.get('is_dynamic_array', False)}")
    print(f"  存储模式: {balances_info.get('storage_pattern')}")
    print(f"  备注: {balances_info.get('note')}")
    
    assert balances_info.get('slot') == 1
    assert balances_info.get('is_mapping') == True
    assert balances_info.get('storage_pattern') == 'keccak256_key_slot'
    print("  ✅ 测试通过")
    
    print("\n[测试3] 动态数组检测")
    print("-" * 40)
    admins_info = analyzer.var_storage_map.get('admins', {})
    print(f"  变量: admins")
    print(f"  槽位: {admins_info.get('slot')}")
    print(f"  类型: {admins_info.get('type')}")
    print(f"  是否为 mapping: {admins_info.get('is_mapping', False)}")
    print(f"  是否为动态数组: {admins_info.get('is_dynamic_array', False)}")
    print(f"  存储模式: {admins_info.get('storage_pattern')}")
    print(f"  备注: {admins_info.get('note')}")
    
    assert admins_info.get('slot') == 2
    assert admins_info.get('is_dynamic_array') == True
    assert admins_info.get('storage_pattern') == 'keccak256_slot'
    print("  ✅ 测试通过")
    
    print("\n" + "=" * 80)
    print("✅ 所有测试通过！")
    print("=" * 80)
    
    # 清理
    import shutil
    if os.path.exists("/tmp/test_mapping_output"):
        shutil.rmtree("/tmp/test_mapping_output")


def test_slot_detection():
    """测试 mapping 访问模式的槽位检测"""
    
    print("\n" + "=" * 80)
    print("测试 Mapping 访问模式的槽位检测")
    print("=" * 80)
    
    # 模拟指令序列
    # 模式1: 直接访问 balance (slot 0)
    direct_access_instructions = [
        {'offset': 0, 'op': 'PUSH1', 'push_data': '64'},  # PUSH 100
        {'offset': 2, 'op': 'PUSH1', 'push_data': '00'},  # PUSH 0 (slot)
        {'offset': 4, 'op': 'SSTORE'}                     # SSTORE
    ]
    
    # 模式2: mapping 访问 balances[key] (slot 1)
    mapping_access_instructions = [
        {'offset': 0, 'op': 'CALLER'},                    # 获取 msg.sender
        {'offset': 1, 'op': 'PUSH1', 'push_data': '00'},  # PUSH 0 (内存位置)
        {'offset': 3, 'op': 'MSTORE'},                    # 存储到内存
        {'offset': 4, 'op': 'PUSH1', 'push_data': '01'},  # PUSH 1 (slot)
        {'offset': 6, 'op': 'PUSH1', 'push_data': '20'},  # PUSH 32
        {'offset': 8, 'op': 'MSTORE'},                    # 存储到内存
        {'offset': 9, 'op': 'PUSH1', 'push_data': '40'},  # PUSH 64
        {'offset': 11, 'op': 'PUSH1', 'push_data': '00'}, # PUSH 0
        {'offset': 13, 'op': 'SHA3'},                     # 计算 keccak256
        {'offset': 14, 'op': 'PUSH1', 'push_data': '64'}, # PUSH 100 (value)
        {'offset': 16, 'op': 'SWAP1'},                    # 交换栈顶
        {'offset': 17, 'op': 'SSTORE'}                    # SSTORE
    ]
    
    from core.taint import TaintAnalyzer
    
    # 创建一个模拟的字节码分析器
    class MockBytecodeAnalyzer:
        def __init__(self):
            self.var_storage_map = {
                'balance': {'slot': 0},
                'balances': {'slot': 1, 'is_mapping': True}
            }
    
    mock_analyzer = MockBytecodeAnalyzer()
    taint_analyzer = TaintAnalyzer(mock_analyzer, "/tmp")
    
    print("\n[测试4] 直接访问检测")
    print("-" * 40)
    result = taint_analyzer._find_slot_in_stack(
        direct_access_instructions, 
        len(direct_access_instructions) - 1,  # SSTORE 的索引（最后一条）
        0   # 查找 slot 0
    )
    print(f"  指令序列: PUSH 100 → PUSH 0 → SSTORE")
    print(f"  查找 slot 0: {result}")
    assert result == True
    print("  ✅ 测试通过")
    
    print("\n[测试5] Mapping 访问检测")
    print("-" * 40)
    result = taint_analyzer._find_slot_in_stack(
        mapping_access_instructions,
        len(mapping_access_instructions) - 1,  # SSTORE 的索引（最后一条）
        1    # 查找 slot 1
    )
    print(f"  指令序列: CALLER → ... → PUSH 1 → ... → SHA3 → PUSH 100 → SSTORE")
    print(f"  查找 slot 1 (通过 SHA3 模式): {result}")
    assert result == True
    print("  ✅ 测试通过")
    
    print("\n[测试6] 错误槽位检测（负向测试）")
    print("-" * 40)
    result = taint_analyzer._find_slot_in_stack(
        direct_access_instructions,
        len(direct_access_instructions) - 1,  # SSTORE 的索引（最后一条）
        1   # 查找 slot 1 (实际是 slot 0)
    )
    print(f"  指令序列: PUSH 100 → PUSH 0 → SSTORE")
    print(f"  查找 slot 1 (实际是 slot 0): {result}")
    assert result == False
    print("  ✅ 测试通过（正确识别为不匹配）")
    
    print("\n" + "=" * 80)
    print("✅ 所有槽位检测测试通过！")
    print("=" * 80)


if __name__ == "__main__":
    test_mapping_metadata()
    test_slot_detection()
    
    print("\n" + "=" * 80)
    print("🎉 所有测试完成！Mapping 类型检测功能正常工作。")
    print("=" * 80)

