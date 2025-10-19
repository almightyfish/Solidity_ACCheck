#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试访问控制修饰符检测功能
"""

import sys
import os

# 添加core目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.source_mapper import SourceMapper


def test_access_control_detection():
    """测试访问控制修饰符检测"""
    
    # 创建测试合约内容
    test_contract = """
pragma solidity ^0.4.24;

contract TestContract {
    address public owner;
    uint256 public balance;
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == owner);
        _;
    }
    
    // 有onlyOwner修饰符的函数 - 应该被跳过，不标记为疑似路径
    function setBalanceWithOwner(uint256 _balance) public onlyOwner {
        balance = _balance;
    }
    
    // 有onlyAdmin修饰符的函数 - 应该被跳过，不标记为疑似路径
    function setBalanceWithAdmin(uint256 _balance) public onlyAdmin {
        balance = _balance;
    }
    
    // 没有修饰符的函数 - 应该被标记为危险或疑似路径
    function setBalanceWithoutModifier(uint256 _balance) public {
        balance = _balance;
    }
    
    // 有require的函数 - 应该被标记为可疑路径（不是完全跳过）
    function setBalanceWithRequire(uint256 _balance) public {
        require(msg.sender == owner);
        balance = _balance;
    }
}
"""
    
    # 保存测试合约
    test_file = "/tmp/test_access_control.sol"
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_contract)
    
    # 创建SourceMapper实例
    mapper = SourceMapper(test_file, "/tmp/test_output")
    
    print("=" * 80)
    print("测试访问控制修饰符检测功能")
    print("=" * 80)
    
    # 测试1: 检测onlyOwner修饰符
    print("\n[测试1] 检测 setBalanceWithOwner 函数的访问控制修饰符:")
    has_modifier = mapper._has_access_control_modifier("setBalanceWithOwner")
    print(f"  结果: {has_modifier}")
    print(f"  期望: True")
    print(f"  {'✅ 通过' if has_modifier else '❌ 失败'}")
    
    # 测试2: 检测onlyAdmin修饰符
    print("\n[测试2] 检测 setBalanceWithAdmin 函数的访问控制修饰符:")
    has_modifier = mapper._has_access_control_modifier("setBalanceWithAdmin")
    print(f"  结果: {has_modifier}")
    print(f"  期望: True")
    print(f"  {'✅ 通过' if has_modifier else '❌ 失败'}")
    
    # 测试3: 无修饰符的函数
    print("\n[测试3] 检测 setBalanceWithoutModifier 函数的访问控制修饰符:")
    has_modifier = mapper._has_access_control_modifier("setBalanceWithoutModifier")
    print(f"  结果: {has_modifier}")
    print(f"  期望: False")
    print(f"  {'✅ 通过' if not has_modifier else '❌ 失败'}")
    
    # 测试4: 有require但无修饰符的函数
    print("\n[测试4] 检测 setBalanceWithRequire 函数的访问控制修饰符:")
    has_modifier = mapper._has_access_control_modifier("setBalanceWithRequire")
    print(f"  结果: {has_modifier}")
    print(f"  期望: False (require不算修饰符)")
    print(f"  {'✅ 通过' if not has_modifier else '❌ 失败'}")
    
    # 测试5: 检查函数映射
    print("\n[测试5] 函数映射:")
    for func_name, func_info in mapper.function_map.items():
        print(f"  - {func_name}: 行 {func_info['start_line']}-{func_info['end_line']}")
    
    print("\n" + "=" * 80)
    print("测试完成！")
    print("=" * 80)
    
    # 清理
    if os.path.exists(test_file):
        os.remove(test_file)


if __name__ == "__main__":
    test_access_control_detection()


