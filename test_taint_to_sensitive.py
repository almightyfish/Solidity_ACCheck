#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试污点传播到敏感函数的关联检测功能

这个测试模拟一个高危场景：
- 用户输入（污点源）
- 传播到关键变量
- 变量被用于敏感函数调用（selfdestruct）
"""

import os
import sys
import tempfile
import shutil

# 添加路径
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.analyzer import AllInOneAnalyzer


def create_vulnerable_contract():
    """
    创建一个有漏洞的测试合约
    
    漏洞场景：
    1. owner 变量可以被任意用户修改（污点传播）
    2. destroy 函数使用 selfdestruct（敏感函数）
    3. 污点数据可以到达敏感函数
    """
    contract_code = """
pragma solidity ^0.4.24;

contract VulnerableContract {
    address public owner;
    uint256 public balance;
    
    // 构造函数
    function VulnerableContract() public {
        owner = msg.sender;
    }
    
    // 🔴 漏洞1: 任何人都可以修改 owner（无访问控制）
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }
    
    // 🔴 漏洞2: selfdestruct 无访问控制
    // 虽然检查了 owner，但 owner 可以被任意修改
    function destroy() public {
        if (msg.sender == owner) {
            selfdestruct(owner);
        }
    }
    
    // 正常函数
    function deposit() public payable {
        balance += msg.value;
    }
}
"""
    return contract_code


def create_safe_contract():
    """
    创建一个安全的测试合约
    
    安全措施：
    1. owner 变量有 onlyOwner 保护
    2. destroy 函数有 onlyOwner 保护
    3. 污点无法到达敏感函数
    """
    contract_code = """
pragma solidity ^0.4.24;

contract SafeContract {
    address public owner;
    uint256 public balance;
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    // 构造函数
    function SafeContract() public {
        owner = msg.sender;
    }
    
    // ✅ 安全: 有 onlyOwner 保护
    function setOwner(address _newOwner) public onlyOwner {
        owner = _newOwner;
    }
    
    // ✅ 安全: 有 onlyOwner 保护
    function destroy() public onlyOwner {
        selfdestruct(owner);
    }
    
    function deposit() public payable {
        balance += msg.value;
    }
}
"""
    return contract_code


def test_vulnerable_contract():
    """测试有漏洞的合约"""
    print("\n" + "=" * 80)
    print("🔴 测试 1: 有漏洞的合约（污点 → 敏感函数）")
    print("=" * 80)
    
    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    contract_path = os.path.join(temp_dir, "VulnerableContract.sol")
    output_dir = os.path.join(temp_dir, "output_vulnerable")
    
    try:
        # 保存合约
        with open(contract_path, 'w', encoding='utf-8') as f:
            f.write(create_vulnerable_contract())
        
        # 运行分析
        analyzer = AllInOneAnalyzer(
            solc_version='0.4.24',
            key_variables=['owner'],
            contract_path=contract_path,
            output_dir=output_dir
        )
        
        result = analyzer.run()
        
        if result:
            print("\n" + "=" * 80)
            print("📊 分析结果")
            print("=" * 80)
            
            # 检查是否检测到污点到敏感函数的流
            flows = result.get('taint_to_sensitive_flows', [])
            
            if flows:
                print(f"\n{Colors.RED}✅ 成功检测到污点传播到敏感函数！{Colors.ENDC}")
                print(f"   发现 {len(flows)} 条危险路径")
                
                for i, flow in enumerate(flows, 1):
                    print(f"\n   路径 {i}:")
                    print(f"     变量: {flow['variable']}")
                    print(f"     路径长度: {flow['path_length']} 个基本块")
                    print(f"     敏感操作数: {flow['sensitive_count']}")
                    print(f"     风险级别: {flow['risk_level']}")
                    
                    for sb in flow.get('sensitive_blocks', []):
                        for op in sb.get('operations', []):
                            print(f"       → {op['opcode']}: {op['description']}")
            else:
                print(f"\n{Colors.YELLOW}⚠️  未检测到污点到敏感函数的流{Colors.ENDC}")
                print("   这可能表示检测逻辑需要调整")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def test_safe_contract():
    """测试安全的合约"""
    print("\n" + "=" * 80)
    print("🟢 测试 2: 安全的合约（有访问控制保护）")
    print("=" * 80)
    
    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    contract_path = os.path.join(temp_dir, "SafeContract.sol")
    output_dir = os.path.join(temp_dir, "output_safe")
    
    try:
        # 保存合约
        with open(contract_path, 'w', encoding='utf-8') as f:
            f.write(create_safe_contract())
        
        # 运行分析
        analyzer = AllInOneAnalyzer(
            solc_version='0.4.24',
            key_variables=['owner'],
            contract_path=contract_path,
            output_dir=output_dir
        )
        
        result = analyzer.run()
        
        if result:
            print("\n" + "=" * 80)
            print("📊 分析结果")
            print("=" * 80)
            
            # 检查是否检测到污点到敏感函数的流
            flows = result.get('taint_to_sensitive_flows', [])
            
            if not flows:
                print(f"\n{Colors.GREEN}✅ 正确：未检测到污点传播到敏感函数{Colors.ENDC}")
                print("   访问控制有效阻止了污点传播")
            else:
                print(f"\n{Colors.YELLOW}⚠️  检测到 {len(flows)} 条流{Colors.ENDC}")
                print("   这可能是误报，需要人工审查")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


# 导入 Colors（如果可用）
try:
    from utils.colors import Colors
except:
    class Colors:
        RED = GREEN = YELLOW = ENDC = ""


if __name__ == "__main__":
    print("=" * 80)
    print("🧪 污点传播到敏感函数的关联检测测试")
    print("=" * 80)
    
    # 测试1: 有漏洞的合约
    test_vulnerable_contract()
    
    # 测试2: 安全的合约
    test_safe_contract()
    
    print("\n" + "=" * 80)
    print("✅ 测试完成")
    print("=" * 80)


