#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的API接口 - 一键运行污点分析
用法：
    python analyze.py <bytecode_file> <var1> <var2> <var3> ...
    
示例：
    python analyze.py bytecode/contract.code owner balance authorized
"""

import sys
import json
import os
from TaintAnalyzer import TaintAnalyzer


def analyze_contract(bytecode_file: str, key_variables: list, output_file: str = None) -> dict:
    """
    对智能合约进行污点分析
    
    参数：
        bytecode_file: runtime bytecode文件路径
        key_variables: 关键变量名列表
        output_file: 可选，输出文件路径
    
    返回：
        包含分析结果的字典
    """
    
    # 检查文件是否存在
    if not os.path.exists(bytecode_file):
        raise FileNotFoundError(f"字节码文件不存在: {bytecode_file}")
    
    # 执行污点分析
    analyzer = TaintAnalyzer(bytecode_file, key_variables)
    results = analyzer.analyze()
    
    # 统计信息
    vulnerable_count = sum(1 for r in results if r['taint_bb'])
    safe_count = len(results) - vulnerable_count
    
    # 构建返回结果
    analysis_result = {
        "bytecode_file": bytecode_file,
        "total_variables": len(results),
        "vulnerable_variables": vulnerable_count,
        "safe_variables": safe_count,
        "details": results,
        "summary": []
    }
    
    # 生成摘要
    for result in results:
        var_summary = {
            "variable": result['name'],
            "storage_slot": result['offset'],
            "is_vulnerable": len(result['taint_bb']) > 0,
            "taint_paths_count": len(result['taint_cfg'])
        }
        analysis_result["summary"].append(var_summary)
    
    # 保存到文件（如果指定）
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, ensure_ascii=False, indent=2)
    
    return analysis_result


def print_results(result: dict):
    """美化打印分析结果"""
    
    print("\n" + "=" * 70)
    print("智能合约污点分析报告")
    print("=" * 70)
    print(f"\n📄 分析文件: {result['bytecode_file']}")
    print(f"📊 分析变量总数: {result['total_variables']}")
    print(f"⚠️  受污点影响: {result['vulnerable_variables']}")
    print(f"✅ 未受影响: {result['safe_variables']}")
    
    print("\n" + "-" * 70)
    print("详细结果:")
    print("-" * 70)
    
    for idx, summary in enumerate(result['summary'], 1):
        var = summary['variable']
        slot = summary['storage_slot']
        is_vuln = summary['is_vulnerable']
        paths = summary['taint_paths_count']
        
        status = "⚠️  有污点" if is_vuln else "✅ 安全"
        
        print(f"\n[{idx}] {var} (slot {slot})")
        print(f"    状态: {status}")
        
        if is_vuln:
            print(f"    污点路径数: {paths}")
            
            # 显示详细路径
            detail = next(d for d in result['details'] if d['name'] == var)
            if detail['taint_bb']:
                print(f"    受影响的基本块: {detail['taint_bb']}")
    
    print("\n" + "=" * 70)
    
    if result['vulnerable_variables'] > 0:
        print("\n⚠️  安全建议:")
        print("  1. 检查受污点影响的变量是否有足够的访问控制")
        print("  2. 确认所有修改这些变量的函数都有 require/modifier 保护")
        print("  3. 考虑使用 OpenZeppelin 的 Ownable/AccessControl 模式")
        print("  4. 进行全面的安全审计")
    else:
        print("\n✅ 所有被分析的变量未检测到明显的污点传播")
        print("   注意：这不代表合约完全安全，仍需进行全面审计")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """命令行入口"""
    
    if len(sys.argv) < 3:
        print("用法: python analyze.py <bytecode_file> <var1> <var2> ...")
        print("\n示例:")
        print("  python analyze.py bytecode/contract.code owner balance")
        print("  python analyze.py my_contract.code owner admin isAuthorized")
        print("\n说明:")
        print("  bytecode_file: runtime bytecode文件路径(.code文件)")
        print("  var1, var2, ...: 需要分析的关键变量名（空格分隔）")
        sys.exit(1)
    
    bytecode_file = sys.argv[1]
    key_variables = sys.argv[2:]
    
    print(f"\n正在分析合约: {bytecode_file}")
    print(f"关键变量: {', '.join(key_variables)}")
    print("请稍候...")
    
    try:
        # 执行分析
        result = analyze_contract(
            bytecode_file=bytecode_file,
            key_variables=key_variables,
            output_file="analysis_result.json"
        )
        
        # 打印结果
        print_results(result)
        
        print("💾 详细结果已保存到: analysis_result.json")
        
    except FileNotFoundError as e:
        print(f"\n❌ 错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 分析过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

