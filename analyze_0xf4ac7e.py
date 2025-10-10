#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新分析 0xf4ac7eccd66a282920c131f96e716e3457120e03 合约
查看失败原因
"""

from core.analyzer import AllInOneAnalyzer
import sys

def main():
    print("🔄 分析合约 0xf4ac7eccd66a282920c131f96e716e3457120e03")
    print("="*80)
    
    contract_path = "/Users/almightyfish/Desktop/AChecker/AC/undependency/0xf4ac7eccd66a282920c131f96e716e3457120e03.sol"
    output_dir = "/Users/almightyfish/Desktop/AChecker/AC/bytecode_analysis/analysis_output/0xf4ac7eccd66a282920c131f96e716e3457120e03"
    
    # 关键变量（从合约中提取）
    key_vars = [
        'owner',
        'tokenOwned',
        'totalSupply',
        'allowed',
        'buyPrice',
        'sellPrice'
    ]
    
    print(f"📝 合约: {contract_path}")
    print(f"🔑 关键变量: {key_vars}")
    print(f"📂 输出: {output_dir}\n")
    
    try:
        # 🔧 注意：虽然pragma是^0.4.4，但代码使用了assert等新特性
        # 需要使用0.4.11+版本（assert从0.4.10开始支持）
        analyzer = AllInOneAnalyzer(
            solc_version='0.4.18',  # 使用稳定的0.4.x版本
            key_variables=key_vars,
            contract_path=contract_path,
            output_dir=output_dir,
        )
        
        print("▶️  开始分析...\n")
        result = analyzer.run()
        
        if result:
            print("\n✅ 分析成功！")
            print(f"📄 报告: {output_dir}/final_report.json")
            print(f"📄 HTML: {output_dir}/final_report.html")
            return 0
        else:
            print("\n❌ 分析失败（run返回False）")
            return 1
            
    except Exception as e:
        print(f"\n❌ 发生异常: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

