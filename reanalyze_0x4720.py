#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新分析 0x4720f2468eeb7a795945c5ffbc3b0178e32250e0 合约
"""

from core.analyzer import AllInOneAnalyzer
import sys

def main():
    print("🔄 重新分析多合约文件")
    print("="*80)
    
    # 合约路径
    contract_path = "/Users/almightyfish/Desktop/AChecker/AC/undependency/0x4720f2468eeb7a795945c5ffbc3b0178e32250e0.sol"
    output_dir = "/Users/almightyfish/Desktop/AChecker/AC/bytecode_analysis/analysis_output/0x4720f2468eeb7a795945c5ffbc3b0178e32250e0"
    
    # 🔧 关键变量：根据合约选择重要的状态变量
    # 这个合约是一个宠物游戏，主要的关键变量包括：
    key_vars = [
        'owner',           # 所有者
        'cfoAddress',      # CFO地址
        'paused',          # 暂停状态
        'saleAuction',     # 拍卖地址
        'mixGenes',        # 基因混合合约地址
    ]
    
    print(f"📝 合约: {contract_path}")
    print(f"🔑 关键变量: {key_vars}")
    print(f"📂 输出: {output_dir}\n")
    
    try:
        analyzer = AllInOneAnalyzer(
            solc_version='0.4.23',  # 根据 pragma solidity ^0.4.23
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
            print("\n❌ 分析失败")
            return 1
            
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
