#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主入口文件 - 运行此文件即可开始分析
"""

import sys
from core.analyzer import AllInOneAnalyzer
from config import SOLC_VERSION, KEY_VARIABLES, CONTRACT_PATH, OUTPUT_DIR


def main():
    """主函数"""
    print("=" * 80)
    print("智能合约污点分析工具")
    print("=" * 80)
    
    # 创建并运行分析器
    analyzer = AllInOneAnalyzer(
        solc_version=SOLC_VERSION,
        key_variables=KEY_VARIABLES,
        contract_path=CONTRACT_PATH,
        output_dir=OUTPUT_DIR
    )
    
    result = analyzer.run()
    
    if result:
        print("\n✅ 分析成功完成！")
        sys.exit(0)
    else:
        print("\n❌ 分析失败！")
        sys.exit(1)


if __name__ == "__main__":
    main()

