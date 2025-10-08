#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新分析最危险的Top5合约，验证require识别修复效果
"""

from core.analyzer import AllInOneAnalyzer
import json
import os
from pathlib import Path

# 根据汇总报告中最危险的5个合约
TOP5_CONTRACTS = [
    {
        'name': '0xf4be3da9df0c12e69115bb5614334786fbaf5ace',
        'key_vars': ['totalSupply', 'upgradeAgentStatus', 'maxTokenSupply', 'maxTokenSale', 
                     'maxTokenForPreSale', 'minInvest', 'maxInvest']
    },
    {
        'name': '0xf459034afc1fc2e0e8bddc8e3645c2b2935186f6',
        'key_vars': ['activator', 'BET', 'ODD', 'EVEN', 'noBets', 'COMMISSION_PERCENTAGE', 
                     'END_DURATION_BETTING_BLOCK', 'TARGET_DURATION_BETTING_BLOCK']
    },
    {
        'name': '0xf46f049967ed63b864a7f6cdf91d6dac9ea23b2c',
        'key_vars': ['WhaleAddr', 'amount']
    },
    {
        'name': '0xf3d86b6974ddf5b8407cfdcd3f874a76f7538b90',
        'key_vars': ['value', 'granter', 'cliff', 'vesting', 'start']
    },
    {
        'name': '0xf4a3679eb0a3d9e8af9824a29bd32dd98d1e7127',
        'key_vars': ['_initTime', '_expirationTime', '_realTokenPrice', '_controllerAddress', '_token']
    }
]

def analyze_contract(contract_info, base_output_dir):
    """分析单个合约"""
    contract_name = contract_info['name']
    key_vars = contract_info['key_vars']
    
    solidity_path = f"/Users/almightyfish/Desktop/AChecker/AC/undependency/{contract_name}.sol"
    output_dir = os.path.join(base_output_dir, contract_name)
    
    if not os.path.exists(solidity_path):
        print(f"  ⚠️  合约文件不存在: {contract_name}")
        return None
    
    print(f"\n{'='*80}")
    print(f"正在分析: {contract_name}")
    print(f"{'='*80}")
    print(f"关键变量: {', '.join(key_vars[:3])}{'...' if len(key_vars) > 3 else ''}")
    
    analyzer = AllInOneAnalyzer(
        solc_version='0.4.18',  # 大多数合约使用此版本
        key_variables=key_vars,
        contract_path=solidity_path,
        output_dir=output_dir,
    )
    
    try:
        result = analyzer.run()
        if result:
            print(f"✅ 分析完成: {contract_name}")
            return {
                'contract': contract_name,
                'status': 'success',
                'report_path': os.path.join(output_dir, 'final_report.json')
            }
        else:
            print(f"❌ 分析失败: {contract_name}")
            return {
                'contract': contract_name,
                'status': 'failed',
                'error': 'Analysis returned False'
            }
    except Exception as e:
        print(f"❌ 分析异常: {contract_name}")
        print(f"   错误: {str(e)}")
        return {
            'contract': contract_name,
            'status': 'error',
            'error': str(e)
        }

def summarize_results(results):
    """汇总分析结果"""
    print("\n" + "="*80)
    print("📊 汇总结果对比")
    print("="*80)
    
    total_dangerous = 0
    total_suspicious = 0
    
    for result in results:
        if result and result['status'] == 'success':
            contract_name = result['contract']
            report_path = result['report_path']
            
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            dangerous_count = 0
            suspicious_count = 0
            
            for var_result in report_data['results']:
                dangerous_count += len(var_result.get('dangerous_locations', []))
                suspicious_count += len(var_result.get('suspicious_locations', []))
            
            total_dangerous += dangerous_count
            total_suspicious += suspicious_count
            
            print(f"\n{contract_name}:")
            print(f"  危险路径: {dangerous_count}")
            print(f"  可疑路径: {suspicious_count}  {'✅ 有改进！' if suspicious_count > 0 else '⚠️  仍然是0'}")
    
    print("\n" + "-"*80)
    print(f"合计:")
    print(f"  危险路径总数: {total_dangerous}")
    print(f"  可疑路径总数: {total_suspicious}  {'✅ 不再全是0！' if total_suspicious > 0 else '❌ 修复未生效'}")
    
    if total_suspicious > 0:
        print("\n✅ 修复成功！require语句被正确识别为可疑路径！")
        print(f"   改进率: 可疑路径从0增加到{total_suspicious}")
    else:
        print("\n⚠️  警告：可疑路径仍然是0，修复可能未完全生效")
    
    print("="*80)

def main():
    print("🚀 重新分析Top5最危险合约 - 验证require识别修复")
    print("="*80)
    print("目标：验证修复后，可疑路径不再全是0")
    print("="*80)
    
    base_output_dir = "/Users/almightyfish/Desktop/AChecker/analysis_output"
    
    results = []
    for contract_info in TOP5_CONTRACTS:
        result = analyze_contract(contract_info, base_output_dir)
        results.append(result)
    
    summarize_results(results)

if __name__ == "__main__":
    main()

