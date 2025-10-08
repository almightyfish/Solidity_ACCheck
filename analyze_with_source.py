#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整的源码级污点分析工具
从Solidity源码开始，编译、分析、映射回源码
"""

import json
import sys
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict
from TaintAnalyzer import TaintAnalyzer
from SourceMapper import SourceMapper, generate_source_mapped_report


class SourceLevelTaintAnalyzer:
    """源码级别的污点分析器"""
    
    def __init__(self, source_file: str, key_variables: List[str]):
        self.source_file = source_file
        self.key_variables = key_variables
        self.bytecode_file = None
        self.combined_json = None
        self.source_map = None
        self.taint_results = None
        self.basic_blocks = None
        
    def compile_contract(self) -> bool:
        """编译Solidity合约，生成bytecode和source map"""
        print(f"\n【步骤1】编译合约: {self.source_file}")
        print("-" * 70)
        
        try:
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, "combined.json")
            
            # 使用solc编译
            cmd = [
                'solc',
                '--combined-json', 'bin-runtime,srcmap-runtime,asm',
                self.source_file,
                '-o', temp_dir
            ]
            
            print(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"❌ 编译失败:")
                print(result.stderr)
                return False
            
            # 保存combined json
            combined_data = json.loads(result.stdout)
            self.combined_json = os.path.join(temp_dir, "combined.json")
            with open(self.combined_json, 'w') as f:
                json.dump(combined_data, f, indent=2)
            
            # 提取runtime bytecode
            contracts = combined_data.get('contracts', {})
            if not contracts:
                print("❌ 未找到编译后的合约")
                return False
            
            # 获取第一个合约
            contract_key = list(contracts.keys())[0]
            contract_data = contracts[contract_key]
            
            # 提取runtime bytecode
            runtime_bytecode = contract_data.get('bin-runtime', '')
            if not runtime_bytecode:
                print("❌ 未找到runtime bytecode")
                return False
            
            # 保存bytecode
            self.bytecode_file = os.path.join(temp_dir, "runtime.code")
            with open(self.bytecode_file, 'w') as f:
                f.write(runtime_bytecode)
            
            # 保存source map
            self.source_map = contract_data.get('srcmap-runtime', '')
            
            print(f"✓ 编译成功")
            print(f"  - Runtime bytecode: {len(runtime_bytecode)} 字符")
            print(f"  - Source map: {'有' if self.source_map else '无'}")
            print(f"  - 输出目录: {temp_dir}")
            
            return True
            
        except FileNotFoundError:
            print("❌ 错误: 未找到solc编译器")
            print("请安装: brew install solidity (macOS) 或 apt-get install solc (Linux)")
            return False
        except Exception as e:
            print(f"❌ 编译过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_taint_analysis(self) -> bool:
        """执行污点分析"""
        print(f"\n【步骤2】执行污点分析")
        print("-" * 70)
        
        try:
            analyzer = TaintAnalyzer(self.bytecode_file, self.key_variables)
            self.taint_results = analyzer.analyze()
            self.basic_blocks = analyzer.bytecode_analyzer.basic_blocks
            
            vulnerable_count = sum(1 for r in self.taint_results if r['taint_bb'])
            
            print(f"✓ 污点分析完成")
            print(f"  - 分析变量: {len(self.taint_results)} 个")
            print(f"  - 检测到污点: {vulnerable_count} 个")
            print(f"  - 基本块数: {len(self.basic_blocks)} 个")
            
            return True
            
        except Exception as e:
            print(f"❌ 污点分析失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def map_to_source(self) -> Dict:
        """将污点分析结果映射回源码"""
        print(f"\n【步骤3】映射到源码")
        print("-" * 70)
        
        try:
            # 创建源码映射器
            mapper = SourceMapper(
                source_file=self.source_file,
                combined_json=self.combined_json
            )
            
            # 生成映射报告
            report = generate_source_mapped_report(
                self.taint_results,
                self.basic_blocks,
                mapper
            )
            
            print(f"✓ 源码映射完成")
            
            return report
            
        except Exception as e:
            print(f"⚠️  源码映射部分失败: {e}")
            print("将使用基于启发式的映射方法...")
            return self._heuristic_mapping()
    
    def _heuristic_mapping(self) -> Dict:
        """
        启发式映射方法（当source map不可用时）
        通过分析源码结构和变量名来推断映射关系
        """
        report = {
            'summary': {
                'total_variables': len(self.taint_results),
                'vulnerable_variables': sum(1 for r in self.taint_results if r['taint_bb']),
                'mapping_method': 'heuristic'
            },
            'results': []
        }
        
        # 读取源码
        with open(self.source_file, 'r') as f:
            source_lines = f.readlines()
        
        for taint_result in self.taint_results:
            var_name = taint_result['name']
            has_taint = len(taint_result['taint_bb']) > 0
            
            # 在源码中查找变量声明和使用
            var_locations = []
            for line_num, line in enumerate(source_lines, 1):
                # 查找变量声明
                if f'{var_name}' in line:
                    var_locations.append({
                        'line': line_num,
                        'code': line.strip(),
                        'type': 'declaration' if any(kw in line for kw in ['uint', 'address', 'bool', 'mapping']) else 'usage'
                    })
            
            result = {
                'variable': var_name,
                'storage_slot': taint_result['offset'],
                'has_taint': has_taint,
                'source_locations': var_locations,
                'taint_info': {
                    'affected_blocks': taint_result['taint_bb'],
                    'path_count': len(taint_result['taint_cfg'])
                }
            }
            
            report['results'].append(result)
        
        return report
    
    def generate_detailed_report(self, report: Dict, output_file: str = None):
        """生成详细的分析报告"""
        print(f"\n【步骤4】生成详细报告")
        print("-" * 70)
        
        # 打印概要
        print(f"\n分析概要:")
        print(f"  总变量数: {report['summary']['total_variables']}")
        print(f"  受污点影响: {report['summary']['vulnerable_variables']}")
        
        # 读取源码用于显示
        with open(self.source_file, 'r') as f:
            source_lines = f.readlines()
        
        # 打印每个变量的详细信息
        print(f"\n详细结果:")
        print("=" * 70)
        
        for idx, result in enumerate(report['results'], 1):
            var_name = result['variable']
            has_taint = result['has_taint']
            
            status = "⚠️  检测到污点" if has_taint else "✅ 未检测到污点"
            print(f"\n[{idx}] 变量: {var_name}")
            print(f"    状态: {status}")
            
            if has_taint:
                # 显示污点信息
                if 'taint_info' in result:
                    print(f"    污点路径数: {result['taint_info']['path_count']}")
                    print(f"    受影响的基本块: {result['taint_info']['affected_blocks']}")
                
                # 显示源码位置（如果有）
                if 'source_locations' in result and result['source_locations']:
                    print(f"\n    源码位置:")
                    for loc in result['source_locations'][:5]:  # 只显示前5个
                        line_num = loc['line']
                        code = loc['code']
                        loc_type = loc.get('type', 'unknown')
                        print(f"      行 {line_num:4d} [{loc_type:11s}]: {code}")
                    
                    if len(result['source_locations']) > 5:
                        print(f"      ... 还有 {len(result['source_locations']) - 5} 个位置")
                
                elif 'affected_source_locations' in result:
                    print(f"\n    受影响的源码行:")
                    for loc in result['affected_source_locations']:
                        print(f"      行 {loc['line']:4d}: {loc['code']}")
                        print(f"               操作: {', '.join(set(loc['opcodes']))}")
        
        print("\n" + "=" * 70)
        
        # 保存到文件
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"\n💾 详细报告已保存到: {output_file}")
        
        # 生成安全建议
        self._print_security_recommendations(report)
    
    def _print_security_recommendations(self, report: Dict):
        """打印安全建议"""
        vulnerable_vars = [r for r in report['results'] if r['has_taint']]
        
        if not vulnerable_vars:
            print("\n✅ 安全评估:")
            print("  所有分析的变量未检测到明显的污点传播")
            print("  建议: 仍需进行全面的安全审计")
            return
        
        print("\n⚠️  安全建议:")
        print("-" * 70)
        
        for result in vulnerable_vars:
            var_name = result['variable']
            print(f"\n变量 '{var_name}':")
            
            # 根据变量名提供特定建议
            if 'owner' in var_name.lower():
                print("  ⚠️  这是一个权限控制变量！")
                print("  建议:")
                print("    1. 确保只有当前owner能修改owner")
                print("    2. 使用 modifier onlyOwner 保护相关函数")
                print("    3. 考虑实现两步转移机制")
                print("    示例代码:")
                print("      modifier onlyOwner() {")
                print("          require(msg.sender == owner, 'Not owner');")
                print("          _;")
                print("      }")
            
            elif 'balance' in var_name.lower():
                print("  ⚠️  这是一个资金相关变量！")
                print("  建议:")
                print("    1. 在修改余额前验证msg.sender")
                print("    2. 使用checks-effects-interactions模式")
                print("    3. 考虑使用SafeMath防止溢出")
                print("    4. 添加提现限额和冷却期")
            
            elif any(kw in var_name.lower() for kw in ['auth', 'admin', 'permission']):
                print("  ⚠️  这是一个权限变量！")
                print("  建议:")
                print("    1. 使用访问控制列表(ACL)")
                print("    2. 考虑使用OpenZeppelin的AccessControl")
                print("    3. 为权限变更添加事件日志")
            
            else:
                print("  建议:")
                print("    1. 检查所有修改此变量的函数")
                print("    2. 确保有适当的访问控制")
                print("    3. 验证所有外部输入")
        
        print("\n通用安全建议:")
        print("  • 使用OpenZeppelin的安全合约库")
        print("  • 进行专业的安全审计")
        print("  • 部署前在测试网充分测试")
        print("  • 考虑使用形式化验证")
        print("  • 实施多签钱包控制关键操作")
    
    def analyze(self, output_file: str = "source_mapped_report.json") -> Dict:
        """执行完整的分析流程"""
        print("\n" + "=" * 70)
        print("源码级智能合约污点分析")
        print("=" * 70)
        print(f"合约文件: {self.source_file}")
        print(f"关键变量: {', '.join(self.key_variables)}")
        
        # 步骤1: 编译
        if not self.compile_contract():
            return None
        
        # 步骤2: 污点分析
        if not self.run_taint_analysis():
            return None
        
        # 步骤3: 源码映射
        report = self.map_to_source()
        
        # 步骤4: 生成报告
        self.generate_detailed_report(report, output_file)
        
        print("\n" + "=" * 70)
        print("分析完成！")
        print("=" * 70 + "\n")
        
        return report


def main():
    """命令行入口"""
    if len(sys.argv) < 3:
        print("用法: python analyze_with_source.py <contract.sol> <var1> <var2> ...")
        print("\n示例:")
        print("  python analyze_with_source.py contracts/MyContract.sol owner balance")
        print("\n说明:")
        print("  contract.sol: Solidity源码文件")
        print("  var1, var2: 需要分析的关键变量名")
        print("\n要求:")
        print("  需要安装 solc 编译器")
        print("  macOS: brew install solidity")
        print("  Linux: apt-get install solc")
        sys.exit(1)
    
    source_file = sys.argv[1]
    key_variables = sys.argv[2:]
    
    if not os.path.exists(source_file):
        print(f"❌ 错误: 文件不存在 {source_file}")
        sys.exit(1)
    
    # 执行分析
    analyzer = SourceLevelTaintAnalyzer(source_file, key_variables)
    result = analyzer.analyze()
    
    if result:
        print("✅ 分析成功完成")
    else:
        print("❌ 分析失败")
        sys.exit(1)


if __name__ == "__main__":
    main()

