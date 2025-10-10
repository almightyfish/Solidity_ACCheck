#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成模块
"""

import json
import os
from datetime import datetime
from typing import List, Dict
from utils.colors import Colors


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, output_dir: str, source_file: str):
        self.output_dir = output_dir
        self.source_file = source_file
        self.source_lines = []
        
        with open(source_file, 'r', encoding='utf-8') as f:
            self.source_lines = f.readlines()
    
    def generate(self, mapped_results: List[Dict]) -> Dict:
        """生成完整报告"""
        print(f"\n{Colors.HEADER}【步骤6】生成报告{Colors.ENDC}")
        print("=" * 80)
        
        # 🔧 新增：读取敏感函数信息
        sensitive_functions = []
        source_mapping_path = os.path.join(self.output_dir, "intermediate", "source_mapping.json")
        try:
            with open(source_mapping_path, 'r', encoding='utf-8') as f:
                source_mapping_data = json.load(f)
                if isinstance(source_mapping_data, dict):
                    sensitive_functions = source_mapping_data.get('sensitive_functions', [])
        except:
            pass
        
        # 使用 has_vulnerability 而不是只看 has_taint
        vulnerable_count = sum(1 for r in mapped_results if r.get('has_vulnerability', r['has_taint']))
        
        # 终端报告（包含敏感函数）
        self._print_terminal_report(mapped_results, vulnerable_count, sensitive_functions)
        
        # JSON报告
        report = {
            'analysis_time': datetime.now().isoformat(),
            'source_file': self.source_file,
            'summary': {
                'total_variables': len(mapped_results),
                'vulnerable_variables': vulnerable_count,
                'safe_variables': len(mapped_results) - vulnerable_count,
                'sensitive_functions_count': len(sensitive_functions),  # 🔧 新增
                'high_risk_sensitive_functions': sum(1 for sf in sensitive_functions if sf['risk_level'] == 'high')
            },
            'results': mapped_results,
            'sensitive_functions': sensitive_functions  # 🔧 新增：敏感函数检测结果
        }
        
        # 保存最终报告
        final_report_path = os.path.join(self.output_dir, "final_report.json")
        with open(final_report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Colors.BLUE}💾 最终报告已保存:{Colors.ENDC}")
        print(f"   {final_report_path}")
        
        # 生成HTML报告（可选）
        html_report_path = os.path.join(self.output_dir, "final_report.html")
        self._generate_html_report(report, html_report_path)
        print(f"   {html_report_path}")
        
        return report
    
    def _print_terminal_report(self, results: List[Dict], vulnerable_count: int, sensitive_functions: List[Dict] = None):
        """打印终端报告（包含敏感函数）"""
        print(f"\n{Colors.BOLD}分析概要:{Colors.ENDC}")
        print(f"  总变量数: {len(results)}")
        print(f"  检测到漏洞: {Colors.RED}{vulnerable_count}{Colors.ENDC}")
        print(f"  安全变量: {Colors.GREEN}{len(results) - vulnerable_count}{Colors.ENDC}")
        
        # 🔧 新增：敏感函数概要
        if sensitive_functions:
            high_risk_count = sum(1 for sf in sensitive_functions if sf['risk_level'] == 'high')
            if high_risk_count > 0:
                print(f"  {Colors.RED}⚠️  高风险敏感函数: {high_risk_count}{Colors.ENDC}")
            else:
                print(f"  {Colors.GREEN}✓ 敏感函数: {len(sensitive_functions)} (已有访问控制){Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}详细结果:{Colors.ENDC}")
        print("=" * 80)
        
        for idx, result in enumerate(results, 1):
            var_name = result['variable']
            has_taint = result['has_taint']
            has_vulnerability = result.get('has_vulnerability', has_taint)
            
            status_color = Colors.RED if has_vulnerability else Colors.GREEN
            status_icon = "⚠️ " if has_vulnerability else "✅"
            
            # 显示检测方法
            if has_vulnerability:
                if has_taint:
                    status_text = "检测到污点传播"
                else:
                    status_text = "检测到访问控制漏洞（补充检测）"
            else:
                status_text = "未检测到漏洞"
            
            print(f"\n{Colors.BOLD}[{idx}] 变量: {var_name}{Colors.ENDC}")
            print(f"    状态: {status_color}{status_icon}{status_text}{Colors.ENDC}")
            print(f"    存储槽位: {result['storage_slot']}")
            
            if has_taint:
                print(f"    污点路径数: {result['taint_paths_count']}")
                
                # 显示路径类型统计（新增）
                if 'dangerous_paths_count' in result and 'suspicious_paths_count' in result:
                    dangerous_count = result['dangerous_paths_count']
                    suspicious_count = result['suspicious_paths_count']
                    print(f"      ├─ {Colors.RED}危险路径: {dangerous_count} 条{Colors.ENDC} (无条件保护)")
                    print(f"      └─ {Colors.YELLOW}可疑路径: {suspicious_count} 条{Colors.ENDC} (有条件判断)")
                
                print(f"    受影响的基本块: {result['affected_basic_blocks']}")
            
            # 源码使用位置（区分读写操作）
            if result['source_usages']:
                write_usages = [u for u in result['source_usages'] if u['operation'] == 'write']
                read_usages = [u for u in result['source_usages'] if u['operation'] == 'read']
                
                print(f"\n    {Colors.CYAN}📄 源码中的使用位置:{Colors.ENDC}")
                print(f"       总计: {len(result['source_usages'])} 处 (✏️  写入: {len(write_usages)}, 👁️  读取: {len(read_usages)})")
                
                # 优先显示写入操作（更重要）
                if write_usages:
                    print(f"\n       {Colors.YELLOW}写入操作:{Colors.ENDC}")
                    for usage in write_usages[:3]:
                        func_info = f" (在函数 {usage['function']})" if usage['function'] else ""
                        print(f"       ✏️  行 {usage['line']:3d}: {usage['code']}{func_info}")
                    if len(write_usages) > 3:
                        print(f"       ... 还有 {len(write_usages) - 3} 个写入位置")
                
                # 然后显示读取操作（参考信息）
                if read_usages:
                    print(f"\n       {Colors.CYAN}读取操作 (不是风险点):{Colors.ENDC}")
                    for usage in read_usages[:2]:
                        func_info = f" (在函数 {usage['function']})" if usage['function'] else ""
                        print(f"       👁️  行 {usage['line']:3d}: {usage['code']}{func_info}")
                    if len(read_usages) > 2:
                        print(f"       ... 还有 {len(read_usages) - 2} 个读取位置")
            
            # 危险位置（新增，重点标记）
            if result.get('dangerous_locations'):
                print(f"\n    {Colors.RED}🔥 危险位置（无条件保护，需立即修复）:{Colors.ENDC}")
                for risk in result['dangerous_locations']:
                    func_name = risk['function'] or '未知函数'
                    detection_method = risk.get('detection_method', 'taint_analysis')
                    warning = risk.get('warning', '')
                    
                    # 🔧 新增：构造函数标识
                    is_constructor = func_name == 'constructor' or '构造函数' in warning
                    if is_constructor:
                        print(f"       {Colors.GREEN}✓ 行 {risk['line']:3d} ({func_name}): {risk['code']}{Colors.ENDC}")
                        print(f"          {Colors.GREEN}🛡️ 这是构造函数，仅在部署时执行一次，属于安全操作{Colors.ENDC}")
                        continue
                    
                    print(f"       {Colors.RED}⛔ 行 {risk['line']:3d} ({func_name}): {risk['code']}{Colors.ENDC}")
                    
                    # 🔧 增强：显示详细的检测信息
                    if detection_method == 'public_function_check':
                        print(f"          {Colors.YELLOW}🔍 检测方式: 补充检测（public函数无访问控制）{Colors.ENDC}")
                    else:
                        print(f"          🔍 检测方式: 污点分析（增强版CFG）")
                    
                    # 🔧 新增：显示字节码和源码检测结果
                    has_bytecode_cond = risk.get('has_bytecode_condition', False)
                    has_source_cond = risk.get('has_source_condition', False)
                    bytecode_types = risk.get('bytecode_condition_types', [])
                    confidence = risk.get('protection_confidence', 'unknown')
                    
                    print(f"          📊 双重检测结果:")
                    print(f"             • 字节码层面: {'✓ 有条件' if has_bytecode_cond else '✗ 无条件'}")
                    if bytecode_types:
                        print(f"               类型: {', '.join(bytecode_types)}")
                    print(f"             • 源码层面: {'✓ 有条件' if has_source_cond else '✗ 无条件'}")
                    print(f"             • 置信度: {confidence}")
                    
                    # 显示警告信息
                    if warning:
                        print(f"          {warning}")
                    
                    # 上下文
                    line_idx = risk['line'] - 1
                    if line_idx > 0:
                        print(f"          上文: {self.source_lines[line_idx - 1].strip()}")
                    if line_idx < len(self.source_lines) - 1:
                        print(f"          下文: {self.source_lines[line_idx + 1].strip()}")
            
            # 可疑位置（新增，需要人工审查）
            if result.get('suspicious_locations'):
                print(f"\n    {Colors.YELLOW}⚠️  可疑位置（检测到条件判断，建议人工审查）:{Colors.ENDC}")
                for risk in result['suspicious_locations']:
                    func_name = risk['function'] or '未知函数'
                    has_bytecode_cond = risk.get('has_bytecode_condition', False)
                    has_source_cond = risk.get('has_source_condition', False)
                    bytecode_types = risk.get('bytecode_condition_types', [])
                    confidence = risk.get('protection_confidence', 'unknown')
                    
                    condition_mark = " ✓" if (has_bytecode_cond or has_source_cond) else ""
                    print(f"       {Colors.YELLOW}⚡ 行 {risk['line']:3d} ({func_name}): {risk['code']}{condition_mark}{Colors.ENDC}")
                    
                    # 🔧 增强：显示详细检测结果
                    print(f"          📊 双重检测结果:")
                    print(f"             • 字节码层面: {'✓ 有条件' if has_bytecode_cond else '✗ 无条件'}")
                    if bytecode_types:
                        condition_desc = {
                            'access_control': '访问控制（CALLER+比较）',
                            'conditional_jump': '条件跳转（JUMPI）',
                            'comparison': '比较操作',
                            'revert': '回滚保护（REVERT）'
                        }
                        types_str = ', '.join([condition_desc.get(t, t) for t in bytecode_types])
                        print(f"               类型: {types_str}")
                    print(f"             • 源码层面: {'✓ 有条件' if has_source_cond else '✗ 无条件'}")
                    print(f"             • 保护强度: {confidence}")
                    
                    if has_bytecode_cond or has_source_cond:
                        print(f"          {Colors.GREEN}↳ 检测到条件保护，但需人工验证是否充分{Colors.ENDC}")
                    
                    # 上下文
                    line_idx = risk['line'] - 1
                    if line_idx > 0:
                        print(f"          上文: {self.source_lines[line_idx - 1].strip()}")
                    if line_idx < len(self.source_lines) - 1:
                        print(f"          下文: {self.source_lines[line_idx + 1].strip()}")
        
        print("\n" + "=" * 80)
        
        # 安全建议
        self._print_security_advice(results)
    
    def _print_security_advice(self, results: List[Dict]):
        """打印安全建议"""
        vulnerable = [r for r in results if r['has_taint']]
        
        if not vulnerable:
            print(f"\n{Colors.GREEN}✅ 安全评估:{Colors.ENDC}")
            print("   未检测到明显的污点传播风险")
            print("   注意：仍建议进行全面的安全审计")
            return
        
        # 分类统计（新增）
        dangerous_vars = [r for r in vulnerable if r.get('dangerous_locations')]
        suspicious_vars = [r for r in vulnerable if r.get('suspicious_locations') and not r.get('dangerous_locations')]
        
        print(f"\n{Colors.YELLOW}⚠️  安全建议:{Colors.ENDC}")
        print("-" * 80)
        
        # 优先显示危险变量
        if dangerous_vars:
            print(f"\n{Colors.RED}{Colors.BOLD}🔥 高危险变量（需立即修复）:{Colors.ENDC}")
            for result in dangerous_vars:
                var_name = result['variable']
                dangerous_count = len(result.get('dangerous_locations', []))
                print(f"\n{Colors.BOLD}变量 '{var_name}' ({dangerous_count} 个危险位置):{Colors.ENDC}")
                self._print_variable_advice(var_name, is_dangerous=True)
        
        # 然后显示可疑变量
        if suspicious_vars:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  可疑变量（建议人工审查）:{Colors.ENDC}")
            for result in suspicious_vars:
                var_name = result['variable']
                suspicious_count = len(result.get('suspicious_locations', []))
                print(f"\n{Colors.BOLD}变量 '{var_name}' ({suspicious_count} 个可疑位置):{Colors.ENDC}")
                self._print_variable_advice(var_name, is_dangerous=False)
    
    def _print_variable_advice(self, var_name: str, is_dangerous: bool):
        """打印变量的具体建议"""
        if is_dangerous:
            priority = f"{Colors.RED}【紧急修复】{Colors.ENDC}"
            urgency_note = f"  {Colors.RED}⚠️  此变量无条件保护，存在直接利用风险！{Colors.ENDC}\n"
        else:
            priority = f"{Colors.YELLOW}【人工审查】{Colors.ENDC}"
            urgency_note = f"  {Colors.GREEN}✓ 已检测到条件判断，但仍需确认保护是否充分{Colors.ENDC}\n"
        
        print(f"  {priority}")
        print(urgency_note)
        
        var_name_lower = var_name.lower()
        
        if 'owner' in var_name_lower:
            print("  这是权限控制变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：任何人都可以修改此变量！{Colors.ENDC}")
            print("  1. 使用 modifier onlyOwner 保护所有修改owner的函数")
            print("  2. 考虑实现两步转移机制（transferOwnership + acceptOwnership）")
            print("  3. 为权限变更添加事件日志")
            print("\n  示例代码:")
            print("    modifier onlyOwner() { require(msg.sender == owner); _; }")
            print("    function changeOwner(address newOwner) public onlyOwner { ... }")
        
        elif 'balance' in var_name_lower or 'supply' in var_name_lower:
            print("  这是资金相关变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：资金可能被任意操控！{Colors.ENDC}")
            print("  1. 使用 Checks-Effects-Interactions 模式")
            print("  2. 在外部调用前更新状态")
            print("  3. 考虑使用 SafeMath 防止溢出")
            print("  4. 添加提现限额和冷却期")
        
        elif any(kw in var_name_lower for kw in ['auth', 'admin', 'pause']):
            print("  这是控制变量，建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：合约控制权可能被夺取！{Colors.ENDC}")
            print("  1. 添加适当的访问控制")
            print("  2. 使用 OpenZeppelin 的 Ownable/AccessControl")
            print("  3. 为状态变更添加事件")
        
        else:
            print("  通用建议:")
            if is_dangerous:
                print(f"  {Colors.RED}✗ 当前状态：变量可被任意修改！{Colors.ENDC}")
            print("  1. 检查所有修改此变量的函数是否有访问控制")
            print("  2. 验证所有外部输入")
            print("  3. 添加必要的 require 检查")
        
        if not is_dangerous:
            print(f"\n  {Colors.CYAN}提示：虽然检测到条件判断，但请确认：{Colors.ENDC}")
            print("    • 条件检查是否充分（不存在绕过方法）")
            print("    • 是否覆盖所有可能的攻击路径")
            print("    • 是否正确使用了 msg.sender 而不是 tx.origin")
    
    def _generate_html_report(self, report: Dict, output_path: str):
        """生成HTML报告"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>智能合约污点分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vulnerable {{ color: #f44336; font-weight: bold; }}
        .safe {{ color: #4CAF50; font-weight: bold; }}
        .variable {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .risk {{ background: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }}
        .code {{ background: #f5f5f5; padding: 10px; font-family: monospace; margin: 5px 0; border-radius: 3px; }}
        .timestamp {{ color: #999; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 智能合约污点分析报告</h1>
        <p class="timestamp">生成时间: {report['analysis_time']}</p>
        <p>源文件: <code>{report['source_file']}</code></p>
        
        <div class="summary">
            <h2>📊 分析概要</h2>
            <p>总变量数: {report['summary']['total_variables']}</p>
            <p class="vulnerable">受污点影响: {report['summary']['vulnerable_variables']}</p>
            <p class="safe">安全变量: {report['summary']['safe_variables']}</p>
        </div>
        
        <h2>📝 详细结果</h2>
"""
        
        for idx, result in enumerate(report['results'], 1):
            status_class = 'vulnerable' if result['has_taint'] else 'safe'
            status_text = '⚠️ 检测到污点' if result['has_taint'] else '✅ 安全'
            
            html_content += f"""
        <div class="variable">
            <h3>[{idx}] 变量: {result['variable']}</h3>
            <p class="{status_class}">状态: {status_text}</p>
            <p>存储槽位: {result['storage_slot']}</p>
"""
            
            if result['has_taint']:
                html_content += f"<p>污点路径数: {result['taint_paths_count']}</p>"
            
            if result['risk_locations']:
                html_content += "<h4>⚠️ 风险位置:</h4>"
                for risk in result['risk_locations']:
                    html_content += f"""
                <div class="risk">
                    <p>行 {risk['line']} (函数: {risk['function'] or '未知'})</p>
                    <div class="code">{risk['code']}</div>
                </div>
"""
            
            html_content += "</div>"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

