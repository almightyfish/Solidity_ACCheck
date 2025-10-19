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
import re

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
        
        # 🔧 新增：读取敏感函数信息和污点流信息
        sensitive_functions = []
        taint_to_sensitive_flows = []
        source_mapping_path = os.path.join(self.output_dir, "intermediate", "source_mapping.json")
        try:
            with open(source_mapping_path, 'r', encoding='utf-8') as f:
                source_mapping_data = json.load(f)
                if isinstance(source_mapping_data, dict):
                    sensitive_functions = source_mapping_data.get('sensitive_functions', [])
                    taint_to_sensitive_flows = source_mapping_data.get('taint_to_sensitive_flows', [])
        except:
            pass
        
        # 使用 has_vulnerability 而不是只看 has_taint
        vulnerable_count = sum(1 for r in mapped_results if r.get('has_vulnerability', r['has_taint']))
        
        # 终端报告（包含敏感函数和污点流）
        self._print_terminal_report(mapped_results, vulnerable_count, sensitive_functions, taint_to_sensitive_flows)
        
        # JSON报告
        report = {
            'analysis_time': datetime.now().isoformat(),
            'source_file': self.source_file,
            'summary': {
                'total_variables': len(mapped_results),
                'vulnerable_variables': vulnerable_count,
                'safe_variables': len(mapped_results) - vulnerable_count,
                'sensitive_functions_count': len(sensitive_functions),  # 🔧 新增
                'high_risk_sensitive_functions': sum(1 for sf in sensitive_functions if sf['risk_level'] == 'high'),
                'taint_to_sensitive_flows': len(taint_to_sensitive_flows),  # 🔧 新增
                'critical_flows': len([f for f in taint_to_sensitive_flows if f.get('risk_level') == 'critical'])
            },
            'results': mapped_results,
            'sensitive_functions': sensitive_functions,  # 🔧 新增：敏感函数检测结果
            'taint_to_sensitive_flows': taint_to_sensitive_flows  # 🔧 新增：污点到敏感函数的流
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
        
        # 🔧 新增：生成LLM漏洞报告（JSONL格式）
        llm_report_path = os.path.join(self.output_dir, "llm_vulnerability_report.jsonl")
        self._generate_llm_report(mapped_results, llm_report_path)
        print(f"   {llm_report_path} (LLM修复输入)")
        
        return report
    
    def _print_terminal_report(self, results: List[Dict], vulnerable_count: int, 
                              sensitive_functions: List[Dict] = None,
                              taint_to_sensitive_flows: List[Dict] = None):
        """打印终端报告（包含敏感函数和污点流）"""
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
        
        # 🔧 新增：污点到敏感函数流概要
        if taint_to_sensitive_flows:
            critical_count = len([f for f in taint_to_sensitive_flows if f.get('risk_level') == 'critical'])
            print(f"  {Colors.RED}🔥 严重: 污点到敏感函数的流: {critical_count} 条{Colors.ENDC}")
        
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
    
    def _generate_llm_report(self, mapped_results: List[Dict], output_path: str):
        """
        🔧 新增：生成面向LLM的漏洞报告（JSONL格式）
        
        每行一个JSON对象，包含：
        - 合约基本信息
        - 漏洞位置和代码
        - 完整函数代码
        - 上下文信息
        - 漏洞描述和数据流
        - 相关声明
        
        Args:
            mapped_results: 源码映射后的分析结果
            output_path: 输出文件路径
        """
        import re
        from pathlib import Path
        
        # 提取合约名称
        contract_name = self._extract_contract_name()
        
        # 读取源码映射器的函数信息（如果有）
        function_map = self._load_function_map()
        
        vulnerabilities = []
        vuln_id_counter = 1
        
        for result in mapped_results:
            variable = result['variable']
            var_slot = result['storage_slot']
            
            # 查找变量声明
            var_declaration = self._find_variable_declaration(variable)
            var_type = self._extract_variable_type(var_declaration) if var_declaration else 'unknown'
            
            # 处理危险路径（critical）
            for dangerous_loc in result.get('dangerous_locations', []):
                vuln = self._create_llm_vulnerability_entry(
                    vuln_id=f"vuln_{vuln_id_counter:03d}",
                    contract_name=contract_name,
                    severity='critical',
                    vuln_type='dangerous_path',
                    variable=variable,
                    var_type=var_type,
                    var_slot=var_slot,
                    location=dangerous_loc,
                    function_map=function_map,
                    var_declaration=var_declaration
                )
                vulnerabilities.append(vuln)
                vuln_id_counter += 1
            
            # 处理可疑路径（suspicious）
            for suspicious_loc in result.get('suspicious_locations', []):
                vuln = self._create_llm_vulnerability_entry(
                    vuln_id=f"vuln_{vuln_id_counter:03d}",
                    contract_name=contract_name,
                    severity='suspicious',
                    vuln_type='suspicious_path',
                    variable=variable,
                    var_type=var_type,
                    var_slot=var_slot,
                    location=suspicious_loc,
                    function_map=function_map,
                    var_declaration=var_declaration
                )
                vulnerabilities.append(vuln)
                vuln_id_counter += 1
        
        # 写入JSONL文件（每行一个JSON）
        with open(output_path, 'w', encoding='utf-8') as f:
            for vuln in vulnerabilities:
                f.write(json.dumps(vuln, ensure_ascii=False) + '\n')
    
    def _create_llm_vulnerability_entry(self, vuln_id: str, contract_name: str,
                                       severity: str, vuln_type: str,
                                       variable: str, var_type: str, var_slot: int,
                                       location: Dict, function_map: Dict,
                                       var_declaration: Dict) -> Dict:
        """
        创建单个LLM漏洞条目
        
        Args:
            vuln_id: 漏洞ID
            contract_name: 合约名称
            severity: 严重程度（critical/suspicious）
            vuln_type: 漏洞类型（dangerous_path/suspicious_path）
            variable: 变量名
            var_type: 变量类型
            var_slot: 存储槽位
            location: 漏洞位置信息
            function_map: 函数映射表
            var_declaration: 变量声明信息
        
        Returns:
            LLM友好的漏洞信息字典
        """
        line = location['line']
        func_name = location.get('function', 'unknown')
        code = location['code']
        
        # 获取完整函数代码
        function_full_code = self._get_function_full_code(func_name, function_map)
        function_signature = self._extract_function_signature(func_name)
        
        # 获取上下文（前后3行）
        context_before, context_after = self._get_context_lines(line, context_size=3)
        
        # 生成描述
        description = self._generate_vulnerability_description(
            variable, severity, vuln_type, location
        )
        
        # 生成攻击场景描述
        attack_scenario = self._generate_attack_scenario(variable, func_name, severity)
        
        # 提取数据流摘要
        data_flow = self._extract_data_flow_summary(location, variable, var_slot)
        
        # 提取已有的检查
        existing_checks = []
        missing_checks = []
        if location.get('has_source_condition'):
            existing_checks = self._extract_existing_checks(func_name, function_map)
        if severity == 'critical':
            missing_checks = ['调用者身份验证', '访问控制检查']
        elif not location.get('has_bytecode_condition') and not location.get('has_source_condition'):
            missing_checks = ['任何形式的条件保护']
        
        # 构建基础漏洞条目
        vuln_entry = {
            # 基本信息
            'contract_file': self.source_file,
            'contract_name': contract_name,
            'vulnerability_id': vuln_id,
            'severity': severity,
            
            # 变量信息
            'variable': variable,
            'variable_type': var_type,
            'variable_slot': var_slot,
            
            # 位置信息
            'line': line,
            'function': func_name,
            'function_signature': function_signature,
            'vulnerable_code': code.strip(),
            
            # 代码上下文
            'function_full_code': function_full_code,
            'context_before': context_before,
            'context_after': context_after,
            
            # 漏洞详情
            'vulnerability_type': vuln_type,
            'description': description,
            'attack_scenario': attack_scenario,
            
            # 保护检测
            'has_condition_protection': location.get('has_bytecode_condition', False) or location.get('has_source_condition', False),
            'has_modifier': self._check_has_modifier(function_signature),
            'has_require_check': location.get('has_source_condition', False),
            
            # 分析详情
            'detection_confidence': self._determine_confidence(location),
            'detection_method': location.get('detection_method', 'taint_analysis'),
            'data_flow': data_flow,
            
            # 相关代码
            'related_declarations': {
                'variable_declaration': var_declaration.get('code', '') if var_declaration else '',
                'variable_init_location': var_declaration.get('init_location', None) if var_declaration else None,
                'variable_init_code': var_declaration.get('init_code', None) if var_declaration else None
            }
        }
        
        # 添加可选字段
        if existing_checks:
            vuln_entry['existing_checks'] = existing_checks
        
        if missing_checks:
            vuln_entry['missing_checks'] = missing_checks
        
        # 对于可疑路径，添加人工审查提示
        if severity == 'suspicious':
            vuln_entry['human_review_notes'] = self._generate_review_notes(variable, func_name)
        
        # 添加字节码条件类型（如果有）
        if 'bytecode_condition_types' in location:
            vuln_entry['bytecode_condition_types'] = location['bytecode_condition_types']
        
        return vuln_entry
    
    def _extract_contract_name(self) -> str:
        """提取合约名称"""
        for line in self.source_lines:
            if 'contract ' in line and 'interface' not in line:
                match = re.search(r'\bcontract\s+(\w+)', line)
                if match:
                    return match.group(1)
        return Path(self.source_file).stem
    
    def _load_function_map(self) -> Dict:
        """加载函数映射表（从source_mapper获取）"""
        # 尝试从source_mapping.json读取
        try:
            source_mapping_path = os.path.join(self.output_dir, "intermediate", "source_mapping.json")
            with open(source_mapping_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # 如果有function_map，返回它
                if 'function_map' in data:
                    return data['function_map']
        except:
            pass
        
        # 否则，简单解析源码
        return self._parse_functions_from_source()
    
    def _parse_functions_from_source(self) -> Dict:
        """从源码解析函数信息（简化版）"""
        import re
        function_map = {}
        
        for i, line in enumerate(self.source_lines, 1):
            # 匹配函数定义
            match = re.search(r'function\s+(\w+)\s*\([^)]*\)', line)
            if match:
                func_name = match.group(1)
                # 找到函数结束位置（简化：找到下一个大括号闭合）
                end_line = self._find_function_end(i)
                function_map[func_name] = {
                    'start_line': i,
                    'end_line': end_line,
                    'signature': line.strip()
                }
            
            # 构造函数
            if 'constructor' in line and '(' in line:
                end_line = self._find_function_end(i)
                function_map['constructor'] = {
                    'start_line': i,
                    'end_line': end_line,
                    'signature': line.strip()
                }
        
        return function_map
    
    def _find_function_end(self, start_line: int) -> int:
        """找到函数结束行（简化版：大括号计数）"""
        brace_count = 0
        found_opening = False
        
        for i in range(start_line - 1, len(self.source_lines)):
            line = self.source_lines[i]
            if '{' in line:
                found_opening = True
            brace_count += line.count('{') - line.count('}')
            
            if found_opening and brace_count == 0 and '}' in line:
                return i + 1
        
        return start_line + 10  # 默认10行
    
    def _find_variable_declaration(self, variable: str) -> Dict:
        """查找变量声明"""
        import re
        for i, line in enumerate(self.source_lines, 1):
            # 匹配变量声明（如：address public owner;）
            if re.search(rf'\b{re.escape(variable)}\b', line):
                # 检查是否是声明行
                if any(kw in line for kw in ['uint', 'address', 'bool', 'mapping', 'string', 'bytes']):
                    # 查找初始化位置
                    init_location, init_code = self._find_variable_initialization(variable)
                    return {
                        'line': i,
                        'code': line.strip(),
                        'init_location': init_location,
                        'init_code': init_code
                    }
        return {}
    
    def _find_variable_initialization(self, variable: str):
        """查找变量初始化位置"""
        import re
        for i, line in enumerate(self.source_lines, 1):
            # 匹配赋值（如：owner = msg.sender;）
            if re.search(rf'\b{re.escape(variable)}\s*=\s*', line):
                # 判断是否在构造函数中
                if self._is_in_constructor(i):
                    return 'constructor', line.strip()
                else:
                    func = self._find_function_at_line(i)
                    return func if func else 'unknown', line.strip()
        return None, None
    
    def _is_in_constructor(self, line_num: int) -> bool:
        """判断行是否在构造函数中"""
        # 向前查找构造函数定义
        for i in range(line_num - 1, max(0, line_num - 20), -1):
            line = self.source_lines[i]
            if 'constructor' in line:
                return True
            if 'function ' in line:
                return False
        return False
    
    def _find_function_at_line(self, line_num: int) -> str:
        """查找指定行所在的函数"""
        import re
        # 向前查找函数定义
        for i in range(line_num - 1, max(0, line_num - 50), -1):
            line = self.source_lines[i]
            match = re.search(r'function\s+(\w+)', line)
            if match:
                return match.group(1)
        return None
    
    def _extract_variable_type(self, var_declaration: Dict) -> str:
        """从声明中提取变量类型"""
        if not var_declaration:
            return 'unknown'
        
        code = var_declaration.get('code', '')
        # 提取类型（如：address public owner; -> address）
        import re
        match = re.search(r'(uint\d*|address|bool|string|bytes\d*|mapping\([^)]+\))', code)
        if match:
            return match.group(1)
        return 'unknown'
    
    def _get_function_full_code(self, func_name: str, function_map: Dict) -> str:
        """获取完整函数代码"""
        if func_name in function_map:
            func_info = function_map[func_name]
            start = func_info['start_line'] - 1
            end = func_info['end_line']
            return ''.join(self.source_lines[start:end])
        
        # 如果找不到，尝试简单搜索
        import re
        for i, line in enumerate(self.source_lines):
            if f'function {func_name}' in line or (func_name == 'constructor' and 'constructor' in line):
                end = self._find_function_end(i + 1)
                return ''.join(self.source_lines[i:end])
        
        return f"// 函数 {func_name} 未找到"
    
    def _extract_function_signature(self, func_name: str) -> str:
        """提取函数签名"""
        import re
        for line in self.source_lines:
            if f'function {func_name}' in line or (func_name == 'constructor' and 'constructor' in line):
                # 提取到 { 之前的部分
                signature = line.split('{')[0].strip()
                return signature
        return f"function {func_name}(...)"
    
    def _get_context_lines(self, line_num: int, context_size: int = 3) -> tuple:
        """获取上下文代码行"""
        before = []
        after = []
        
        # 获取之前的行
        for i in range(max(0, line_num - context_size - 1), line_num - 1):
            if i < len(self.source_lines):
                before.append(self.source_lines[i].rstrip())
        
        # 获取之后的行
        for i in range(line_num, min(len(self.source_lines), line_num + context_size)):
            if i < len(self.source_lines):
                after.append(self.source_lines[i].rstrip())
        
        return before, after
    
    def _generate_vulnerability_description(self, variable: str, severity: str, 
                                           vuln_type: str, location: Dict) -> str:
        """生成漏洞描述"""
        has_condition = location.get('has_bytecode_condition', False) or location.get('has_source_condition', False)
        
        if severity == 'critical':
            if has_condition:
                return f"变量'{variable}'被写入，虽有条件检查但可能不足以防止攻击"
            else:
                return f"关键变量'{variable}'被直接写入，函数无任何访问控制保护"
        else:  # suspicious
            return f"变量'{variable}'被写入，检测到条件判断但需人工验证是否充分"
    
    def _generate_attack_scenario(self, variable: str, func_name: str, severity: str) -> str:
        """生成攻击场景描述"""
        var_lower = variable.lower()
        
        if 'owner' in var_lower or 'admin' in var_lower:
            return f"攻击者可以调用{func_name}函数并传入自己的地址，夺取合约控制权"
        elif 'balance' in var_lower or 'amount' in var_lower:
            return f"攻击者可能操纵资金相关变量，导致资金损失或账目混乱"
        elif 'paused' in var_lower or 'stopped' in var_lower:
            return f"攻击者可能修改合约状态控制变量，影响合约正常运行"
        else:
            return f"攻击者可以无限制地修改变量'{variable}'，影响合约业务逻辑"
    
    def _extract_data_flow_summary(self, location: Dict, variable: str, var_slot: int) -> str:
        """提取数据流摘要"""
        # 简化的数据流描述
        return f"user_input -> SSTORE(slot_{var_slot}:{variable})"
    
    def _extract_existing_checks(self, func_name: str, function_map: Dict) -> List[Dict]:
        """提取已有的检查"""
        checks = []
        if func_name in function_map:
            func_info = function_map[func_name]
            start = func_info['start_line'] - 1
            end = func_info['end_line']
            
            for line in self.source_lines[start:end]:
                if 'require(' in line:
                    # 提取require条件
                    import re
                    match = re.search(r'require\(([^,)]+)', line)
                    if match:
                        condition = match.group(1).strip()
                        checks.append({
                            'type': 'require',
                            'condition': condition,
                            'purpose': self._infer_check_purpose(condition)
                        })
        
        return checks
    
    def _infer_check_purpose(self, condition: str) -> str:
        """推断检查的目的"""
        condition_lower = condition.lower()
        if 'msg.sender' in condition_lower and ('owner' in condition_lower or 'admin' in condition_lower):
            return '访问控制检查'
        elif '>' in condition or '<' in condition or '==' in condition:
            return '数值范围检查'
        elif '!= 0' in condition or '!= address(0)' in condition:
            return '零值检查'
        else:
            return '条件检查'
    
    def _check_has_modifier(self, function_signature: str) -> bool:
        """检查函数是否有modifier"""
        common_modifiers = ['onlyOwner', 'onlyAdmin', 'whenNotPaused', 'nonReentrant']
        return any(mod in function_signature for mod in common_modifiers)
    
    def _determine_confidence(self, location: Dict) -> str:
        """确定检测置信度"""
        detection_method = location.get('detection_method', 'taint_analysis')
        has_bytecode_condition = location.get('has_bytecode_condition', False)
        has_source_condition = location.get('has_source_condition', False)
        
        if detection_method == 'taint_analysis' and not has_bytecode_condition and not has_source_condition:
            return 'high'
        elif has_bytecode_condition or has_source_condition:
            return 'medium'
        else:
            return 'low'
    
    def _generate_review_notes(self, variable: str, func_name: str) -> str:
        """生成人工审查提示"""
        var_lower = variable.lower()
        
        if 'balance' in var_lower or 'amount' in var_lower:
            return f"需要确认{func_name}函数的业务逻辑：是owner专用操作还是用户余额系统？现有检查是否充分？"
        elif 'owner' in var_lower or 'admin' in var_lower:
            return f"虽然检测到条件判断，但需验证是否包含足够的访问控制（如msg.sender == owner）"
        else:
            return f"需要人工审查{func_name}函数的条件检查是否足以保护变量'{variable}'"

