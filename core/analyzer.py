#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主分析器模块
"""

import os
from typing import List, Dict
from utils.colors import Colors
from .compiler import SolcManager, ContractCompiler
from .bytecode import BytecodeAnalyzer
from .taint import TaintAnalyzer
from .source_mapper import SourceMapper
from .report import ReportGenerator


class AllInOneAnalyzer:
    """一体化分析器"""
    
    def __init__(self, solc_version: str, key_variables: List[str], 
                 contract_path: str, output_dir: str = "analysis_output"):
        self.solc_version = solc_version
        self.key_variables = key_variables
        self.contract_path = contract_path
        self.output_dir = output_dir
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "intermediate"), exist_ok=True)
    
    def run(self) -> Dict:
        """运行完整分析流程"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * 80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}智能合约一体化污点分析工具{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'=' * 80}{Colors.ENDC}")
        print(f"\n配置:")
        print(f"  Solc版本: {self.solc_version}")
        print(f"  合约路径: {self.contract_path}")
        print(f"  关键变量: {', '.join(self.key_variables)}")
        print(f"  输出目录: {self.output_dir}")
        
        try:
            # 步骤1: 检查和切换Solc版本
            solc_manager = SolcManager(self.solc_version)
            if not solc_manager.check_and_switch_version():
                return None
            
            # 步骤2: 编译合约
            compiler = ContractCompiler(solc_manager.solc_path, self.output_dir)
            if not compiler.compile(self.contract_path):
                return None
            
            # 步骤3: 字节码分析
            bytecode_analyzer = BytecodeAnalyzer(
                compiler.runtime_bytecode,
                self.key_variables,
                self.output_dir
            )
            if not bytecode_analyzer.analyze():
                return None
            
            # 步骤4: 污点分析
            taint_analyzer = TaintAnalyzer(bytecode_analyzer, self.output_dir)
            if not taint_analyzer.analyze():
                return None
            
            # 步骤5: 源码映射（使用srcmap）
            source_mapper = SourceMapper(
                self.contract_path, 
                self.output_dir,
                srcmap_runtime=compiler.srcmap_runtime,  # 🔧 新增：传递srcmap
                runtime_bytecode=compiler.runtime_bytecode  # 🔧 新增：传递bytecode
            )
            mapped_results = source_mapper.map_to_source(
                taint_analyzer.taint_results,
                bytecode_analyzer
            )
            
            # 步骤6: 生成报告
            report_generator = ReportGenerator(self.output_dir, self.contract_path)
            final_report = report_generator.generate(mapped_results)
            
            # 完成
            print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.GREEN}✅ 分析完成！{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 80}{Colors.ENDC}")
            print(f"\n所有结果已保存到: {Colors.CYAN}{self.output_dir}/{Colors.ENDC}")
            print(f"  - 最终报告: final_report.json")
            print(f"  - HTML报告: final_report.html")
            print(f"  - 中间结果: intermediate/")
            
            return final_report
            
        except Exception as e:
            print(f"\n{Colors.RED}❌ 分析过程中发生错误: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            return None

