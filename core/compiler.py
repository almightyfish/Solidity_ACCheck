#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solc编译器管理和合约编译模块
"""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional
from utils.colors import Colors


class SolcManager:
    """Solc版本管理器"""
    
    def __init__(self, version: str):
        self.version = version
        self.solc_path = None
    
    def check_and_switch_version(self) -> bool:
        """检查并切换到指定的solc版本"""
        print(f"\n{Colors.HEADER}【步骤1】检查和切换Solc版本{Colors.ENDC}")
        print("-" * 80)
        
        # 检查是否安装了solc-select
        try:
            result = subprocess.run(['solc-select', 'versions'], 
                                  capture_output=True, text=True, timeout=10)
            has_solc_select = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            has_solc_select = False
        
        if has_solc_select:
            print(f"✓ 检测到 solc-select")
            return self._use_solc_select()
        else:
            print(f"⚠️  未检测到 solc-select，尝试使用系统solc")
            return self._use_system_solc()
    
    def _use_solc_select(self) -> bool:
        """使用solc-select切换版本"""
        try:
            # 检查是否已安装所需版本
            result = subprocess.run(['solc-select', 'versions'], 
                                  capture_output=True, text=True)
            installed_versions = result.stdout
            
            if self.version not in installed_versions:
                print(f"📦 安装 solc {self.version}...")
                subprocess.run(['solc-select', 'install', self.version], 
                             check=True, capture_output=True)
                print(f"✓ 安装完成")
            
            # 切换版本
            print(f"🔄 切换到 solc {self.version}...")
            subprocess.run(['solc-select', 'use', self.version], 
                         check=True, capture_output=True)
            
            self.solc_path = 'solc'
            
            # 验证版本
            result = subprocess.run(['solc', '--version'], 
                                  capture_output=True, text=True)
            print(f"✓ 当前版本: {result.stdout.split('Version:')[1].split()[0]}")
            return True
            
        except Exception as e:
            print(f"❌ solc-select切换失败: {e}")
            return False
    
    def _use_system_solc(self) -> bool:
        """使用系统默认solc"""
        try:
            result = subprocess.run(['solc', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                version_info = result.stdout
                print(f"✓ 找到系统solc")
                print(f"  版本信息: {version_info.split('Version:')[1].split()[0] if 'Version:' in version_info else 'Unknown'}")
                self.solc_path = 'solc'
                return True
            return False
        except FileNotFoundError:
            print(f"❌ 未找到solc编译器")
            print(f"\n安装建议:")
            print(f"  1. 使用 solc-select (推荐):")
            print(f"     pip install solc-select")
            print(f"     solc-select install {self.version}")
            print(f"     solc-select use {self.version}")
            print(f"  2. 或安装系统solc:")
            print(f"     macOS: brew install solidity")
            print(f"     Linux: apt-get install solc")
            return False


class ContractCompiler:
    """合约编译器"""
    
    def __init__(self, solc_path: str, output_dir: str):
        self.solc_path = solc_path
        self.output_dir = output_dir
        self.bytecode = None
        self.runtime_bytecode = None
        self.asm = None
        self.srcmap = None  # 部署时源码映射
        self.srcmap_runtime = None  # 运行时源码映射
        self.combined_json = None  # combined.json 数据
    
    def compile(self, contract_path: str) -> bool:
        """编译合约"""
        print(f"\n{Colors.HEADER}【步骤2】编译合约{Colors.ENDC}")
        print("-" * 80)
        print(f"源文件: {contract_path}")
        
        try:
            # 🔧 改进：使用 combined-json 获取 srcmap 和 AST
            # 先生成 combined-json（包含srcmap）
            combined_json_path = os.path.join(self.output_dir, 'combined.json')
            cmd_combined = [
                self.solc_path,
                '--combined-json', 'bin,bin-runtime,srcmap,srcmap-runtime,asm,ast',
                contract_path
            ]
            
            print(f"执行命令（combined-json）: {' '.join(cmd_combined)}")
            result_combined = subprocess.run(cmd_combined, capture_output=True, text=True, timeout=30)
            
            if result_combined.returncode == 0:
                # 保存 combined.json
                with open(combined_json_path, 'w', encoding='utf-8') as f:
                    f.write(result_combined.stdout)
                print(f"✓ Combined JSON 已生成")
            
            # 再生成单独的文件（保持兼容性）
            # 🔧 修复：旧版本solc不支持 --overwrite，需要版本判断
            cmd = [
                self.solc_path,
                '--bin', '--bin-runtime', '--asm',
                '-o', self.output_dir,
                contract_path
            ]
            
            # 🔧 只在支持的版本上添加 --overwrite（0.4.11+）
            if self._supports_overwrite():
                cmd.insert(4, '--overwrite')  # 在 -o 之前插入
            
            print(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"{Colors.RED}❌ 编译失败:{Colors.ENDC}")
                print(result.stderr)
                return False
            
            # 读取编译产物
            # 🔧 改进：尝试找到有runtime bytecode的合约
            contract_names = self._extract_all_contract_names(contract_path)
            contract_name = self._find_valid_contract(contract_names)
            
            if not contract_name:
                print(f"{Colors.RED}❌ 未找到有效的合约{Colors.ENDC}")
                return False
            
            print(f"  ✓ 选择合约: {contract_name}")
            self._load_artifacts(contract_name)
            
            # 🔧 新增：加载 combined.json（包含srcmap）
            self._load_combined_json(combined_json_path, contract_path)
            
            print(f"{Colors.GREEN}✓ 编译成功{Colors.ENDC}")
            # 🔧 修复：处理 None 值（某些合约可能是interface）
            if self.runtime_bytecode:
                print(f"  - Runtime bytecode: {len(self.runtime_bytecode)} 字符")
            else:
                print(f"  - Runtime bytecode: 未生成（可能是interface）")
            
            if self.bytecode:
                print(f"  - Bytecode: {len(self.bytecode)} 字符")
            else:
                print(f"  - Bytecode: 未生成")
            
            if self.srcmap_runtime:
                print(f"  - Runtime srcmap: {len(self.srcmap_runtime.split(';'))} 个映射")
            if self.srcmap:
                print(f"  - Deploy srcmap: {len(self.srcmap.split(';'))} 个映射")
            
            # 保存中间结果
            self._save_intermediate_files()
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}❌ 编译超时{Colors.ENDC}")
            return False
        except Exception as e:
            print(f"{Colors.RED}❌ 编译错误: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            return False
    
    def _supports_overwrite(self) -> bool:
        """🔧 新增：检查solc版本是否支持 --overwrite 选项"""
        try:
            # 获取版本号
            result = subprocess.run([self.solc_path, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            version_str = result.stdout
            
            # 提取版本号（如 0.4.11+commit.68ef5810）
            match = re.search(r'Version:\s*(\d+)\.(\d+)\.(\d+)', version_str)
            if match:
                major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
                
                # --overwrite 在 0.4.11+ 版本开始支持
                if major > 0 or (major == 0 and minor > 4) or (major == 0 and minor == 4 and patch >= 11):
                    return True
            
            return False
        except:
            # 如果无法判断版本，保守起见不使用 --overwrite
            return False
    
    def _extract_contract_name(self, contract_path: str) -> str:
        """提取合约名称（兼容方法，返回第一个合约）"""
        with open(contract_path, 'r') as f:
            content = f.read()
        match = re.search(r'contract\s+(\w+)', content)
        return match.group(1) if match else Path(contract_path).stem
    
    def _extract_all_contract_names(self, contract_path: str) -> List[str]:
        """🔧 新增：提取所有合约名称"""
        contract_names = []
        with open(contract_path, 'r', encoding='utf-8') as f:
            for line in f:
                # 匹配 contract ContractName { 或 contract ContractName is ...
                # 但排除 interface
                if 'interface' not in line:
                    match = re.search(r'\bcontract\s+(\w+)', line)
                    if match:
                        contract_names.append(match.group(1))
        return contract_names if contract_names else [Path(contract_path).stem]
    
    def _find_valid_contract(self, contract_names: List[str]) -> Optional[str]:
        """🔧 新增：找到有runtime bytecode的合约"""
        for contract_name in contract_names:
            # 检查是否有runtime bytecode文件
            runtime_file = os.path.join(self.output_dir, f"{contract_name}.bin-runtime")
            if os.path.exists(runtime_file):
                # 检查文件是否为空
                with open(runtime_file, 'r') as f:
                    content = f.read().strip()
                    if content:  # 有内容
                        return contract_name
        
        # 如果都没有runtime bytecode，返回第一个
        return contract_names[0] if contract_names else None
    
    def _load_artifacts(self, contract_name: str):
        """加载编译产物"""
        base_path = os.path.join(self.output_dir, contract_name)
        
        # 读取各种编译产物（兼容不同solc版本）
        files = {
            'bin': 'bytecode',
            'bin-runtime': 'runtime_bytecode',
            'asm': 'asm'
        }
        
        for ext, attr in files.items():
            file_path = f"{base_path}.{ext}"
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    setattr(self, attr, f.read().strip())
    
    def _load_combined_json(self, combined_json_path: str, contract_path: str):
        """加载 combined.json 并提取 srcmap"""
        if not os.path.exists(combined_json_path):
            print(f"  ⚠️  未找到 combined.json")
            return
        
        import json
        with open(combined_json_path, 'r', encoding='utf-8') as f:
            self.combined_json = json.load(f)
        
        # 提取 srcmap（需要找到正确的合约键）
        # combined.json 的格式: {"contracts": {"path:ContractName": {...}}}
        contracts = self.combined_json.get('contracts', {})
        
        # 查找包含当前合约路径的键
        for contract_key, contract_data in contracts.items():
            if contract_path in contract_key or os.path.basename(contract_path) in contract_key:
                self.srcmap = contract_data.get('srcmap', '')
                self.srcmap_runtime = contract_data.get('srcmap-runtime', '')
                print(f"  ✓ 加载 srcmap: {contract_key}")
                break
    
    def _save_intermediate_files(self):
        """保存中间文件"""
        intermediate_dir = os.path.join(self.output_dir, "intermediate")
        os.makedirs(intermediate_dir, exist_ok=True)
        
        # 保存runtime bytecode（如果存在）
        if self.runtime_bytecode:
            with open(os.path.join(intermediate_dir, "runtime_bytecode.hex"), 'w') as f:
                f.write(self.runtime_bytecode)
        
        # 🔧 新增：保存 srcmap
        if self.srcmap_runtime:
            with open(os.path.join(intermediate_dir, "srcmap_runtime.txt"), 'w', encoding='utf-8') as f:
                f.write(self.srcmap_runtime)
        
        if self.srcmap:
            with open(os.path.join(intermediate_dir, "srcmap.txt"), 'w', encoding='utf-8') as f:
                f.write(self.srcmap)
        
        # 保存 combined.json
        if self.combined_json:
            import json
            with open(os.path.join(intermediate_dir, "combined.json"), 'w', encoding='utf-8') as f:
                json.dump(self.combined_json, f, indent=2, ensure_ascii=False)
        
        print(f"  → 中间文件已保存到: {intermediate_dir}/")

