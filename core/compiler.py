#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solc编译器管理和合约编译模块
"""

import os
import re
import subprocess
from pathlib import Path
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
        self.srcmap = None
        self.srcmap_runtime = None
    
    def compile(self, contract_path: str) -> bool:
        """编译合约"""
        print(f"\n{Colors.HEADER}【步骤2】编译合约{Colors.ENDC}")
        print("-" * 80)
        print(f"源文件: {contract_path}")
        
        try:
            # 编译命令（兼容不同版本）
            cmd = [
                self.solc_path,
                '--bin', '--bin-runtime', '--asm',
                '--overwrite',
                '-o', self.output_dir,
                contract_path
            ]
            
            print(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"{Colors.RED}❌ 编译失败:{Colors.ENDC}")
                print(result.stderr)
                return False
            
            # 读取编译产物
            contract_name = self._extract_contract_name(contract_path)
            self._load_artifacts(contract_name)
            
            print(f"{Colors.GREEN}✓ 编译成功{Colors.ENDC}")
            print(f"  - Runtime bytecode: {len(self.runtime_bytecode)} 字符")
            print(f"  - Bytecode: {len(self.bytecode)} 字符")
            
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
    
    def _extract_contract_name(self, contract_path: str) -> str:
        """提取合约名称"""
        with open(contract_path, 'r') as f:
            content = f.read()
        match = re.search(r'contract\s+(\w+)', content)
        return match.group(1) if match else Path(contract_path).stem
    
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
    
    def _save_intermediate_files(self):
        """保存中间文件"""
        intermediate_dir = os.path.join(self.output_dir, "intermediate")
        os.makedirs(intermediate_dir, exist_ok=True)
        
        # 保存runtime bytecode
        with open(os.path.join(intermediate_dir, "runtime_bytecode.hex"), 'w') as f:
            f.write(self.runtime_bytecode)
        
        print(f"  → 中间文件已保存到: {intermediate_dir}/")

