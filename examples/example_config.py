#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件示例 - 展示不同场景的配置方法
"""

# ============================================================================
# 示例 1: 分析Token合约的供应量和余额
# ============================================================================
"""
SOLC_VERSION = "0.4.25"
KEY_VARIABLES = ["totalSupply", "balances", "owner"]
CONTRACT_PATH = "/path/to/your/TokenContract.sol"
OUTPUT_DIR = "analysis_output_token"
"""


# ============================================================================
# 示例 2: 分析DeFi合约的资金池
# ============================================================================
"""
SOLC_VERSION = "0.8.0"
KEY_VARIABLES = ["liquidityPool", "userDeposits", "rewardRate"]
CONTRACT_PATH = "/path/to/your/DeFiContract.sol"
OUTPUT_DIR = "analysis_output_defi"
"""


# ============================================================================
# 示例 3: 分析多签钱包的权限控制
# ============================================================================
"""
SOLC_VERSION = "0.6.12"
KEY_VARIABLES = ["owners", "required", "transactions"]
CONTRACT_PATH = "/path/to/your/MultiSigWallet.sol"
OUTPUT_DIR = "analysis_output_multisig"
"""


# ============================================================================
# 使用说明
# ============================================================================
"""
1. 复制上述任一示例到 config.py
2. 修改参数为你的实际值
3. 运行: python main.py
"""

