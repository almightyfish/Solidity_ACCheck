# 智能合约访问控制漏洞检测工具 - 使用指南

## 📖 目录

- [快速开始](#快速开始)
- [使用方法](#使用方法)
- [分析结果解读](#分析结果解读)
- [常见问题](#常见问题)
- [最佳实践](#最佳实践)

---

## 🚀 快速开始

### 1. 环境要求

- Python 3.8+
- solc-select（用于管理Solidity编译器版本）
- 必要的Python包（见requirements.txt）

### 2. 安装依赖

```bash
cd /Users/almightyfish/Desktop/AChecker/AC/bytecode_analysis

# 安装Python依赖
pip install -r requirements.txt

# 安装solc-select
pip install solc-select

# 安装需要的Solidity编译器版本
solc-select install 0.4.24
solc-select install 0.5.16
solc-select install 0.8.0
```

### 3. 第一次运行

**单个合约分析**：

```bash
# 基本用法
python -m core.analyzer \
    --contract /path/to/contract.sol \
    --key-vars "owner,balance,totalSupply" \
    --solc-version 0.4.24

# 完整示例
python -m core.analyzer \
    --contract ../undependency/0xf4be3da9df0c12e69115bb5614334786fbaf5ace.sol \
    --key-vars "totalSupply,owner" \
    --solc-version 0.4.18 \
    --output-dir ./output
```

**生成HTML报告**：

分析完成后，会自动生成：
- `final_report.json` - JSON格式详细报告
- `final_report.html` - HTML可视化报告

直接在浏览器中打开HTML文件即可查看！

---

## 📋 使用方法

### 方式1：命令行直接运行

```bash
python -m core.analyzer \
    --contract <合约路径> \
    --key-vars "<变量1>,<变量2>,<变量3>" \
    --solc-version <版本号> \
    [--output-dir <输出目录>]
```

**参数说明**：
- `--contract`: Solidity合约文件路径（必需）
- `--key-vars`: 关键变量列表，用逗号分隔（必需）
- `--solc-version`: Solidity编译器版本（必需）
- `--output-dir`: 输出目录（可选，默认为`./output`）

### 方式2：使用Python API

```python
from core.analyzer import AllInOneAnalyzer

# 创建分析器实例
analyzer = AllInOneAnalyzer(
    solc_version='0.4.24',
    key_variables=['owner', 'totalSupply', 'balance'],
    contract_path='/path/to/contract.sol',
    output_dir='./output'
)

# 运行分析
result = analyzer.run()

if result:
    print("✅ 分析成功！")
    print(f"报告保存在: {analyzer.output_dir}/final_report.json")
else:
    print("❌ 分析失败")
```

### 方式3：批量分析多个合约

```python
import os
from core.analyzer import AllInOneAnalyzer

contracts = [
    {
        'path': '../undependency/contract1.sol',
        'vars': ['owner', 'balance'],
        'version': '0.4.24'
    },
    {
        'path': '../undependency/contract2.sol',
        'vars': ['totalSupply', 'admin'],
        'version': '0.5.16'
    }
]

for contract in contracts:
    print(f"\n分析: {os.path.basename(contract['path'])}")
    
    analyzer = AllInOneAnalyzer(
        solc_version=contract['version'],
        key_variables=contract['vars'],
        contract_path=contract['path'],
        output_dir=f"./output_{os.path.basename(contract['path'])}"
    )
    
    analyzer.run()
```

---

## 📊 分析结果解读

### 1. 风险级别分类

#### 🔥 危险（Dangerous）

**定义**：完全没有任何访问控制或条件保护的写入操作

**特征**：
- 没有modifier保护
- 没有require/assert语句
- 没有if条件判断
- 任何人都可以调用并修改

**示例**：
```solidity
function setOwner(address newOwner) public {
    owner = newOwner;  // 🔥 危险！任何人都能修改
}
```

**建议**：**立即修复**，添加访问控制！

---

#### ⚠️ 可疑（Suspicious）

**定义**：有一些条件判断，但不是访问控制

**特征**：
- 有require/assert/if语句
- 但条件不是检查调用者身份
- 条件可能不够充分或可以被绕过

**示例**：
```solidity
function burn(uint value) public {
    require(value > 0);              // ⚠️ 只检查参数
    require(balance >= value);       // ⚠️ 只检查余额
    totalSupply -= value;           // 可疑：没有检查调用者
}
```

**建议**：**人工审查**，确认条件是否充分！

---

#### ✅ 安全（Safe）

**定义**：有明确的访问控制机制

**特征**：
- 有modifier保护（如onlyOwner）
- 有msg.sender检查
- 有明确的权限验证

**示例**：
```solidity
function setOwner(address newOwner) public onlyOwner {
    owner = newOwner;  // ✅ 安全：有onlyOwner保护
}

function withdraw() public {
    require(msg.sender == owner);  // ✅ 安全：检查调用者
    // ...
}
```

---

### 2. 报告结构

**JSON报告格式**：

```json
{
  "contract_path": "合约路径",
  "key_variables": ["变量1", "变量2"],
  "summary": {
    "total_variables": 2,
    "vulnerable_count": 1,
    "safe_count": 1,
    "dangerous_paths_total": 3,
    "suspicious_paths_total": 2
  },
  "results": [
    {
      "variable": "owner",
      "storage_slot": 0,
      "has_vulnerability": true,
      "dangerous_paths_count": 2,
      "suspicious_paths_count": 1,
      "dangerous_locations": [
        {
          "line": 123,
          "code": "owner = newOwner;",
          "function": "setOwner",
          "has_source_condition": false,
          "detection_method": "public_function_check",
          "warning": "⚠️ public函数无访问控制"
        }
      ],
      "suspicious_locations": [
        {
          "line": 145,
          "code": "owner = msg.sender;",
          "function": "transferOwnership",
          "has_source_condition": true,
          "detection_method": "taint_analysis"
        }
      ]
    }
  ]
}
```

**字段说明**：

| 字段 | 说明 |
|------|------|
| `has_vulnerability` | 是否检测到漏洞 |
| `dangerous_paths_count` | 危险路径数量 |
| `suspicious_paths_count` | 可疑路径数量 |
| `dangerous_locations` | 危险位置列表 |
| `suspicious_locations` | 可疑位置列表 |
| `has_source_condition` | 是否有条件判断 |
| `detection_method` | 检测方法（taint_analysis/public_function_check） |

---

### 3. 终端输出解读

```
================================================================================
[1] 变量: owner
    状态: ⚠️ 检测到访问控制漏洞
    存储槽位: 0

    📊 漏洞路径统计:
      ├─ 危险路径: 2 条 (无条件保护)
      └─ 可疑路径: 1 条 (有条件判断)

    🔥 危险位置（无条件保护，需立即修复）:
       ⛔ 行 123 (setOwner): owner = newOwner;
          🔍 检测方式: 补充检测（public函数无访问控制）
          ⚠️ public函数无访问控制

    ⚠️  可疑位置（有条件判断，需人工审查）:
       ⚠️  行 145 (transferOwnership): owner = msg.sender;
          🔍 检测方式: 污点分析
          检测到条件保护，但建议人工审查条件是否充分
================================================================================
```

**符号说明**：
- 🔥 危险：需要立即修复
- ⚠️ 可疑：需要人工审查
- ✅ 安全：通过检测
- 📊 统计信息
- 🔍 检测方法

---

## ❓ 常见问题

### Q1: 为什么构造函数中的赋值被标记为风险？

**A**: 已修复！构造函数中的赋值是初始化操作，不会被标记为风险。

### Q2: 为什么常量声明被标记为危险？

**A**: 已修复！变量声明（包括常量）不是运行时操作，不会被检测。

### Q3: 有require语句的函数为什么还被标记？

**A**: 已改进！有require/if等条件判断的会被标记为"可疑"而非"危险"。
   - 需要人工审查条件是否充分
   - 条件可能不是访问控制，而只是状态检查

### Q4: 如何选择正确的Solidity版本？

**A**: 查看合约文件第一行的`pragma solidity`语句：
```solidity
pragma solidity ^0.4.24;  → 使用 0.4.24
pragma solidity ^0.5.0;   → 使用 0.5.16
pragma solidity ^0.8.0;   → 使用 0.8.0
```

### Q5: 分析速度慢怎么办？

**A**: 
- 只指定必要的关键变量
- 大型合约可能需要几分钟
- 可以使用后台运行

### Q6: 编译失败怎么办？

**A**:
1. 检查Solidity版本是否匹配
2. 确保合约语法正确
3. 检查是否缺少依赖合约
4. 查看错误信息调整版本

---

## 🎯 最佳实践

### 1. 选择关键变量

**应该检测的变量**：
- ✅ 所有权变量：`owner`, `admin`, `controller`
- ✅ 余额变量：`balance`, `totalSupply`, `funds`
- ✅ 权限变量：`authorized`, `whitelist`, `roles`
- ✅ 关键配置：`price`, `rate`, `limit`

**不需要检测的变量**：
- ❌ 常量：`constant`变量
- ❌ 内部临时变量
- ❌ 只读变量

### 2. 解读分析结果

**优先级**：
1. **危险位置** → 立即修复
2. **可疑位置** → 人工审查
3. **污点路径** → 深入分析

**审查重点**：
- 检查函数是否应该是`internal`或`private`
- 验证访问控制modifier是否正确
- 确认条件判断是否充分

### 3. 修复建议

#### 示例1：添加访问控制

**修复前** ❌：
```solidity
function setOwner(address newOwner) public {
    owner = newOwner;
}
```

**修复后** ✅：
```solidity
modifier onlyOwner() {
    require(msg.sender == owner);
    _;
}

function setOwner(address newOwner) public onlyOwner {
    owner = newOwner;
}
```

#### 示例2：改为internal函数

**修复前** ❌：
```solidity
function _mint(address to, uint amount) public {
    balance[to] += amount;
}
```

**修复后** ✅：
```solidity
function _mint(address to, uint amount) internal {
    balance[to] += amount;
}
```

#### 示例3：增强条件判断

**修复前** ⚠️：
```solidity
function burn(uint value) public {
    require(value > 0);
    totalSupply -= value;
}
```

**修复后** ✅：
```solidity
function burn(uint value) public {
    require(value > 0);
    require(balance[msg.sender] >= value);  // 额外检查
    balance[msg.sender] -= value;
    totalSupply -= value;
}
```

### 4. 批量分析建议

```python
# 推荐：使用配置文件
contracts_config = [
    {
        'name': 'TokenContract',
        'path': '../contracts/token.sol',
        'vars': ['totalSupply', 'owner', 'balances'],
        'version': '0.4.24'
    },
    # ... 更多合约
]

# 分析并生成汇总报告
results = []
for config in contracts_config:
    analyzer = AllInOneAnalyzer(
        solc_version=config['version'],
        key_variables=config['vars'],
        contract_path=config['path'],
        output_dir=f"./output/{config['name']}"
    )
    result = analyzer.run()
    results.append({
        'name': config['name'],
        'success': result,
        'output': analyzer.output_dir
    })

# 打印汇总
for r in results:
    status = "✅" if r['success'] else "❌"
    print(f"{status} {r['name']}: {r['output']}")
```

---

## 📚 更多信息

- **文件结构**：见 `README_项目结构.md`
- **处理逻辑**：见 `README_处理逻辑.md`
- **技术细节**：查看源码注释

---

## 🆘 获取帮助

遇到问题？

1. 检查本文档的"常见问题"章节
2. 查看生成的错误日志
3. 验证输入参数是否正确
4. 提供具体的错误信息和合约示例

---

**版本**: v2.8  
**更新日期**: 2025年10月7日  
**状态**: 稳定版

🎉 **祝您使用愉快！发现漏洞，保护资产！**

