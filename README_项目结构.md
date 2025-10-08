# 智能合约访问控制漏洞检测工具 - 项目结构

## 📁 目录结构

```
bytecode_analysis/
├── core/                           # 核心分析模块
│   ├── __init__.py
│   ├── analyzer.py                 # 主分析器（一体化入口）
│   ├── bytecode_analyzer.py        # 字节码分析器
│   ├── cfg_builder.py              # 控制流图构建器
│   ├── compiler.py                 # Solidity编译器封装
│   ├── dataflow_analyzer.py        # 数据流分析器
│   ├── report.py                   # 报告生成器
│   ├── source_mapper.py            # 源码映射器（核心检测逻辑）
│   ├── storage_analyzer.py         # 存储槽位分析器
│   ├── taint_analyzer.py           # 污点分析器
│   └── variable_finder.py          # 变量查找器
│
├── utils/                          # 工具模块
│   ├── __init__.py
│   ├── opcode.py                   # EVM操作码定义
│   └── colors.py                   # 终端颜色输出
│
├── examples/                       # 示例合约和测试
│   └── test_contracts/
│
├── test_*.py                       # 各种测试脚本
├── README_使用指南.md              # 使用指南（本文档的兄弟文档）
├── README_项目结构.md              # 项目结构（本文档）
└── README_处理逻辑.md              # 处理逻辑和算法
```

---

## 🧩 核心模块说明

### 1. `analyzer.py` - 主分析器

**作用**：一体化分析入口，协调所有子模块

**主要类**：
```python
class AllInOneAnalyzer:
    """一体化智能合约分析器"""
    
    def __init__(self, solc_version, key_variables, contract_path, output_dir):
        """初始化分析器"""
        
    def run(self) -> bool:
        """运行完整的分析流程"""
        # 1. 编译合约
        # 2. 分析字节码
        # 3. 构建CFG
        # 4. 分析存储
        # 5. 数据流分析
        # 6. 污点分析
        # 7. 源码映射
        # 8. 生成报告
```

**关键方法**：
- `run()`: 执行完整分析流程
- `_setup_environment()`: 环境初始化
- `_validate_inputs()`: 输入验证

---

### 2. `compiler.py` - 编译器封装

**作用**：管理Solidity编译器，生成字节码和汇编

**功能**：
- 切换solc版本
- 编译Solidity源码
- 生成bytecode和runtime bytecode
- 生成汇编代码

**示例**：
```python
compiler = SolidityCompiler(
    solc_version='0.4.24',
    contract_path='contract.sol',
    output_dir='./output'
)
result = compiler.compile()
```

---

### 3. `bytecode_analyzer.py` - 字节码分析

**作用**：解析和反汇编EVM字节码

**主要功能**：
- 字节码反汇编
- 识别基本块
- 提取跳转目标
- 识别函数选择器

**输出**：指令序列、基本块列表

---

### 4. `cfg_builder.py` - 控制流图构建

**作用**：构建程序的控制流图（CFG）

**数据结构**：
```python
class BasicBlock:
    id: int              # 基本块ID
    instructions: List   # 指令列表
    successors: List     # 后继基本块
    predecessors: List   # 前驱基本块
```

**算法**：
- 识别基本块边界
- 建立块间跳转关系
- 构建完整CFG

---

### 5. `storage_analyzer.py` - 存储分析

**作用**：分析智能合约的存储布局

**主要功能**：
- 识别状态变量
- 计算存储槽位
- 映射变量到槽位
- 处理复杂类型（mapping、数组等）

**示例输出**：
```json
{
  "owner": {
    "slot": 0,
    "type": "address"
  },
  "totalSupply": {
    "slot": 1,
    "type": "uint256"
  }
}
```

---

### 6. `dataflow_analyzer.py` - 数据流分析

**作用**：追踪数据在程序中的流动

**分析类型**：
- 定义-使用分析
- 活跃变量分析
- 到达定义分析

**应用**：
- 识别变量依赖关系
- 追踪污点传播路径
- 辅助漏洞检测

---

### 7. `taint_analyzer.py` - 污点分析

**作用**：追踪不可信数据（污点）的传播

**核心概念**：
- **污点源（Source）**：不可信输入（如`CALLDATALOAD`）
- **污点传播**：污点数据的计算和赋值
- **污点汇（Sink）**：关键变量写入（如`SSTORE`）

**算法**：
1. 标记污点源
2. 追踪污点传播
3. 检测污点到达关键汇点
4. 分析路径条件

**输出**：
```json
{
  "has_taint": true,
  "taint_paths": [
    {
      "source": "CALLDATALOAD at offset 100",
      "sink": "SSTORE slot 0",
      "path": ["Block1", "Block2", "Block3"],
      "has_condition": false
    }
  ]
}
```

---

### 8. `source_mapper.py` - 源码映射器 ⭐

**作用**：将字节码分析结果映射回源码，核心检测逻辑所在

**核心功能**：

#### 8.1 变量使用识别
```python
def _find_variable_usages(self, var_name: str) -> List[Dict]:
    """在源码中查找变量的所有使用位置"""
    # 返回：行号、代码、操作类型（read/write）、所属函数
```

#### 8.2 构造函数识别
```python
def _load_and_parse_source(self):
    """解析源码，识别函数和构造函数"""
    # 识别 constructor() 和 function ContractName()
    # 支持多合约文件
```

#### 8.3 访问控制检查
```python
def _check_public_function_has_access_control(self, func_name: str) -> Tuple[bool, str]:
    """检查函数是否有访问控制"""
    # 检查modifier、visibility等
    # 返回：(有无访问控制, 原因)
```

#### 8.4 条件判断检查
```python
def _check_source_has_condition(self, usage: Dict) -> bool:
    """检查操作是否有条件保护"""
    # 检查 require/assert/if 语句
    # 不仅限于访问控制，任何条件都算
```

#### 8.5 敏感函数检测
```python
def _check_sensitive_functions(self) -> List[Dict]:
    """检测敏感函数调用"""
    # 检测 selfdestruct, delegatecall, suicide, callcode
    # 检查是否有访问控制
```

#### 8.6 风险分级逻辑
```python
def map_to_source(self, bytecode_results: List[Dict], taint_results: List[Dict]) -> List[Dict]:
    """核心映射逻辑"""
    
    # 过滤链：
    # 1. 跳过变量声明（type == 'declaration'）
    # 2. 跳过构造函数操作（is_constructor == True）
    # 3. 检查访问控制（modifier/visibility）
    # 4. 检查条件判断（require/if/assert）
    
    # 风险分级：
    # - 有访问控制 → 安全（不标记）
    # - 有条件判断 → 可疑（需审查）
    # - 无任何保护 → 危险（需修复）
```

---

### 9. `report.py` - 报告生成

**作用**：生成分析报告（JSON + HTML + 终端）

**输出格式**：

#### 9.1 JSON报告
```json
{
  "contract_path": "...",
  "summary": {
    "total_variables": 5,
    "vulnerable_count": 2,
    "dangerous_paths_total": 3,
    "suspicious_paths_total": 2
  },
  "results": [...]
}
```

#### 9.2 HTML报告
- 可视化展示
- 代码高亮
- 风险位置标注

#### 9.3 终端报告
- 彩色输出
- 分级显示
- 实时反馈

---

## 🔄 数据流转

```
┌─────────────────┐
│ Solidity源码    │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 编译器 (solc)   │  → bytecode, runtime-bytecode, asm
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 字节码分析      │  → 指令序列
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ CFG构建         │  → 基本块、跳转关系
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 存储分析        │  → 变量→槽位映射
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 数据流分析      │  → 变量依赖关系
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 污点分析        │  → 污点传播路径
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ 源码映射 ⭐      │  → 风险位置定位
└────────┬────────┘  （核心检测逻辑）
         │
         ↓
┌─────────────────┐
│ 报告生成        │  → JSON + HTML + 终端
└─────────────────┘
```

---

## 🎯 核心检测流程

### 污点分析路径

```
1. 识别污点源
   └─> CALLDATALOAD, CALLVALUE 等

2. 追踪污点传播
   └─> 通过 CFG 追踪数据流

3. 检测到达汇点
   └─> SSTORE 写入关键变量

4. 分析路径条件
   └─> 是否有 JUMPI（条件跳转）

5. 映射到源码
   └─> 定位具体代码行
```

### 补充检测路径

```
1. 识别public函数
   └─> 无 modifier 保护

2. 检查写入操作
   └─> 跳过 declaration 和 constructor

3. 检查条件判断
   └─> require/assert/if 语句

4. 风险分级
   ├─> 有条件 → 可疑
   └─> 无条件 → 危险
```

---

## 🛠️ 关键算法

### 1. 存储槽位计算

```python
def calculate_slot(var_index: int, var_type: str) -> int:
    """计算变量的存储槽位"""
    if var_type in ['uint256', 'address', 'bool']:
        return var_index
    elif var_type == 'mapping':
        # mapping 使用哈希计算
        return keccak256(key + slot)
    elif var_type == 'array':
        # 动态数组
        return keccak256(slot) + index
```

### 2. 污点传播规则

```python
def propagate_taint(instruction, taint_set):
    """污点传播"""
    if instruction.opcode in ['ADD', 'SUB', 'MUL', 'DIV']:
        # 算术运算：任一操作数有污点，结果就有污点
        if instruction.operand1 in taint_set or instruction.operand2 in taint_set:
            taint_set.add(instruction.result)
    
    elif instruction.opcode == 'SLOAD':
        # 从存储读取：结果可能有污点
        taint_set.add(instruction.result)
    
    elif instruction.opcode == 'SSTORE':
        # 写入存储：如果值有污点，记录为污点汇点
        if instruction.value in taint_set:
            record_taint_sink(instruction)
```

### 3. 路径条件检测

```python
def has_path_condition(path: List[Block]) -> bool:
    """检查路径是否有条件判断"""
    for block in path:
        # 检查是否有条件跳转（JUMPI）
        if any(instr.opcode == 'JUMPI' for instr in block.instructions):
            return True
    return False
```

---

## 📊 输出文件结构

```
output/
├── intermediate/                   # 中间结果
│   ├── bytecode_analysis.json     # 字节码分析结果
│   ├── cfg.json                   # 控制流图
│   ├── storage_mapping.json       # 存储映射
│   ├── dataflow.json              # 数据流分析
│   ├── taint_analysis.jsonl       # 污点分析结果
│   └── source_mapping.json        # 源码映射结果
│
├── ContractName.bin               # 字节码
├── ContractName.bin-runtime       # 运行时字节码
├── ContractName.evm               # 汇编代码
├── final_report.json              # 最终JSON报告
└── final_report.html              # 最终HTML报告
```

---

## 🧪 测试文件说明

- `test_miboodle.py` - 测试require识别修复
- `test_declaration_fix.py` - 测试变量声明过滤
- `test_ethflip.py` - 测试多合约构造函数
- `test_comprehensive_fixes.py` - 综合测试
- `test_uec_token.py` - 测试条件判断改进

---

## 🔧 配置和扩展

### 添加新的污点源

编辑 `taint_analyzer.py`:
```python
TAINT_SOURCES = [
    'CALLDATALOAD',   # 函数参数
    'CALLVALUE',      # msg.value
    'CALLER',         # msg.sender
    'ORIGIN',         # tx.origin
    # 添加新的污点源
    'GASPRICE',       # tx.gasprice
]
```

### 添加新的敏感操作

编辑 `source_mapper.py`:
```python
sensitive_keywords = {
    'selfdestruct': '合约自毁',
    'delegatecall': '委托调用',
    'suicide': '合约自毁（已弃用）',
    'callcode': '代码调用（已弃用）',
    # 添加新的敏感操作
    'transfer': '转账操作',
    'send': '发送以太币',
}
```

---

## 📚 依赖关系

```
analyzer.py
├── compiler.py
├── bytecode_analyzer.py
│   └── opcode.py
├── cfg_builder.py
│   └── bytecode_analyzer.py
├── storage_analyzer.py
├── dataflow_analyzer.py
│   └── cfg_builder.py
├── taint_analyzer.py
│   ├── cfg_builder.py
│   └── dataflow_analyzer.py
├── variable_finder.py
├── source_mapper.py ⭐
│   ├── variable_finder.py
│   └── taint_analyzer.py
└── report.py
    └── colors.py
```

---

## 🎓 核心设计原则

1. **模块化**：每个模块职责单一，便于维护
2. **可扩展**：易于添加新的检测规则
3. **可测试**：每个模块都有对应的测试
4. **高效率**：优化算法，支持大型合约
5. **准确性**：多重检测，减少误报和漏报

---

**版本**: v2.8  
**更新日期**: 2025年10月7日

📖 **相关文档**：
- 使用指南：`README_使用指南.md`
- 处理逻辑：`README_处理逻辑.md`

