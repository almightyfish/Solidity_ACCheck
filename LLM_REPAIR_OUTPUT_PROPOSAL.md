# 面向大模型修复的输出格式优化方案

## 一、新增输出文件：`llm_repair_input.json`

### 1.1 整体结构

```json
{
  "metadata": {
    "contract_file": "path/to/contract.sol",
    "analysis_time": "2025-10-19T12:00:00",
    "solc_version": "0.8.0",
    "total_vulnerabilities": 3,
    "critical_count": 2,
    "suspicious_count": 1
  },
  
  "source_code": {
    "full_content": "完整的合约源代码...",
    "line_count": 150,
    "functions": [
      {
        "name": "transferOwnership",
        "start_line": 45,
        "end_line": 52,
        "visibility": "public",
        "has_modifiers": false,
        "full_code": "完整函数代码..."
      }
    ]
  },
  
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "severity": "critical",
      "type": "dangerous_path",
      "variable": "owner",
      
      "location": {
        "line": 48,
        "column": 8,
        "function": "transferOwnership",
        "code_snippet": "owner = newOwner;"
      },
      
      "context": {
        "function_full_code": "完整函数代码（含签名）",
        "surrounding_lines": {
          "before": ["function transferOwnership(address newOwner) public {", "  // no check"],
          "current": "  owner = newOwner;",
          "after": ["  emit OwnershipTransferred(owner, newOwner);", "}"]
        }
      },
      
      "vulnerability_details": {
        "description": "关键变量'owner'被写入，但函数无访问控制",
        "attack_vector": "任何人都可以调用此函数夺取合约所有权",
        "detection_method": "taint_analysis + public_function_check",
        "has_bytecode_condition": false,
        "has_source_condition": false,
        "taint_path_summary": "CALLER → CALLDATALOAD → SSTORE(slot_0)"
      },
      
      "suggested_fixes": [
        {
          "strategy": "add_onlyOwner_modifier",
          "description": "添加onlyOwner修饰符限制调用者",
          "example": "function transferOwnership(address newOwner) public onlyOwner { ... }",
          "priority": 1
        },
        {
          "strategy": "add_require_check",
          "description": "在函数开头添加require检查",
          "example": "require(msg.sender == owner, \"Only owner\");",
          "priority": 2
        }
      ],
      
      "related_code": {
        "modifier_onlyOwner_exists": false,
        "owner_declaration": "address public owner;",
        "constructor_code": "constructor() { owner = msg.sender; }"
      }
    }
  ],
  
  "repair_guidelines": {
    "general_advice": [
      "对于所有危险路径，必须添加访问控制",
      "对于可疑路径，需验证现有条件是否充分",
      "优先使用modifier而非内联require",
      "确保使用msg.sender而非tx.origin"
    ],
    "contract_specific": {
      "missing_modifiers": ["onlyOwner", "onlyAdmin"],
      "suggested_patterns": [
        "modifier onlyOwner() { require(msg.sender == owner, \"Only owner\"); _; }"
      ]
    }
  }
}
```

### 1.2 关键改进点

#### ✅ 改进1：完整的函数上下文
```json
"context": {
  "function_full_code": "包含完整函数体（从签名到结束大括号）",
  "surrounding_lines": "危险语句前后3-5行代码"
}
```
**原因**：LLM需要看到完整函数才能理解逻辑并生成正确的修复

#### ✅ 改进2：明确的修复建议
```json
"suggested_fixes": [
  {
    "strategy": "add_onlyOwner_modifier",
    "description": "具体的修复描述",
    "example": "可直接使用的代码示例",
    "priority": 1
  }
]
```
**原因**：指导LLM修复方向，减少生成错误修复的概率

#### ✅ 改进3：相关代码片段
```json
"related_code": {
  "modifier_onlyOwner_exists": false,
  "owner_declaration": "address public owner;",
  "constructor_code": "..."
}
```
**原因**：LLM需要知道是否已有可用的modifier，owner变量如何声明等

#### ✅ 改进4：简化的路径表示
```json
"taint_path_summary": "CALLER → CALLDATALOAD → SSTORE(slot_0)"
```
**原因**：用高层次的数据流描述代替基本块序列，LLM更容易理解

#### ✅ 改进5：漏洞分类优先级
```json
"severity": "critical",  // critical / suspicious / info
"type": "dangerous_path",  // dangerous_path / suspicious_path / sensitive_function
```
**原因**：让LLM知道哪些需要立即修复，哪些需要人工审查

---

## 二、实现方案

### 2.1 在 `report.py` 中新增 `LLMRepairGenerator` 类

```python
class LLMRepairGenerator:
    """生成面向LLM修复的输出"""
    
    def __init__(self, report_data: Dict, source_file: str):
        self.report_data = report_data
        self.source_file = source_file
        self.source_lines = []
        with open(source_file, 'r') as f:
            self.source_lines = f.readlines()
    
    def generate(self, output_path: str):
        """生成 llm_repair_input.json"""
        llm_input = {
            'metadata': self._build_metadata(),
            'source_code': self._build_source_code_section(),
            'vulnerabilities': self._build_vulnerabilities(),
            'repair_guidelines': self._build_repair_guidelines()
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(llm_input, f, indent=2, ensure_ascii=False)
    
    def _build_vulnerabilities(self) -> List[Dict]:
        """构建漏洞列表（核心方法）"""
        vulnerabilities = []
        
        for result in self.report_data['results']:
            # 处理危险路径
            for dangerous_loc in result.get('dangerous_locations', []):
                vuln = self._create_vulnerability_entry(
                    result['variable'],
                    dangerous_loc,
                    severity='critical',
                    type='dangerous_path'
                )
                vulnerabilities.append(vuln)
            
            # 处理可疑路径
            for suspicious_loc in result.get('suspicious_locations', []):
                vuln = self._create_vulnerability_entry(
                    result['variable'],
                    suspicious_loc,
                    severity='suspicious',
                    type='suspicious_path'
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability_entry(self, variable: str, 
                                   location: Dict, 
                                   severity: str,
                                   type: str) -> Dict:
        """创建单个漏洞条目（关键方法）"""
        line = location['line']
        func_name = location.get('function', 'unknown')
        
        return {
            'id': f"vuln_{line}_{variable}",
            'severity': severity,
            'type': type,
            'variable': variable,
            
            'location': {
                'line': line,
                'function': func_name,
                'code_snippet': location['code']
            },
            
            'context': {
                'function_full_code': self._get_function_code(func_name),
                'surrounding_lines': self._get_surrounding_lines(line)
            },
            
            'vulnerability_details': {
                'description': self._generate_description(variable, location, severity),
                'attack_vector': self._generate_attack_vector(variable, func_name),
                'detection_method': location.get('detection_method', 'taint_analysis'),
                'has_bytecode_condition': location.get('has_bytecode_condition', False),
                'has_source_condition': location.get('has_source_condition', False),
                'bytecode_condition_types': location.get('bytecode_condition_types', []),
                'taint_path_summary': self._simplify_taint_path(location)
            },
            
            'suggested_fixes': self._generate_fix_suggestions(variable, func_name, location),
            'related_code': self._extract_related_code(variable, func_name)
        }
    
    def _get_function_code(self, func_name: str) -> str:
        """提取完整函数代码"""
        # 从 function_map 中获取函数行范围
        # 返回完整函数代码
        pass
    
    def _generate_fix_suggestions(self, variable: str, 
                                  func_name: str, 
                                  location: Dict) -> List[Dict]:
        """生成修复建议（核心逻辑）"""
        suggestions = []
        
        # 策略1: 添加访问控制modifier
        if 'owner' in variable.lower() or 'admin' in variable.lower():
            suggestions.append({
                'strategy': 'add_access_control_modifier',
                'description': f'为函数{func_name}添加onlyOwner修饰符',
                'example': f'function {func_name}(...) public onlyOwner {{ ... }}',
                'priority': 1
            })
        
        # 策略2: 添加require检查
        suggestions.append({
            'strategy': 'add_require_check',
            'description': '在函数开头添加msg.sender检查',
            'example': 'require(msg.sender == owner, "Unauthorized");',
            'priority': 2
        })
        
        # 策略3: 限制函数可见性
        suggestions.append({
            'strategy': 'reduce_visibility',
            'description': '如果函数只需内部调用，改为internal',
            'example': f'function {func_name}(...) internal {{ ... }}',
            'priority': 3
        })
        
        return suggestions
```

### 2.2 修改 `ReportGenerator.generate()` 方法

在现有的报告生成后，添加LLM输出生成：

```python
def generate(self, mapped_results: List[Dict]) -> Dict:
    # ... 现有代码 ...
    
    # 🔧 新增：生成LLM修复输入
    llm_generator = LLMRepairGenerator(report, self.source_file)
    llm_output_path = os.path.join(self.output_dir, "llm_repair_input.json")
    llm_generator.generate(llm_output_path)
    
    print(f"   {llm_output_path} (LLM修复输入)")
    
    return report
```

---

## 三、大模型提示词模板建议

配合新的输出格式，建议使用以下提示词结构：

```markdown
# 智能合约漏洞修复任务

## 输入
{llm_repair_input.json的内容}

## 任务要求
1. 分析每个漏洞，理解其根本原因
2. 根据suggested_fixes选择最合适的修复策略
3. 生成完整的修复后代码（不是patch，是完整文件）
4. 确保修复不破坏现有功能
5. 为每个修复添加注释说明

## 输出格式
```json
{
  "fixed_contract": "完整的修复后源代码",
  "changes": [
    {
      "vulnerability_id": "vuln_001",
      "fix_applied": "add_onlyOwner_modifier",
      "description": "为transferOwnership函数添加onlyOwner修饰符",
      "changed_lines": [45]
    }
  ],
  "verification_notes": "人工审查要点：..."
}
```

## 修复原则
- 优先使用modifier而非重复的require
- 确保使用msg.sender而非tx.origin
- 为关键操作添加事件日志
- 保持代码风格一致
```

---

## 四、优化效果对比

### 🔴 当前输出（不适合LLM）
```json
{
  "variable": "owner",
  "dangerous_locations": [
    {
      "line": 48,
      "code": "owner = newOwner;",
      "function": "transferOwnership",
      "has_bytecode_condition": false
    }
  ],
  "taint_cfg": [[0, 145, 289, 334, ...]]  // 基本块序列
}
```
**问题**：
- ❌ 缺少完整函数代码
- ❌ 基本块序列难以理解
- ❌ 没有修复建议
- ❌ 缺少相关上下文

### 🟢 优化后输出（LLM友好）
```json
{
  "id": "vuln_001",
  "severity": "critical",
  "variable": "owner",
  
  "context": {
    "function_full_code": "function transferOwnership(address newOwner) public {\n  owner = newOwner;\n  emit OwnershipTransferred(owner, newOwner);\n}",
    "surrounding_lines": {...}
  },
  
  "vulnerability_details": {
    "description": "关键变量'owner'被写入，但函数无访问控制",
    "attack_vector": "任何人都可以调用此函数夺取合约所有权",
    "taint_path_summary": "CALLER → CALLDATALOAD → SSTORE(slot_0)"
  },
  
  "suggested_fixes": [
    {
      "strategy": "add_onlyOwner_modifier",
      "example": "function transferOwnership(address newOwner) public onlyOwner { ... }",
      "priority": 1
    }
  ],
  
  "related_code": {
    "modifier_onlyOwner_exists": false,
    "owner_declaration": "address public owner;"
  }
}
```
**优势**：
- ✅ 完整的函数代码
- ✅ 高层次的数据流描述
- ✅ 明确的修复建议和示例
- ✅ 相关代码上下文

---

## 五、实施步骤

### Phase 1: 基础实现（1-2天）
1. 在 `report.py` 中创建 `LLMRepairGenerator` 类
2. 实现 `_create_vulnerability_entry()` 核心方法
3. 实现完整函数代码提取
4. 生成基础版 `llm_repair_input.json`

### Phase 2: 增强功能（2-3天）
1. 实现智能修复建议生成
2. 添加相关代码片段提取
3. 优化路径表示（简化为高层次描述）
4. 添加合约全局上下文

### Phase 3: 集成测试（1-2天）
1. 在批量分析中测试
2. 与LLM对接测试
3. 根据LLM反馈调整输出格式
4. 优化提示词模板

---

## 六、额外建议

### 6.1 输出分级
建议生成三个级别的输出：

1. **llm_repair_input_minimal.json** (轻量级)
   - 只包含关键信息
   - 适合token限制严格的场景

2. **llm_repair_input.json** (标准)
   - 包含完整上下文和建议
   - 适合大多数场景

3. **llm_repair_input_full.json** (完整)
   - 包含所有中间分析数据
   - 适合需要深度理解的场景

### 6.2 批量修复支持
```json
{
  "batch_mode": true,
  "contracts": [
    {
      "file": "Contract1.sol",
      "vulnerabilities": [...]
    },
    {
      "file": "Contract2.sol",
      "vulnerabilities": [...]
    }
  ]
}
```

### 6.3 增量修复
如果一个合约有多个漏洞，支持增量修复：
```json
{
  "repair_strategy": "incremental",
  "priority_order": ["vuln_001", "vuln_003", "vuln_002"]
}
```

---

## 七、预期收益

### 提高修复成功率
- **当前**：LLM可能生成错误的修复（30-50%失败率）
- **优化后**：明确的上下文+建议（预计10-20%失败率）

### 减少迭代次数
- **当前**：平均需要2-3轮对话才能正确修复
- **优化后**：一次生成正确修复的概率显著提高

### 支持自动化流程
```
分析 → 生成LLM输入 → LLM修复 → 验证 → 部署
```
整个流程可以实现半自动化

---

## 八、参考实现

完整的实现代码请参考：
- `core/report.py` - 添加 `LLMRepairGenerator` 类
- `examples/llm_repair_input_example.json` - 输出样例
- `prompts/repair_prompt.template` - LLM提示词模板

## 总结

通过以上优化，可以：
1. 🎯 **提供完整上下文**：LLM能看到完整函数，而非孤立的一行代码
2. 🎯 **明确修复方向**：通过suggested_fixes指导LLM
3. 🎯 **简化技术细节**：用高层次描述代替基本块序列
4. 🎯 **增加相关信息**：提供modifier是否存在、变量声明等关键信息
5. 🎯 **支持批量处理**：一次处理多个漏洞

