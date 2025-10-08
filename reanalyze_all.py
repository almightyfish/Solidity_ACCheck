#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新分析所有合约 - 使用修复后的代码更新统计数据
"""

import json
import os
from core.analyzer import AllInOneAnalyzer

# JSONL 文件路径
JSONL_PATH = "/Users/almightyfish/Desktop/AChecker/AC/solidity_analysis_deepseek_with_llm_longtail.jsonl"
OUTPUT_ROOT = "/Users/almightyfish/Desktop/AChecker/analysis_output"


def extract_critical_vars_from_llm(raw_text: str):
    """从 llm_response_raw 中提取关键变量"""
    import re
    if not raw_text:
        return []
    
    critical_vars = []
    json_pattern = re.compile(r"\{.*?\}", re.DOTALL)
    matches = json_pattern.findall(raw_text)
    
    for m in matches:
        try:
            obj = json.loads(m)
            if obj.get("is_critical") is True and obj.get("variable_name"):
                critical_vars.append(obj["variable_name"].strip())
        except json.JSONDecodeError:
            continue
    
    # 去重
    seen = set()
    result = []
    for name in critical_vars:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def extract_solc_version(sol_file: str):
    """从源码文件中提取 Solidity 版本"""
    import re
    pragma_pattern = re.compile(r"pragma\s+solidity\s+(\^?\d+\.\d+\.\d+)", re.IGNORECASE)
    
    try:
        with open(sol_file, "r", encoding="utf-8") as f:
            for line in f:
                match = pragma_pattern.search(line)
                if match:
                    version = match.group(1).lstrip("^>=")
                    return version
    except Exception as e:
        print(f"⚠️ 无法读取 {sol_file}: {e}")
    return None


def main():
    print("🔄 开始批量重新分析所有合约...")
    print(f"📁 输出目录: {OUTPUT_ROOT}\n")
    
    total = 0
    success = 0
    failed = 0
    skipped = 0
    
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
        total = len([l for l in lines if l.strip()])
    
    print(f"📊 共 {total} 个合约待处理\n")
    print("="*80)
    
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"❌ [{idx}/{total}] JSON解析失败: {e}")
                failed += 1
                continue
            
            filename = item.get("filename")
            solidity_path = item.get("filepath")
            llm_raw = item.get("llm_response_raw")
            
            if not solidity_path or not os.path.isfile(solidity_path):
                print(f"⏭️  [{idx}/{total}] 跳过 {filename} (文件不存在)")
                skipped += 1
                continue
            
            solc_version = extract_solc_version(solidity_path)
            if not solc_version:
                print(f"⏭️  [{idx}/{total}] 跳过 {filename} (无Solidity版本)")
                skipped += 1
                continue
            
            key_vars = extract_critical_vars_from_llm(llm_raw)
            if not key_vars:
                print(f"⏭️  [{idx}/{total}] 跳过 {filename} (无关键变量)")
                skipped += 1
                continue
            
            # 输出目录
            output_dir = os.path.join(OUTPUT_ROOT, os.path.splitext(filename)[0])
            os.makedirs(output_dir, exist_ok=True)
            
            print(f"\n▶️  [{idx}/{total}] 分析: {filename}")
            print(f"    版本: {solc_version} | 变量: {', '.join(key_vars)}")
            
            analyzer = AllInOneAnalyzer(
                solc_version=solc_version,
                key_variables=key_vars,
                contract_path=solidity_path,
                output_dir=output_dir,
            )
            
            try:
                result = analyzer.run()
                if result:
                    print(f"    ✅ 成功")
                    success += 1
                else:
                    print(f"    ❌ 失败")
                    failed += 1
            except Exception as e:
                print(f"    💥 错误: {e}")
                failed += 1
    
    print("\n" + "="*80)
    print("📊 重新分析完成!")
    print(f"   总计: {total} 个")
    print(f"   成功: {success} 个 ✅")
    print(f"   失败: {failed} 个 ❌")
    print(f"   跳过: {skipped} 个 ⏭️")
    print("="*80)
    print("\n💡 现在可以运行 generate_summary.py 查看正确的汇总数据")


if __name__ == "__main__":
    main()

