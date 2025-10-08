#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量分析启动器 - 自动读取 JSONL 配置并对每个合约运行分析
支持从 llm_response_raw 中提取关键变量
"""

import json
import os
import re
from core.analyzer import AllInOneAnalyzer

# JSONL 文件路径
JSONL_PATH = "/Users/almightyfish/Desktop/AChecker/AC/solidity_analysis_deepseek_with_llm_longtail.jsonl"

# 输出目录根路径
OUTPUT_ROOT = "analysis_output"

# Solidity 版本匹配正则
PRAGMA_PATTERN = re.compile(r"pragma\s+solidity\s+(\^?\d+\.\d+\.\d+)", re.IGNORECASE)

# JSON 匹配正则：提取 llm_response_raw 中的结构体
JSON_EXTRACT_PATTERN = re.compile(r"\{.*?\}", re.DOTALL)


def extract_solc_version(sol_file: str):
    """从源码文件中提取 Solidity 版本"""
    try:
        with open(sol_file, "r", encoding="utf-8") as f:
            for line in f:
                match = PRAGMA_PATTERN.search(line)
                if match:
                    version = match.group(1)
                    # ✅ 去掉开头的 "^" 或 ">=" 等
                    version = version.lstrip("^>=")
                    return version
    except Exception as e:
        print(f"⚠️ 无法读取 {sol_file}: {e}")
    return None


def extract_critical_vars_from_llm(raw_text: str):
    """
    从 llm_response_raw 中提取关键变量
    raw_text 是字符串，可能包含多个 JSONL 段
    """
    if not raw_text:
        return []

    critical_vars = []
    matches = JSON_EXTRACT_PATTERN.findall(raw_text)
    for m in matches:
        try:
            obj = json.loads(m)
            if obj.get("is_critical") is True and obj.get("variable_name"):
                critical_vars.append(obj["variable_name"].strip())
        except json.JSONDecodeError:
            continue

    # 去重保持顺序
    seen = set()
    result = []
    for name in critical_vars:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def main():
    skipped_files = []

    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"❌ JSON解析失败（第{line_num}行）: {e}")
                continue

            filename = item.get("filename")
            solidity_path = item.get("filepath")
            llm_raw = item.get("llm_response_raw")

            if not solidity_path or not os.path.isfile(solidity_path):
                print(f"❌ 文件不存在: {solidity_path}")
                continue

            solc_version = extract_solc_version(solidity_path)
            if not solc_version:
                print(f"⏭️ 跳过 {filename}（未声明 Solidity 版本）")
                skipped_files.append(filename)
                continue

            key_vars = extract_critical_vars_from_llm(llm_raw)
            if not key_vars:
                print(f"⚠️ {filename} 未发现关键变量")
                continue

            # 创建单独输出目录
            output_dir = os.path.join(OUTPUT_ROOT, os.path.splitext(filename)[0])
            os.makedirs(output_dir, exist_ok=True)

            print("\n" + "=" * 80)
            print(f"▶️  开始分析: {filename}")
            print(f"🧩 Solidity 版本: {solc_version}")
            print(f"🔑 关键变量: {key_vars}")
            print("=" * 80)

            analyzer = AllInOneAnalyzer(
                solc_version=solc_version,
                key_variables=key_vars,
                contract_path=solidity_path,
                output_dir=output_dir,
            )

            try:
                result = analyzer.run()
                if result:
                    print(f"✅ {filename} 分析成功！")
                else:
                    print(f"❌ {filename} 分析失败！")
            except Exception as e:
                print(f"💥 分析 {filename} 时出错: {e}")

    if skipped_files:
        print("\n⏭️ 以下文件被跳过（无 Solidity 版本声明）：")
        for name in skipped_files:
            print(f" - {name}")

    print("\n🎯 所有任务完成！")


if __name__ == "__main__":
    main()