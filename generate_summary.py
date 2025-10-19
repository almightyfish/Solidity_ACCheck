#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
汇总所有合约分析结果，重点突出危险路径与可疑路径
"""

import os
import json
import csv
from datetime import datetime

ROOT_DIR = "analysis_output_pretty_smart"
SUMMARY_JSON = "analysis_summary_pretty_smart.json"
SUMMARY_CSV = "analysis_summary_pretty_smart.csv"


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ 无法读取 {path}: {e}")
        return None


def collect_results(root_dir=ROOT_DIR):
    results = []
    failed_contracts = []  # 🔧 新增：记录失败的合约

    for folder in os.listdir(root_dir):
        # 跳过隐藏文件和非目录
        if folder.startswith('.') or not os.path.isdir(os.path.join(root_dir, folder)):
            continue
        
        report_path = os.path.join(root_dir, folder, "final_report.json")
        if not os.path.isfile(report_path):
            # 🔧 新增：记录失败的合约
            failed_contracts.append({
                'filename': folder,
                'reason': '缺少final_report.json（分析失败或编译失败）'
            })
            continue

        data = read_json(report_path)
        if not data:
            failed_contracts.append({
                'filename': folder,
                'reason': 'final_report.json无法解析'
            })
            continue

        summary = data.get("summary", {})
        result_items = data.get("results", [])
        filename = os.path.basename(folder)
        source_file = data.get("source_file", "")
        analysis_time = data.get("analysis_time")

        total_dangerous_paths = 0
        total_suspicious_paths = 0
        vulnerable_vars = []

        # 遍历每个变量的结果
        for var in result_items:
            total_dangerous_paths += var.get("dangerous_paths_count", 0)
            total_suspicious_paths += var.get("suspicious_paths_count", 0)

            if var.get("has_vulnerability"):
                vulnerable_vars.append(var.get("variable"))

        results.append({
            "filename": filename,
            "source_file": source_file,
            "analysis_time": analysis_time,
            "total_variables": summary.get("total_variables", 0),
            "vulnerable_variables": summary.get("vulnerable_variables", 0),
            "safe_variables": summary.get("safe_variables", 0),
            "dangerous_paths_total": total_dangerous_paths,
            "suspicious_paths_total": total_suspicious_paths,
            "vuln_variable_names": vulnerable_vars,
        })

    return results, failed_contracts  # 🔧 新增：返回失败列表


def save_json(results):
    data = {
        "generated_at": datetime.now().isoformat(),
        "total_contracts": len(results),
        "contracts": results,
    }
    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ JSON 汇总报告已生成：{SUMMARY_JSON}")


def save_csv(results):
    headers = [
        "文件名",
        "总变量数",
        "存在漏洞变量数",
        "危险路径总数",
        "可疑路径总数",
        "存在漏洞的变量名",
        "分析时间",
        "源码文件路径",
    ]
    with open(SUMMARY_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for r in results:
            vuln_names = ", ".join(r["vuln_variable_names"])
            writer.writerow([
                r["filename"],
                r["total_variables"],
                r["vulnerable_variables"],
                r["dangerous_paths_total"],
                r["suspicious_paths_total"],
                vuln_names,
                r["analysis_time"],
                r["source_file"],
            ])
    print(f"✅ CSV 汇总报告已生成：{SUMMARY_CSV}")


def print_top_risks(results, top_n=5):
    """控制台输出前几个最危险的合约"""
    sorted_items = sorted(
        results,
        key=lambda x: (x["dangerous_paths_total"], x["suspicious_paths_total"]),
        reverse=True,
    )
    print("\n⚠️  最危险的前 %d 个合约：" % top_n)
    for i, item in enumerate(sorted_items[:top_n], 1):
        print(f"{i}. {item['filename']}")
        print(f"   危险路径: {item['dangerous_paths_total']}, 可疑路径: {item['suspicious_paths_total']}, 漏洞变量: {', '.join(item['vuln_variable_names']) or '无'}")


def print_failed_contracts(failed_contracts):
    """🔧 新增：打印编译/分析失败的合约"""
    if not failed_contracts:
        print("\n✅ 所有合约均成功分析！")
        return
    
    print(f"\n{'='*80}")
    print(f"❌ 编译/分析失败的合约（共 {len(failed_contracts)} 个）")
    print(f"{'='*80}")
    
    for i, item in enumerate(failed_contracts, 1):
        print(f"{i}. {item['filename']}")
        print(f"   原因: {item['reason']}")
        
        # 尝试提供更多信息
        folder_path = os.path.join(ROOT_DIR, item['filename'])
        intermediate_path = os.path.join(folder_path, 'intermediate')
        
        if os.path.exists(intermediate_path):
            files = os.listdir(intermediate_path) if os.path.isdir(intermediate_path) else []
            if files:
                print(f"   中间文件: {', '.join(files)}")
            else:
                print(f"   中间文件: 无（编译失败）")
        
        # 检查是否有编译产物
        has_bin = any(f.endswith('.bin') for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f)))
        if has_bin:
            print(f"   状态: 编译成功，但后续分析失败")
        else:
            print(f"   状态: 编译失败")
    
    print(f"{'='*80}")
    print(f"\n💡 建议：")
    print(f"  1. 检查源码语法是否正确")
    print(f"  2. 确认Solidity版本是否匹配")
    print(f"  3. 查看具体错误日志")
    print(f"  4. 尝试使用不同的solc版本（如0.4.18, 0.5.16等）")

def main():
    print("📊 开始汇总分析结果...\n")
    results, failed_contracts = collect_results()  # 🔧 新增：接收失败列表
    
    if not results and not failed_contracts:
        print("❌ 未找到任何合约分析目录。")
        return
    
    if results:
        save_json(results)
        save_csv(results)
        print_top_risks(results)
        print(f"\n🎯 汇总完成，成功分析 {len(results)} 个合约。")
    
    # 🔧 新增：打印失败的合约
    print_failed_contracts(failed_contracts)


if __name__ == "__main__":
    main()