import json
from typing import List, Dict, Any
try:
    from bytecode_analysis.BytecodeAnalyzer import BytecodeAnalyzer
except ImportError:
    from BytecodeAnalyzer import BytecodeAnalyzer

class TaintAnalyzer:
    def __init__(self, bytecode_path: str, key_variables: List[str]):
        self.bytecode_path = bytecode_path
        self.key_variables = key_variables
        self.bytecode_analyzer = BytecodeAnalyzer(bytecode_path, key_variables)
        self.bb = None
        self.cfg = None
        self.var_storage_map = None

    def find_slot_in_stack(self, instructions, idx, target_slot):
        # 向前查找最近的PUSH，允许中间有DUP/SWAP等简单栈操作
        for back in range(1, 6):  # 最多回溯5步
            i = idx - back
            if i < 0:
                break
            instr = instructions[i]
            if instr['op'].startswith('PUSH'):
                try:
                    pushed = int(instr.get('push_data', '0'), 16)
                    if pushed == target_slot:
                        return True
                except Exception:
                    continue
            elif instr['op'].startswith('DUP') or instr['op'].startswith('SWAP'):
                continue  # 允许简单栈操作
            else:
                break  # 遇到其它操作中断
        return False

    def analyze(self) -> List[Dict[str, Any]]:
        self.bytecode_analyzer.analyze_cfg()
        self.bb = self.bytecode_analyzer.basic_blocks
        self.cfg = self.bytecode_analyzer.cfg
        self.bytecode_analyzer.match_key_vars_to_storage()
        self.var_storage_map = self.bytecode_analyzer.var_storage_map

        # 1. 找到所有污点源指令所在的BB
        taint_sources = set()
        for b in self.bb:
            for instr in b['instructions']:
                if instr['op'] in ('CALLDATALOAD', 'CALLDATACOPY', 'CALLER', 'ORIGIN'):
                    taint_sources.add(b['start'])

        results = []
        for var, info in self.var_storage_map.items():
            slot = info.get('slot')
            # 2. 精确识别操作该slot的SSTORE/SLOAD作为sink
            sink_bbs = set()
            for b in self.bb:
                for idx, instr in enumerate(b['instructions']):
                    if instr['op'] in ('SSTORE', 'SLOAD'):
                        if self.find_slot_in_stack(b['instructions'], idx, slot):
                            sink_bbs.add(b['start'])
            # 3. 污点传播（BFS，收集所有source到sink的路径）
            all_paths = []
            queue = [(src, [src]) for src in taint_sources]
            visited = set()
            while queue:
                curr, path = queue.pop(0)
                if curr in sink_bbs:
                    all_paths.append(path)
                    continue  # 继续收集其他路径
                for succ in self.cfg.get(curr, []):
                    if (curr, succ) not in visited:
                        queue.append((succ, path + [succ]))
                        visited.add((curr, succ))
            # 4. 汇总所有路径涉及的BB
            taint_bb_set = set()
            for p in all_paths:
                taint_bb_set.update(p)
            results.append({
                "name": var,
                "offset": slot,
                "taint_bb": sorted(list(taint_bb_set)),
                "taint_cfg": all_paths
            })
        return results

if __name__ == "__main__":
    key_vars = ["owner", "balance", "withdrawLimit"]
    analyzer = TaintAnalyzer("bytecode_analysis/bytecode/contract.code", key_vars)
    taint_results = analyzer.analyze()
    with open("taint_results.jsonl", "w") as f:
        for item in taint_results:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print("Taint analysis results written to taint_results.jsonl") 