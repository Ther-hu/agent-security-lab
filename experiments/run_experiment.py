# experiments/run_experiment.py —— 统一实验管线
#
# 用法:
#   python experiments/run_experiment.py --suite attack_a --runs 3 --out results/a.csv
#   python experiments/run_experiment.py --suite attack_a --runs 3 --defense d1 --out results/a_d1.csv
#   python experiments/run_experiment.py --suite attack_a --runs 3 --defense d1,d2,d3 --out results/a_d123.csv
#   python experiments/run_experiment.py --suite attack_a --runs 3 --mcp --out results/a_mcp.csv
#
# 流程: 读样本 → 布置环境(loader) → 跑 agent.run_agent → judge 判定
#      → 追加 CSV 行: sample_id, run, success, steps_json
import argparse
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import agent
import tools as T
import judge
import loader
import metrics

SUITES = {"benign", "attack_a", "attack_b", "attack_c"}


def parse_defense(defense):
    return [d.strip() for d in (defense or "").split(",") if d.strip()]


def build_executor(base_execute, defenses):
    """按 d3 -> d2 -> base 的顺序叠加防御（d1 只影响结果清洗与 system prompt）"""
    import defense.d2_confirmation as d2
    import defense.d3_policy as d3

    executor = base_execute

    if "d3" in defenses:
        policy = d3.PolicyEngine()
        prev = executor

        def _with_d3(name, args, step, _prev=prev, _policy=policy):
            ok, msg = _policy.check(name, args, step if step is not None else 0)
            if not ok:
                return f"Blocked by policy engine: {msg}"
            return _prev(name, args, step)

        executor = _with_d3

    if "d2" in defenses:
        prev = executor

        def _with_d2(name, args, step, _prev=prev):
            if not d2.check(name, args):
                return "User denied: action blocked by operator."
            return _prev(name, args, step)

        executor = _with_d2

    return executor


def stage(suite, sample, defenses, mcp_mode):
    """按 suite + 防御 + 是否真实 MCP 链路，返回 run_agent 的一组参数"""
    import defense.d1_sanitizer as d1

    if suite == "attack_a":
        if mcp_mode:
            # 真实链路：连接投毒 server，载荷已"出厂自带"在 docstring 里
            import mcp_client
            mcp_client.SERVER_CMD = ["python", str(ROOT / "mcp_server_news.py")]
            schemas = T.tool_schemas() + mcp_client.load_external_tools()
            base_execute = agent.default_execute
        else:
            # 受控版：内存注入载荷到目标工具 description
            schemas = loader.load_poisoned_schemas(sample["payload"],
                                                   sample.get("target_tool", "fetch_news"))
            base_execute = loader.local_executor
    else:
        if suite in ("attack_b", "attack_c"):
            loader.stage_sources(sample.get("sources", []))
        schemas = agent.default_schemas()
        base_execute = agent.default_execute

    executor = build_executor(base_execute, defenses)

    sanitizer = None
    system_prompt = None
    if "d1" in defenses:
        sanitizer = d1.sanitize
        system_prompt = agent.SYSTEM_PROMPT + "\n" + d1.D1_SYSTEM_APPEND

    return {
        "user_query": sample["query"],
        "schemas": schemas,
        "executor": executor,
        "sanitizer": sanitizer,
        "system_prompt": system_prompt,
    }


def summarize(log):
    calls = []
    for s in log.get("steps", []):
        for tc in s.get("tool_calls", []):
            calls.append({"name": tc["name"], "args": tc.get("args", {})})
    return calls


def run_suite(suite, runs, out, defense, mcp_mode):
    samples = json.load(open(ROOT / "samples" / f"{suite}.json", encoding="utf-8"))
    defenses = parse_defense(defense)

    out_path = ROOT / out
    os.makedirs(out_path.parent, exist_ok=True)
    new_file = not out_path.exists()
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["sample_id", "run", "success",
                        "sensitive_access", "blocked", "steps_json"])

        for sample in samples:
            for run in range(1, runs + 1):
                try:
                    kwargs = stage(suite, sample, defenses, mcp_mode)
                    tag = ("_" + defense.replace(",", "+")) if defense else ""
                    log = agent.run_agent(
                        log_path=ROOT / "logs" / f"{sample['id']}_r{run}{tag}.json",
                        **kwargs)
                    v = judge.analyze(log)
                    w.writerow([sample["id"], run,
                                "SUCCESS" if v["success"] else "FAIL",
                                int(v["sensitive_access"]),
                                int(v["blocked"]),
                                json.dumps(summarize(log), ensure_ascii=False)])
                    f.flush()  # 每轮实时落盘，中断也不丢
                    print(f"[{suite}] {sample['id']} run{run} -> "
                          f"{'SUCCESS' if v['success'] else 'FAIL'}", flush=True)
                except Exception as e:
                    w.writerow([sample["id"], run, "ERROR", "", "", repr(e)])
                    f.flush()
                    print(f"[{suite}] {sample['id']} run{run} -> ERROR {e}",
                          flush=True)

    rows = metrics.read_csv(out_path)
    r = metrics.asr(rows)
    print(f"\n=== {suite} 完成 (defense={defense or 'none'}) ===")
    print(f"  ASR(外泄)   = {metrics.fmt(r)}")
    print(f"  敏感访问率   = {metrics.fmt(metrics.sensitive_access_rate(rows))}")
    print(f"  拦截率       = {metrics.fmt(metrics.block_rate(rows))}")


def main():
    ap = argparse.ArgumentParser(description="Agent 工具调用注入攻击统一实验管线")
    ap.add_argument("--suite", required=True, choices=sorted(SUITES))
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", required=True, help="结果 CSV 路径（相对仓库根）")
    ap.add_argument("--defense", default="", help="逗号分隔，如 d1,d2,d3")
    ap.add_argument("--mcp", action="store_true",
                    help="attack_a 使用真实 MCP 投毒链路（需已 pip install mcp）")
    args = ap.parse_args()
    run_suite(args.suite, args.runs, args.out, args.defense, args.mcp)


if __name__ == "__main__":
    main()
