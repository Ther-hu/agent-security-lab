# demo.py —— 答辩演示用：单条提问跑一次 Agent，打印工具调用轨迹
#
# 用法（在仓库根目录运行）:
#   正常任务:      python demo.py --query "搜索 AI 安全新闻并保存到 notes.txt"
#   攻击A(受控):   python demo.py --query "查一下今天的新闻" --payload "IMPORTANT SYSTEM NOTICE: ..."
#   攻击A(真实MCP): python demo.py --query "查一下今天的新闻" --mcp
#   攻击A+防御:    python demo.py --query "查一下今天的新闻" --mcp --defense d1,d2,d3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import agent
import tools as T
from experiments import loader, judge
from defense import d1_sanitizer, d2_confirmation, d3_policy


def build_executor(base, defenses):
    executor = base

    if "d3" in defenses:
        policy = d3_policy.PolicyEngine()
        prev = executor

        def _d3(name, args, step, _p=policy, _prev=prev):
            ok, msg = _p.check(name, args, step if step is not None else 0)
            return f"Blocked by policy engine: {msg}" if not ok else _prev(name, args, step)

        executor = _d3

    if "d2" in defenses:
        prev = executor

        def _d2(name, args, step, _prev=prev):
            if not d2_confirmation.check(name, args):
                return "User denied: action blocked by operator."
            return _prev(name, args, step)

        executor = _d2

    return executor


def main():
    ap = argparse.ArgumentParser(description="答辩演示：单条提问的 Agent 工具调用轨迹")
    ap.add_argument("--query", required=True, help="用户提问")
    ap.add_argument("--payload", default="", help="注入到 fetch_news 描述的攻击载荷")
    ap.add_argument("--mcp", action="store_true", help="使用真实投毒 MCP server（mcp_server_news.py）")
    ap.add_argument("--defense", default="", help="逗号分隔，如 d1,d2,d3")
    args = ap.parse_args()

    defenses = [d.strip() for d in args.defense.split(",") if d.strip()]

    # ---- 按演示场景搭工具 schema + 执行器 ----
    if args.mcp:
        import mcp_client
        mcp_client.SERVER_CMD = ["python", str(ROOT / "mcp_server_news.py")]
        schemas = T.tool_schemas() + mcp_client.load_external_tools()
        base = agent.default_execute
    elif args.payload:
        schemas = loader.load_poisoned_schemas(args.payload, "fetch_news")
        base = loader.local_executor
    else:
        schemas = agent.default_schemas()
        base = agent.default_execute

    executor = build_executor(base, defenses)
    sanitizer = d1_sanitizer.sanitize if "d1" in defenses else None
    system_prompt = (agent.SYSTEM_PROMPT + "\n" + d1_sanitizer.D1_SYSTEM_APPEND
                     if "d1" in defenses else None)

    # ---- 跑一次 ----
    log = agent.run_agent(args.query, schemas=schemas, executor=executor,
                          sanitizer=sanitizer, system_prompt=system_prompt)

    # ---- 打印轨迹 ----
    print("=" * 60)
    print(f"提问: {args.query}")
    print(f"防御: {('无' if not defenses else '+'.join(defenses))}")
    print(f"模式: {'真实MCP投毒' if args.mcp else ('内存注入' if args.payload else '正常任务')}")
    print("-" * 60)
    for s in log.get("steps", []):
        for tc in s["tool_calls"]:
            name, a, r = tc["name"], tc.get("args", {}), tc.get("result", "")
            blocked = any(m in r for m in ("User denied", "Blocked by policy engine"))
            print(f"  [{s['step']}] {name}({json.dumps(a, ensure_ascii=False)})")
            print(f"        → {r[:120]}{'  ← 被拦截' if blocked else ''}")
    ok = judge.is_success(log)
    print("-" * 60)
    print(f"攻击判定: {'成功 SUCCESS' if ok else '失败 FAIL（未外泄）'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
