# experiments/attack_a.py —— 工具描述投毒（内存注入受控版 / 真实 MCP 链路）
#
# 用法:
#   python experiments/attack_a.py --runs 3 --out results/a.csv
#   python experiments/attack_a.py --runs 3 --mcp --out results/a_mcp.csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_experiment import run_suite

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="攻击 A：工具描述投毒")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default="results/a.csv")
    ap.add_argument("--defense", default="")
    ap.add_argument("--mcp", action="store_true")
    args = ap.parse_args()
    run_suite("attack_a", args.runs, args.out, args.defense, args.mcp)
