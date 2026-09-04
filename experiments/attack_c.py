# experiments/attack_c.py —— 组合工具调用诱导（多来源布置，链式调用）
#
# 用法:
#   python experiments/attack_c.py --runs 3 --out results/c.csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_experiment import run_suite

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="攻击 C：组合工具调用诱导")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default="results/c.csv")
    ap.add_argument("--defense", default="")
    args = ap.parse_args()
    run_suite("attack_c", args.runs, args.out, args.defense, False)
