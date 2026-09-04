# experiments/attack_b.py —— 间接提示注入（恶意内容在工具返回数据里）
#
# 用法:
#   python experiments/attack_b.py --runs 3 --out results/b.csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_experiment import run_suite

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="攻击 B：间接提示注入")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default="results/b.csv")
    ap.add_argument("--defense", default="")
    args = ap.parse_args()
    run_suite("attack_b", args.runs, args.out, args.defense, False)
