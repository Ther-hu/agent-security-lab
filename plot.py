#!/usr/bin/env python
# plot.py —— 读 results/*.csv，一键生成答辩三张图，并打印汇总数字
#
# 用法: python plot.py
# 输出: figures/fig1_asr_no_defense.png / fig2_asr_vs_defense.png / fig3_d2_misblock.png
import csv
import glob
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SAMPLES = ROOT / "samples"
LOGS = ROOT / "logs"
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)

import matplotlib
matplotlib.use("Agg")  # 无显示环境也能存图
import matplotlib.pyplot as plt

# 中文字体（Windows）
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

# 攻击类型：key -> (显示名, 颜色)。颜色在图1/图2里保持一致。
ATTACKS = {
    "a": ("攻击A 描述投毒", "#1f77b4"),
    "b": ("攻击B 间接注入", "#ff7f0e"),
    "c": ("攻击C 组合诱导", "#2ca02c"),
}
# 防御层级：key -> (显示名, 结果文件模板)
DEFENSE_LEVELS = [
    ("none", "无防御", "{t}.csv"),
    ("d1", "D1", "{t}_d1.csv"),
    ("d12", "D1+D2", "{t}_d12.csv"),
    ("d123", "D1+D2+D3", "{t}_d123.csv"),
]


def read_asr(path: Path):
    """读一个结果 CSV，返回 ASR（0~1）。文件不存在或为空时返回 None。"""
    if not path.exists():
        return None
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if not rows:
        return None
    succ = sum(1 for r in rows if str(r["success"]).strip() == "SUCCESS")
    return succ / len(rows)


def misblock():
    """D2 误拦率：正常任务中被 'User denied' 拦掉的样本占比。"""
    total = len(json.load(open(SAMPLES / "benign.json", encoding="utf-8")))
    blocked_ids = set()
    for f in glob.glob(str(LOGS / "N*_r*_d2.json")):
        d = json.load(open(f, encoding="utf-8"))
        hit = any("User denied" in str(t.get("result", ""))
                  for s in d.get("steps", [])
                  for t in s.get("tool_calls", []))
        if hit:
            m = re.match(r"(N\d+-\d+)", os.path.basename(f))
            if m:
                blocked_ids.add(m.group(1))
    return len(blocked_ids), total


def fig1():
    """图1：无防御 ASR × 攻击类型"""
    labels, vals, colors = [], [], []
    for t, (name, color) in ATTACKS.items():
        v = read_asr(RESULTS / f"{t}.csv")
        labels.append(name)
        vals.append((v if v is not None else 0) * 100)
        colors.append(color)
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    bars = ax.bar(labels, vals, color=colors, width=0.55)
    ax.set_ylim(0, 100)
    ax.set_ylabel("ASR (%)")
    ax.set_title("图1  无防御攻击成功率（Qwen3-8B）")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.0f}%",
                ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(FIG / "fig1_asr_no_defense.png", dpi=150)
    plt.close(fig)


def fig2():
    """图2：ASR 随防御叠加下降曲线（一条线一个攻击类型）"""
    fig, ax = plt.subplots(figsize=(6.8, 4.5))
    x = list(range(len(DEFENSE_LEVELS)))
    for t, (name, color) in ATTACKS.items():
        vals = []
        for _, _, fname_tpl in DEFENSE_LEVELS:
            v = read_asr(RESULTS / fname_tpl.format(t=t))
            vals.append((v if v is not None else 0) * 100)
        ax.plot(x, vals, marker="o", color=color, linewidth=2, label=name)
    ax.set_xticks(x)
    ax.set_xticklabels([d[1] for d in DEFENSE_LEVELS])
    ax.set_ylim(0, 100)
    ax.set_ylabel("ASR (%)")
    ax.set_xlabel("防御层数（叠加）")
    ax.set_title("图2  ASR 随防御叠加下降曲线")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / "fig2_asr_vs_defense.png", dpi=150)
    plt.close(fig)


def fig3():
    """图3：D2 误拦率（可用性代价）"""
    blocked, total = misblock()
    rate = (blocked / total * 100) if total else 0
    fig, ax = plt.subplots(figsize=(4.5, 4.0))
    ax.bar(["D2 误拦率"], [rate], color="#d62728", width=0.4)
    ax.set_ylim(0, 100)
    ax.set_ylabel("误拦率 (%)")
    ax.set_title("图3  D2 可用性代价（正常任务被误拦）")
    ax.text(0, rate + 1.5, f"{blocked}/{total} = {rate:.0f}%", ha="center")
    fig.tight_layout()
    fig.savefig(FIG / "fig3_d2_misblock.png", dpi=150)
    plt.close(fig)


def summary():
    """打印汇总数字，方便填进答辩稿。"""
    print("\n===== 汇总数字 =====")
    for t, (name, _) in ATTACKS.items():
        row = []
        for _, lname, fname_tpl in DEFENSE_LEVELS:
            v = read_asr(RESULTS / fname_tpl.format(t=t))
            row.append(f"{lname}={ (v*100 if v is not None else -1):.0f}%")
        print(f"{name}: " + "  ".join(row))
    blocked, total = misblock()
    print(f"D2 误拦率: {blocked}/{total} = {blocked/total*100:.0f}%" if total else "D2 误拦率: 无数据")


if __name__ == "__main__":
    fig1()
    fig2()
    fig3()
    summary()
    print(f"\n三张图已保存到 {FIG}")
