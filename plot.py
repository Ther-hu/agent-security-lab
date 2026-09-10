#!/usr/bin/env python
# plot.py —— 读 results/*.csv，一键生成答辩四张图，并打印带置信区间的汇总数字
#
# 用法: python plot.py
# 输出:
#   figures/fig1_asr_no_defense.png  无防御 ASR（带 95%CI 误差棒）
#   figures/fig2_asr_vs_defense.png  ASR 随防御叠加下降（带 95%CI 误差棒）
#   figures/fig3_misblock.png        各防御配置误拦率
#   figures/fig4_defense_eval.png    防护评估全景（ASR 降幅 + 拦截率/误拦率）
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SAMPLES = ROOT / "samples"
LOGS = ROOT / "logs"
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)

sys.path.insert(0, str(ROOT))
from experiments import metrics

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
# 防御层级：key -> (显示名, 结果文件模板)。口径统一为"外泄=成功"。
DEFENSE_LEVELS = [
    ("none", "无防御", "{t}.csv"),
    ("d1", "D1", "{t}_d1.csv"),
    ("d123", "D1+D2+D3", "{t}_d123.csv"),
]


def read_rate(path: Path):
    """读一个结果 CSV，返回 ASR 的 (rate, lo, hi, n)。文件不存在/为空返回 None。"""
    if not path.exists():
        return None
    rows = metrics.read_csv(path)
    if not rows:
        return None
    return metrics.asr(rows)


def _pct_ci(r):
    """rate tuple -> (百分比值, 上下误差) 用于 errorbar。"""
    rate, lo, hi, n = r
    return rate * 100, (hi - lo) / 2 * 100


def _read_block_rate(path: Path):
    if not path.exists():
        return None
    rows = metrics.read_csv(path)
    if not rows:
        return None
    return metrics.false_block_rate(rows)


def fig1():
    """图1：无防御 ASR × 攻击类型（带 95%CI 误差棒）"""
    labels, vals, errs, colors = [], [], [], []
    for t, (name, color) in ATTACKS.items():
        r = read_rate(RESULTS / f"{t}.csv")
        labels.append(name)
        colors.append(color)
        if r is None:
            vals.append(0.0)
            errs.append(0.0)
        else:
            v, e = _pct_ci(r)
            vals.append(v)
            errs.append(e)
    fig, ax = plt.subplots(figsize=(6.5, 4.4))
    bars = ax.bar(labels, vals, yerr=errs, capsize=5, color=colors, width=0.55,
                  error_kw={"elinewidth": 1.2, "ecolor": "#333"})
    ax.set_ylim(0, 100)
    ax.set_ylabel("ASR (%)  外泄口径")
    ax.set_title("图1  无防御攻击成功率（Qwen3-8B，误差棒=95% CI）")
    for b, v, e in zip(bars, vals, errs):
        ax.text(b.get_x() + b.get_width() / 2, v + e + 2, f"{v:.0f}%",
                ha="center", va="bottom", fontsize=10)
    fig.tight_layout()
    fig.savefig(FIG / "fig1_asr_no_defense.png", dpi=150)
    plt.close(fig)


def fig2():
    """图2：ASR 随防御叠加下降（一条线一个攻击类型，带 95%CI 误差棒）"""
    fig, ax = plt.subplots(figsize=(6.8, 4.6))
    x = list(range(len(DEFENSE_LEVELS)))
    for t, (name, color) in ATTACKS.items():
        vals, errs = [], []
        for _, _, fname_tpl in DEFENSE_LEVELS:
            r = read_rate(RESULTS / fname_tpl.format(t=t))
            if r is None:
                vals.append(0.0)
                errs.append(0.0)
            else:
                v, e = _pct_ci(r)
                vals.append(v)
                errs.append(e)
        ax.errorbar(x, vals, yerr=errs, marker="o", color=color, linewidth=2,
                    capsize=4, label=name)
    ax.set_xticks(x)
    ax.set_xticklabels([d[1] for d in DEFENSE_LEVELS])
    ax.set_ylim(0, 100)
    ax.set_ylabel("ASR (%)  外泄口径")
    ax.set_xlabel("防御层数（叠加）")
    ax.set_title("图2  ASR 随防御叠加下降（误差棒=95% CI）")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / "fig2_asr_vs_defense.png", dpi=150)
    plt.close(fig)


def fig3():
    """图3：各防御配置误拦率（正常任务被 D2/D3 误拦的占比）"""
    configs = [("d2", "D2"), ("d123", "D1+D2+D3")]
    labels, vals, errs = [], [], []
    for dkey, dname in configs:
        r = _read_block_rate(RESULTS / f"benign_{dkey}.csv")
        labels.append(dname)
        if r is None:
            vals.append(0.0)
            errs.append(0.0)
        else:
            v, e = _pct_ci(r)
            vals.append(v)
            errs.append(e)
    fig, ax = plt.subplots(figsize=(4.6, 4.2))
    bars = ax.bar(labels, vals, yerr=errs, capsize=5, color="#d62728", width=0.45,
                  error_kw={"elinewidth": 1.2, "ecolor": "#333"})
    ax.set_ylim(0, 100)
    ax.set_ylabel("误拦率 (%)")
    ax.set_title("图3  可用性代价（正常任务被误拦，95% CI）")
    for b, v, e in zip(bars, vals, errs):
        ax.text(b.get_x() + b.get_width() / 2, v + e + 2, f"{v:.0f}%",
                ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(FIG / "fig3_misblock.png", dpi=150)
    plt.close(fig)


def fig4():
    """图4：防护评估全景 —— 左：ASR 无防御 vs 全防御；右：拦截率/误拦率"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 4.4))

    # 左：每类攻击 无防御 vs 全防御 的 ASR（带 CI）
    import numpy as np
    labels = [ATTACKS[t][0] for t in ATTACKS]
    x = np.arange(len(labels))
    width = 0.36
    for i, (dkey, dname, color) in enumerate(
            [("none", "无防御", "#1f77b4"), ("d123", "全防御", "#d62728")]):
        vals, errs = [], []
        for t in ATTACKS:
            r = read_rate(RESULTS / DEFENSE_LEVELS[0 if dkey == "none" else 2][2].format(t=t))
            if r is None:
                vals.append(0.0)
                errs.append(0.0)
            else:
                v, e = _pct_ci(r)
                vals.append(v)
                errs.append(e)
        ax1.bar(x + (i - 0.5) * width, vals, yerr=errs, width=width, capsize=4,
                color=color, label=dname, error_kw={"elinewidth": 1.1, "ecolor": "#333"})
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=12)
    ax1.set_ylim(0, 100)
    ax1.set_ylabel("ASR (%)")
    ax1.set_title("ASR：无防御 vs 全防御")
    ax1.legend()

    # 右：拦截率（攻击集，全防御）与 误拦率（良性集）
    import numpy as _np
    group_labels = ["拦截率\n(攻击集,全防御)", "误拦率\n(良性集,D2)", "误拦率\n(良性集,全防御)"]
    gvals, gerrs = [], []
    # 拦截率：三类攻击在全防御下 blocked 占比的平均
    brs = []
    for t in ATTACKS:
        p = RESULTS / f"{t}_d123.csv"
        rows = metrics.read_csv(p) if p.exists() else []
        if rows:
            brs.append(metrics.block_rate(rows)[0])
    br = (sum(brs) / len(brs)) if brs else 0.0
    gvals.append(br * 100)
    gerrs.append(0.0)
    for dkey in ("d2", "d123"):
        r = _read_block_rate(RESULTS / f"benign_{dkey}.csv")
        if r is None:
            gvals.append(0.0)
            gerrs.append(0.0)
        else:
            v, e = _pct_ci(r)
            gvals.append(v)
            gerrs.append(e)
    bars = ax2.bar(group_labels, gvals, yerr=gerrs, capsize=5,
                   color=["#2ca02c", "#ff7f0e", "#ff7f0e"], width=0.5,
                   error_kw={"elinewidth": 1.2, "ecolor": "#333"})
    ax2.set_ylim(0, 100)
    ax2.set_ylabel("比例 (%)")
    ax2.set_title("拦截率 / 误拦率（95% CI）")
    for b, v, e in zip(bars, gvals, gerrs):
        ax2.text(b.get_x() + b.get_width() / 2, v + e + 2, f"{v:.0f}%",
                 ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(FIG / "fig4_defense_eval.png", dpi=150)
    plt.close(fig)


def summary():
    """打印带置信区间的汇总数字，方便填进答辩稿。"""
    print("\n===== 汇总数字（外泄口径，95% Wilson CI）=====")
    for t, (name, _) in ATTACKS.items():
        row = []
        for _, lname, fname_tpl in DEFENSE_LEVELS:
            r = read_rate(RESULTS / fname_tpl.format(t=t))
            row.append(f"{lname}={metrics.fmt(r) if r else 'N/A'}")
        print(f"{name}:")
        for r in row:
            print(f"    {r}")
    print("\n误拦率（良性集）:")
    for dkey, dname in [("d2", "D2"), ("d123", "D1+D2+D3")]:
        r = _read_block_rate(RESULTS / f"benign_{dkey}.csv")
        print(f"    {dname:<10}: {metrics.fmt(r) if r else 'N/A'}")


if __name__ == "__main__":
    fig1()
    fig2()
    fig3()
    fig4()
    summary()
    print(f"\n四张图已保存到 {FIG}")
