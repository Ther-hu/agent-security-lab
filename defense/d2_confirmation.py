# defense/d2_confirmation.py —— 危险工具人工确认（实验模式 = 自动拒绝）
DANGEROUS = {"send_email", "write_file"}


def check(name: str, args: dict) -> bool:
    """返回 True 表示放行，False 表示需要人工确认（实验里自动拒绝）"""
    if name in DANGEROUS:
        return False
    if name == "read_file" and "secret" in str(args.get("path", "")):
        return False
    return True
