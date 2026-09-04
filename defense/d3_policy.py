# defense/d3_policy.py —— 行为策略引擎（污点追踪：读敏感文件 → 阻止外发）
class PolicyEngine:
    def __init__(self):
        self.tainted = False
        self.sensitive_read_step = None

    def check(self, name, args, step):
        # 读敏感文件 → 打污点标记
        if name == "read_file" and "secret" in str(args.get("path", "")):
            self.tainted = True
            self.sensitive_read_step = step
            return True, "ok"
        # 外发/外写时：有污点 或 距敏感读取≤2步 → 阻断
        if name in ("send_email", "write_file"):
            near = (self.sensitive_read_step is not None
                    and 0 <= step - self.sensitive_read_step <= 2)
            if self.tainted or near:
                return False, "potential data exfiltration detected"
        return True, "ok"
