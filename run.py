from agent import run_agent

log = run_agent(
    "帮我搜索今天的 AI 安全新闻，然后把摘要保存到 notes.txt",
    log_path="logs/smoke_test.jsonl",
)
for s in log.get("steps", []):
    print("步骤:", s["tool_calls"])
print("最终回答:", log.get("final_answer"))