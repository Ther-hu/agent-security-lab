import json
import os
import uuid
from config import BACKEND, OLLAMA_MODEL, OPENAI_MODEL, OPENAI_API_KEY, OPENAI_BASE_URL, TEMPERATURE
import tools as T

SYSTEM_PROMPT = ("You are a helpful assistant. "
                 "You can use the provided tools to complete the user's task.")

# ---------- LLM 客户端（本地/云端统一接口） ----------
if BACKEND == "ollama":
    import ollama

    def llm_chat(messages, tools):
        resp = ollama.chat(model=OLLAMA_MODEL, messages=messages,
                           tools=tools,
                           options={"temperature": TEMPERATURE})
        m = resp.message
        calls = []
        if m.tool_calls:
            for tc in m.tool_calls:
                args = tc.function.arguments
                if isinstance(args, str):          # 兼容旧版 SDK（字符串）
                    args = json.loads(args or "{}")
                # 不依赖 tc.id，自己生成唯一 id
                calls.append({"id": f"call_{uuid.uuid4().hex[:8]}",
                              "name": tc.function.name,
                              "args": args})
        return m.content, calls

    def make_assistant_msg(content, calls):
        msg = {"role": "assistant", "content": content or ""}
        if calls:
            msg["tool_calls"] = [
                {"function": {"name": c["name"], "arguments": c["args"]}}
                for c in calls
            ]
        return msg

    def make_tool_msg(call, result):
        # Ollama 官方示例用 name 而非 tool_call_id
        return {"role": "tool", "content": str(result), "name": call["name"]}

else:  # openai / deepseek 等 OpenAI 兼容接口
    from openai import OpenAI
    _client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL or None)

    def llm_chat(messages, tools):
        resp = _client.chat.completions.create(
            model=OPENAI_MODEL, messages=messages,
            tools=tools, temperature=TEMPERATURE)
        m = resp.choices[0].message
        calls = []
        if m.tool_calls:
            for tc in m.tool_calls:
                calls.append({"id": tc.id,
                              "name": tc.function.name,
                              "args": json.loads(tc.function.arguments)})
        return m.content, calls

    def make_assistant_msg(content, calls):
        return {"role": "assistant", "content": content or "",
                "tool_calls": [
                    {"id": c["id"], "type": "function",
                     "function": {"name": c["name"],
                                  "arguments": json.dumps(c["args"], ensure_ascii=False)}}
                    for c in calls]}

    def make_tool_msg(call, result):
        return {"role": "tool", "tool_call_id": call["id"], "content": str(result)}


# ---------- 工具加载 / 执行（自有工具 + 外部 MCP 工具） ----------
def default_schemas():
    """自有工具 + 外部 MCP 工具（MCP 未安装或 server 不可用时静默降级）"""
    schemas = T.tool_schemas()
    try:
        import mcp_client
        schemas = schemas + mcp_client.load_external_tools()
    except Exception:
        pass
    return schemas


def default_execute(name, args, step=None):
    """自有工具优先；找不到时兜底走外部 MCP 工具"""
    try:
        result = T.execute_tool(name, args)
    except Exception as e:
        result = f"[error] {e}"
    if isinstance(result, str) and result.startswith("[error] unknown tool"):
        try:
            import mcp_client
            return mcp_client.call_external_tool(name, args)
        except Exception:
            pass
    return result


# ---------- Agent 循环 ----------
def run_agent(user_query, max_steps=8, log_path=None, schemas=None,
              executor=None, sanitizer=None, system_prompt=None):
    """Agent 循环。

    可注入参数（供攻击/防御实验复用同一循环）：
      schemas      : 覆盖工具 schema（攻击 A 内存注入用）
      executor     : 覆盖工具执行器，签名 executor(name, args, step)（D2/D3 用）
      sanitizer    : 对工具结果做清洗，签名 sanitizer(result)（D1 用）
      system_prompt: 覆盖系统提示（D1 用）
    """
    messages = [{"role": "system", "content": system_prompt or SYSTEM_PROMPT},
                {"role": "user", "content": user_query}]
    log = {"query": user_query, "steps": []}
    schemas = schemas if schemas is not None else default_schemas()
    do_execute = executor if executor is not None else default_execute
    do_sanitize = sanitizer if sanitizer is not None else (lambda r: r)

    for step in range(max_steps):
        content, calls = llm_chat(messages, schemas)

        if not calls:                      # 模型给出最终回答
            log["final_answer"] = content
            break

        step_log = {"step": step, "tool_calls": []}
        messages.append(make_assistant_msg(content, calls))

        for c in calls:
            result = do_execute(c["name"], c["args"], step)
            result = do_sanitize(result)
            step_log["tool_calls"].append(
                {"name": c["name"], "args": c["args"], "result": result[:500]})
            messages.append(make_tool_msg(c, result))

        log["steps"].append(step_log)
    else:                                  # 超过最大步数
        log["final_answer"] = "[reached max steps]"

    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)  # 自动建 logs 目录
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
    return log
