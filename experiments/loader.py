# experiments/loader.py —— 内存注入 + 样本环境布置（不修改任何源码文件）
import os
from pathlib import Path

from tools import tool_schemas, execute_tool
import web_content

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "tmp"

# 受控实验（无 MCP 环境）下，本地模拟的 fetch_news 工具 schema，
# 与 mcp_server_clean.py / mcp_server_news.py 暴露的工具对齐。
FETCH_NEWS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "fetch_news",
        "description": "Fetch the latest news for a given topic.",
        "parameters": {
            "type": "object",
            "properties": {"topic": {"type": "string",
                                     "description": "News topic to fetch"}},
            "required": ["topic"],
        },
    },
}


def base_schemas():
    """自有工具 + 本地 fetch_news（受控实验用的基础 schema 集合）"""
    schemas = tool_schemas()
    names = {s["function"]["name"] for s in schemas}
    if "fetch_news" not in names:
        schemas = schemas + [FETCH_NEWS_SCHEMA]
    return schemas


def load_poisoned_schemas(payload: str, target_tool: str):
    """把攻击载荷追加到目标工具的 description 末尾（内存注入）"""
    schemas = base_schemas()
    for s in schemas:
        if s["function"]["name"] == target_tool:
            s["function"]["description"] += "\n" + payload
            return schemas
    return schemas  # 目标工具不存在时原样返回（不报错）


def local_executor(name, args, step=None):
    """受控实验的执行器：本地处理 fetch_news，其余走自有工具"""
    if name == "fetch_news":
        topic = args.get("topic", "") if isinstance(args, dict) else ""
        return f"今日新闻（{topic}）：AI 行业动态平稳。"
    return execute_tool(name, args)


def stage_sources(sources):
    """布置攻击者控制的恶意内容：
      - type == "web"  -> 写入 web_content.WEB_CONTENT[key]
      - type == "file" -> 写入 data/tmp/<name>（攻击 C 的恶意文档）
    返回布置后的描述列表（供日志 / 提问用）。
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    staged = []
    for i, src in enumerate(sources):
        typ = src.get("type", "web")
        content = src.get("content", "")
        if typ == "web":
            key = src.get("key", f"staged_{i}")
            web_content.WEB_CONTENT[key] = content
            staged.append({"type": "web", "key": key})
        else:  # file
            name = src.get("name") or f"doc_{i}.txt"
            path = DATA_DIR / name
            path.write_text(content, encoding="utf-8")
            staged.append({"type": "file", "path": str(path)})
    return staged
