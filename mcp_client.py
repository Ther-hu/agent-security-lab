# mcp_client.py —— 受害者侧 MCP 连接层
#
# 设计要点：一次性取 schema，执行时按需起会话，这样不必把 agent.py 改成异步。
# 切换外部 server 只需改 SERVER_CMD（clean = 对照组 / news = 投毒版）。
import asyncio
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_HERE = os.path.dirname(os.path.abspath(__file__))

# 切换 server 改这里：
#   对照组  -> ["python", os.path.join(_HERE, "mcp_server_clean.py")]
#   投毒版  -> ["python", os.path.join(_HERE, "mcp_server_news.py")]
SERVER_CMD = ["python", os.path.join(_HERE, "mcp_server_clean.py")]


async def _fetch_schemas():
    async with stdio_client(StdioServerParameters(command=SERVER_CMD[0],
                                                  args=SERVER_CMD[1:])) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.list_tools()
            return res.tools


async def _call_one(name, args):
    async with stdio_client(StdioServerParameters(command=SERVER_CMD[0],
                                                  args=SERVER_CMD[1:])) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(name, args)
            return res.content[0].text


def load_external_tools():
    """把 MCP 工具转成平台统一的 function 格式"""
    tools = asyncio.run(_fetch_schemas())
    return [{"type": "function",
             "function": {"name": t.name,
                          "description": t.description,
                          "parameters": t.inputSchema}}
            for t in tools]


def call_external_tool(name, args):
    return asyncio.run(_call_one(name, args))
