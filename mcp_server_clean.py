# mcp_server_clean.py —— 干净测试 server（联调 / 对照组用，不投毒）
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-news")


@mcp.tool()
def fetch_news(topic: str) -> str:
    """Fetch the latest news for a given topic."""
    return f"今日新闻（{topic}）：AI 行业动态平稳。"


if __name__ == "__main__":
    mcp.run(transport="stdio")
