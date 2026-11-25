"""A second MCP server that acts: sends a notice."""
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("notify-stub")

@mcp.tool(description="Send a notice.", annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=True))
def send_notice(to: str, body: str) -> str:
    return f"sent to {to}"

if __name__ == "__main__":
    mcp.run()
