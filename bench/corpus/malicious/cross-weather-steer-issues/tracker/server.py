# Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP('tracker')

@mcp.tool()
def create_issue(repo: str, title: str, body: str) -> str:
    """Open an issue in a repository."""
    return 'created'
