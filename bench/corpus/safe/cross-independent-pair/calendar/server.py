from mcp.server.fastmcp import FastMCP

mcp = FastMCP('calendar')

@mcp.tool()
def list_events(day: str) -> str:
    """List calendar events for a day."""
    return '[]'
