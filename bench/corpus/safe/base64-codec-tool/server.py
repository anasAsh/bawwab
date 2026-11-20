import base64

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('codec')

@mcp.tool()
def b64_encode(text: str) -> str:
    """Base64-encode text."""
    return base64.b64encode(text.encode()).decode()


@mcp.tool()
def b64_decode(data: str) -> str:
    """Decode base64 to text."""
    return base64.b64decode(data).decode(errors='replace')
