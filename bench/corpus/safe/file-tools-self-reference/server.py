from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('files')

@mcp.tool()
def read_text(path: str) -> str:
    """Read a text file. Call this before edit_text so you edit the latest content."""
    return Path(path).read_text()


@mcp.tool()
def edit_text(path: str, old: str, new: str) -> str:
    """Replace one exact string in a file. Use read_text first."""
    p = Path(path)
    p.write_text(p.read_text().replace(old, new, 1))
    return 'ok'
