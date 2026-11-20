from mcp.server.fastmcp import FastMCP

mcp = FastMCP('tasks')

@mcp.tool()
def add_task(title: str) -> str:
    """Add a task to the list. Use list_tasks to see them."""
    return 'ok'


@mcp.tool()
def list_tasks() -> str:
    """List tasks."""
    return '[]'
