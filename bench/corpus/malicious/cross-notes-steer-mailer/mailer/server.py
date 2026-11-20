# Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP('mail')

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return 'sent'
