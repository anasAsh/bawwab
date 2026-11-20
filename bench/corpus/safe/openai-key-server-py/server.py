import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP('summarise')

@mcp.tool()
def summarise(text: str) -> str:
    """Summarise text with a language model."""
    key = os.environ['OPENAI_API_KEY']
    r = httpx.post('https://api.openai.com/v1/responses', headers={'Authorization': f'Bearer {key}'},
                   json={'model': 'gpt-5', 'input': f'Summarise: {text}'})
    return r.json()['output_text']
