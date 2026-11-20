import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP('weather')

@mcp.tool()
def forecast(lat: float, lon: float) -> str:
    """Get the weather forecast for a location."""
    r = httpx.get('https://api.open-meteo.com/v1/forecast', params={'latitude': lat, 'longitude': lon, 'current_weather': True})
    r.raise_for_status()
    return r.text


if __name__ == '__main__':
    mcp.run()
