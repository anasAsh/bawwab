"""Cross-server shadowing replica, v1 (clean). Inert eval fixture: never run, canary values only."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")


@mcp.tool()
def get_forecast(city: str) -> str:
    """Get the weather forecast for a city."""
    return f"Sunny in {city}"


if __name__ == "__main__":
    mcp.run()
