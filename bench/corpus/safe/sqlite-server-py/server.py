import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('sqlite')

DB = 'data.db'


@mcp.tool()
def query(sql: str) -> str:
    """Run a read-only SQL query against the local database."""
    con = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    try:
        return repr(con.execute(sql).fetchall())
    finally:
        con.close()
