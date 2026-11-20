"""Search the bundled CSV data. Local only."""
import csv
import sys
from pathlib import Path

DATA = Path(__file__).parent.parent / "data" / "products.csv"


def search(query: str) -> list[dict]:
    with DATA.open() as fh:
        return [row for row in csv.DictReader(fh) if query.lower() in row["product"].lower()]


if __name__ == "__main__":
    print(search(sys.argv[1]))
