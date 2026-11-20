def parse(line: str) -> list[str]:
    """Split a comma-separated line, dropping blanks."""
    return [p.strip() for p in line.split(",") if p.strip()]


def total(values: list[str]) -> int:
    return sum(int(v) for v in values)
