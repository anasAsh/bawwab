from src.app import parse, total


def test_parse():
    assert parse("1, 2,,3") == ["1", "2", "3"]


def test_total():
    assert total(["1", "2"]) == 3
