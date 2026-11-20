"""R62: taxonomy.json maps every catalog rule to OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS and CWE ids."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bawwab.scan.rules.catalog import CATALOG

PATH = Path(__file__).resolve().parent.parent / "bawwab" / "scan" / "rules" / "data" / "taxonomy.json"
SCHEMES = {
    "owasp_llm": re.compile(r"LLM(0[1-9]|10)"),
    "owasp_agentic": re.compile(r"ASI(0[1-9]|10)"),
    "atlas": re.compile(r"AML\.T\d{4}(\.\d{3})?"),
    "cwe": re.compile(r"CWE-[1-9]\d*"),
}


@pytest.fixture(scope="module")
def tax():
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_shape(tax):
    assert {"about", "sources", "known_ids", "rules"} <= tax.keys()
    assert tax["about"].strip()
    for s in tax["sources"]:
        assert set(s) == {"name", "url", "version", "retrieved"} and s["url"].startswith("https://")
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", s["retrieved"])
    assert set(tax["known_ids"]) == set(SCHEMES)
    for entry in tax["rules"].values():
        assert set(entry) == set(SCHEMES) | {"note"}
        assert isinstance(entry["note"], str)


def test_every_catalog_rule_has_an_entry(tax):
    assert sorted(set(CATALOG) - set(tax["rules"])) == []


def test_no_entry_names_an_unknown_rule(tax):
    assert sorted(set(tax["rules"]) - set(CATALOG)) == []


def test_ids_match_their_scheme_pattern(tax):
    bad = [(rule, scheme, i) for rule, e in tax["rules"].items() for scheme, pat in SCHEMES.items()
           for i in e[scheme] if not pat.fullmatch(i)]
    assert bad == []
    bad_known = [(scheme, i) for scheme, pat in SCHEMES.items() for i in tax["known_ids"][scheme] if not pat.fullmatch(i)]
    assert bad_known == []


def test_ids_are_in_the_source_backed_lists(tax):
    unknown = [(rule, scheme, i) for rule, e in tax["rules"].items() for scheme in SCHEMES
               for i in e[scheme] if i not in tax["known_ids"][scheme]]
    assert unknown == []
    for scheme in SCHEMES:
        assert all(isinstance(t, str) and t.strip() for t in tax["known_ids"][scheme].values()), scheme


def test_owasp_lists_are_complete(tax):
    """Both OWASP lists are copied whole (ten entries each), so a missing or extra id is a copy error."""
    assert sorted(tax["known_ids"]["owasp_llm"]) == [f"LLM{n:02d}" for n in range(1, 11)]
    assert sorted(tax["known_ids"]["owasp_agentic"]) == [f"ASI{n:02d}" for n in range(1, 11)]


def test_no_duplicates_within_an_entry(tax):
    dup = [(rule, scheme) for rule, e in tax["rules"].items() for scheme in SCHEMES if len(e[scheme]) != len(set(e[scheme]))]
    assert dup == []
