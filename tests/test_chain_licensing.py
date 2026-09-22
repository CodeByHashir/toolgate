"""Committed chain fixtures must not redistribute third-party content.

This is a licensing regression test, and it exists because the failure already
happened once. `chains/latency_chain.json` was a recorded 25-call agent chain,
and because `agent.run` records each tool result verbatim, it captured ~5 KB
excerpts of five Wikipedia articles, an MDN page, W3C and python.org pages and
a Project Gutenberg text -- several under CC BY-SA, which is share-alike and
not compatible with this repository's MIT licence. Worse, `load_benign()`
globs `chains/*.json`, so that text also flowed into the benign evaluation
corpus and its JSONL export.

Nothing caught it: the fixture was committed by a milestone, the licence
implication was not obvious from a diff, and no check existed. The file has
since been removed (`plan.md` 2.27). This test is the part that stops it
coming back, because the same thing will happen again the next time someone
runs `mcp-shield run-agent --out chains/something.json` against real URLs and
commits the result.

The rule enforced: a committed chain may only record `fetch` results from
hosts whose content carries no redistribution restriction.
"""

from __future__ import annotations

import json
import pathlib
from urllib.parse import urlparse

import pytest

from llmshield_mcp.config import REPO_ROOT

#: Hosts whose fetched content may be committed inside this MIT repository.
#:
#: * example.com / .org / .net -- IANA reserved domains whose placeholder text
#:   says outright it is "for use in documentation examples without needing
#:   permission" (RFC 2606, RFC 6761).
#: * httpbin.org -- ISC licensed, and its endpoints return synthetic echo data.
#:
#: Deliberately short. Adding a host here is a licensing decision, not a
#: convenience: check what that host's content is actually licensed under, and
#: record it in THIRD_PARTY_NOTICES.md. "It is publicly readable" is not a
#: licence to redistribute.
ALLOWED_FETCH_HOSTS: frozenset[str] = frozenset(
    {
        "example.com",
        "www.example.com",
        "example.org",
        "www.example.org",
        "example.net",
        "www.example.net",
        "httpbin.org",
    }
)

CHAINS_DIR = REPO_ROOT / "chains"


def _committed_chains() -> list[tuple[str, dict]]:
    if not CHAINS_DIR.is_dir():
        return []
    return [
        (path.name, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(CHAINS_DIR.glob("*.json"))
    ]


def test_there_is_at_least_one_chain_to_check() -> None:
    """Guards against this whole module silently passing on an empty glob."""
    assert _committed_chains(), "no chain fixtures found; this test would pass vacuously"


@pytest.mark.parametrize("name,chain", _committed_chains())
def test_committed_chain_fetches_only_licence_clean_hosts(name: str, chain: dict) -> None:
    offenders: list[tuple[str, int]] = []
    for call in chain.get("calls", []):
        if call.get("tool") != "fetch":
            continue
        url = (call.get("arguments") or {}).get("url")
        if not url:
            continue
        host = (urlparse(str(url)).hostname or "").lower()
        if host not in ALLOWED_FETCH_HOSTS:
            offenders.append((str(url), len(call.get("result_text", ""))))

    assert not offenders, (
        f"{name} records fetched content from hosts outside ALLOWED_FETCH_HOSTS:\n"
        + "\n".join(f"  {url}  ({chars} chars of body text)" for url, chars in offenders)
        + "\n\nA recorded chain stores each tool result verbatim, so committing this "
        "redistributes that content under this repository's MIT licence. Either drop "
        "the fixture, re-record it against allowed hosts, or -- only after checking "
        "the actual licence and recording it in THIRD_PARTY_NOTICES.md -- add the host "
        "to ALLOWED_FETCH_HOSTS."
    )


@pytest.mark.parametrize("name,chain", _committed_chains())
def test_committed_chain_carries_no_known_third_party_markers(name: str, chain: dict) -> None:
    """Belt and braces: catch third-party prose that arrived some other way.

    The host allowlist covers `fetch`. A filesystem read of a vendored file, or
    a tool this project has not seen yet, could still carry restricted text, so
    the recorded bodies are also scanned for a few unmistakable markers.
    """
    markers = ("Moby-Dick", "Wikipedia", "Jump to content", "MDN Web Docs", "Creative Commons")
    hits: list[tuple[str, str]] = []
    for call in chain.get("calls", []):
        text = call.get("result_text", "")
        for marker in markers:
            if marker in text:
                hits.append((call.get("tool", "?"), marker))

    assert not hits, (
        f"{name} contains third-party content markers {sorted(set(hits))}. "
        "See this module's docstring; committing it redistributes that content."
    )


def test_chain_fixtures_are_still_a_benign_corpus_source() -> None:
    """Documents why the tests above protect more than the fixtures themselves.

    `load_benign()` globs `chains/*.json`, so anything a recorded chain
    captures also flows into the benign evaluation corpus and its JSONL export
    -- which is how the original CC BY-SA text reached
    `corpus/payload_corpus.jsonl` as well as the fixture.

    A naive scan of `load_benign()` output cannot check this: the loader also
    globs `tests/**/*.py`, so it reads this very file and matches on the marker
    list above. Asserting the coupling instead is the honest version -- if this
    glob is ever removed the corpus gets safer, not less safe, and this test
    failing is the signal to re-read the reasoning above rather than to panic.
    """
    from llmshield_mcp.corpus import sources

    source = pathlib.Path(sources.__file__).read_text(encoding="utf-8")
    assert '"chains/*.json"' in source, (
        "load_benign() no longer globs chains/*.json. That is a safety improvement, "
        "but this test and the ones above were written around that coupling -- "
        "re-read tests/test_chain_licensing.py's module docstring before deleting them."
    )
