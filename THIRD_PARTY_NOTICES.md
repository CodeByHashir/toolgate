# Third-Party Notices

Everything committed to this repository is MIT licensed ([`LICENSE`](LICENSE)).
This file records how that is kept true: what was removed to make it so, what is
fetched at runtime rather than vendored, and what is deliberately not
distributed at all.

---

## Resolved: `chains/latency_chain.json` (removed)

A recorded 25-call agent chain used to live at `chains/latency_chain.json`. It
was produced by an agent making real `fetch` calls, and because a chain record
stores every tool result verbatim, it embedded roughly 1.5–5 KB excerpts each of
five Wikipedia articles (CC BY-SA 4.0), an MDN page (CC BY-SA 2.5), W3C, IANA
and python.org pages, and a Project Gutenberg text.

**CC BY-SA is share-alike and is not compatible with this repository's MIT
licence.** Whether share-alike obligations actually attach to a JSON benchmark
fixture containing verbatim excerpts is a legal question this project is not
qualified to answer — so rather than attributing the content and hoping the
answer was favourable, **the file was deleted** (`plan.md` 2.27).

Nothing depended on it programmatically: no test and no script read it, and the
SQLite database its published latency figures were computed from was never
committed either. Its numbers remain in `docs/LATENCY-BENCHMARK.md` section 2 as
a recorded historical measurement, with the command to reproduce one.

`chains/baseline.json` is retained. Its only `fetch` call is to `example.com`,
an IANA reserved domain whose placeholder text states it is "for use in
documentation examples without needing permission" (RFC 2606, RFC 6761).

### Preventing recurrence

The failure was structural, not careless: `mcp-shield run-agent --out` records
whatever a tool returned, and `corpus/sources.py:load_benign()` globs
`chains/*.json`, so fetched web content reached both the fixture *and* the
benign evaluation corpus. Nothing in review would reliably catch that in a
diff.

`tests/test_chain_licensing.py` now enforces it: every committed chain may only
record `fetch` results from an explicit allowlist of hosts whose content carries
no redistribution restriction, and recorded bodies are additionally scanned for
third-party content markers. Adding a host to that allowlist is a licensing
decision that must also be recorded here.

**Note on history.** These commits remain in the git history, which is public.
Rewriting published history was judged disproportionate for a few kilobytes of
encyclopedia excerpts in a benchmark fixture, and would break existing clones
and pull-request references. If that judgement is ever revisited, the remedy is
`git filter-repo` plus a force push, and it should be a deliberate decision
rather than a cleanup.

## Evaluation corpora — fetched, never vendored

None of the following is committed to this repository. Each is downloaded on
demand into `corpus/external/` (gitignored) by
`src/llmshield_mcp/corpus/sources.py`, pinned to an upstream commit SHA and
verified against a recorded SHA-256:

| Source | Licence |
|---|---|
| [BIPIA](https://github.com/microsoft/BIPIA) (Microsoft) | MIT |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (UIUC) | MIT |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) (Microsoft) | MIT |

All three permit redistribution. They are fetched rather than vendored to keep
the repository small and to make the pinning explicit, not because of any
licence restriction.

## Reused model artifacts — not distributed

The V0 and V3 detector weights reused from the LLMShield dissertation, and the
~19,000-row training corpus used for decontamination, are **not in this
repository** and are gitignored (`models/`, `corpus/reference/`). The training
corpus is assembled from mixed-licence public datasets over which this project
holds no redistribution rights; see `config/decontamination.yaml`.

## Reference MCP servers — invoked, not included

`config/servers.yaml` launches `@modelcontextprotocol/server-filesystem` (MIT)
and `mcp-server-fetch` (MIT) via `npx`/`uvx` at pinned versions. Neither is
vendored.

## Python dependencies

Declared in `pyproject.toml` and pinned in `uv.lock`; each retains its own
licence. No dependency source is vendored into this repository.
