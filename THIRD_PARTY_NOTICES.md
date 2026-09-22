# Third-Party Notices

The repository's own source, tests, configuration and documentation are MIT
licensed ([`LICENSE`](LICENSE)). Some committed **data files** are not, and MIT
does not extend to them. This file records what they are and under what terms.

---

## `chains/latency_chain.json` — contains third-party web content

This file is a recorded MCP tool-call chain used by the latency benchmark
(`scripts/benchmark_latency.py`, [`docs/LATENCY-BENCHMARK.md`](docs/LATENCY-BENCHMARK.md)).
It was produced by an agent making real `fetch` calls, and it therefore embeds
verbatim excerpts (roughly 1.5–5 KB each) of pages served by third parties:

| Source | Calls | Licence of the excerpted content |
|---|---|---|
| `en.wikipedia.org` (HTTP, JSON, Python, Software testing, Latency) | 5 | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| `developer.mozilla.org` (Web/HTTP) | 1 | [CC BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/) |
| `www.w3.org`, `www.w3.org/TR/` | 2 | [W3C Document Licence](https://www.w3.org/copyright/document-license/) |
| `www.iana.org`, `www.iana.org/domains/reserved` | 2 | IANA / ICANN terms |
| `www.python.org` | 1 | PSF website terms |
| `httpbin.org` | 2 | [ISC](https://github.com/postmanlabs/httpbin/blob/master/LICENSE) |
| `example.com` / `.org` / `.net` | 3 | IANA reserved-domain placeholder text |
| Project Gutenberg (*Moby-Dick* excerpt, via a fetched page) | 1 | Project Gutenberg Licence; the underlying work is public domain |

Attribution is given above. Each excerpt remains under its own licence, and
nothing here relicenses it.

### Known issue, stated rather than assumed

The Wikipedia and MDN excerpts are under **share-alike** licences. Share-alike
attaches obligations to derivative works, and whether a JSON benchmark fixture
containing verbatim excerpts counts as one — and if so, whether the obligation
reaches the fixture, the benchmark, or neither — is a legal question this
project is not qualified to answer. It is recorded here rather than resolved.

`plan.md` section 16's own instruction applies: document the finding and flag
anything needing human or legal confirmation instead of assuming an answer.

**If this becomes a problem, the fix is cheap.** The latency benchmark needs
content *lengths* and token counts, not the prose. `chains/latency_chain.json`
can be regenerated against sources whose licences permit redistribution without
share-alike, at the cost of re-running the benchmark and restating the numbers
in `docs/LATENCY-BENCHMARK.md`. That has not been done yet because it would
invalidate published figures for a reason that is not yet established.

---

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
