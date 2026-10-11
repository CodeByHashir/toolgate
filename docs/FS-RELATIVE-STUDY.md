# Relative-path fix study (v0.3): results

> **With relative paths resolved against the working directory `wrap`
> shares with the server, toolgate refused nothing in 40 runs. Haiku 4.5
> completed 10 of 10 new file tasks with toolgate on and 10 of 10 off, and
> sent 13 relative path arguments in the `on` arm (8 of its 10 runs), all
> of which reached the server and succeeded. Sonnet 5.5 completed 10 of 10
> in both arms but sent only absolute paths, so for Sonnet the fix was not
> exercised. All three pre-registered expectations were met. Ten tasks per
> cell cannot bound a small refusal rate (upper bound about 28 %); what the
> study shows is that the cause found in the first study no longer refuses
> calls in this configuration.**

Pre-registration: [`FS-RELATIVE-STUDY-PREREG.md`](FS-RELATIVE-STUDY-PREREG.md).
Frozen 2026-10-11 at commit `e779ecc`; every run and the analysis checked
the hashes (including the gate, pump and `wrap` files) unchanged. Per-run
summaries: `results/fs-relative-study/runs/`. The study it follows up:
[`FS-UTILITY-STUDY.md`](FS-UTILITY-STUDY.md).

## 1. What ran

Claude Code 2.1.288 on the Windows dev machine, 2026-10-11, logged in to a
claude.ai account (no API key), isolated as in `scripts/record_agent_demo.py`
and started from the workspace.
`@modelcontextprotocol/server-filesystem@2026.8.31`, rooted at a fresh copy
of the fixed workspace per run; arm `on` behind `toolgate wrap` with
`policy_for(workspace)`. Ten new tasks, none repeating the first study's.
Haiku 4.5, then Sonnet 5.5, `off` then `on` per task. 40 runs, 0 failed,
0 retries. Every `on` run wrote audit rows.

## 2. Results (Wilson 95 %)

| Model | Done, off | Done, on | On-runs with a false refusal | Relative path arguments (off / on) | Discordant (off only / on only) |
|---|---|---|---|---|---|
| Haiku 4.5 | 10/10 [72.2, 100] | **10/10** [72.2, 100] | **0/10** [0, 27.8] | 14 / **13** | 0 / 0 |
| Sonnet 5.5 | 10/10 [72.2, 100] | 10/10 [72.2, 100] | 0/10 [0, 27.8] | 0 / 0 | 0 / 0 |

For comparison, the first study (different tasks, toolgate before the fix):
Haiku 10/10 off, 8/10 on, 4 of 10 on-runs refused, 15 refused calls, all
relative paths.

## 3. Expectations

1. **Haiku `on` within one task of `off`: met** (10 vs 10).
2. **Zero false refusals of a relative path inside the workspace: met**
   for both models (no `block` row in any audit log).
3. **Haiku passes at least one relative path in `on`: met** (13 arguments
   in 8 runs: `append`, `copy`, `count`, `largest`, `nested`, `rename`,
   `row`, `size`), so expectation 2 was tested, not vacuous. Example:
   `read_text_file {"path": "notes/todo.txt"}`, then `edit_file` on the
   same relative path. None of those calls returned a tool error.

## 4. What this means

- The false refusals measured in the first study came from one cause, and
  in the configuration tested here (host started from the sandbox) that
  cause is gone: a Haiku-class model using relative paths lost no task.
- Sonnet 5.5 used absolute paths throughout, as in the first study; its
  10/10 shows only that the change did not break absolute paths.
- Not tested: a host started outside the sandbox. There `wrap` warns at
  startup and relative paths are still refused, by design.

## 5. Limitations

Ten tasks, one run per cell, two models, one host, one machine (Windows),
one server. The prompts name relative paths, which made relative arguments
likely; that was the behaviour under test, not a sample of typical use.
Model behaviour may change between versions.

## 6. Deviations from the pre-registration

None. No run was retried or re-run.

## 7. Cost

Claude Code reported, over 20 runs each: Haiku about 297K cache-read, 34K
cache-write, 0.4K uncached input and 6.6K output tokens (median 9.4 s off,
11.3 s on); Sonnet about 251K cache-read, 23K cache-write, 0.1K uncached
input and 4.2K output tokens (median 7.1 s off, 9.3 s on). Billed against a
subscription's usage limit, not API credit.

## 8. Reproduce

```
uv run python scripts/fs_relative_study.py freeze
uv run python scripts/fs_relative_study.py run
uv run python scripts/fs_relative_study.py analyse
uv run pytest tests/test_fs_relative_study.py   # no model calls
```
