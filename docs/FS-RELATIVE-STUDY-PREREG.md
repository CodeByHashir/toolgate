# Relative-path fix study (v0.3): pre-registration

Written before any model call. `scripts/fs_relative_study.py freeze` records
the sha256 of this file, the study's code (`src/toolgate/fs_relative_study.py`,
`src/toolgate/fs_utility_study.py`, `scripts/fs_relative_study.py`) and the
toolgate code the fix lives in (`src/toolgate/gating/tool_calls.py`,
`src/toolgate/proxy/pump.py`, `src/toolgate/proxy/wrap.py`), plus the git
commit, in `results/fs-relative-study/frozen.json`; `run` and `analyse`
refuse if any file changed. Results are reported against this document,
deviations included.

## 1. Question

The filesystem false-refusal study ([`FS-UTILITY-STUDY.md`](FS-UTILITY-STUDY.md))
found that toolgate refused every relative path argument (`notes/meeting.md`,
`.`), which the server accepts: Haiku 4.5 completed 8 of 10 tasks with
toolgate on against 10 of 10 off, and 4 of its 10 on-runs hit a refusal.
`wrap` now resolves a relative path against the working directory it shares
with the server (PR #11). **Does the fix remove those false refusals for a
real agent, without costing tasks?**

That study is not re-run: its ten tasks are known and the fix was written
after seeing them. This study uses ten new tasks.

## 2. Setup

Identical to the first study (its section 2 and Amendment 1), except the
tasks and the toolgate version:

- **Host.** Claude Code (version recorded at freeze), headless, isolated as
  in `scripts/record_agent_demo.py` (`--strict-mcp-config`, `--tools ""`,
  `--allowedTools mcp__filesystem`, `--permission-prompts none`,
  `--setting-sources local`, `--no-session-persistence`,
  `--append-system-prompt` with the same `SYSTEM`), **started from the
  workspace**. Windows dev machine. Logged in to a claude.ai account; no API
  key.
- **Models.** `claude-haiku-4-5-20251001`, `claude-sonnet-5-5`.
- **Server.** `@modelcontextprotocol/server-filesystem@2026.8.31`, rooted at
  a fresh copy of the same fixed workspace (`make_workspace`) per run.
- **Arms.** `off`: the server started directly. `on`: through `toolgate
  wrap` with the same `policy_for(workspace)` (`default: block`, every path
  tool confined to `{sandbox}` and `{sandbox}/**`). `wrap` inherits the
  workspace as its working directory, so this tests the fix in the
  configuration the README recommends (host started from the sandbox).
- **Tasks.** The ten in `src/toolgate/fs_relative_study.py` (`count`,
  `attendees`, `append`, `copy`, `largest`, `rename`, `size`, `nested`,
  `folder`, `row`). None repeats a task of the first study (tested). Each
  prompt names its files as relative paths, as a user typically does; this
  invites, but does not force, relative path arguments. Each has a
  deterministic check on the workspace and the final answer, tested to fail
  on the untouched workspace and pass on a correct outcome. No task is
  adversarial and every task stays inside the workspace.

## 3. Runs

2 models x 2 arms x 10 tasks = **40 runs**, one per cell; per model, task by
task, `off` then `on`. A run that fails for infrastructure reasons is
retried once and reported either way, never counted as not done. **Stop
rule:** on the usage limit the runner stops; completed runs are reported as
partial, missing cells named, nothing re-run to change a result.

## 4. Outcomes

- **Done:** the task's check passes.
- **False refusal:** any `block` row in arm `on`'s audit log (a refused
  `tools/call` or a withheld tool), with its rule note.
- **Relative-path calls:** from each run's tool calls, the number of path
  arguments that were relative (`is_relative_path`), per arm. This shows
  whether the fix was exercised at all; a run where the model used only
  absolute paths says nothing about the fix.
- **Evidence of wrapping:** audit rows per arm-`on` run; zero is flagged.
- Category (`classify_run`), tool calls, turns, tokens, wall time.

## 5. Analysis

Per model and arm: done rate and the share of runs with a false refusal
(Wilson 95 %); paired done/not-done discordance per task; every false
refusal listed with its rule note and the argument shape that caused it
(workspace path sanitised); relative-path argument counts per arm.

**Expectations, stated in advance.**

1. **Primary:** Haiku's done count in `on` is within one task of `off`
   (the bar set in the private roadmap before this study was designed;
   the first study's result, 8 vs 10, misses it).
2. Zero false refusals of a relative path inside the workspace, for both
   models.
3. Haiku passes at least one relative path argument in `on` (otherwise the
   fix was not exercised and expectation 2 is reported as untested, not as
   met).

Any false refusal is reported as found, with its cause. If expectation 1 or
2 fails, the README says so and the fix is not described as measured; the
result is not re-run after a further fix (a later study would use new tasks
again).

## 6. Limits stated in advance

Ten tasks, one run each, two models, one host, one machine (Windows), one
server, the configuration where the host runs in the sandbox. Ten runs per
cell cannot bound a small refusal rate (0/10 has a Wilson upper bound of
about 28 %); like the first study, this one is built to find refusal causes.
The prompts name relative paths, which makes relative arguments likelier
than in the first study; that is the behaviour under test, not a sample of
typical use. A host started outside the sandbox is not tested here (`wrap`
warns at startup; those calls are still refused).
