# Filesystem false-refusal study (v0.2): pre-registration

Written before any model call. `scripts/fs_utility_study.py freeze` records
the sha256 of this file, `src/toolgate/fs_utility_study.py` and
`scripts/fs_utility_study.py` in `results/fs-utility-study/frozen.json`;
`run` and `analyse` refuse if any changed. Results are reported against this
document, deviations included.

## 1. Question

Do toolgate's argument rules refuse legitimate calls? The mail study
(docs/UTILITY-STUDY.md) could not answer this: its policy had no argument
rules. Here the real filesystem server is wrapped with `paths` rules that
confine every tool to the run's workspace, and every task stays inside that
workspace, so **any toolgate refusal in arm `on` is a false refusal**. The
likeliest source is path handling: a model may pass a relative path, a
different separator or a different spelling of the workspace root, which the
server accepts and the rule might not.

## 2. Setup

- **Host.** Claude Code (version recorded at freeze), headless, with the
  isolation of `scripts/record_agent_demo.py`: only this server
  (`--strict-mcp-config`), no built-in tools, `--allowedTools
  mcp__filesystem`, `--permission-prompts none`, `--setting-sources local`
  from an empty working directory, `--no-session-persistence`,
  `--append-system-prompt` with `SYSTEM`. Windows dev machine.
- **Models.** `claude-haiku-4-5-20251001`, `claude-sonnet-5-5`.
- **Server.** `@modelcontextprotocol/server-filesystem@2026.8.31` (the demo's
  pinned version), rooted at a fresh copy of the fixed workspace
  (`make_workspace`) for every run.
- **Arms.** `off`: the server started directly. `on`: started through
  `toolgate wrap --name filesystem` with `policy_for(workspace)`: `default:
  block`, every path tool confined to `{sandbox}` and `{sandbox}/**`, the
  other string arguments classified as the server declares them (the demo
  policy; what `policy suggest` drafts with its placeholder replaced). Its
  classification of the real server's tools is checked by
  `tests/test_fs_utility_study.py`.
- **Tasks.** The ten tasks in `TASKS` (read, list, write, edit, search,
  move, sum, mkdir, compare, tree), each with a deterministic check on the
  workspace after the run and on the final answer. Every check is tested to
  fail on the untouched workspace and pass on a correct outcome. No task is
  adversarial and every task stays inside the workspace.

## 3. Runs

2 models x 2 arms x 10 tasks = **40 runs**, one per cell; per model, task by
task, `off` then `on`. A run that fails for infrastructure reasons is
retried once and reported either way, never counted as not done. **Stop
rule:** on the usage limit the runner stops; completed runs are reported as
partial, missing cells named, nothing re-run to change a result.

## 4. Outcomes

- **Done:** the task's check passes.
- **False refusal:** any `block` row in arm `on`'s audit log: a refused
  `tools/call` (`toolgate_blocks`) or a withheld tool (`toolgate_withheld`).
  Each refusal's rule note is kept.
- **Evidence of wrapping:** the number of audit rows per arm-`on` run; a run
  with zero rows is flagged.
- Category (`classify_run`), tool calls, turns, tokens, wall time.

## 5. Analysis

Per model and arm: done rate and the share of runs with a false refusal,
with Wilson 95 % intervals; paired done/not-done discordance per task; every
false refusal listed with its rule note and the argument shape that caused
it (from the tool call; the workspace path is sanitised).

**Expectation, stated in advance.** Zero false refusals, and done in `on`
within one task of `off` per model. Any false refusal is reported as found,
with its cause, as a utility cost of toolgate, and becomes a bug to fix in
a later version; the result is not re-run after a fix.

## 6. Limits stated in advance

Ten tasks, one run each, two models, one host, one machine (Windows), one
server. Ten runs per cell cannot estimate a small false-refusal rate
precisely (0/10 has a Wilson upper bound of about 28 %); the study is built
to find refusal causes, not to bound their rate.
