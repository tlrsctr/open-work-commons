# Seeded cross-agent handoff benchmark v0

This benchmark asks whether a verified Open Work Commons resume bundle helps a fresh coding agent continue an interrupted task. It is deliberately small, synthetic, deterministic, and capable of producing a null or negative result.

The participant receives only a copy of `interrupted/` and `ISSUE.md`. The source agent also received the clarifications in `source-session-interventions.md` before interruption. In the assisted condition those decisions must arrive through the verified resume bundle; in the baseline condition they do not. The evaluator is held outside the participant workspace during a run.

## Frozen comparison

Run four conditions from byte-identical interrupted repositories:

1. Codex baseline: issue and repository only.
2. Codex assisted: issue, repository, and Claude-originated resume bundle.
3. Claude baseline: issue and repository only.
4. Claude assisted: issue, repository, and Codex-originated resume bundle.

The evaluator, interruption snapshot, issue, time limit, and measures are frozen before the first run. Do not change them after inspecting a result. A run may fail, and an assisted run may perform worse.

## Task

The interrupted package implements a fail-closed release-evidence gate. Its public tests pass at the interruption point, but several decisions made during the source session are not yet implemented. The receiving agent must finish the implementation without access to the source transcript.

The hidden acceptance suite covers the visible issue plus the recorded source-session decisions. It uses only synthetic values and makes no network calls.

## Preparing a run

Copy `interrupted/` into a fresh Git repository. Give the participant `ISSUE.md`; for an assisted run also give it the resume Markdown. Do not copy this README, the interventions file, `benchmark.json`, or `evaluator/` into the participant workspace.

Record the start and stop time, agent and version, direction, condition, input and output token counts when available, repeated questions, human corrections, and the final commit digest. Run public tests during the task with:

```sh
npm test
```

After the participant stops, evaluate from the benchmark custodian checkout:

```sh
OWC_BENCHMARK_CANDIDATE=/absolute/path/to/candidate \
  node --test evaluator/acceptance.test.mjs
```

The candidate path is intentionally explicit; the evaluator never searches parent directories or a network service.

## Measures

The primary result is whether every acceptance test passes. Secondary measures are time or tokens to first correct action, total time and tokens, questions whose answer already existed in the resume bundle, source-session constraints missed or contradicted, and human correction count.

Report raw values for all four runs. Do not collapse the result into a claim of general agent superiority.

## Custody and leakage

The evaluator and reference implementation are public for auditability but hidden operationally by workspace separation. Any run in which the participant reads the evaluator, reference, or interventions is invalid. No real transcript, credential, personal data, private repository content, or hidden chain-of-thought is part of this benchmark.
