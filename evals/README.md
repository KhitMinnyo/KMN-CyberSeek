# KMN-CyberSeek Reasoning Evals

A small harness that measures the **quality of the AI's next-step decisions**
against fixed engagement scenarios, so a change to `ai/prompts.py` (or the model)
can be judged by a score delta instead of a gut feeling.

Each scenario freezes a realistic engagement state and asserts methodology
properties about the decision the AI returns — e.g. *fingerprint before running
CMS-specific tools*, *never blindly repeat a completed scan*, *reuse discovered
credentials*, *use the hostname (not the raw IP) for virtual-host routing*, and
*every command must be non-interactive*. Because the model is stochastic, each
scenario can be run several times and the harness reports the **mean score and
variance**.

## Running

```bash
# Score against your configured provider (DeepSeek API or local Ollama).
# Uses the same KMN_AI_Connector the live loop uses, so it exercises the real
# prompt + parsing path.
python3 evals/run_evals.py --runs 3

# Validate the scoring rules themselves — no model or network needed.
python3 evals/run_evals.py --selfcheck
```

Provider selection follows the normal config: a valid `DEEPSEEK_API_KEY` forces
API mode; otherwise it uses local Ollama (`OLLAMA_URL` / `OLLAMA_MODEL`). If
neither is available the harness prints a clear skip message and exits `2`.

## Interpreting output

```
  OK web_fingerprint_before_cms         mean= 1.00 var=0.000
  ~  credential_reuse_priority          mean= 0.67 var=0.056  failed: tests_other_service
  ...
  OVERALL REASONING SCORE: 92.00%  (5 scenarios x 3 runs)
```

* `mean` — fraction of a scenario's checks passed, averaged across runs (1.0 = perfect).
* `var`  — variance across runs; high variance means the model is inconsistent on
  that property and the prompt could be tightened.
* `failed:` — the checks that missed at least once, so you know exactly what to fix.

## Workflow for improving a prompt

1. Record a baseline: `python3 evals/run_evals.py --runs 5`.
2. Edit `ai/prompts.py`.
3. Re-run and compare the overall score and the per-scenario `failed:` lists.

## Adding scenarios

Append to `SCENARIOS` in `evals/scenarios.py`. Reuse the predicates in
`evals/rules.py` (`contains_any`, `excludes_all`, `command_regex`,
`not_equal_to`, `reasoning_or_cmd_mentions`, `is_non_interactive`, `valid_phase`)
or add new ones. Then extend the `_GOOD` / `_BAD` maps in `run_evals.py` so
`--selfcheck` continues to prove the new rules actually discriminate.
```
