# ClawPass Repo Autoresearch

The target is the application and SDK surface that materially changes producer and approver behavior:

- `pyproject.toml`
- `Dockerfile`
- `docker-compose.yml`
- `src/ledgerclaw_server/**/*.py`
- `src/ledgerclaw_sdk_py/**/*.py`
- `ts-sdk/**/*`
- `tests/**/*.py`
- `examples/**/*.py`
- `README.md`
- `docs/**/*`
- repo-local autoresearch files in `autoresearch/` and `scripts/repo_autoresearch_eval.py`

## Goal

Improve correctness, contract clarity, and producer-facing ergonomics while keeping changes small and reproducible.

## Baseline

Run:

```bash
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.fast.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "baseline"
```

## Experiment Loop

1. Choose one bounded hypothesis.
2. Change only files inside the allowed surface.
3. Run the fast pack against the current tree.
4. Keep only changes that improve the repo or materially clarify the contract without regressing checks.
5. Run the full pack before calling a candidate strong.

## Good Targets

- input validation that prevents misleading 500s
- lifecycle truth for approval requests and webhook events
- SDK parity with the HTTP API
- narrow performance fixes with regression coverage

## Avoid

- broad rewrites without a concrete contract thesis
- evaluator or pack churn mixed into scored experiments
- generated artifact churn without a linked behavior change
