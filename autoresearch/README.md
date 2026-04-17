# ClawPass Autoresearch

This directory provides a repo-local outer-loop harness for improving `clawpass`.

Scope is intentionally limited:

- package/runtime entrypoints in `pyproject.toml`, `Dockerfile`, and `docker-compose.yml`
- core service and API code in `src/`
- SDK surfaces in `src/clawpass_sdk_py/` and `ts-sdk/`
- repo tests and examples
- repo-local autoresearch control files and evaluator

The goal is to keep experiments reviewable and grounded in reproducible checks, rather than mutating the whole repo blindly.

## Packs

- `benchmark-pack.fast.json`: quick keep/discard pass for iteration speed
- `benchmark-pack.full.json`: broader confirmation pass before keeping a stronger candidate, including both Python and TypeScript SDK round-trip checks

Run the fast pack from the repo root:

```bash
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.fast.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "baseline"
```

Use [`program.md`](./program.md) as the human-authored control file for future loops.
