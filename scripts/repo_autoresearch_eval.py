#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class BenchmarkResult:
    benchmark_id: str
    command: str
    weight: float
    passed: bool
    returncode: int
    stdout: str
    stderr: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_pack(pack_path: Path) -> dict:
    with pack_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _git_changed_files(repo_root: Path, diff_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", diff_ref, "--"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git diff failed for {diff_ref}")
    changed = {line.strip() for line in result.stdout.splitlines() if line.strip()}

    untracked_result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if untracked_result.returncode != 0:
        raise RuntimeError(untracked_result.stderr.strip() or "git ls-files failed")
    changed.update(line.strip() for line in untracked_result.stdout.splitlines() if line.strip())
    return sorted(changed)


def _is_allowed(path: str, allowed_surface: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in allowed_surface)


def _run_benchmark(repo_root: Path, benchmark: dict) -> BenchmarkResult:
    command = benchmark["command"]
    result = subprocess.run(
        command,
        cwd=repo_root,
        shell=True,
        check=False,
        capture_output=True,
        text=True,
    )
    return BenchmarkResult(
        benchmark_id=benchmark["id"],
        command=command,
        weight=float(benchmark.get("weight", 1.0)),
        passed=result.returncode == 0,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _append_results_tsv(path: Path, *, timestamp: str, pack_name: str, description: str, diff_ref: str, score: float, scope_ok: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("timestamp\tpack\tdescription\tdiff_ref\tscore\tscope_ok\n", encoding="utf-8")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{timestamp}\t{pack_name}\t{description}\t{diff_ref}\t{score:.2f}\t{int(scope_ok)}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a repo-local autoresearch benchmark pack.")
    parser.add_argument("--pack", required=True, help="Path to the benchmark pack JSON.")
    parser.add_argument("--diff-ref", default="HEAD", help="Git ref used for scope enforcement.")
    parser.add_argument("--results-tsv", help="Optional TSV file to append run summaries to.")
    parser.add_argument("--description", default="", help="Short description for the run summary.")
    args = parser.parse_args()

    repo_root = _repo_root()
    pack_path = (repo_root / args.pack).resolve()
    pack = _load_pack(pack_path)
    allowed_surface = list(pack.get("allowed_surface", []))
    changed_files = _git_changed_files(repo_root, args.diff_ref)
    disallowed_files = [path for path in changed_files if not _is_allowed(path, allowed_surface)]
    scope_ok = not disallowed_files

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(f"pack: {pack.get('name', pack_path.name)}")
    print(f"diff_ref: {args.diff_ref}")
    print(f"changed_files: {len(changed_files)}")
    if changed_files:
        for path in changed_files:
            print(f"  - {path}")
    if not scope_ok:
        print("scope_error:")
        for path in disallowed_files:
            print(f"  - {path}")

    benchmark_results: list[BenchmarkResult] = []
    total_weight = 0.0
    earned_weight = 0.0

    if scope_ok:
        for benchmark in pack.get("benchmarks", []):
            result = _run_benchmark(repo_root, benchmark)
            benchmark_results.append(result)
            total_weight += result.weight
            if result.passed:
                earned_weight += result.weight
            status = "PASS" if result.passed else "FAIL"
            print(f"[{status}] {result.benchmark_id}: {result.command}")
            if result.stdout.strip():
                print(result.stdout.rstrip())
            if result.stderr.strip():
                print(result.stderr.rstrip(), file=sys.stderr)

    score = 100.0 if total_weight == 0 else (earned_weight / total_weight) * 100.0
    if not scope_ok:
        score = 0.0

    summary = {
        "pack": pack.get("name", pack_path.name),
        "description": args.description,
        "diff_ref": args.diff_ref,
        "scope_ok": scope_ok,
        "changed_files": changed_files,
        "score": round(score, 2),
        "benchmarks": [
            {
                "id": result.benchmark_id,
                "passed": result.passed,
                "returncode": result.returncode,
                "weight": result.weight,
            }
            for result in benchmark_results
        ],
    }
    print(json.dumps(summary, indent=2))

    if args.results_tsv:
        _append_results_tsv(
            (repo_root / args.results_tsv).resolve(),
            timestamp=timestamp,
            pack_name=summary["pack"],
            description=args.description,
            diff_ref=args.diff_ref,
            score=score,
            scope_ok=scope_ok,
        )

    failed = any(not result.passed for result in benchmark_results)
    return 1 if failed or not scope_ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
