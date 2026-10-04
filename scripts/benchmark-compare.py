#!/usr/bin/env python3
"""Run other model scanners over the Socair detection benchmark corpus.

Write the corpus first (it is generated, defanged, and safe):

    SOCAIR_BENCHMARK_CORPUS=/tmp/corpus go test ./internal/benchmark -count=1

then point this at it, with each scanner on PATH or named by flag:

    scripts/benchmark-compare.py /tmp/corpus [--picklescan PATH] [--modelscan PATH]
        [--modelaudit PATH] [--fickling PATH] > compare.json

Each scanner is judged by its documented exit code: a finding, clean, or
unable to scan (an error or an unsupported file). The scanners never load the
files; neither does Socair.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

TIMEOUT = 120


def artifact(case_dir):
    if os.path.isdir(os.path.join(case_dir, "model")):
        return os.path.join(case_dir, "model")
    files = [f for f in sorted(os.listdir(case_dir))
             if not f.endswith(".json") and f != "denylist.txt"]
    return os.path.join(case_dir, files[0]) if files else None


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return p.returncode, (p.stdout + p.stderr)[-400:]
    except subprocess.TimeoutExpired:
        return None, "timeout"


# Each scanner's verdict, read the way its documentation describes it. A
# "suspicious" result (picklescan's suspicious globals, fickling's SUSPICIOUS)
# counts as a finding, as Socair's LEAD does.
def count(out, label):
    for line in out.splitlines():
        if line.strip().startswith(label + ":"):
            try:
                return int(line.split(":")[1])
            except ValueError:
                return 0
    return 0


def picklescan(exe, path):
    code, out = run([exe, "-p", path])
    if code is None or count(out, "Scanned files") == 0:
        return "could not scan", out
    if count(out, "Dangerous globals") or count(out, "Infected files"):
        return "finding", out
    if count(out, "Suspicious globals"):
        return "finding (suspicious)", out
    return ("clean" if code == 0 else "could not scan"), out


def modelscan(exe, path):
    code, out = run([exe, "-p", path, "--show-skipped"])
    if code == 1:
        return "finding", out
    if code == 0 and "was skipped" not in out and "Total skipped" not in out:
        return "clean", out
    return "could not scan", out


def modelaudit(exe, path):
    code, out = run([exe, "scan", path])
    return {0: "clean", 1: "finding"}.get(code, "could not scan"), out


def fickling(exe, path):
    if os.path.isdir(path):
        return "could not scan", "directory"
    report = path + ".fickling.json"
    code, out = run([exe, "--check-safety", "--json-output", report, path])
    try:
        with open(report) as f:
            sev = json.load(f).get("severity", "")
        os.remove(report)
    except (OSError, ValueError):
        return "could not scan", out
    if sev == "LIKELY_SAFE":
        return "clean", sev
    if sev == "SUSPICIOUS":
        return "finding (suspicious)", sev
    return ("finding" if sev else "could not scan"), sev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    for tool in ("picklescan", "modelscan", "modelaudit", "fickling"):
        ap.add_argument("--" + tool, default=shutil.which(tool))
    a = ap.parse_args()
    tools = {"picklescan": (a.picklescan, picklescan), "modelscan": (a.modelscan, modelscan),
             "modelaudit": (a.modelaudit, modelaudit), "fickling": (a.fickling, fickling)}
    results = {}
    for case in sorted(os.listdir(a.corpus)):
        path = artifact(os.path.join(a.corpus, case))
        if not path:
            continue
        results[case] = {}
        for name, (exe, fn) in tools.items():
            if not exe:
                continue
            verdict, out = fn(exe, path)
            results[case][name] = {"verdict": verdict, "tail": out}
    json.dump(results, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
