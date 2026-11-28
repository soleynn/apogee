#!/usr/bin/env python3
"""Measure Wine/Proton runners against each other with the official FFXIV benchmark.

The one driver for a runner comparison, from host checks to the verdict. Standard library only.

    runner-sweep.py example-config > sweep.json     # a starting configuration to edit
    runner-sweep.py run sweep.json --dry-run        # print the whole plan, launch nothing
    runner-sweep.py run sweep.json                  # run it (resumable; re-run to continue)
    runner-sweep.py run sweep.json --blocks 6-10    # the second session, on another day
    runner-sweep.py analyze sweep.json              # cross-run statistics and the decision
    runner-sweep.py selftest                        # the statistics, offline

What one sweep does
-------------------
Every cell is one runner in its own prefix with its own shader-cache directories (DXVK, NVIDIA,
Mesa) under $HOME, so pressure-vessel can see them and no cell inherits another's compiled
pipelines. One extra cell, the A/A control, is a second copy of the main candidate in its own prefix
and cache: anything that separates the two copies is noise, and the sweep's decision threshold is
derived from it.

  1. Preflight: kernel and userspace NVIDIA driver agree, Vulkan is on a real GPU, the driver is new
     enough for DXVK 3's descriptor heap, ntsync is present if used, the CPU governor is
     `performance`, automatic upgrades are stopped, and nothing on the deny list is running.
  2. Prefixes: created and initialised before any timed pass; never inside a measured run.
  3. Cold runs: each from emptied caches. Load times from these see a warm page cache and are not
     ranked; the time to reach steady frame rate is.
  4. Warm-up to convergence: passes repeat until the cache stops growing (under 1% between passes)
     and the stall count stops falling; at least 2, at most 5, one repeat after cooldown if not.
  5. Blocks: one measured warm run of every cell per block, in an independent random order per
     block derived from the recorded seed. Cooldown between runs.

Each run deletes the benchmark's launcher ini (a killed run leaves a cancel flag in it that boots
the next one to a black screen), launches `game/ffxiv_dx11.exe` directly with the configured
`SYS.*` arguments, waits for the score, and records: the ini's [SCORE] section, the MangoHud log and
`apogee-cli bench analyze --json` over it, the DXVK version from its info log, cache sizes, a
host-side GPU sampler (clock, temperature, throttle reasons), and CPU time used outside the game's
process tree. All of it lands in one manifest JSON per cell.

The statistics
--------------
The unit of analysis is the run. The leader is the candidate with the highest median warm 1% low;
each other candidate is compared with it by an exact two-sided Wilcoxon signed-rank test on the
paired per-block 1%-low differences, Holm-corrected across those comparisons. The leader beats a
runner only when the corrected p is under 0.05, the median paired difference is at least the
threshold (3%, or twice the A/A noise floor if larger), and the leader's median stall count is no
worse. The sweep is invalid if the noise floor is over 5% or the A/A pair itself tests different.
Ties are broken by jitter, then p99.9 frametime, then average FPS (2% margin), then cold time to
steady, then the configured stability order.

Nothing here downloads the benchmark or ships any of its bytes: point `bench_dir` at the copy you
downloaded and agreed to.
"""

from __future__ import annotations

import argparse
import configparser
import itertools
import json
import math
import os
import random
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------------------------
# Constants of the protocol. Changing one changes what a result means; record it if you do.
# ---------------------------------------------------------------------------------------------

ALPHA = 0.05
MIN_THRESHOLD_PCT = 3.0
NOISE_FLOOR_MAX_PCT = 5.0
AVG_FPS_MARGIN_PCT = 2.0
MAX_INVALID_RUNS = 1
TIME_TO_STEADY_MAX_RATIO = 1.5
STEADY_WINDOW_S = 5.0
STEADY_TOLERANCE = 0.05
CONVERGE_GROWTH = 0.01
CONVERGE_STALL_ABS = 2
CONVERGE_STALL_REL = 0.20
WARMUP_MIN = 2
WARMUP_MAX = 5
OUTSIDE_CPU_CORE_FRACTION = 0.05
OUTSIDE_CPU_MAX_SECONDS = 2
CLOCK_DIP_FRACTION = 0.05
CLOCK_DIP_MAX_S = 2.0
LOADING_FPS = 5.0
LOADING_MIN_MS = 1000.0
LOADING_MIN_FRAMES = 2
NVIDIA_CACHE_SIZE = "10737418240"
BOOTSTRAP_RESAMPLES = 10000

# NVML throttle-reason bits, as nvidia-smi prints them in clocks_throttle_reasons.active.
THROTTLE_GPU_IDLE = 0x1
THROTTLE_HW_SLOWDOWN = 0x8
THROTTLE_SW_THERMAL = 0x20
THROTTLE_HW_THERMAL = 0x40
THROTTLE_THERMAL = THROTTLE_HW_SLOWDOWN | THROTTLE_SW_THERMAL | THROTTLE_HW_THERMAL

# Process names that must not be running during a block, matched against /proc/<pid>/comm (which
# the kernel truncates to 15 characters), case-insensitively. A trailing `*` matches a prefix.
DEFAULT_DENY = [
    "firefox", "firefox-bin", "chrome", "chromium*", "brave*", "vivaldi*", "opera", "epiphany",
    "Discord", "vesktop", "steam", "steamwebhelper", "lutris", "heroic",
    "code", "codium", "idea", "clion", "pycharm", "rustrover", "zed", "rust-analyzer",
    "baloo_file", "tracker-miner*", "localsearch*", "updatedb", "packagekitd",
    "apt", "apt-get", "dpkg", "unattended-upgr", "dnf", "pacman", "flatpak", "nix-build",
    "obs", "gamescope*", "wineserver", "ffxiv_dx11.exe",
]


class SweepError(Exception):
    """A condition that stops the sweep, with a message saying what to fix."""


# ---------------------------------------------------------------------------------------------
# Statistics. Pure functions over numbers, exercised by `selftest`.
# ---------------------------------------------------------------------------------------------


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def average_ranks(values):
    """Ranks of `values` (1-based), ties sharing the mean of the ranks they span."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def wilcoxon_signed_rank(differences):
    """Exact two-sided Wilcoxon signed-rank test. Returns (W+, p, n used).

    Zero differences are dropped (Wilcoxon's convention). Tied magnitudes share average ranks, and
    the null distribution is enumerated over those same ranks, so the p-value stays exact with ties.
    """
    d = [x for x in differences if x != 0]
    n = len(d)
    if n == 0:
        return 0.0, 1.0, 0
    ranks = average_ranks([abs(x) for x in d])
    # Doubled ranks are integers even when ties make them half-integers.
    doubled = [int(round(2 * r)) for r in ranks]
    w_plus2 = sum(r for r, x in zip(doubled, d) if x > 0)
    counts = {0: 1}
    for r in doubled:
        nxt = dict(counts)
        for s, c in counts.items():
            nxt[s + r] = nxt.get(s + r, 0) + c
        counts = nxt
    space = 2**n
    lower = sum(c for s, c in counts.items() if s <= w_plus2) / space
    upper = sum(c for s, c in counts.items() if s >= w_plus2) / space
    # The distribution is symmetric about total/2, so doubling the smaller tail is exact.
    p = min(1.0, 2 * min(lower, upper))
    return w_plus2 / 2, p, n


def holm(pvalues):
    """Holm step-down adjusted p-values, in the input order."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def bootstrap_median_ci(values, seed, level=0.95, resamples=BOOTSTRAP_RESAMPLES):
    """Percentile bootstrap CI of the median. Reported only; never used to decide."""
    if not values:
        return None
    rng = random.Random(seed)
    meds = sorted(
        statistics.median(rng.choices(values, k=len(values))) for _ in range(resamples)
    )
    lo = meds[int(math.floor((1 - level) / 2 * resamples))]
    hi = meds[min(resamples - 1, int(math.ceil((1 + level) / 2 * resamples)) - 1)]
    return [lo, hi]


def pct_diff(leader, other):
    """How far `other` falls below `leader`, in percent of the leader."""
    return 100.0 * (leader - other) / leader


def block_order(seed, block, cells):
    """The cell order for one block: an independent permutation keyed by the seed and the block, so
    a block run on another day (or re-run) gets the same order it was planned with."""
    order = sorted(cells)
    random.Random(f"{seed}:{block}").shuffle(order)
    return order


def converged(sizes, stalls):
    """Whether the warm-up passes so far have converged, per the two-part rule.

    `sizes` are the cell's total cache bytes after each pass and `stalls` the stall counts (frames
    over 50 ms outside loading windows), oldest first.
    """
    if len(sizes) < max(WARMUP_MIN, 2):
        return False
    prev, last = sizes[-2], sizes[-1]
    growth_ok = prev > 0 and (last - prev) / prev < CONVERGE_GROWTH
    s_prev, s_last = stalls[-2], stalls[-1]
    if s_prev is None or s_last is None:
        return False
    allowed = max(CONVERGE_STALL_ABS, CONVERGE_STALL_REL * s_prev)
    stall_ok = (s_prev - s_last) <= allowed
    return growth_ok and stall_ok


def split_loading(frames):
    """Drop loading windows from `(frametime_ms, fps or None)` frames. A window is a run of at least
    two consecutive frames under 5 FPS whose frametimes sum to at least a second. Anything else slow
    is a stall and stays, including a single frame however long (the same rule as the CLI)."""
    out, i = [], 0
    slow = lambda f: (f[1] if f[1] is not None else 1000.0 / f[0]) < LOADING_FPS  # noqa: E731
    while i < len(frames):
        if not slow(frames[i]):
            out.append(frames[i][0])
            i += 1
            continue
        j = i
        while j < len(frames) and slow(frames[j]):
            j += 1
        run = frames[i:j]
        if len(run) < LOADING_MIN_FRAMES or sum(f[0] for f in run) < LOADING_MIN_MS:
            out.extend(f[0] for f in run)
        i = j
    return out


def low_fps(frametimes, fraction):
    """FPS of the mean frametime of the slowest `fraction` of frames (the same rule as the CLI)."""
    if not frametimes:
        return None
    s = sorted(frametimes)
    count = max(1, min(len(s), math.ceil(len(s) * fraction)))
    tail = s[-count:]
    return 1000.0 / (sum(tail) / count)


def rolling_fps(frametimes, window_s=STEADY_WINDOW_S, step_s=1.0):
    """FPS over the trailing `window_s` of benchmark time, sampled every `step_s`, as {t: fps}.

    Benchmark time is the cumulative frametime from the log's first frame. The benchmark's camera
    path is deterministic and logging starts a fixed time after launch, so the same t is the same
    point in the scene across runs.
    """
    t, times = 0.0, []
    for ft in frametimes:
        t += ft / 1000.0
        times.append(t)
    out, lo, k = {}, 0, 0
    grid = window_s
    while times and grid <= times[-1]:
        while k < len(times) and times[k] <= grid:
            k += 1
        while lo < k and times[lo] <= grid - window_s:
            lo += 1
        out[round(grid, 3)] = (k - lo) / window_s
        grid += step_s
    return out


def time_to_steady(cold, warm_runs):
    """The first t after which the cold run's rolling FPS stays within 5% of the median warm rolling
    FPS at the same t. `cold` and each of `warm_runs` are {t: fps}. None if never steady."""
    grid = sorted(t for t in cold if all(t in w for w in warm_runs))
    if not grid or not warm_runs:
        return None
    steady_from = None
    for t in grid:
        ref = statistics.median(w[t] for w in warm_runs)
        ok = ref > 0 and abs(cold[t] - ref) <= STEADY_TOLERANCE * ref
        if ok and steady_from is None:
            steady_from = t
        elif not ok:
            steady_from = None
    # The window ends at t, so the run is steady from the start of the first steady window.
    return None if steady_from is None else max(0.0, steady_from - STEADY_WINDOW_S)


def longest_dip_seconds(samples, fraction=CLOCK_DIP_FRACTION):
    """Longest contiguous stretch, in seconds, that the GPU clock spent `fraction` below the median.

    `samples` are (seconds, clock_mhz, throttle_bits). Samples with the idle bit set (loading
    screens, menus) are left out, since an idle GPU lowering its clock is not throttling.
    """
    busy = [(t, c) for t, c, bits in samples if c and not (bits & THROTTLE_GPU_IDLE)]
    if not busy:
        return None
    floor = statistics.median(c for _, c in busy) * (1 - fraction)
    longest, start, prev = 0.0, None, None
    for t, c in busy:
        if c < floor:
            if start is None:
                start = prev if prev is not None else t
            longest = max(longest, t - start)
        else:
            start = None
        prev = t
    return longest


def outside_cpu_invalid(per_second_cpu):
    """Whether the CPU used outside the game's process tree invalidates the run."""
    over = sum(1 for s in per_second_cpu if s > OUTSIDE_CPU_CORE_FRACTION)
    return over > OUTSIDE_CPU_MAX_SECONDS


# ---------------------------------------------------------------------------------------------
# The decision, over per-cell run summaries.
# ---------------------------------------------------------------------------------------------


def run_metrics(analyze_report):
    """The per-run figures the decision reads, from one `bench analyze --json` report."""
    measured = analyze_report.get("measured") or {}
    stats = measured.get("stats") or analyze_report.get("all_frames") or {}
    return {
        "low_1pct": stats.get("low_1pct"),
        "average_fps": stats.get("average_fps"),
        "stalls_50": (measured.get("stalls_over_50ms") or {}).get("count"),
        "jitter_ms": measured.get("jitter_ms"),
        "p99_9_ms": measured.get("p99_9_ms"),
        "valid": bool((analyze_report.get("validity") or {}).get("valid", False)),
    }


def decide(cells, seed=0):
    """The verdict over the cells' warm runs.

    `cells` maps a cell name to:
      role:      "candidate", "reference" (reported, never selected) or "control" (the A/A copy)
      runs:      {block: metrics dict as from run_metrics, plus "valid"} for the warm blocks
      crashed:   any run crashed or hung
      time_to_steady: median cold time to steady in seconds, or None
      stability: lower is more conservative, the last tie-break
      control_of: (control only) the candidate it copies
    """
    report = {"cells": {}, "comparisons": [], "invalid": [], "winner": None}
    for name, cell in cells.items():
        runs = cell["runs"]
        invalid = sum(1 for r in runs.values() if not r["valid"])
        good = [r for r in runs.values() if r["valid"]]
        report["cells"][name] = {
            "role": cell["role"],
            "runs": len(runs),
            "invalid_runs": invalid,
            "median_low_1pct": median(r["low_1pct"] for r in good),
            "median_stalls_50": median(r["stalls_50"] for r in good),
            "median_jitter_ms": median(r["jitter_ms"] for r in good),
            "median_p99_9_ms": median(r["p99_9_ms"] for r in good),
            "median_average_fps": median(r["average_fps"] for r in good),
            "time_to_steady_s": cell.get("time_to_steady"),
            "disqualified": [],
        }
        row = report["cells"][name]
        if cell.get("crashed"):
            row["disqualified"].append("a run crashed or hung")
        if invalid > MAX_INVALID_RUNS:
            row["disqualified"].append(f"{invalid} invalid runs")
    tts = [c["time_to_steady_s"] for c in report["cells"].values()
           if c["role"] == "candidate" and c["time_to_steady_s"] is not None]
    if tts:
        best = min(tts)
        for row in report["cells"].values():
            t = row["time_to_steady_s"]
            if row["role"] == "candidate" and t is not None and t > TIME_TO_STEADY_MAX_RATIO * best:
                row["disqualified"].append("cold time to steady over 1.5x the best")

    def paired(a, b):
        ra, rb = cells[a]["runs"], cells[b]["runs"]
        blocks = sorted(k for k in ra if k in rb and ra[k]["valid"] and rb[k]["valid"])
        return blocks, [pct_diff(ra[k]["low_1pct"], rb[k]["low_1pct"]) for k in blocks]

    # The noise floor, from the A/A pair: the median magnitude of their paired differences. The
    # magnitude, because a signed median of noise centres on zero however loud the noise is.
    controls = [n for n, c in cells.items() if c["role"] == "control"]
    noise_floor, aa_p = None, None
    if controls:
        ctrl = controls[0]
        _, diffs = paired(cells[ctrl]["control_of"], ctrl)
        if diffs:
            noise_floor = statistics.median(abs(d) for d in diffs)
            aa_p = wilcoxon_signed_rank(diffs)[1]
    else:
        report["invalid"].append("no A/A control cell, so there is no noise floor")
    if noise_floor is not None and noise_floor > NOISE_FLOOR_MAX_PCT:
        report["invalid"].append(f"noise floor {noise_floor:.2f}% is over {NOISE_FLOOR_MAX_PCT}%")
    if aa_p is not None and aa_p < ALPHA:
        report["invalid"].append(f"the A/A pair tests different (p = {aa_p:.4f})")
    if controls and noise_floor is None:
        report["invalid"].append("the A/A pair has no paired valid blocks")
    threshold = max(MIN_THRESHOLD_PCT, 2 * (noise_floor or 0.0))
    report.update(noise_floor_pct=noise_floor, aa_p=aa_p, threshold_pct=threshold)

    eligible = [n for n, row in report["cells"].items()
                if row["role"] == "candidate" and not row["disqualified"]
                and row["median_low_1pct"] is not None]
    if not eligible:
        report["invalid"].append("no eligible candidate")
        return report
    leader = max(eligible, key=lambda n: report["cells"][n]["median_low_1pct"])
    report["leader"] = leader

    others = [n for n in eligible if n != leader]
    raw = []
    for other in others:
        blocks, diffs = paired(leader, other)
        w, p, used = wilcoxon_signed_rank(diffs)
        raw.append(p)
        report["comparisons"].append({
            "leader": leader, "other": other, "blocks": blocks, "diffs_pct": diffs,
            "median_diff_pct": median(diffs), "w_plus": w, "n": used, "p": p,
            "ci95_median_diff_pct": bootstrap_median_ci(diffs, seed=f"{seed}:{other}"),
        })
    for comp, adj in zip(report["comparisons"], holm(raw)):
        lead, oth = report["cells"][leader], report["cells"][comp["other"]]
        stalls_ok = (lead["median_stalls_50"] is not None and oth["median_stalls_50"] is not None
                     and lead["median_stalls_50"] <= oth["median_stalls_50"])
        comp["p_holm"] = adj
        comp["leader_beats"] = (adj < ALPHA and comp["median_diff_pct"] is not None
                                and comp["median_diff_pct"] >= threshold and stalls_ok)
    # References are compared for the record, outside the corrected family.
    for name, row in report["cells"].items():
        if row["role"] == "reference" and row["median_low_1pct"] is not None:
            blocks, diffs = paired(leader, name)
            report.setdefault("references", []).append({
                "other": name, "median_diff_pct": median(diffs),
                "p_uncorrected": wilcoxon_signed_rank(diffs)[1],
            })

    tied = [leader] + [c["other"] for c in report["comparisons"] if not c["leader_beats"]]
    report["tied_with_leader"] = tied
    report["tie_break"] = []
    pool = list(tied)
    row = report["cells"]

    def keep_best(key, lower_is_better, margin_pct=0.0):
        nonlocal pool
        known = [n for n in pool if row[n][key] is not None] if key in row[pool[0]] else []
        if len(pool) <= 1 or not known:
            return
        best = (min if lower_is_better else max)(row[n][key] for n in known)
        if lower_is_better:
            keep = [n for n in known if row[n][key] <= best]
        else:
            keep = [n for n in known if row[n][key] >= best * (1 - margin_pct / 100)]
        if len(keep) < len(pool):
            report["tie_break"].append({"by": key, "kept": keep})
        pool = keep

    keep_best("median_jitter_ms", True)
    keep_best("median_p99_9_ms", True)
    keep_best("median_average_fps", False, AVG_FPS_MARGIN_PCT)
    keep_best("time_to_steady_s", True)
    if len(pool) > 1:
        pool.sort(key=lambda n: cells[n].get("stability", 0))
        report["tie_break"].append({"by": "stability", "kept": pool[:1]})
        pool = pool[:1]
    report["winner"] = None if report["invalid"] else pool[0]
    return report


# ---------------------------------------------------------------------------------------------
# Configuration and the plan.
# ---------------------------------------------------------------------------------------------

EXAMPLE_CONFIG = {
    "output": "~/apogee-sweep/results",
    "cell_root": "~/apogee-sweep/cells",
    "prefix_root": "~/apogee-sweep/prefixes",
    "bench_dir": "~/ffxiv-dawntrail-bench",
    "bench_ini": "ffxivbenchmarklauncher.ini",
    "sys_args": ["SYS.Language=1"],
    "resolution": "1280x720",
    "apogee_cli": "apogee-cli",
    "umu_run": "umu-run",
    "seed": 20261121,
    "blocks": 10,
    "cold_runs": 3,
    "driver_cold_runs": 0,
    "sync": "ntsync",
    "min_driver": "595.84",
    "log_duration_s": 400,
    "run_timeout_s": 900,
    "cooldown_min_s": 60,
    "cooldown_max_s": 900,
    "cooldown_gpu_delta_c": 3,
    "allowed_cpus": None,
    "deny": DEFAULT_DENY,
    "attest": {
        "compositor_effects_off": False,
        "game_vsync_off": False,
        "vrr_off": False,
        "xwayland_not_gamescope": False,
    },
    "cells": [
        {"name": "ge-proton-11-12", "kind": "proton", "runner": "~/runners/GE-Proton11-12",
         "version": "GE-Proton11-12", "role": "candidate", "stability": 1},
        {"name": "wine-xiv", "kind": "wine", "runner": "~/runners/wine-xiv/bin/wine",
         "version": "10.8.r0.a2ca9e4", "role": "candidate", "stability": 0,
         "dxvk_dir": "~/runners/dxvk-2.6"},
        {"name": "umu-proton", "kind": "proton", "runner": "~/runners/UMU-Proton",
         "version": "UMU-Proton stable", "role": "reference"},
    ],
    "aa_control": "ge-proton-11-12",
}


def expand(p):
    return Path(os.path.expandvars(os.path.expanduser(str(p))))


SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")


def load_config(path):
    cfg = dict(EXAMPLE_CONFIG)
    cfg.update(json.loads(Path(path).read_text()))
    names = [c["name"] for c in cfg["cells"]]
    # Cell names become directory names that are emptied and deleted, so each must be one plain path
    # component: no separator, no "..", nothing absolute.
    for name in names:
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or name in (".", ".."):
            raise SweepError(f"cell name {name!r} must be letters, digits, '.', '_' or '-'")
    ini = cfg.get("bench_ini")
    if not isinstance(ini, str) or not SAFE_NAME.fullmatch(ini) or ini in (".", ".."):
        raise SweepError("bench_ini must be a bare file name inside bench_dir")
    if len(set(names)) != len(names):
        raise SweepError("cell names must be unique")
    for c in cfg["cells"]:
        if c.get("kind") not in ("proton", "wine"):
            raise SweepError(f"cell {c['name']}: kind must be proton or wine")
        if c.get("role", "candidate") not in ("candidate", "reference"):
            raise SweepError(f"cell {c['name']}: role must be candidate or reference")
        c.setdefault("role", "candidate")
    aa = cfg.get("aa_control")
    if aa not in names:
        raise SweepError("aa_control must name a candidate cell")
    control = dict(next(c for c in cfg["cells"] if c["name"] == aa))
    control.update(name=f"{aa}-aa", role="control", control_of=aa)
    cfg["cells"] = cfg["cells"] + [control]
    home = Path.home().resolve()
    cell_root = expand(cfg["cell_root"])
    if home not in cell_root.resolve().parents and cell_root.resolve() != home:
        raise SweepError("cell_root must be under $HOME, where pressure-vessel can see it")
    return cfg


def cell_dirs(cfg, cell):
    root = expand(cfg["cell_root"]) / cell["name"]
    return {"root": root, "dxvk": root / "dxvk", "nv": root / "nv", "mesa": root / "mesa"}


def prefix_dir(cfg, cell):
    return expand(cfg["prefix_root"]) / cell["name"]


def parse_blocks(spec, total):
    if not spec:
        return list(range(1, total + 1))
    lo, _, hi = spec.partition("-")
    lo, hi = int(lo), int(hi or lo)
    if not 1 <= lo <= hi <= total:
        raise SweepError(f"--blocks {spec} is outside 1-{total}")
    return list(range(lo, hi + 1))


def run_env(cfg, cell, run_dir):
    """The environment one measured run gets, on top of the caller's."""
    d = cell_dirs(cfg, cell)
    mango = ",".join([
        "autostart_log=1", f"log_duration={cfg['log_duration_s']}", "log_interval=0",
        "log_versioning=1", f"output_folder={run_dir / 'mangohud'}", "fps", "frametime",
        "cpu_stats", "cpu_temp", "cpu_mhz", "gpu_stats", "gpu_temp", "gpu_core_clock",
        "gpu_mem_clock", "gpu_power", "vram", "ram",
    ])
    env = {
        "WINEPREFIX": str(prefix_dir(cfg, cell)),
        "DXVK_SHADER_CACHE_PATH": str(d["dxvk"]),
        "DXVK_STATE_CACHE_PATH": str(d["dxvk"]),
        "__GL_SHADER_DISK_CACHE": "1",
        "__GL_SHADER_DISK_CACHE_PATH": str(d["nv"]),
        "__GL_SHADER_DISK_CACHE_SIZE": NVIDIA_CACHE_SIZE,
        "__GL_SHADER_DISK_CACHE_SKIP_CLEANUP": "1",
        "MESA_SHADER_CACHE_DIR": str(d["mesa"]),
        "MESA_SHADER_CACHE_MAX_SIZE": "8G",
        "DXVK_LOG_LEVEL": "info",
        "DXVK_LOG_PATH": str(run_dir / "dxvk"),
        "DXVK_CONFIG": "dxgi.syncInterval = 0",
        "MANGOHUD": "1",
        "MANGOHUD_CONFIG": mango,
    }
    if cfg["sync"] == "fsync":
        env.update(WINEFSYNC="1", WINENTSYNC="0", PROTON_NO_NTSYNC="1")
    if cell["kind"] == "proton":
        env.update(GAMEID="0", PROTONPATH=str(expand(cell["runner"])))
    elif cell.get("dxvk_dir"):
        env["WINEDLLOVERRIDES"] = DXVK_OVERRIDES
    env.update(cell.get("env", {}))
    return env


# The DLLs a plain-wine cell's own DXVK replaces, loaded native over wine's builtins.
DXVK_OVERRIDES = "d3d9,d3d10core,d3d11,dxgi=n"

# Variables that would move a cache, draw on screen, or change the present path behind the sweep.
UNSET = ["PROTON_LOCAL_SHADER_CACHE", "DXVK_HUD", "DXVK_FRAME_RATE", "STEAM_COMPAT_SHADER_PATH",
         "MESA_SHADER_CACHE_DISABLE", "__GL_SYNC_TO_VBLANK", "vblank_mode", "ENABLE_GAMESCOPE_WSI"]


def launch_command(cfg, cell):
    exe = expand(cfg["bench_dir"]) / "game" / "ffxiv_dx11.exe"
    head = [cfg["umu_run"]] if cell["kind"] == "proton" else [str(expand(cell["runner"]))]
    cmd = head + [str(exe)] + list(cfg["sys_args"])
    if cfg.get("allowed_cpus"):
        cmd = ["systemd-run", "--user", "--scope", "--quiet", "-p",
               f"AllowedCPUs={cfg['allowed_cpus']}", "--"] + cmd
    return cmd


def plan(cfg, blocks):
    """The ordered list of passes the sweep will run, as dicts."""
    cells = [c for c in cfg["cells"]]
    names = [c["name"] for c in cells]
    ranked = [c["name"] for c in cells if c["role"] != "control"]
    steps = [{"phase": "prefix", "cell": n} for n in names]
    for k in range(cfg["cold_runs"]):
        for n in block_order(cfg["seed"], f"cold-{k + 1}", ranked):
            steps.append({"phase": "cold", "cell": n, "block": f"cold-{k + 1}"})
    for k in range(cfg["driver_cold_runs"]):
        for n in block_order(cfg["seed"], f"driver-cold-{k + 1}", ranked):
            steps.append({"phase": "driver-cold", "cell": n, "block": f"driver-cold-{k + 1}"})
    for n in names:
        steps.append({"phase": "warmup", "cell": n})
    for b in blocks:
        for pos, n in enumerate(block_order(cfg["seed"], b, names)):
            steps.append({"phase": "warm", "cell": n, "block": b, "position": pos})
    return steps


# ---------------------------------------------------------------------------------------------
# Host checks.
# ---------------------------------------------------------------------------------------------


def sh(cmd, **kw):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)
        return out.returncode, out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)


def version_tuple(text):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def kernel_driver():
    try:
        text = Path("/proc/driver/nvidia/version").read_text()
    except OSError:
        return None, None
    m = re.search(r"Kernel Module(?:\s+for\s+\S+)?\s+([\d.]+)", text)
    return (m.group(1) if m else None), text.strip()


def processes():
    """{pid: (ppid, comm, utime+stime ticks)} for every visible process."""
    out = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            raw = Path(entry.path, "stat").read_text()
        except OSError:
            continue
        comm = raw[raw.index("(") + 1: raw.rindex(")")]
        fields = raw[raw.rindex(")") + 2:].split()
        out[int(entry.name)] = (int(fields[1]), comm, int(fields[11]) + int(fields[12]))
    return out


def running_denied(deny):
    exact = {d.lower()[:15] for d in deny if not d.endswith("*")}
    prefixes = [d.lower()[:-1] for d in deny if d.endswith("*")]
    hits = set()
    for pid, (_, comm, _) in processes().items():
        if pid == os.getpid():
            continue
        c = comm.lower()
        if c in exact or any(c.startswith(p) for p in prefixes):
            hits.add(comm)
    return sorted(hits)


def governors():
    found = set()
    for p in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq"):
        for name in ("energy_performance_preference", "scaling_governor"):
            try:
                found.add((name, (p / name).read_text().strip()))
            except OSError:
                pass
    return found


def preflight(cfg, strict=True):
    """Run every host check. Returns (fingerprint, failures)."""
    failures = []
    kmod, kmod_text = kernel_driver()
    code, user = sh(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"])
    user = user.splitlines()[0].strip() if code == 0 and user else None
    if not kmod:
        failures.append("no NVIDIA kernel module version in /proc/driver/nvidia/version")
    elif kmod != user:
        failures.append(f"kernel module {kmod} != userspace driver {user}: reboot after the update")
    elif version_tuple(kmod) < version_tuple(cfg["min_driver"]):
        failures.append(f"driver {kmod} is below {cfg['min_driver']}, which DXVK 3's descriptor "
                        "heap requires")
    code, vk = sh(["vulkaninfo", "--summary"])
    devices = re.findall(r"deviceName\s*=\s*(.+)", vk or "")
    if code != 0 or not devices:
        failures.append("vulkaninfo reported no device")
    elif all("llvmpipe" in d for d in devices):
        failures.append("Vulkan is on llvmpipe (CPU rendering): reboot after a driver update")
    if cfg["sync"] == "ntsync" and not Path("/dev/ntsync").exists():
        failures.append("ntsync is selected but /dev/ntsync is missing (modprobe ntsync)")
    govs = governors()
    if not any(v == "performance" for _, v in govs):
        failures.append(f"CPU governor/EPP is not performance: {sorted(govs)}")
    code, active = sh(["systemctl", "is-active", "unattended-upgrades"])
    if active == "active":
        failures.append("unattended-upgrades is running; stop it for the sweep")
    denied = running_denied(cfg["deny"])
    if denied:
        failures.append(f"denied processes running: {', '.join(denied)}")
    for key, ok in cfg["attest"].items():
        if not ok:
            failures.append(f"attest.{key} is not confirmed in the configuration")
    if not os.environ.get("APOGEE_SWEEP_INHIBITED"):
        failures.append("not running under systemd-inhibit (run re-executes itself; use run)")
    code, mango = sh(["mangohud", "--version"])
    fingerprint = {
        "driver": kmod,
        "driver_string": kmod_text,
        "kernel": os.uname().release,
        "mangohud": mango if code == 0 else None,
        "session": os.environ.get("XDG_SESSION_TYPE"),
        "governor": sorted(v for _, v in govs),
        "allowed_cpus": cfg.get("allowed_cpus"),
        "resolution": cfg["resolution"],
        "sync": cfg["sync"],
        "vulkan_devices": devices,
    }
    if strict and failures:
        raise SweepError("preflight failed:\n  " + "\n  ".join(failures))
    return fingerprint, failures


# ---------------------------------------------------------------------------------------------
# Running.
# ---------------------------------------------------------------------------------------------


def dir_bytes(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def cache_sizes(cfg, cell):
    d = cell_dirs(cfg, cell)
    return {k: dir_bytes(d[k]) for k in ("dxvk", "nv", "mesa")}


def global_glcache():
    return dir_bytes(Path.home() / ".cache" / "nvidia" / "GLCache")


def empty(path):
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)


def read_ini_score(path):
    """The [SCORE] section of the benchmark's launcher ini, or {}."""
    try:
        raw = path.read_bytes()
    except OSError:
        return {}
    for enc in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return {}
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        return {}
    return dict(parser["SCORE"]) if parser.has_section("SCORE") else {}


def dxvk_info(log_dir):
    """DXVK's version and any descriptor-heap lines from its info logs."""
    version, heap = None, []
    for log in sorted(Path(log_dir).glob("*.log")):
        try:
            text = log.read_text(errors="replace")
        except OSError:
            continue
        m = re.search(r"DXVK:\s*(v[\w.\-+]+)", text)
        version = version or (m.group(1) if m else None)
        heap += [line.strip() for line in text.splitlines() if "descriptor heap" in line.lower()]
    return {"version": version, "descriptor_heap": sorted(set(heap)) or None}


class Sampler:
    """Per-run host telemetry: nvidia-smi every 500 ms, and per-second CPU time outside the game."""

    def __init__(self, run_dir, game_pid):
        self.run_dir, self.game_pid = run_dir, game_pid
        self.stop = threading.Event()
        self.outside, self.host, self.offenders = [], [], {}
        self.smi = None

    def __enter__(self):
        self.smi_file = open(self.run_dir / "gpu.csv", "w")
        try:
            self.smi = subprocess.Popen(
                ["nvidia-smi", "--query-gpu=timestamp,clocks.gr,temperature.gpu,"
                 "clocks_throttle_reasons.active", "--format=csv,noheader,nounits", "-lms", "500"],
                stdout=self.smi_file, stderr=subprocess.DEVNULL)
        except OSError:
            self.smi = None
        self.thread = threading.Thread(target=self._cpu, daemon=True)
        self.thread.start()
        return self

    def _cpu(self):
        tick = os.sysconf("SC_CLK_TCK")
        mine = {os.getpid()} | ({self.smi.pid} if self.smi else set())
        prev, prev_stat = processes(), Path("/proc/stat").read_text().split("\n")[0]
        while not self.stop.wait(1.0):
            now = processes()
            tree = {self.game_pid}
            changed = True
            while changed:
                changed = False
                for pid, (ppid, _, _) in now.items():
                    if ppid in tree and pid not in tree:
                        tree.add(pid)
                        changed = True
            used = 0.0
            for pid, (ppid, comm, ticks) in now.items():
                # Kernel threads (children of kthreadd) serve the game's own I/O and GPU work.
                if pid in tree or pid in mine or ppid == 2 or pid == 2:
                    continue
                delta = (ticks - prev[pid][2]) / tick if pid in prev else 0.0
                if delta > 0:
                    used += delta
                    self.offenders[comm] = self.offenders.get(comm, 0.0) + delta
            self.outside.append(used)
            stat = Path("/proc/stat").read_text().split("\n")[0]
            a = [int(x) for x in prev_stat.split()[1:]]
            b = [int(x) for x in stat.split()[1:]]
            total = sum(b) - sum(a)
            idle = (b[3] + b[4]) - (a[3] + a[4])
            self.host.append(round(1 - idle / total, 4) if total else None)
            prev, prev_stat = now, stat

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=5)
        if self.smi:
            self.smi.terminate()
            self.smi.wait(timeout=5)
        self.smi_file.close()

    def summary(self):
        samples = []
        start = None
        for line in (self.run_dir / "gpu.csv").read_text().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            try:
                ts = time.mktime(time.strptime(parts[0].split(".")[0], "%Y/%m/%d %H:%M:%S"))
                ms = float("0." + parts[0].split(".")[1]) if "." in parts[0] else 0.0
                t = ts + ms
                start = t if start is None else start
                samples.append((t - start, float(parts[1]), float(parts[2]), int(parts[3], 16)))
            except (ValueError, IndexError):
                continue
        dip = longest_dip_seconds([(t, c, bits) for t, c, _, bits in samples])
        thermal = any(bits & THROTTLE_THERMAL for *_, bits in samples)
        top = sorted(self.offenders.items(), key=lambda kv: -kv[1])[:5]
        return {
            "gpu_samples": len(samples),
            "gpu_temp_max": max((s[2] for s in samples), default=None),
            "longest_clock_dip_s": dip,
            "clock_dipped": None if dip is None else dip > CLOCK_DIP_MAX_S,
            "thermal_throttle": thermal if samples else None,
            "outside_cpu_per_s": [round(x, 4) for x in self.outside],
            "outside_cpu_invalid": outside_cpu_invalid(self.outside),
            "outside_top": [[n, round(s, 2)] for n, s in top],
            "host_busy_per_s": self.host,
        }


def gpu_temp():
    code, out = sh(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"])
    try:
        return float(out.splitlines()[0]) if code == 0 else None
    except (ValueError, IndexError):
        return None


def cpu_package_temp():
    for hw in Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            name = (hw / "name").read_text().strip()
        except OSError:
            continue
        if name in ("k10temp", "coretemp", "zenpower"):
            try:
                return int((hw / "temp1_input").read_text()) / 1000
            except (OSError, ValueError):
                return None
    return None


def cooldown(cfg, baseline_gpu):
    """Wait until the GPU is near its idle baseline and the CPU package has settled."""
    start = time.monotonic()
    history = []
    while True:
        elapsed = time.monotonic() - start
        g, c = gpu_temp(), cpu_package_temp()
        history.append(c)
        gpu_ok = g is None or baseline_gpu is None or g <= baseline_gpu + cfg["cooldown_gpu_delta_c"]
        window = [x for x in history[-6:] if x is not None]
        cpu_ok = len(window) < 6 or max(window) - min(window) <= 1.0
        if elapsed >= cfg["cooldown_min_s"] and gpu_ok and cpu_ok:
            return {"seconds": round(elapsed), "gpu_temp": g, "cpu_temp": c, "settled": True}
        if elapsed >= cfg["cooldown_max_s"]:
            return {"seconds": round(elapsed), "gpu_temp": g, "cpu_temp": c, "settled": False}
        time.sleep(5)


def stop_prefix(cfg, cell, env):
    if cell["kind"] == "proton":
        sh([cfg["umu_run"], "wineboot", "-k"], env=env)
    else:
        server = expand(cell["runner"]).with_name("wineserver")
        sh([str(server) if server.exists() else "wineserver", "-k"], env=env)


def make_prefix(cfg, cell):
    pfx = prefix_dir(cfg, cell)
    env = dict(os.environ, WINEPREFIX=str(pfx))
    if cell["kind"] == "proton":
        env.update(GAMEID="0", PROTONPATH=str(expand(cell["runner"])))
    if pfx.exists():
        return {"created": False}
    pfx.mkdir(parents=True)
    if cell["kind"] == "proton":
        code, out = sh([cfg["umu_run"], "wineboot", "-u"], env=env)
    else:
        code, out = sh([str(expand(cell["runner"])), "wineboot", "-i"], env=env)
        dxvk = cell.get("dxvk_dir")
        if code == 0 and dxvk:
            for arch, target in (("x64", "system32"), ("x32", "syswow64")):
                for dll in Path(expand(dxvk), arch).glob("*.dll"):
                    shutil.copy2(dll, pfx / "drive_c" / "windows" / target / dll.name)
            env["WINEDLLOVERRIDES"] = DXVK_OVERRIDES
    stop_prefix(cfg, cell, env)
    if code != 0:
        shutil.rmtree(pfx, ignore_errors=True)
        raise SweepError(f"prefix for {cell['name']} failed to initialise: {out[-500:]}")
    return {"created": True}


def prefix_version_ok(cfg, cell):
    """A Proton prefix records the prefix version its runner writes; they must match."""
    if cell["kind"] != "proton":
        return True, None
    try:
        recorded = (prefix_dir(cfg, cell) / "version").read_text().strip()
        script = (expand(cell["runner"]) / "proton").read_text(errors="replace")
    except OSError as e:
        return False, str(e)
    m = re.search(r'CURRENT_PREFIX_VERSION\s*=\s*"([^"]+)"', script)
    expected = m.group(1) if m else None
    return recorded == expected, {"recorded": recorded, "runner": expected}


def one_run(cfg, cell, run_dir, apogee_cli):
    """Launch one benchmark pass and collect everything it produced."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "mangohud").mkdir(exist_ok=True)
    (run_dir / "dxvk").mkdir(exist_ok=True)
    for path in cell_dirs(cfg, cell).values():
        path.mkdir(parents=True, exist_ok=True)
    ini = expand(cfg["bench_dir"]) / cfg["bench_ini"]
    try:
        ini.unlink()
    except FileNotFoundError:
        pass
    env = {k: v for k, v in os.environ.items() if k not in UNSET}
    env.update(run_env(cfg, cell, run_dir))
    before, glc_before = cache_sizes(cfg, cell), global_glcache()
    started = time.time()
    proc = subprocess.Popen(launch_command(cfg, cell), env=env,
                            cwd=expand(cfg["bench_dir"]) / "game", start_new_session=True,
                            stdout=open(run_dir / "stdout.log", "w"), stderr=subprocess.STDOUT)
    outcome = "hang"
    with Sampler(run_dir, proc.pid) as sampler:
        deadline = started + cfg["run_timeout_s"]
        while time.time() < deadline:
            if read_ini_score(ini).get("SCORE"):
                outcome = "ok"
                time.sleep(5)
                break
            if proc.poll() is not None:
                outcome = "ok" if read_ini_score(ini).get("SCORE") else "crash"
                break
            time.sleep(1)
    score = read_ini_score(ini)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    stop_prefix(cfg, cell, env)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
    logs = sorted((p for p in (run_dir / "mangohud").glob("*.csv")
                   if not p.name.endswith("_summary.csv")), key=lambda p: p.stat().st_mtime)
    analysis = None
    if logs:
        code, out = sh([apogee_cli, "bench", "analyze", "--json", str(logs[-1])])
        try:
            analysis = json.loads(out)[0]
        except (ValueError, IndexError):
            analysis = {"error": out[-500:]}
    gpu = sampler.summary()
    record = {
        "started": started,
        "seconds": round(time.time() - started, 1),
        "outcome": outcome,
        "score": score,
        "csv": str(logs[-1]) if logs else None,
        "analyze": analysis,
        "dxvk": dxvk_info(run_dir / "dxvk"),
        "cache_before": before,
        "cache_after": cache_sizes(cfg, cell),
        "global_glcache_before": glc_before,
        "global_glcache_after": global_glcache(),
        "sampler": gpu,
    }
    record["invalid_reasons"] = invalid_reasons(record)
    return record


def invalid_reasons(record):
    reasons = []
    if record["outcome"] != "ok":
        reasons.append(record["outcome"])
    report = (record.get("analyze") or {}).get("report")
    if not report:
        reasons.append("no frame log analysis")
    elif not report["validity"]["valid"]:
        reasons.append("frame log validity flags")
    s = record["sampler"]
    if s.get("clock_dipped"):
        reasons.append("GPU clock dipped")
    if s.get("thermal_throttle"):
        reasons.append("thermal throttle")
    if s.get("outside_cpu_invalid"):
        reasons.append("host noise")
    return reasons


class Manifest:
    """One cell's manifest: its fingerprint, prefix, and every run."""

    def __init__(self, cfg, cell):
        self.path = expand(cfg["output"]) / "cells" / cell["name"] / "manifest.json"
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"cell": cell, "runs": [], "cache_checks": []}

    def save(self):
        atomic_json(self.path, self.data)

    def runs(self, phase, block=None):
        return [r for r in self.data["runs"] if r["phase"] == phase
                and (block is None or r.get("block") == block)]


def cache_check(manifest, record, first):
    """Per-cell cache isolation: the cell's own driver cache grows on the first pass while the
    global one does not, and it never shrinks afterwards (shrinking is eviction)."""
    b, a = record["cache_before"], record["cache_after"]
    problems = []
    own_grew = (a["nv"] > b["nv"]) or (a["mesa"] > b["mesa"])
    if first and not own_grew:
        problems.append("the cell's driver cache did not grow on the first pass")
    if first and record["global_glcache_after"] > record["global_glcache_before"]:
        problems.append("the global NVIDIA cache grew: the redirect is not taking")
    if not first and (a["nv"] < b["nv"] or a["mesa"] < b["mesa"]):
        problems.append("the cell's driver cache shrank: eviction")
    manifest.data["cache_checks"].append({"first": first, "problems": problems})
    return problems


def stall_count(record):
    report = (record.get("analyze") or {}).get("report") or {}
    return ((report.get("measured") or {}).get("stalls_over_50ms") or {}).get("count")


def sweep(cfg, args):
    blocks = parse_blocks(args.blocks, cfg["blocks"])
    steps = plan(cfg, blocks)
    if args.dry_run:
        print_plan(cfg, steps)
        return 0
    if not os.environ.get("APOGEE_SWEEP_INHIBITED") and shutil.which("systemd-inhibit"):
        os.environ["APOGEE_SWEEP_INHIBITED"] = "1"
        os.execvp("systemd-inhibit", ["systemd-inhibit", "--what=idle:sleep:handle-lid-switch",
                                      "--why=runner benchmark sweep", sys.executable,
                                      os.path.abspath(__file__)] + sys.argv[1:])
    fingerprint, _ = preflight(cfg)
    apogee_cli = shutil.which(cfg["apogee_cli"]) or cfg["apogee_cli"]
    out = expand(cfg["output"])
    sweep_file = out / "sweep.json"
    meta = json.loads(sweep_file.read_text()) if sweep_file.exists() else {}
    if meta.get("fingerprint") and meta["fingerprint"]["driver"] != fingerprint["driver"]:
        raise SweepError("the driver changed since this sweep started; start a new output")
    meta.setdefault("fingerprint", fingerprint)
    meta.setdefault("seed", cfg["seed"])
    meta.setdefault("sessions", []).append({"session": args.session, "blocks": blocks,
                                            "fingerprint": fingerprint, "started": time.time()})
    atomic_json(sweep_file, meta)
    baseline = gpu_temp()
    cells = {c["name"]: c for c in cfg["cells"]}
    manifests = {n: Manifest(cfg, c) for n, c in cells.items()}

    def record_run(name, phase, extra, run_dir):
        cell = cells[name]
        denied = running_denied(cfg["deny"])
        if denied:
            raise SweepError(f"denied processes started during the sweep: {', '.join(denied)}")
        rec = one_run(cfg, cell, run_dir, apogee_cli)
        rec.update(phase=phase, session=args.session, **extra)
        rec["cooldown"] = cooldown(cfg, baseline)
        m = manifests[name]
        m.data["runs"].append(rec)
        m.save()
        print(f"{phase:<12} {name:<24} {extra.get('block', ''):<14} {rec['outcome']:<6} "
              f"{', '.join(rec['invalid_reasons']) or 'valid'}", flush=True)
        return rec

    redo = []
    for step in steps:
        name, phase = step["cell"], step["phase"]
        cell, m = cells[name], manifests[name]
        run_root = out / "cells" / name / "runs"
        if phase == "prefix":
            m.data["prefix"] = {"path": str(prefix_dir(cfg, cell)), **make_prefix(cfg, cell)}
            ok, detail = prefix_version_ok(cfg, cell)
            m.data["prefix"]["version"] = detail
            if not ok:
                raise SweepError(f"{name}: prefix version does not match its runner: {detail}")
            m.data["fingerprint"] = fingerprint
            m.save()
        elif phase in ("cold", "driver-cold"):
            if m.runs(phase, step["block"]):
                continue
            d = cell_dirs(cfg, cell)
            for k in (("nv", "mesa") if phase == "driver-cold" else ("dxvk", "nv", "mesa")):
                empty(d[k])
            record_run(name, phase, {"block": step["block"]}, run_root / step["block"])
        elif phase == "warmup":
            if args.skip_warmup:
                continue
            for attempt in (1, 2):
                sizes, stalls = [], []
                for k in range(WARMUP_MAX):
                    first = not m.data["cache_checks"]
                    rec = record_run(name, "warmup", {"attempt": attempt, "pass": k + 1,
                                                      "block": f"warmup-{args.session}"},
                                     run_root / f"warmup-{args.session}-{attempt}-{k + 1}")
                    problems = cache_check(m, rec, first)
                    m.save()
                    if problems:
                        raise SweepError(f"{name}: cache isolation failed: {'; '.join(problems)}")
                    sizes.append(sum(rec["cache_after"].values()))
                    stalls.append(stall_count(rec))
                    if converged(sizes, stalls):
                        break
                m.data.setdefault("convergence", []).append(
                    {"session": args.session, "attempt": attempt, "passes": len(sizes),
                     "converged": converged(sizes, stalls)})
                m.save()
                if converged(sizes, stalls):
                    break
                cooldown(cfg, baseline)
        elif phase == "warm":
            b = step["block"]
            if m.runs("warm", b):
                continue
            if step["position"] == 0:
                # The whole checklist again before every block, not only at the start: a driver
                # update or a reopened browser mid-sweep is exactly what it exists to catch.
                now, _ = preflight(cfg)
                if now["driver"] != fingerprint["driver"] or now["kernel"] != fingerprint["kernel"]:
                    raise SweepError("the driver or kernel changed mid-sweep; start a new output")
            rec = record_run(name, "warm", {"block": b, "position": step["position"]},
                             run_root / f"block-{b}")
            if "host noise" in rec["invalid_reasons"] and b not in redo:
                redo.append(b)
    # A run spoiled by host noise is re-run at the end in the same position of a fresh block,
    # which repeats the whole block in its planned order so its runs stay paired.
    for b in redo:
        for pos, name in enumerate(block_order(cfg["seed"], b, list(cells))):
            if any(r.get("redo_of") == b for r in manifests[name].runs("warm")):
                continue
            record_run(name, "warm", {"block": f"{b}r", "redo_of": b, "position": pos},
                       out / "cells" / name / "runs" / f"block-{b}r")
    return 0


def print_plan(cfg, steps):
    fingerprint, failures = preflight(cfg, strict=False)
    print("# Preflight (informational in a dry run)")
    for key, value in fingerprint.items():
        if key != "driver_string":
            print(f"  {key}: {value}")
    for f in failures:
        print(f"  WOULD FAIL: {f}")
    print("\n# Cells")
    for cell in cfg["cells"]:
        d = cell_dirs(cfg, cell)
        print(f"  {cell['name']} ({cell['role']}, {cell['kind']} {cell.get('version')})")
        print(f"    prefix: {prefix_dir(cfg, cell)}")
        print(f"    caches: {d['root']}/{{dxvk,nv,mesa}}")
        sample = Path(cfg["output"]) / "cells" / cell["name"] / "runs" / "<run>"
        print(f"    launch: {' '.join(launch_command(cfg, cell))}")
        for k, v in sorted(run_env(cfg, cell, expand(sample)).items()):
            print(f"      {k}={v}")
    print(f"    unset:  {' '.join(UNSET)}")
    print(f"\n# Each run: delete {expand(cfg['bench_dir']) / cfg['bench_ini']}, launch, wait for "
          f"[SCORE] (timeout {cfg['run_timeout_s']} s), stop the prefix, sample GPU and host CPU, "
          "analyze the log, cool down")
    print(f"\n# Steps (seed {cfg['seed']})")
    for s in steps:
        tail = f" block {s['block']}" if "block" in s else ""
        tail += f" position {s['position']}" if "position" in s else ""
        if s["phase"] == "warmup":
            tail = f" until converged ({WARMUP_MIN}-{WARMUP_MAX} passes, one repeat)"
        print(f"  {s['phase']:<12} {s['cell']}{tail}")


# ---------------------------------------------------------------------------------------------
# Analysis over the recorded manifests.
# ---------------------------------------------------------------------------------------------


def csv_frames(path):
    """(frametime_ms, fps or None) per kept frame from a MangoHud CSV, with the same artifact rule
    as `bench analyze`."""
    frames, header = [], None
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        cells = line.split(",")
        if header is None:
            if cells and cells[0] == "fps" and "frametime" in cells:
                header = [c.strip() for c in cells]
            continue
        try:
            ft = float(cells[header.index("frametime")])
        except (ValueError, IndexError):
            continue
        fps = el = None
        try:
            fps = float(cells[header.index("fps")])
        except (ValueError, IndexError):
            pass
        if "elapsed" in header:
            try:
                el = float(cells[header.index("elapsed")])
            except (ValueError, IndexError):
                pass
        if el is not None and ft > el / 1e6:
            continue
        frames.append((ft, fps))
    return frames


def analyze(cfg, args):
    out = expand(cfg["output"])
    manifests = {}
    for cell in cfg["cells"]:
        path = out / "cells" / cell["name"] / "manifest.json"
        if path.exists():
            manifests[cell["name"]] = json.loads(path.read_text())
    if not manifests:
        raise SweepError(f"no manifests under {out}")
    prints = {json.dumps({k: v for k, v in m.get("fingerprint", {}).items()
                          if k in ("driver", "kernel", "mangohud", "session", "governor",
                                   "allowed_cpus", "resolution")}, sort_keys=True)
              for m in manifests.values()}
    if len(prints) > 1:
        raise SweepError("cells were recorded under different fingerprints; they are not comparable")

    cells = {}
    for cell in cfg["cells"]:
        m = manifests.get(cell["name"], {"runs": []})
        runs = {}
        warm = [r for r in m["runs"] if r["phase"] == "warm"]
        for r in warm:
            key = str(r.get("redo_of") or r["block"])
            if r.get("redo_of") or key not in runs:
                rep = (r.get("analyze") or {}).get("report")
                metrics = run_metrics(rep) if rep else {"low_1pct": None, "valid": False}
                metrics["valid"] = bool(rep) and not r["invalid_reasons"] and \
                    metrics.get("low_1pct") is not None
                metrics["session"] = r.get("session")
                runs[key] = metrics
        warm_rolling = [rolling_fps(split_loading(csv_frames(r["csv"])))
                        for r in warm if r.get("csv") and not r["invalid_reasons"]]
        cold = [r for r in m["runs"] if r["phase"] == "cold" and r.get("csv")]
        tts = [time_to_steady(rolling_fps(split_loading(csv_frames(r["csv"]))), warm_rolling)
               for r in cold]
        known = [t for t in tts if t is not None]
        pooled = list(itertools.chain.from_iterable(
            split_loading(csv_frames(r["csv"])) for r in warm
            if r.get("csv") and not r["invalid_reasons"]))
        cells[cell["name"]] = {
            "role": cell["role"],
            "runs": runs,
            "crashed": any(r["outcome"] in ("crash", "hang") for r in m["runs"]),
            "time_to_steady": statistics.median(known) if known else
            (float("inf") if tts else None),
            "stability": cell.get("stability", 0),
            "control_of": cell.get("control_of"),
            "pooled_low_0_1pct": low_fps(pooled, 0.001),
            "cold_scores": [r["score"].get("SCORE") for r in cold],
            "dxvk": sorted({(r.get("dxvk") or {}).get("version") or "?" for r in m["runs"]}),
        }
    report = decide(cells, seed=cfg["seed"])
    for name, cell in cells.items():
        row = report["cells"][name]
        row.update(pooled_low_0_1pct=cell["pooled_low_0_1pct"], dxvk=cell["dxvk"],
                   cold_scores=cell["cold_scores"])
    report["drift"] = session_drift(cells, report["threshold_pct"])
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
    return 0 if report["winner"] else 1


def session_drift(cells, threshold):
    """Runners whose median 1% low moved more than the threshold between sessions while the A/A
    noise floor did not: drift to investigate, not to average."""
    out = []
    for name, cell in cells.items():
        by = {}
        for r in cell["runs"].values():
            if r["valid"]:
                by.setdefault(r.get("session"), []).append(r["low_1pct"])
        if len(by) < 2:
            continue
        meds = {s: statistics.median(v) for s, v in by.items()}
        hi, lo = max(meds.values()), min(meds.values())
        if lo > 0 and 100 * (hi - lo) / hi > threshold:
            out.append({"cell": name, "session_medians": meds})
    return out


def print_report(r):
    print(f"noise floor: {r['noise_floor_pct']}%  A/A p: {r['aa_p']}  "
          f"threshold: {r['threshold_pct']:.2f}%")
    for name, c in r["cells"].items():
        print(f"  {name:<24} {c['role']:<9} 1%low {c['median_low_1pct']}  stalls "
              f"{c['median_stalls_50']}  jitter {c['median_jitter_ms']}  p99.9 "
              f"{c['median_p99_9_ms']}  invalid {c['invalid_runs']}/{c['runs']}  "
              f"tts {c['time_to_steady_s']}  {'; '.join(c['disqualified'])}")
    for comp in r["comparisons"]:
        print(f"  {comp['leader']} vs {comp['other']}: median diff {comp['median_diff_pct']}%  "
              f"p {comp['p']:.4f}  holm {comp['p_holm']:.4f}  beats {comp['leader_beats']}")
    for d in r.get("drift", []):
        print(f"  DRIFT: {d}")
    for why in r["invalid"]:
        print(f"  INVALID: {why}")
    print(f"winner: {r['winner']}  (tie-breaks: {r['tie_break']})")


# ---------------------------------------------------------------------------------------------
# Self-test: the statistics and the plan, offline.
# ---------------------------------------------------------------------------------------------


class SelfTest(unittest.TestCase):
    def test_a_cell_name_or_ini_that_leaves_its_directory_is_refused(self):
        import tempfile
        for bad in ("../x", "/abs", "a/b", "..", ""):
            for key in ("name", "ini"):
                cfg = dict(EXAMPLE_CONFIG)
                cfg["cells"] = [dict(c) for c in EXAMPLE_CONFIG["cells"]]
                if key == "name":
                    cfg["cells"][0]["name"] = bad
                    cfg["aa_control"] = bad
                else:
                    cfg["bench_ini"] = bad
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                    json.dump(cfg, f)
                with self.assertRaises(SweepError, msg=f"{key}={bad!r}"):
                    load_config(f.name)
                os.unlink(f.name)

    def test_wilcoxon_all_one_sign_hits_the_smallest_p(self):
        _, p, n = wilcoxon_signed_rank([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        self.assertEqual(n, 10)
        self.assertAlmostEqual(p, 2 / 1024)
        # At six blocks no comparison could clear 0.05 after correction.
        self.assertAlmostEqual(wilcoxon_signed_rank([1, 2, 3, 4, 5, 6])[1], 2 / 64)

    def test_wilcoxon_matches_a_hand_enumeration(self):
        d = [1.5, -0.5, 2.0, 3.0, -1.0, 4.0]
        w, p, _ = wilcoxon_signed_rank(d)
        ranks = average_ranks([abs(x) for x in d])
        expect_w = sum(r for r, x in zip(ranks, d) if x > 0)
        self.assertEqual(w, expect_w)
        sums = [sum(r for r, s in zip(ranks, signs) if s)
                for signs in itertools.product([0, 1], repeat=6)]
        lo = sum(1 for s in sums if s <= w) / 64
        hi = sum(1 for s in sums if s >= w) / 64
        self.assertAlmostEqual(p, min(1, 2 * min(lo, hi)))

    def test_wilcoxon_ties_and_zeros(self):
        # Zeros are dropped; tied magnitudes share a rank and the test stays exact over them.
        w, p, n = wilcoxon_signed_rank([0, 0, 2, 2, -2, 2])
        self.assertEqual(n, 4)
        self.assertEqual(w, 7.5)
        self.assertAlmostEqual(p, 0.625)
        self.assertEqual(wilcoxon_signed_rank([0, 0]), (0.0, 1.0, 0))
        self.assertEqual(wilcoxon_signed_rank([]), (0.0, 1.0, 0))

    def test_wilcoxon_is_symmetric(self):
        d = [3.1, -1.2, 4.4, 0.7, -2.5, 5.0, 1.1]
        self.assertAlmostEqual(wilcoxon_signed_rank(d)[1],
                               wilcoxon_signed_rank([-x for x in d])[1])

    def test_holm(self):
        self.assertEqual(holm([0.01, 0.04]), [0.02, 0.04])
        # Monotone: a larger raw p never gets a smaller adjusted one.
        self.assertEqual(holm([0.04, 0.01, 0.03]), [0.06, 0.03, 0.06])
        self.assertEqual(holm([0.9, 0.8]), [1.0, 1.0])
        self.assertEqual(holm([]), [])

    def test_block_orders_are_reproducible_and_independent(self):
        cells = ["a", "b", "c", "d"]
        self.assertEqual(block_order(7, 3, cells), block_order(7, 3, list(reversed(cells))))
        orders = {tuple(block_order(7, b, cells)) for b in range(1, 11)}
        self.assertGreater(len(orders), 1)
        self.assertNotEqual([block_order(7, b, cells) for b in range(1, 11)],
                            [block_order(8, b, cells) for b in range(1, 11)])

    def test_convergence(self):
        self.assertFalse(converged([100], [10]))
        self.assertTrue(converged([100, 100.5], [10, 9]))
        self.assertFalse(converged([100, 102], [10, 9]))       # still growing
        self.assertFalse(converged([100, 100], [30, 20]))      # stalls still falling
        self.assertTrue(converged([100, 100], [30, 25]))       # within 20%
        self.assertTrue(converged([100, 100], [3, 1]))         # within 2 stalls
        self.assertFalse(converged([0, 0], [1, 1]))            # an empty cache is not converged

    def test_loading_split_keeps_short_freezes(self):
        frames = [(10, 100)] * 5 + [(400, 2.5)] + [(10, 100)] * 5 + [(300, 3)] * 4
        kept = split_loading(frames)
        self.assertIn(400, kept)
        self.assertEqual(len(kept), 11)

    def test_loading_split_keeps_a_single_long_frame(self):
        # One 1.5 s frame is long enough for a load, but a load is never exactly one frame.
        frames = [(10, 100)] * 100 + [(1500, 1000 / 1500)] + [(10, 100)] * 99
        kept = split_loading(frames)
        self.assertEqual(len(kept), 200)
        self.assertEqual([ft for ft in kept if ft > 50], [1500])
        self.assertEqual([ft for ft in kept if ft > 100], [1500])
        # Two slow frames that reach a second between them are a load.
        frames = [(10, 100)] * 100 + [(500, 2)] * 2 + [(10, 100)] * 100
        self.assertEqual(split_loading(frames), [10] * 200)

    def test_time_to_steady(self):
        warm = [rolling_fps([10.0] * 3000) for _ in range(3)]
        cold = rolling_fps([30.0] * 500 + [10.0] * 2000)
        tts = time_to_steady(cold, warm)
        self.assertIsNotNone(tts)
        self.assertGreater(tts, 10)
        self.assertLess(tts, 20)
        self.assertEqual(time_to_steady(warm[0], warm), 0.0)
        self.assertIsNone(time_to_steady(rolling_fps([30.0] * 2000), warm))

    def test_clock_dip_ignores_idle(self):
        samples = [(i * 0.5, 1800, 0) for i in range(20)]
        samples += [(10 + i * 0.5, 1500, 0) for i in range(6)]
        samples += [(13 + i * 0.5, 300, THROTTLE_GPU_IDLE) for i in range(20)]
        samples += [(23 + i * 0.5, 1800, 0) for i in range(4)]
        self.assertAlmostEqual(longest_dip_seconds(samples), 3.0)
        self.assertIsNone(longest_dip_seconds([(0, 0, 0)]))

    def test_outside_cpu(self):
        self.assertFalse(outside_cpu_invalid([0.06, 0.06, 0.01]))
        self.assertTrue(outside_cpu_invalid([0.06, 0.06, 0.06]))

    def test_bootstrap_is_seeded(self):
        v = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertEqual(bootstrap_median_ci(v, 1, resamples=500),
                         bootstrap_median_ci(v, 1, resamples=500))
        lo, hi = bootstrap_median_ci(v, 1, resamples=500)
        self.assertLessEqual(lo, 3.0)
        self.assertGreaterEqual(hi, 3.0)

    # The decision rule over synthetic cells.

    @staticmethod
    def cell(role, lows, stalls=5, jitter=1.0, p999=30.0, fps=100.0, invalid=(), **kw):
        runs = {str(b + 1): {"low_1pct": low, "stalls_50": stalls, "jitter_ms": jitter,
                             "p99_9_ms": p999, "average_fps": fps, "valid": b not in invalid}
                for b, low in enumerate(lows)}
        return {"role": role, "runs": runs, **kw}

    def sweep_cells(self, other_lows, aa_noise=0.2, **other_kw):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        aa = [x * (1 + (aa_noise if b % 2 else -aa_noise) / 100) for b, x in enumerate(base)]
        return {
            "ge": self.cell("candidate", base, stability=1),
            "ge-aa": self.cell("control", aa, control_of="ge"),
            "xiv": self.cell("candidate", other_lows, stability=0, **other_kw),
        }

    def test_a_clear_loser_is_beaten(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        r = decide(self.sweep_cells([x * 0.9 for x in base]))
        self.assertEqual(r["leader"], "ge")
        self.assertTrue(r["comparisons"][0]["leader_beats"])
        self.assertEqual(r["winner"], "ge")
        self.assertEqual(r["invalid"], [])

    def test_a_small_difference_is_a_tie_settled_by_tie_breaks(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        r = decide(self.sweep_cells([x * 0.99 for x in base], jitter=0.5))
        self.assertFalse(r["comparisons"][0]["leader_beats"])
        self.assertEqual(r["winner"], "xiv")     # lower jitter wins the tie
        self.assertEqual(r["tie_break"][0]["by"], "median_jitter_ms")

    def test_worse_stalls_block_a_win(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        cells = self.sweep_cells([x * 0.9 for x in base], stalls=1)
        r = decide(cells)
        self.assertFalse(r["comparisons"][0]["leader_beats"])

    def test_a_loud_machine_invalidates_the_sweep(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        r = decide(self.sweep_cells([x * 0.9 for x in base], aa_noise=6.0))
        self.assertTrue(any("noise floor" in why for why in r["invalid"]))
        self.assertIsNone(r["winner"])

    def test_an_aa_pair_that_tests_different_invalidates_the_sweep(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        cells = self.sweep_cells([x * 0.9 for x in base])
        cells["ge-aa"] = self.cell("control", [x * 0.98 for x in base], control_of="ge")
        r = decide(cells)
        self.assertTrue(any("A/A" in why for why in r["invalid"]))
        self.assertIsNone(r["winner"])

    def test_the_threshold_follows_the_noise_floor(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        loud = decide(self.sweep_cells([x * 0.96 for x in base], aa_noise=2.5))
        self.assertAlmostEqual(loud["threshold_pct"], 5.0)
        # A 4% gap clears the 3% minimum but not twice a 2.5% floor.
        self.assertFalse(loud["comparisons"][0]["leader_beats"])
        quiet = decide(self.sweep_cells([x * 0.96 for x in base], aa_noise=0.2))
        self.assertEqual(quiet["threshold_pct"], MIN_THRESHOLD_PCT)
        self.assertTrue(quiet["comparisons"][0]["leader_beats"])

    def test_disqualification(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        crashed = self.sweep_cells([x * 1.2 for x in base], crashed=True)
        r = decide(crashed)
        self.assertEqual(r["leader"], "ge")
        self.assertIn("a run crashed or hung", r["cells"]["xiv"]["disqualified"])
        two_bad = self.sweep_cells([x * 1.2 for x in base], invalid=(0, 1))
        self.assertTrue(decide(two_bad)["cells"]["xiv"]["disqualified"])
        one_bad = self.sweep_cells([x * 1.2 for x in base], invalid=(0,))
        self.assertFalse(decide(one_bad)["cells"]["xiv"]["disqualified"])
        slow = self.sweep_cells([x * 1.2 for x in base], time_to_steady=400.0)
        slow["ge"]["time_to_steady"] = 100.0
        self.assertTrue(decide(slow)["cells"]["xiv"]["disqualified"])

    def test_a_reference_cell_never_wins(self):
        base = [50.0 + (b % 3) * 0.5 for b in range(10)]
        cells = self.sweep_cells([x * 0.9 for x in base])
        cells["umu"] = self.cell("reference", [x * 1.5 for x in base])
        r = decide(cells)
        self.assertEqual(r["winner"], "ge")
        self.assertEqual(r["references"][0]["other"], "umu")

    def test_plan_puts_prefixes_first_and_every_cell_in_every_block(self):
        cfg = dict(EXAMPLE_CONFIG)
        cfg["cells"] = EXAMPLE_CONFIG["cells"] + [
            dict(EXAMPLE_CONFIG["cells"][0], name="ge-proton-11-12-aa", role="control")]
        steps = plan(cfg, [1, 2])
        names = {c["name"] for c in cfg["cells"]}
        self.assertTrue(all(s["phase"] == "prefix" for s in steps[:len(names)]))
        for b in (1, 2):
            self.assertEqual({s["cell"] for s in steps if s.get("block") == b}, names)
        cold = [s for s in steps if s["phase"] == "cold"]
        self.assertNotIn("ge-proton-11-12-aa", {s["cell"] for s in cold})
        self.assertEqual(len(cold), 3 * 3)

    def test_analyze_reads_recorded_manifests_end_to_end(self):
        import contextlib
        import io
        import tempfile

        def report(low, stalls=2):
            stats = {"low_1pct": low, "average_fps": 100.0}
            return {"report": {"all_frames": stats, "validity": {"valid": True}, "measured": {
                "stats": stats, "stalls_over_50ms": {"count": stalls}, "jitter_ms": 1.0,
                "p99_9_ms": 30.0}}}

        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            cfg = dict(EXAMPLE_CONFIG, output=d, cell_root=d)
            cfg["cells"] = [
                {"name": "ge", "kind": "proton", "runner": "/x", "role": "candidate"},
                {"name": "xiv", "kind": "wine", "runner": "/y", "role": "candidate"},
                {"name": "ge-aa", "kind": "proton", "runner": "/x", "role": "control",
                 "control_of": "ge"},
            ]
            csv = Path(d) / "log.csv"
            csv.write_text("fps,frametime,elapsed\n" + "100,10,1e15\n" * 2000)
            fp = {"driver": "595.84", "kernel": "k"}
            # The A/A copy sits a little above or below the original, never consistently one way.
            lows = {"ge": lambda b: 50.0 + (b % 3) * 0.1,
                    "ge-aa": lambda b: 50.0 + (b % 3) * 0.1 + (0.1 if b % 2 else -0.1),
                    "xiv": lambda b: 44.0 + (b % 3) * 0.1}
            for name, low in lows.items():
                runs = [{"phase": "warm", "block": b, "outcome": "ok", "invalid_reasons": [],
                         "csv": str(csv), "analyze": report(low(b)), "score": {}}
                        for b in range(1, 11)]
                # A noisy block 4 for ge, re-run at the end: the redo is what counts.
                if name == "ge":
                    runs[3]["invalid_reasons"] = ["host noise"]
                    runs.append(dict(runs[0], block="4r", redo_of=4, analyze=report(50.1)))
                atomic_json(Path(d) / "cells" / name / "manifest.json",
                            {"fingerprint": fp, "runs": runs})
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = analyze(cfg, argparse.Namespace(json=True))
            result = json.loads(out.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(result["winner"], "ge")
            self.assertEqual(result["cells"]["ge"]["invalid_runs"], 0)
            self.assertEqual(result["comparisons"][0]["n"], 10)
            self.assertAlmostEqual(result["cells"]["ge"]["pooled_low_0_1pct"], 100.0)

            # A cell recorded under another driver cannot be compared with the rest.
            m = Path(d) / "cells" / "xiv" / "manifest.json"
            data = json.loads(m.read_text())
            data["fingerprint"] = {"driver": "595.71.05", "kernel": "k"}
            atomic_json(m, data)
            with self.assertRaises(SweepError):
                analyze(cfg, argparse.Namespace(json=True))

    def test_ini_score_reads_both_encodings(self):
        import tempfile
        body = "[SCORE]\nSCORE=12345\nSCORE_FPSAVERAGE=88.1\nT0=1.2\n"
        with tempfile.TemporaryDirectory() as d:
            for enc in ("utf-8", "utf-16"):
                p = Path(d) / f"{enc}.ini"
                p.write_bytes(body.encode(enc))
                self.assertEqual(read_ini_score(p)["SCORE"], "12345")
            self.assertEqual(read_ini_score(Path(d) / "missing.ini"), {})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("example-config", help="print a configuration to start from")
    run = sub.add_parser("run", help="run the sweep (resumable)")
    run.add_argument("config")
    run.add_argument("--dry-run", action="store_true", help="print the plan; launch nothing")
    run.add_argument("--blocks", help="which blocks to run this session, e.g. 1-5")
    run.add_argument("--session", default="1", help="a label for this session (recorded)")
    run.add_argument("--skip-warmup", action="store_true",
                     help="skip the convergence passes (only when the caches are known warm)")
    an = sub.add_parser("analyze", help="cross-run statistics and the decision")
    an.add_argument("config")
    an.add_argument("--json", action="store_true")
    sub.add_parser("selftest", help="run the offline self-test")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "example-config":
            print(json.dumps(EXAMPLE_CONFIG, indent=2))
            return 0
        if args.cmd == "selftest":
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest)
            return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        cfg = load_config(args.config)
        return sweep(cfg, args) if args.cmd == "run" else analyze(cfg, args)
    except SweepError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
