#!/usr/bin/env python3
"""Dependency release-age gate.

AGENTS.md requires every dependency version to be published at least
OXIDE_DEP_MIN_AGE_DAYS (default 7) days before adoption — newly
published releases have not been vetted and a non-trivial fraction of
supply-chain attacks are yanked within days. This script is the
machine check for that rule: every registry package in `Cargo.lock`
is looked up on crates.io and its `created_at` must be older than
the cutoff, else the check fails and names the offenders.

A package that cannot be verified (API error, version missing)
fails the gate too — an unverifiable dependency age is a
supply-chain hole, and transient crates.io failures are retried
before counting as errors.

Run: scripts/check-dep-age.py [path-to-Cargo.lock]
"""

import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

LOCK = sys.argv[1] if len(sys.argv) > 1 else "Cargo.lock"
MIN_AGE_DAYS = int(os.environ.get("OXIDE_DEP_MIN_AGE_DAYS", "7"))
UA = "oxide-check-dep-age (https://github.com/cognition-ai/oxide)"


def registry_packages(lock_path):
    """Yield (name, version) for every crates.io-registry package.

    Workspace members and path/git deps carry no `source = "registry…"`
    line — their age is the repository's own, not a publish date.
    Non-registry sources are rejected by `deny.toml` anyway.
    """
    pkgs = []
    name = ver = None
    registry = False
    with open(lock_path) as f:
        for line in f:
            if line.startswith("[[package]]"):
                if name and registry:
                    pkgs.append((name, ver))
                name = ver = None
                registry = False
            elif line.startswith("name = ") and '"' in line:
                name = line.split('"')[1]
            elif line.startswith("version = ") and '"' in line:
                ver = line.split('"')[1]
            elif line.startswith('source = "registry+'):
                registry = True
    if name and registry:
        pkgs.append((name, ver))
    return pkgs


def created_at(name, version):
    """The version's publish timestamp, or None if unverifiable."""
    url = f"https://crates.io/api/v1/crates/{name}/{version}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.load(resp)
            stamp = data["version"]["created_at"]
            return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except (urllib.error.URLError, KeyError, ValueError):
            if attempt == 2:
                return None
            time.sleep(1 << attempt)
    return None


def main():
    pkgs = registry_packages(LOCK)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=MIN_AGE_DAYS
    )
    too_young = []
    unverifiable = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda nv: (nv, created_at(*nv)), pkgs))
    for (name, ver), ts in results:
        if ts is None:
            unverifiable.append(f"{name} {ver}")
        elif ts > cutoff:
            too_young.append((name, ver, ts.isoformat()))

    if too_young:
        print(f"Dependencies younger than {MIN_AGE_DAYS} days:")
        for name, ver, ts in sorted(too_young):
            print(f"  {name} {ver} (published {ts})")
    if unverifiable:
        print("Dependencies whose publish date could not be verified:")
        for nv in sorted(unverifiable):
            print(f"  {nv}")
    if too_young or unverifiable:
        sys.exit(1)
    print(f"ok — {len(pkgs)} registry dependencies all older than {MIN_AGE_DAYS} days")


if __name__ == "__main__":
    main()
