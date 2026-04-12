#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyyaml>=6.0",
#     "requests>=2.28",
# ]
# ///
"""
Build signatures.json for the NekoBox Hardening Fork's Phase 4 scanner.

Reads publishers.yaml (hand-curated) and optionally cross-references
with Exodus Privacy's public tracker database, then emits a
deterministically-sorted signatures.json consumed by clients at VPN
start via HostileSignatureUpdater.

Run manually:
    uv run build-signatures.py

Or in CI via the GitHub Action `.github/workflows/build.yml`.

Exit codes:
    0 — signatures.json is up to date OR was successfully regenerated
    1 — publishers.yaml failed to parse, or another fatal error
    2 — Exodus fetch failed AND --strict-exodus was passed
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent
PUBLISHERS_YAML = REPO_ROOT / "publishers.yaml"
SIGNATURES_JSON = REPO_ROOT / "signatures.json"

EXODUS_TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
EXODUS_TIMEOUT = 15

# Substrings in an Exodus tracker's `name` or `code_signature` that
# flag it as relevant to our threat model. Matching is case-insensitive.
# Conservative by default — we extend via publishers.yaml rather than
# dragging in every tracker Exodus knows about.
EXODUS_RELEVANT_KEYWORDS = [
    # Russia
    "yandex", "appmetrica", "mail.ru", "mytracker", "mytarget",
    "vk", "vkontakte", "sberbank", "tinkoff", "kaspersky", "drweb",
    # China
    "tencent", "bugly", "mmkv", "alipay", "alibaba", "bytedance",
    "baidu", "xiaomi", "mipush", "meituan", "dianping", "ucweb",
]


def log(msg: str) -> None:
    print(f"[build-signatures] {msg}", file=sys.stderr)


def load_publishers(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open() as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        log(f"ERROR parsing {path}: {e}")
        sys.exit(1)
    if not isinstance(data, list):
        log(f"ERROR: {path} must be a top-level YAML list, got {type(data).__name__}")
        sys.exit(1)
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            log(f"ERROR: entry {i} is not a mapping")
            sys.exit(1)
        if "publisher" not in entry:
            log(f"ERROR: entry {i} missing required field `publisher`")
            sys.exit(1)
    log(f"loaded {len(data)} publishers from {path.name}")
    return data


def fetch_exodus_trackers(strict: bool) -> dict[str, Any]:
    log(f"GET {EXODUS_TRACKERS_URL}")
    try:
        resp = requests.get(EXODUS_TRACKERS_URL, timeout=EXODUS_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        log(f"WARNING: Exodus fetch failed: {e}")
        if strict:
            sys.exit(2)
        return {}
    data = resp.json()
    trackers = data.get("trackers") or {}
    log(f"fetched {len(trackers)} Exodus trackers")
    return trackers


def filter_exodus_relevant(trackers: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the subset of Exodus trackers whose name or code_signature
    contains any of EXODUS_RELEVANT_KEYWORDS (case-insensitive).
    """
    relevant: list[dict[str, Any]] = []
    for tid, t in trackers.items():
        name = (t.get("name") or "").lower()
        code = (t.get("code_signature") or "").lower()
        if any(k in name or k in code for k in EXODUS_RELEVANT_KEYWORDS):
            relevant.append(t)
    log(f"filtered to {len(relevant)} Russia/Iran/China-relevant Exodus entries")
    return relevant


def exodus_class_prefixes(relevant: list[dict[str, Any]]) -> set[str]:
    """Extract class-name prefixes from Exodus's `code_signature` regexes.
    Exodus stores these as `|`-separated pipe alternations like
    `com.yandex.metrica|io.appmetrica.analytics`. We split on `|`,
    strip whitespace, skip empties.
    """
    out: set[str] = set()
    for t in relevant:
        code = t.get("code_signature") or ""
        for part in code.split("|"):
            part = part.strip()
            if part:
                out.add(part)
    return out


def exodus_domain_patterns(relevant: list[dict[str, Any]]) -> set[str]:
    """Extract plain domain strings from Exodus's `network_signature`
    regexes when they look like simple `host\\.tld` or
    `subdomain\\.host\\.tld` patterns. We skip entries that contain
    complex regex metacharacters to avoid false positives.
    """
    out: set[str] = set()
    for t in relevant:
        sig = t.get("network_signature") or ""
        for part in sig.split("|"):
            part = part.strip()
            if not part:
                continue
            # Conservative: accept only patterns that look like an
            # escaped-dot domain. Skip alternations, character classes,
            # anchors, etc.
            if "[" in part or "(" in part or "^" in part or "$" in part:
                continue
            domain = part.replace("\\.", ".").strip("/").lstrip(".")
            # Must look like a valid-ish FQDN: contains dots and only
            # DNS-safe chars.
            if "." in domain and all(
                c.isalnum() or c in ".-_"
                for c in domain
            ):
                out.add(domain)
    return out


def aggregate(
    publishers: list[dict[str, Any]],
    exodus_relevant: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Combine publishers.yaml and filtered Exodus data into the
    signatures.json field lists. Deduplicated + sorted.
    """
    fields: dict[str, set[str]] = {
        "package_prefixes": set(),
        "cert_fingerprints": set(),
        "metadata_keys": set(),
        "provider_authorities": set(),
        "suspicious_permissions": set(),
        "class_prefixes": set(),
        "domain_patterns": set(),
    }

    # From publishers.yaml
    for p in publishers:
        for f in ("package_prefixes", "cert_sha256", "metadata_keys",
                  "provider_authorities", "class_prefixes",
                  "domain_patterns"):
            for v in (p.get(f) or []):
                if not isinstance(v, str):
                    continue
                v = v.strip()
                if v:
                    key = "cert_fingerprints" if f == "cert_sha256" else f
                    fields[key].add(v)

    # From Exodus (additive only — never shrinks the publisher list)
    for prefix in exodus_class_prefixes(exodus_relevant):
        fields["class_prefixes"].add(prefix)
    for dom in exodus_domain_patterns(exodus_relevant):
        fields["domain_patterns"].add(dom)

    # Sorted for deterministic output
    return {k: sorted(v) for k, v in fields.items()}


def load_previous_signatures(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        log(f"WARNING: previous {path.name} is invalid JSON ({e}), starting fresh")
        return {}


def content_hash(fields: dict[str, list[str]]) -> str:
    """Stable content hash that ignores `version` and `updated_at` —
    used to decide whether to bump the version or not.
    """
    blob = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict-exodus",
        action="store_true",
        help="Fail if Exodus fetch fails (default: warn and continue)",
    )
    parser.add_argument(
        "--force-bump",
        action="store_true",
        help="Bump version even if content is unchanged",
    )
    args = parser.parse_args()

    publishers = load_publishers(PUBLISHERS_YAML)
    exodus_trackers = fetch_exodus_trackers(strict=args.strict_exodus)
    exodus_relevant = filter_exodus_relevant(exodus_trackers)

    fields = aggregate(publishers, exodus_relevant)
    new_hash = content_hash(fields)

    prev = load_previous_signatures(SIGNATURES_JSON)
    prev_version = int(prev.get("version", 0))
    prev_hash = prev.get("_content_hash", "")

    if prev_hash == new_hash and not args.force_bump:
        log(f"no content change since v{prev_version}; not rewriting")
        return 0

    new_version = prev_version + 1
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )

    out = {
        "version": new_version,
        "updated_at": now,
        "_content_hash": new_hash,
        **fields,
    }

    # Write with a stable key order + 2-space indent for readable diffs
    key_order = [
        "version",
        "updated_at",
        "_content_hash",
        "package_prefixes",
        "cert_fingerprints",
        "metadata_keys",
        "provider_authorities",
        "suspicious_permissions",
        "class_prefixes",
        "domain_patterns",
    ]
    ordered = {k: out[k] for k in key_order if k in out}

    SIGNATURES_JSON.write_text(
        json.dumps(ordered, indent=2, ensure_ascii=False) + "\n"
    )

    log(f"wrote {SIGNATURES_JSON.name} v{new_version}")
    log(f"  package_prefixes:       {len(fields['package_prefixes'])}")
    log(f"  cert_fingerprints:      {len(fields['cert_fingerprints'])}")
    log(f"  metadata_keys:          {len(fields['metadata_keys'])}")
    log(f"  provider_authorities:   {len(fields['provider_authorities'])}")
    log(f"  suspicious_permissions: {len(fields['suspicious_permissions'])}")
    log(f"  class_prefixes:         {len(fields['class_prefixes'])}")
    log(f"  domain_patterns:        {len(fields['domain_patterns'])}")
    return 0


if __name__ == "__main__":
    sys.exit(build())
