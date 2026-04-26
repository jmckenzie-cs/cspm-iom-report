#!/usr/bin/env python3
"""
CrowdStrike CSPM IOM Weekly Report Generator
Uses cloud-security-evaluations API — one entry per resource+rule, includes custom policies.

Required API scope: CSPM Registration (Read)

Usage:
    export FALCON_CLIENT_ID=<your_client_id>
    export FALCON_CLIENT_SECRET=<your_client_secret>
    python iom_report.py

Optional env vars:
    FALCON_BASE_URL  - API base URL (default: https://api.crowdstrike.com)
    FALCON_CLOUD     - us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2
                       (overrides FALCON_BASE_URL if set)
    REPORT_OUTPUT    - Output file path (default: iom_report_<date>.md)
    FILTER_CLOUD     - Scope report to one provider: azure | aws | gcp (optional)

State file:
    iom_state_<client_id>[_<cloud>].json — written after each run and read on the
    next run to detect new and corrected policies.

Filtering logic (matches UI "Failed + Active" view):
    - Excludes findings where resource.status == "ResourceDeleted" (UI "Active" filter)
    - Excludes findings where evaluation.extension.status == "Suppressed"
"""

import os
import sys
import json
import time
import argparse
import textwrap
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed. Run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CLOUD_URLS = {
    "us-1":     "https://api.crowdstrike.com",
    "us-2":     "https://api.us-2.crowdstrike.com",
    "eu-1":     "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

QUERY_EP  = "/cloud-security-evaluations/queries/ioms/v1"
ENTITY_EP = "/cloud-security-evaluations/entities/ioms/v1"

SEV_KEYS   = ["critical", "high", "medium", "informational"]
SEV_LABELS = {k: k.title() for k in SEV_KEYS}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_token(base_url: str, client_id: str, client_secret: str) -> str:
    resp = requests.post(
        f"{base_url}/oauth2/token",
        data={"client_id": client_id, "client_secret": client_secret},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _is_active(entity: dict) -> bool:
    """Return True if the entity should be included in the report.

    Matches the UI "Failed + Active" filter:
      - Excludes resources that have been deleted (resource.status == "ResourceDeleted")
      - Excludes suppressed findings (evaluation.extension.status == "Suppressed")
    """
    res_status = entity.get("resource", {}).get("status", "")
    ext_status = entity.get("evaluation", {}).get("extension", {}).get("status", "")
    return res_status != "ResourceDeleted" and ext_status != "Suppressed"


def _fetch_all_entities(
    base_url: str, token: str, filter_cloud: str | None = None
) -> list[dict]:
    """Page all non-compliant IOM IDs via cursor pagination and fetch entity details.

    Uses next_token cursor pagination (not offset) because the API rejects offsets
    beyond 10,000. The API always returns a next_token even on the last page, so
    the stop condition is len(ids) >= total rather than absence of a next_token.
    """
    headers = {"Authorization": f"Bearer {token}"}
    cloud_part = f"+cloud_provider:'{filter_cloud}'" if filter_cloud else ""
    fql = f"status:'non-compliant'{cloud_part}"

    # Collect all IDs via cursor pagination
    all_ids: list[str] = []
    next_token: str | None = None
    while True:
        params: dict = {"filter": fql, "limit": 500}
        if next_token:
            params["next_token"] = next_token
        resp = requests.get(
            f"{base_url}{QUERY_EP}",
            headers=headers,
            params=params,
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()
        page = body.get("resources", [])
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        next_token = body.get("meta", {}).get("next")
        all_ids.extend(page)
        if not page or len(all_ids) >= total:
            break
        time.sleep(0.2)

    if not all_ids:
        return []

    print(f"    Fetching details for {len(all_ids)} non-compliant evaluation(s) ...")

    # Fetch entity details in batches of 100
    entities: list[dict] = []
    for i in range(0, len(all_ids), 100):
        batch = all_ids[i: i + 100]
        resp = requests.get(
            f"{base_url}{ENTITY_EP}",
            headers=headers,
            params=[("ids", id_) for id_ in batch],
            timeout=60,
        )
        resp.raise_for_status()
        entities.extend(resp.json().get("resources", []))
        time.sleep(0.1)

    return entities


def get_severity_counts(
    entities: list[dict],
) -> tuple[dict[str, int], int]:
    """Return (counts_by_severity_label, total) from pre-fetched active entities.

    Counts only active, non-suppressed findings — matches the UI "Failed + Active" view.
    """
    counts: dict[str, int] = {SEV_LABELS[k]: 0 for k in SEV_KEYS}
    for e in entities:
        if _is_active(e):
            sev = e.get("evaluation", {}).get("severity", "")
            label = SEV_LABELS.get(sev)
            if label:
                counts[label] += 1
    return counts, sum(counts.values())


def get_all_active_policies(
    entities: list[dict],
) -> dict[str, str]:
    """Return {policy_id: rule_name} for every active, non-suppressed finding.

    Deduplicates by policy_id — used to detect new and corrected policies
    by diffing against the previous run's state.
    """
    policies: dict[str, str] = {}
    for e in entities:
        if not _is_active(e):
            continue
        rule = e.get("evaluation", {}).get("rule", {})
        pid  = str(rule.get("policy_id", ""))
        name = rule.get("name", "")
        if pid and name and pid not in policies:
            policies[pid] = name
    return policies


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------

def load_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: str, run_date: str, active_policies: dict[str, str]) -> None:
    with open(path, "w") as f:
        json.dump({"run_date": run_date, "active_policies": active_policies}, f, indent=2)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_policy_list(policies: dict[str, str]) -> list[str]:
    lines = []
    for pid, name in sorted(policies.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        lines.append(f"  {pid} {name}".rstrip())
    return lines


def generate_report(
    counts: dict[str, int],
    total: int,
    current_policies: dict[str, str],
    new_policies: dict[str, str],
    corrected_policies: dict[str, str],
    report_date: str,
    filter_cloud: str | None = None,
) -> str:
    scope = f" [{filter_cloud.upper()}]" if filter_cloud else ""
    report_lines = [
        f"IOM Report{scope} — {report_date}",
        "=" * 50,
        "",
        f"Total number of IOMs = {total}",
        f"Number of Critical IOMs = {counts.get('Critical', 0)}",
        f"Number of High IOMs = {counts.get('High', 0)}",
        f"Number of Medium IOMs = {counts.get('Medium', 0)}",
        f"Number of Informational IOMs = {counts.get('Informational', 0)}",
        "",
        f"Number of new IOMs from last week's report = {len(new_policies)}",
        f"Number of corrected IOMs from last week's report = {len(corrected_policies)}",
        "",
        "Misconfigurations must be remediated within the following timelines:",
        "  Critical      - 15 days",
        "  High          - 30 days",
        "  Medium        - 60 days",
        "  Informational - 90 days",
        "",
        "New IOM Policy(s):",
    ]

    new_lines = build_policy_list(new_policies)
    report_lines.extend(new_lines if new_lines else ["  (none)"])
    report_lines += ["", "Corrected IOM Policy(s):"]
    corrected_lines = build_policy_list(corrected_policies)
    report_lines.extend(corrected_lines if corrected_lines else ["  (none)"])
    report_lines += ["", "Current IOM Policy(s):"]
    current_lines = build_policy_list(current_policies)
    report_lines.extend(current_lines if current_lines else ["  (none)"])
    report_lines.append("")

    return "\n".join(report_lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a weekly CrowdStrike CSPM IOM report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Environment variables (alternative to flags):
              FALCON_CLIENT_ID      API client ID
              FALCON_CLIENT_SECRET  API client secret
              FALCON_BASE_URL       API base URL (default: https://api.crowdstrike.com)
              FALCON_CLOUD          us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2
              REPORT_OUTPUT         Output file path
              FILTER_CLOUD          Scope report to one provider: azure | aws | gcp
        """),
    )
    parser.add_argument("--client-id",     default=os.environ.get("FALCON_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.environ.get("FALCON_CLIENT_SECRET"))
    parser.add_argument("--base-url",      default=None,
                        help="API base URL. Overrides FALCON_BASE_URL / FALCON_CLOUD.")
    parser.add_argument("--cloud",         default=os.environ.get("FALCON_CLOUD"),
                        choices=list(CLOUD_URLS.keys()),
                        help="CrowdStrike cloud region.")
    parser.add_argument("--output",        default=os.environ.get("REPORT_OUTPUT"),
                        help="Output file path (default: iom_report_<date>.md)")
    parser.add_argument("--filter-cloud",
                        default=os.environ.get("FILTER_CLOUD"),
                        metavar="PROVIDER",
                        help="Scope report to a single cloud provider: azure | aws | gcp")
    args = parser.parse_args()

    # Resolve base URL
    base_url = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
    if args.cloud:
        base_url = CLOUD_URLS[args.cloud]
    if args.base_url:
        base_url = args.base_url.rstrip("/")

    if not args.client_id or not args.client_secret:
        print("ERROR: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are required.")
        print("       Set them as environment variables or use --client-id / --client-secret.")
        sys.exit(1)

    filter_cloud = args.filter_cloud.lower() if args.filter_cloud else None

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output_path = args.output or f"iom_report_{report_date}.md"
    if filter_cloud and not args.output:
        output_path = f"iom_report_{filter_cloud}_{report_date}.md"

    state_path = f"iom_state_{args.client_id}{'_' + filter_cloud if filter_cloud else ''}.json"

    print(f"[*] Authenticating to {base_url} ...")
    token = get_token(base_url, args.client_id, args.client_secret)
    print(f"    State file: {state_path}")

    print("[*] Fetching all non-compliant IOM evaluations ...")
    entities = _fetch_all_entities(base_url, token, filter_cloud=filter_cloud)
    print(f"    Retrieved {len(entities)} evaluation(s).")

    print("[*] Computing counts and active policies ...")
    counts, total = get_severity_counts(entities)
    print(f"    Total (active): {total}  (Critical={counts.get('Critical',0)}  High={counts.get('High',0)}  Medium={counts.get('Medium',0)}  Informational={counts.get('Informational',0)})")

    state = load_state(state_path)
    prev_policies: dict[str, str] = state.get("active_policies", {})

    current_policies = get_all_active_policies(entities)
    print(f"    Found {len(current_policies)} unique active IOM policy(s).")

    # New = currently failing but not in previous run's state
    # Corrected = were failing last run but no longer present
    new_policies       = {k: v for k, v in current_policies.items() if k not in prev_policies}
    corrected_policies = {k: v for k, v in prev_policies.items()    if k not in current_policies}

    if prev_policies:
        print(f"    New since last run: {len(new_policies)}  |  Corrected since last run: {len(corrected_policies)}")
    else:
        print("    No previous state found — new/corrected counts will appear on next run.")

    save_state(state_path, report_date, current_policies)

    print("[*] Building report ...")
    report = generate_report(
        counts=counts,
        total=total,
        current_policies=current_policies,
        new_policies=new_policies,
        corrected_policies=corrected_policies,
        report_date=report_date,
        filter_cloud=filter_cloud,
    )

    with open(output_path, "w") as f:
        f.write(report)

    print(f"[+] Report written to: {output_path}")
    print()
    print(report)


if __name__ == "__main__":
    main()
