# CrowdStrike CSPM IOM Weekly Report Generator

Generates a weekly markdown report of CrowdStrike Falcon Cloud Security Posture Management (CSPM)
Indicators of Misconfiguration (IOMs) that matches exactly what you see in the Falcon UI
dashboard under **Failed + Active** findings.

---

## Quick Start

```bash
pip install requests

export FALCON_CLIENT_ID=<your_client_id>
export FALCON_CLIENT_SECRET=<your_client_secret>
export FALCON_CLOUD=us-2   # or us-1, eu-1, us-gov-1, us-gov-2

python iom_report.py
```

**Required API scope:** `CSPM Registration (Read)`

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `FALCON_CLIENT_ID` | Yes | Falcon API client ID |
| `FALCON_CLIENT_SECRET` | Yes | Falcon API client secret |
| `FALCON_CLOUD` | No | Cloud region: `us-1` \| `us-2` \| `eu-1` \| `us-gov-1` \| `us-gov-2` |
| `FALCON_BASE_URL` | No | Override API base URL directly |
| `REPORT_OUTPUT` | No | Output file path (default: `iom_report_<date>.md`) |
| `FILTER_CLOUD` | No | Scope to one provider: `aws` \| `azure` \| `gcp` |

All variables can also be passed as CLI flags — run `python iom_report.py --help` for details.

---

## API Endpoints Used

The script uses the **Cloud Security Evaluations** API, not the older Detects IOM API:

| Purpose | Endpoint |
|---|---|
| Query IOM IDs | `GET /cloud-security-evaluations/queries/ioms/v1` |
| Fetch IOM details | `GET /cloud-security-evaluations/entities/ioms/v1` |

> **Why not `/detects/queries/iom/v2`?**
> The older endpoint was deprecated in favor of this one. It returned findings scoped only
> to the current scan cycle, missed custom policies entirely, and required complex
> per-region deduplication. The `cloud-security-evaluations` endpoint returns one entry
> per resource+rule, includes custom policies, and is the endpoint recommended by
> CrowdStrike engineering.

---

## How the UI Filters Map to the API

The Falcon UI dashboard "Failed + Active" view applies two filters that are **not** directly
expressible as FQL query parameters. They must be applied in Python after fetching entity details.

### "Active" filter → `resource.status != "ResourceDeleted"`

When the UI shows **Active** resources, it excludes findings where the underlying cloud resource
no longer exists. In the API entity response, deleted resources have:

```json
{
  "resource": {
    "status": "ResourceDeleted"
  }
}
```

Active resources have no `status` field in the `resource` object at all (the field is absent).

There is **no FQL operator to negate a field value** on this endpoint (`resource_status!:'...'`
is not supported), so filtering must be done in Python after fetching entity details.

### "Failed" / Unresolved filter → `evaluation.extension.status != "Suppressed"`

Suppressed findings appear as `non-compliant` in the FQL query but are excluded from the UI
active count. The suppression status is found in:

```json
{
  "evaluation": {
    "extension": {
      "status": "Suppressed"
    }
  }
}
```

Unsuppressed (active/unresolved) findings have `extension.status = "Unresolved"`.

### Summary: UI view vs API fields

| UI filter | API field | Value to exclude |
|---|---|---|
| Active resources only | `resource.status` | `"ResourceDeleted"` |
| Unsuppressed only | `evaluation.extension.status` | `"Suppressed"` |
| Non-compliant | FQL: `status:'non-compliant'` | (query filter) |

### Verified count match (2026-04-26)

| Severity | UI | API (script) |
|---|---|---|
| Critical | 0 | 0 ✓ |
| High | 34 | 34 ✓ |
| Medium | 267 | 267 ✓ |
| Informational | 138 | 138 ✓ |
| **Total** | **439** | **439** ✓ |

---

## State File and New/Corrected Detection

After each run the script writes a state file:

```
iom_state_<client_id>[_<cloud_provider>].json
```

It stores the complete set of active non-compliant policy IDs from the current run.
On the next run, it diffs the current set against the saved set:

- **New** = policies with active non-compliant findings that were **not** in last run's state
- **Corrected** = policies that **were** in last run's state but are no longer non-compliant

This approach is more reliable than filtering by `first_detected` date because:
- It catches policies that were corrected and then regressed
- It doesn't require per-policy API calls for the corrected check
- It works regardless of scan timing

> **Note:** The first run after a fresh state file produces no new/corrected counts.
> Baseline is established on the first run; deltas appear on the second run.

---

## Report Format

```
IOM Report — 2026-04-26
==================================================

Total number of IOMs = 439
Number of Critical IOMs = 0
Number of High IOMs = 34
Number of Medium IOMs = 267
Number of Informational IOMs = 138

Number of new IOMs from last week's report = 12
Number of corrected IOMs from last week's report = 3

Misconfigurations must be remediated within the following timelines:
  Critical      - 15 days
  High          - 30 days
  Medium        - 60 days
  Informational - 90 days

New IOM Policy(s):
  147 ECR repository not set to Scan on Push
  ...

Corrected IOM Policy(s):
  525 KMS key scheduled for deletion
  ...

Current IOM Policy(s):
  1 IAM user access key active longer than 90 days
  ...
```

---

## Files

| File | Description |
|---|---|
| `iom_report.py` | Main script |
| `iom_state_<client_id>.json` | State file from last run (auto-generated) |
| `iom_report_<date>.md` | Generated report (auto-generated) |
