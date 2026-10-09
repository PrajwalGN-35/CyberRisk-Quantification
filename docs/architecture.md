# CyberRisk Quantification

## Objective
Continuously quantify cyber risk, prioritize security gaps, and optimize
security investments under a defined budget.

## Required security data domains
1. Assets
2. Vulnerabilities
3. Threats
4. Incidents
5. Security controls

## Project structure
- backend/contracts.py: shared team interfaces
- backend/core/: risk engine, prioritizer and optimizer
- backend/data/: synthetic security data generation
- backend/services/: monitoring and AI orchestration
- backend/main.py: FastAPI backend
- app.py: Streamlit dashboard
- tests/: automated tests

## Engineering principles
- Risk calculations must be explainable and deterministic.
- Investment selection must respect the available budget.
- Avoid double-counting overlapping risk-reduction benefits.
- Use real platform outputs as evidence for AI explanations.
- Label synthetic data clearly.
- Treat risk scores as modeled indicators, not calibrated probabilities.

## Risk engine and security-gap prioritizer

The shared function signatures are declared in `backend/contracts.py`. The
record fields and result shapes below are implementation schemas for those
functions; they are not additional shared-contract requirements. Scores are
modeled indicators, not calibrated probabilities of a breach.

### Input normalization

The canonical input is a list of dictionaries. Records with missing or
unrecognized optional values do not contribute that factor. A malformed
record or reference to an unknown asset is excluded and reported in
`data_quality.warnings`. An invalid score is excluded from scoring and
reported; valid identifying/evidence fields in that record are retained.
Invalid or missing data does not silently become a zero score. Input order
does not affect results. Asset IDs and evidence IDs are case-sensitive strings
after trimming whitespace.

| Record | Required association | Fields used |
| --- | --- | --- |
| Asset | `asset_id` | `name` (or `asset_name`), `criticality`, `exposure` |
| Vulnerability | `asset_id` | `vulnerability_id` (or `id`), `severity` (or `cvss_score`), `title`, `name`, `remediation`, `recommendation`, `fix` |
| Threat | `asset_id` | `threat_id` (or `id`), `likelihood`, `name` |
| Incident | `asset_id` | `incident_id` (or `id`), `severity`, `occurred_at`, `summary` |
| Control | `asset_id` or `asset_ids` | `control_id` (or `id`), `domain` or `domains`, `effectiveness`, `name`, `remediation`, `recommendation`, `fix` |

`criticality`, `severity`, `likelihood`, `exposure`, and `effectiveness` also
accept the corresponding `*_score` field. Numeric criticality, exposure, and
control effectiveness use 0–1 as a fraction and 0–100 as a percentage. Numeric
vulnerability/incident severity uses 0–10 (including CVSS) or 0–100; values
from 0 through 10 are interpreted on the 0–10 scale and multiplied by 10,
while values above 10 through 100 are retained as percentages. Numeric threat
likelihood uses 0–1 as a probability (multiplied by 100) or values above 1
through 100 as a percentage. For the other 0–1-or-100 fields, values through
1 are interpreted as fractions and values above 1 through 100 as percentages.
Values outside the applicable ranges are invalid. Case-insensitive labels map
to their category lower bounds: Low=0, Moderate=25, High=50, Critical=75.

Vulnerabilities and incidents with the same stable ID and asset are one piece
of evidence; repeated copies do not increase risk. When no stable ID is
provided, exact canonical duplicate records are collapsed. Records that are
not exact matches remain distinct. For a stable-ID collision, retain the
highest normalized severity; ties are resolved by a stable normalized record
ordering. Threats and controls follow the same stable-ID/exact-record
deduplication rule, retaining the highest likelihood or effectiveness for a
stable-ID collision in the same asset/domain scope. Duplicate asset records
are combined by retaining the highest valid criticality and exposure values
and the lexicographically smallest non-empty name.

### Risk scores and result shape

For each asset, calculate the inherent score from available factor scores:

```text
inherent = sum(weight[factor] * score[factor] for available factors)
           / sum(weight[factor] for available factors)
```

The fixed weights are criticality 25%, vulnerability severity 30%, threat
likelihood 20%, incident severity/history 15%, and exposure 10%. Unavailable
factors are omitted and remaining weights are renormalized. The incident
factor, when incident records exist, is 70% mean normalized incident severity
and 30% a recurrence score of 10 points per distinct incident, capped at 100;
if incident severity is unavailable, use only the recurrence score. This
bounded count is a transparent history indicator, not a frequency estimate.

Controls mitigate only a factor whose asset association and matching domain
are explicit in the input. Supported domains are `vulnerability`, `threat`,
`incident`, and `exposure` (singular or plural). Controls do not mitigate
criticality. For overlapping controls on the same asset and domain, use the
highest normalized effectiveness once rather than multiplying reductions.
For each available factor, its residual contribution is its inherent
contribution multiplied by `(1 - effectiveness / 100)` for the strongest
applicable control, or left unchanged without one. Residual risk is the sum of
residual contributions divided by the same available-factor weight sum.
Controls without a usable asset association, supported domain, and
effectiveness do not reduce risk.

Each asset result contains `asset_id`, optional `asset_name`,
`inherent_risk_score`, `residual_risk_score`, `category`, normalized `factors`,
`risk_drivers`, human-readable `reasons`, and evidence grouped by
`vulnerabilities`, `threats`, `incidents`, and `controls`. A factor unavailable
from the input is `null`. An asset with no available risk factors has null
scores and category `Unknown`; missing information is not represented as zero.
`data_quality.warnings` reports malformed and unassociated records.

The exact result mapping has this shape (factor and evidence arrays contain
the normalized values and deduplicated input records described above):

```text
{
  "organization": {
    "asset_count": int,
    "scored_asset_count": int,
    "inherent_risk_score": float | null,
    "residual_risk_score": float | null,
    "category": "Low" | "Moderate" | "High" | "Critical" | "Unknown",
    "top_risk_drivers": [factor_name, ...]
  },
  "assets": [{
    "asset_id": str,
    "asset_name": str | null,
    "inherent_risk_score": float | null,
    "residual_risk_score": float | null,
    "category": category,
    "factors": {
      "criticality": float | null,
      "vulnerability_severity": float | null,
      "threat_likelihood": float | null,
      "incident_history": float | null,
      "exposure": float | null,
      "control_effectiveness": {factor_domain: float, ...}
    },
    "risk_drivers": [factor_name, ...],
    "reasons": [str, ...],
    "evidence": {
      "vulnerabilities": [input_record, ...],
      "threats": [input_record, ...],
      "incidents": [input_record, ...],
      "controls": [input_record, ...]
    }
  }],
  "data_quality": {"warnings": [str, ...]}
}
```

The organization summary reports `asset_count`, `scored_asset_count`,
arithmetic-mean inherent and residual scores across scored assets, a category,
and top risk drivers. Each asset contributes once regardless of evidence
record count; scores are not summed across assets. If no asset has a score,
organization scores are null and its category is `Unknown`.

Categories use unrounded scores: Low [0, 25), Moderate [25, 50), High [50, 75),
Critical [75, 100]. Scores are bounded to 0–100 and rounded to two decimal
places in results.

### Gap ranking

The prioritizer consumes the risk result's `assets` list and evidence above.
It emits one result per vulnerability evidence item with a stable ID, title,
name, or valid severity, and per explicitly associated control whose
effectiveness is below 100. An asset association alone is not enough to create
a vulnerability gap. It does not create a gap for an absent vulnerability or
control, or infer technical details.
Where supplied, `remediation` is used as the recommendation; otherwise the
recommendation asks the owner to review the recorded evidence and apply an
approved remediation without prescribing an unsupported fix.

The priority score is the weighted mean of available inputs, with applicable
weights renormalized when evidence is missing:

| Input | Weight |
| --- | ---: |
| Asset residual risk | 35% |
| Asset criticality | 20% |
| Associated vulnerability severity | 20% |
| Asset exposure | 10% |
| Asset incident history factor | 10% |
| Gap-specific control weakness | 5% |

For a control gap, control weakness is `100 - effectiveness`; its vulnerability
factor is the asset's normalized vulnerability factor when present. For a
vulnerability gap, use that vulnerability's severity and only use control
weakness when an explicitly vulnerability-scoped control exists for the asset.
Unavailable values are omitted and weights renormalized. A gap with no
available numeric ranking inputs is retained with null priority and category
`Unknown`, sorted below scored gaps.

Gap output records contain `asset_id`, `asset_name`, `gap_type`, `gap_id`,
`title`, `priority_score`, `category`, the supplied `evidence`, an `explanation`,
and `recommendation`. Deduplicate by asset ID plus stable gap ID; without a
stable ID, use an exact canonical key only when the evidence has enough identifying
fields, otherwise collapse exact duplicate evidence only. Sort by descending
priority, then ascending asset ID, gap type, and gap ID/title. These weights
are prioritization heuristics, not calibrated probabilities or a claim that
one remediation will reduce risk by the priority score.

The exact prioritizer result is a list of:

```text
{
  "asset_id": str,
  "asset_name": str | null,
  "gap_type": "vulnerability" | "control",
  "gap_id": str | null,
  "title": str | null,
  "priority_score": float | null,
  "category": "Low" | "Moderate" | "High" | "Critical" | "Unknown",
  "evidence": input_record,
  "explanation": str,
  "recommendation": str
}
```

## Team coordination
Coordinate changes to shared interfaces before merging feature branches.
