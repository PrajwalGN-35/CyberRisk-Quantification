# Member 3: Security Data Generation and Monitoring

## Contract status

This is a **provisional Member 3 schema** because
[`backend/contracts.py`](../backend/contracts.py) declares the generator and
monitoring function signatures but does not define record fields, an event
selector, or a response shape. The implementation deliberately leaves that
shared contract and all other members' modules unchanged. Prajwal should approve
or adapt this schema before team integration.

## Module interface

```python
from backend.data.generator import generate_security_data
from backend.services.monitoring import simulate_security_event

state = generate_security_data()
state["event_type"] = "critical_vulnerability_discovered"
result = simulate_security_event(state)
updated_state = result["state"]
event = result["event"]
```

The callable signatures are:

```python
def generate_security_data() -> dict[str, Any]: ...
def simulate_security_event(state: dict[str, Any]) -> dict[str, Any]: ...
```

Generation is deterministic and takes no arguments, as required by the shared
function signature. Every call returns a new set of lists and records; callers
can safely mutate the result without affecting subsequent generations.

## State and record schema

`generate_security_data()` returns these keys:

| Key | Type | Demonstration count | Proposed fields |
| --- | --- | ---: | --- |
| `assets` | `list[dict]` | 6 | `id`, `name`, `type`, `environment`, `criticality`, `owner` |
| `vulnerabilities` | `list[dict]` | 6 | `id`, `asset_id`, `title`, `description`, `severity`, `status`, `discovered_at`; remediated records also have `remediated_at` |
| `threats` | `list[dict]` | 4 | `id`, `name`, `category`, `likelihood`, `relevance`, `description` |
| `incidents` | `list[dict]` | 3 | `id`, `asset_id`, `title`, `description`, `severity`, `status`, `detected_at`; resolved records also have `resolved_at` |
| `controls` | `list[dict]` | 6 | `id`, `asset_id`, `name`, `type`, `status`, `effectiveness` |
| `investments` | `list[dict]` | 3 | `id`, `name`, `asset_id`, `cost`, `risk_reduction` |
| `event_history` | `list[dict]` | 0 initially | Monitoring event records; described below |

IDs are unique within their record domain. Vulnerability, incident, and control
`asset_id` values reference an existing asset. `effectiveness` and investment
`risk_reduction` are demonstration fractions in the inclusive range 0–1;
investment `cost` is a non-negative numeric value.

### Proposed field definitions

All fields below are provisional, with ordinary string and numeric values
intended for interchange as JSON. Unknown fields should be preserved by
consumers where practical so this schema can be adapted without losing data.

| Record | Field | Proposed type and meaning |
| --- | --- | --- |
| Asset | `id` | String identifier, currently `AST-###`; unique among assets. |
| Asset | `name` | Human-readable asset name. |
| Asset | `type` | Asset category string, such as `database_server` or `web_server`. |
| Asset | `environment` | Environment label, such as `production`, `corporate`, or `internal`. |
| Asset | `criticality` | One of `critical`, `high`, `medium`, or `low`. |
| Asset | `owner` | Responsible team or owner label. |
| Vulnerability | `id` | String identifier, currently `VUL-###`; simulated additions use `VUL-SIM-####`. |
| Vulnerability | `asset_id` | Existing asset's `id`. |
| Vulnerability | `title`, `description` | Short label and explanatory text. |
| Vulnerability | `severity` | One of `critical`, `high`, `medium`, or `low`. |
| Vulnerability | `status` | `open` or `remediated`. |
| Vulnerability | `discovered_at` | Discovery timestamp as an ISO 8601 string with UTC offset. |
| Vulnerability | `remediated_at` | Optional ISO 8601 timestamp; present on generated remediated example. |
| Threat | `id` | String identifier, currently `THR-###`; unique among threats. |
| Threat | `name`, `description` | Threat label and explanatory text. |
| Threat | `category` | Category string, currently malware, phishing, ransomware, or credential compromise. |
| Threat | `likelihood`, `relevance` | Qualitative labels, each one of `low`, `medium`, or `high`. |
| Incident | `id` | String identifier, currently `INC-###`; simulated additions use `INC-SIM-####`. |
| Incident | `asset_id` | Existing asset's `id`. |
| Incident | `title`, `description` | Short label and explanatory text. |
| Incident | `severity` | One of `critical`, `high`, `medium`, or `low`. |
| Incident | `status` | `active` or `resolved`. |
| Incident | `detected_at` | Detection timestamp as an ISO 8601 string with UTC offset. |
| Incident | `resolved_at` | Optional ISO 8601 timestamp for resolved examples. |
| Control | `id` | String identifier, currently `CTL-###`; unique among controls. |
| Control | `asset_id` | Existing asset's `id`. |
| Control | `name` | Human-readable control name. |
| Control | `type` | Category string, e.g. `firewall`, `endpoint_protection`, or `backup_system`. |
| Control | `status` | One of `active`, `operational`, `degraded`, `maintenance`, or `unavailable`. |
| Control | `effectiveness` | Numeric demonstration fraction from 0 through 1, inclusive. |
| Investment | `id` | String identifier, currently `INV-###`; unique among investments. |
| Investment | `name` | Human-readable proposed investment name. |
| Investment | `asset_id` | Existing asset's `id`. |
| Investment | `cost` | Non-negative numeric demonstration cost; currency is not specified. |
| Investment | `risk_reduction` | Numeric demonstration fraction from 0 through 1, inclusive. |

The generated top-level `event_history` starts as an empty list. Simulation
requires an input-only top-level `event_type` string, which is not included in
the generated initial state. It must equal one of the five event types below.
When a control is degraded, its record temporarily gains
`pre_degradation_status` (the previous `active` or `operational` status) and
`pre_degradation_effectiveness` (the previous numeric effectiveness from 0
through 1); restoration removes both fields.

Asset `type` values demonstrate database servers, web servers, employee
workstations, financial applications, and file servers. Asset `criticality`
varies among critical, high, and medium. Vulnerability `severity` varies among
critical, high, medium, and low, and status is open or remediated. Threat
categories include malware, phishing, ransomware, and credential compromise;
likelihood and relevance use low, medium, or high. Incidents include active
and resolved examples. Control types include firewalls, multi-factor
authentication, endpoint protection, intrusion detection, and backup systems.
Control status includes active and maintenance, with distinct effectiveness
levels.

All records are fabricated demonstration data; no real system or confidential
information is queried.

### Example initial state

```python
{
    "assets": [
        {
            "id": "AST-001",
            "name": "Production Customer Database",
            "type": "database_server",
            "environment": "production",
            "criticality": "critical",
            "owner": "Data Operations",
        },
        # Five further synthetic assets.
    ],
    "vulnerabilities": [
        {
            "id": "VUL-001",
            "asset_id": "AST-001",
            "title": "Unpatched database service",
            "description": "...",
            "severity": "high",
            "status": "open",
            "discovered_at": "2026-01-12T09:00:00+00:00",
        },
        # Five further records.
    ],
    "threats": [...],
    "incidents": [...],
    "controls": [...],
    "investments": [...],
    "event_history": [],
}
```

This abbreviated example illustrates the proposed shape; the module returns the
complete records.

## Monitoring event selection and response

Provide `event_type` in the input state to select one event:

1. `critical_vulnerability_discovered`: creates a critical open vulnerability
   referencing the highest-criticality available asset.
2. `security_incident_detected`: creates a high-severity active incident on a
   critical/high asset.
3. `control_degraded`: selects the first active/operational control, sets its
   status to `degraded`, and reduces effectiveness by 0.25 (floor 0). The
   previous status and effectiveness are stored temporarily for exact recovery
   and both temporary fields are recorded in the event changes.
4. `vulnerability_remediated`: selects the first open vulnerability, changes
   its status to `remediated`, and adds `remediated_at`.
5. `control_restored`: selects a degraded control, restores its previous
    active/operational status and pre-degradation effectiveness, and removes
    the temporary recovery fields. A control degraded by this simulator always
    has those saved values. If the input already contains a degraded control
    without them, status is set to `active` and effectiveness increases by 0.25
    (capped at 1.0).

The simulation validates domain lists, record dictionaries, unique IDs,
asset relationships, control effectiveness bounds, event-history shape, and
the event selector. It raises `TypeError` or `ValueError` for malformed input,
unsupported event types, and events without eligible records. It deep-copies
the caller's state and does not mutate it. The returned state retains
`event_type`; set it to the next event type before calling again.

The response is:

```python
{
    "state": updated_state,
    "event": {
        "event_id": "EVT-0001",
        "timestamp": "2026-02-01T00:00:00+00:00",
        "event_type": "critical_vulnerability_discovered",
        "description": "Critical vulnerability discovered on asset AST-001.",
        "affected_entities": [
            {"entity_type": "asset", "entity_id": "AST-001"},
            {"entity_type": "vulnerability", "entity_id": "VUL-SIM-0001"},
        ],
        "state_changes": [
            {
                "entity_type": "vulnerability",
                "entity_id": "VUL-SIM-0001",
                "field": "record",
                "before": None,
                "after": {"...": "new vulnerability record"},
            },
        ],
    },
}
```

`event_history` receives a copy of the same event record. Event IDs are
collision-checked sequential IDs. Timestamps use a fixed synthetic epoch and
advance one minute per recorded event, making test runs repeatable rather than
representing wall-clock time. Each `state_changes` entry records the entity,
field, and before/after values; added records use `field="record"` and
`before=None`.

The event response fields are defined as follows:

| Event field | Proposed shape and meaning |
| --- | --- |
| `event_id` | String identifier, currently `EVT-####`, collision-checked against the event history. |
| `timestamp` | Deterministic ISO 8601 UTC timestamp, based on the fixed simulation epoch and history length. |
| `event_type` | The selected value from the five supported event types. |
| `description` | Human-readable summary of the simulated change. |
| `affected_entities` | List of `{ "entity_type": string, "entity_id": string }` references to affected records. |
| `state_changes` | Ordered list of `{ "entity_type": string, "entity_id": string, "field": string, "before": JSON value or null, "after": JSON value or null }`. For a new record, `field` is `record`, `before` is null, and `after` is the complete new record. |
| Response `state` | Deep-copied updated input state, preserving all five domains, ancillary keys, and the selected `event_type`; appends the event to `event_history`. |
| Response `event` | The event record described above; its value equals the appended event-history entry. |

### Example event call

```python
state = generate_security_data()
state["event_type"] = "vulnerability_remediated"
result = simulate_security_event(state)
assert result["event"]["event_type"] == "vulnerability_remediated"
assert result["state"]["event_history"][-1] == result["event"]
```

## Continuous risk reassessment integration

Member 3 does not implement risk scoring. Once the risk-engine module is
available, the team lead can pass the five domain lists to the existing
contract without transforming or duplicating records:

```python
from backend.contracts import calculate_risk

state = generate_security_data()
risk_before = calculate_risk(
    state["assets"],
    state["vulnerabilities"],
    state["threats"],
    state["incidents"],
    state["controls"],
)

state["event_type"] = "control_degraded"
result = simulate_security_event(state)
updated = result["state"]
risk_after = calculate_risk(
    updated["assets"],
    updated["vulnerabilities"],
    updated["threats"],
    updated["incidents"],
    updated["controls"],
)
# Compare risk_before and risk_after using the risk engine's returned schema.
```

The current `backend/contracts.py` defines `calculate_risk(...)` but leaves its
body unimplemented. Consequently, an end-to-end risk comparison is blocked
until another team member supplies the risk engine; this implementation only
ensures remediation and control status/effectiveness changes are present in
the five inputs for that future calculation.

## Team integration checklist

Please have Prajwal confirm:

- The seven top-level keys and the proposed fields/enumerations above.
- Whether event selection should remain `state["event_type"]`.
- Whether the response should remain `{"state": ..., "event": ...}` and
  whether `event_history` belongs in the security-state payload.
- Identifier formats, timestamp policy, status/effectiveness units, and whether
  the optional investment records belong in this state.

The five risk-engine argument lists remain compatible with the shared function
signature. Once agreed, update this schema and its focused tests to match the
team contract before integrating across members.

## Run tests

From the repository root in the VS Code terminal:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_security_data.py tests\test_monitoring.py
```
