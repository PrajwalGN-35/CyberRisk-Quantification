# Security Investment Optimizer

## Interface

The public function is `backend.services.investment_optimizer.optimize_investments(
risk_assessments, investments, budget)`. The shared declaration in
`backend/contracts.py` specifies this function signature but does not currently
define field-level or output schemas. This service therefore uses the canonical
shape below; integration owners should align upstream producers before wiring it
into the API.

`risk_assessments` is a mapping with an `assets` list. Each asset requires a
unique non-empty string `asset_id` and a finite, non-negative `risk_score`.
`security_gaps` is optional and defaults to an empty list. A gap is either an ID
string or a mapping with `gap_id` and optional `risk_score`. If no gap has an
explicit score, the asset score is divided equally over its listed gaps. If all
gaps have scores, those scores are used directly as the asset's modeled risk
contributions. Mixing scored and unscored gaps is invalid. An asset without
gaps contributes one asset-level risk atom.

Each investment requires a unique non-empty string `investment_id`, finite
non-negative `cost`, and `effectiveness` in the closed interval [0, 1]. Optional
`covers_assets` and `covers_gaps` are lists of IDs and default to empty lists.
Every coverage ID must exist in the risk assessment or input validation raises
`ValueError`. Coverage of an asset applies to its risk atoms; coverage of a gap
applies to that gap on every assessed asset. The budget must be a finite
non-negative number. Monetary values are compared using decimal representations
of the provided numbers.

The result includes `optimization_status`, `budget`, `total_cost`,
`remaining_budget`, `selected_investments`, `excluded_investments`,
`estimated_risk_reduction`, `baseline_risk_score`, `residual_risk_score`,
`selection_explanations`, `assumptions`, and `limitations`. Selected entries
include the investment ID, cost, effectiveness, coverage, marginal modeled
risk reduction, and a selection explanation in ID order. Excluded entries
include the ID, reason, and explanation. Exclusions distinguish unaffordable
relevant options, options with no positive relevant coverage, and affordable
options omitted from the globally optimal portfolio. Invalid records raise
`ValueError` and are not silently converted to exclusions.

Missing required fields, malformed lists or IDs, duplicate asset/gap/investment
IDs, negative values, non-finite numbers, and out-of-range effectiveness raise
`ValueError`. Optional coverage and gap fields may be omitted. Inputs are read
without mutation. Empty assets and investments are valid; empty assets yield a
zero baseline score. A finite set of asset-level values whose aggregate
overflows the finite float range is also rejected.

## Objective And Method

For each assessed asset-gap pair (a risk atom) with baseline score $r_j$, let
$e_{ij}$ be investment $i$'s modeled effectiveness on that atom when covered,
and zero otherwise. For a selected portfolio $S$, the residual risk is

$$
R(S) = \sum_j r_j \prod_{i \in S}(1 - e_{ij}),
$$

and the objective is to maximize $R(\emptyset) - R(S)$ subject to
$\sum_{i \in S} c_i \leq B$. This multiplicative residual model makes
overlapping effects diminishing: two 50% controls on the same risk atom yield
75% combined reduction, not 100%.

The implementation performs exact branch-and-bound subset search. Its
admissible bounds use both the effect of hypothetically taking every remaining
investment and a fractional budget relaxation of remaining marginal benefits.
When the best possible remaining objective only ties the incumbent, another
fractional relaxation lower-bounds the cost needed to match it; this prunes
equal-benefit branches that cannot improve incumbent cost. Candidate priority
is descending standalone modeled reduction per cost, then ID (free options
first); traversal explores inclusion before exclusion. The winner is chosen by
modeled reduction, then lower cost, then first portfolio in this stable
traversal order. This makes equal-cost ties reproducible under investment
input reordering.

Exact search states are memoized by candidate index, decimal spend, and exact
residual-risk vector. Reaching the same state again cannot change any feasible
completion's objective or cost, so the first include-first traversal prefix is
retained and equivalent later subtrees are skipped. This particularly reduces
search for interchangeable, heavily overlapping investments without relaxing
the objective or budget bounds.

Adjacent candidates with exactly equal decimal cost and equal per-atom
effectiveness coverage are searched as a selected-count choice. For any chosen
count, the earliest members in candidate order are retained, matching
include-first traversal and its tie rule. This removes symmetric subset
permutations for those adjacent groups; distinct or interleaved candidate
groups still have exponential worst-case search.

For $n$ affordable relevant investments and $m$ risk atoms, worst-case time is
$O(2^n(nm + n\log n))$: the search may visit every subset and computes marginal
bounds over remaining investments and atoms at each node. Suffix factors use
$O(nm)$ memory. The memoized state set can use $O(Vm)$ memory for $V$ visited
states, with $V$ exponential in the worst case. Symmetric portfolios with
exactly repeated cost and coverage are collapsed, but instances with many
distinct, overlapping groups remain expensive. The opt-in pytest benchmark
covers 20, 50, 100, and 200 independent equal-value options without imposing
timing thresholds. It also measures equally priced options with identical
coverage to expose the effect of state memoization under overlap:

```powershell
$env:RUN_OPTIMIZER_BENCHMARKS = "1"
python -m pytest tests/test_investment_optimizer.py -k scaling_benchmark -s
```

Costs are accumulated as decimals for budget feasibility. Risk scores and
effectiveness are validated and normalized to finite floats at input, then
converted to exact rational values for portfolio effects and branch bounds;
reported numeric result fields are floats. This avoids float overflow or
rounding in objective bounds while keeping the established numeric interface.
Non-finite scores/effectiveness and values outside the finite float range raise
`ValueError`.

## Assumptions And Limitations

- Effectiveness is interpreted as a fractional reduction in remaining covered
  risk, not as an independently additive benefit or a measured guarantee.
- The multiplicative overlap rule is a modeling convention equivalent to
  compounding independent fractional effects; it is not evidence that real
  controls are independent or that their effectiveness has been validated.
- Asset-level risk is split evenly across listed gaps when gap-level scores are
  absent. Explicit gap scores replace that asset's aggregate score in the
  baseline total.
- Listed asset/gap coverage is complete, and coverage/effectiveness do not vary
  by deployment context or investment interactions beyond multiplicative
  overlap.
- Risk scores and resulting reductions are modeled decision-support indicators,
  not calibrated real-world breach probabilities.
- No shared contract defines an allowed risk-score scale or upper bound. The
  implementation rejects negative and non-finite scores but otherwise preserves
  finite nonnegative inputs; teams must agree on scale and aggregation semantics.
- Duplicate asset IDs are rejected rather than treated as independent
  assessments, preventing accidental double-counting. Repeated observations
  require an upstream aggregation rule that is not currently defined.
- Estimates should be replaced or calibrated with empirical evidence when
  available; costs, coverage, and effectiveness may be uncertain.

## Tests

From the repository root, run the focused tests with:

```powershell
python -m pytest tests/test_investment_optimizer.py
```

Run the repository test suite with `python -m pytest`.