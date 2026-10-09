"""Exact, explainable budget-constrained security investment optimization."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from fractions import Fraction
from math import isfinite
from numbers import Real
from typing import Any, Mapping


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (Real, Decimal)):
        raise ValueError(f"{field} must be a finite number")
    try:
        number = float(value)
    except OverflowError as error:
        raise ValueError(f"{field} must be a finite number") from error
    if not isfinite(number) or (number == 0 and value != 0):
        raise ValueError(f"{field} must be a finite number")
    return number


def _cost(value: Any, field: str) -> Decimal:
    _number(value, field)
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError(f"{field} must be a finite number") from error
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return amount


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _list_field(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _risk_atoms(risk_assessments: Any) -> list[tuple[str, str | None, float]]:
    if not isinstance(risk_assessments, Mapping):
        raise ValueError("risk_assessments must be a mapping")
    if "assets" not in risk_assessments:
        raise ValueError("risk_assessments.assets is required")

    atoms: list[tuple[str, str | None, float]] = []
    asset_ids: set[str] = set()
    for asset_index, asset in enumerate(
        _list_field(risk_assessments["assets"], "risk_assessments.assets")
    ):
        field = f"risk_assessments.assets[{asset_index}]"
        if not isinstance(asset, Mapping):
            raise ValueError(f"{field} must be a mapping")
        if "asset_id" not in asset or "risk_score" not in asset:
            raise ValueError(f"{field} requires asset_id and risk_score")

        asset_id = _identifier(asset["asset_id"], f"{field}.asset_id")
        if asset_id in asset_ids:
            raise ValueError(f"duplicate asset_id: {asset_id}")
        asset_ids.add(asset_id)
        asset_risk = _number(asset["risk_score"], f"{field}.risk_score")
        if asset_risk < 0:
            raise ValueError(f"{field}.risk_score must be non-negative")

        gaps = _list_field(asset.get("security_gaps", []), f"{field}.security_gaps")
        if not gaps:
            atoms.append((asset_id, None, asset_risk))
            continue

        parsed_gaps: list[tuple[str, float | None]] = []
        gap_ids: set[str] = set()
        for gap_index, gap in enumerate(gaps):
            gap_field = f"{field}.security_gaps[{gap_index}]"
            if isinstance(gap, str):
                gap_id = _identifier(gap, gap_field)
                gap_risk = None
            elif isinstance(gap, Mapping):
                if "gap_id" not in gap:
                    raise ValueError(f"{gap_field}.gap_id is required")
                gap_id = _identifier(gap["gap_id"], f"{gap_field}.gap_id")
                gap_risk = None
                if "risk_score" in gap:
                    gap_risk = _number(gap["risk_score"], f"{gap_field}.risk_score")
                    if gap_risk < 0:
                        raise ValueError(f"{gap_field}.risk_score must be non-negative")
            else:
                raise ValueError(f"{gap_field} must be a string or mapping")
            if gap_id in gap_ids:
                raise ValueError(f"duplicate gap_id {gap_id} on asset {asset_id}")
            gap_ids.add(gap_id)
            parsed_gaps.append((gap_id, gap_risk))

        scored = [gap_risk is not None for _, gap_risk in parsed_gaps]
        if any(scored) and not all(scored):
            raise ValueError(f"{field}.security_gaps must score every gap or none")
        if all(scored):
            atoms.extend(
                (asset_id, gap_id, gap_risk)
                for gap_id, gap_risk in parsed_gaps
                if gap_risk is not None
            )
        else:
            share = asset_risk / len(parsed_gaps)
            atoms.extend((asset_id, gap_id, share) for gap_id, _ in parsed_gaps)
    return atoms


def _investment_records(investments: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, investment in enumerate(_list_field(investments, "investments")):
        field = f"investments[{index}]"
        if not isinstance(investment, Mapping):
            raise ValueError(f"{field} must be a mapping")
        for required in ("investment_id", "cost", "effectiveness"):
            if required not in investment:
                raise ValueError(f"{field}.{required} is required")

        investment_id = _identifier(investment["investment_id"], f"{field}.investment_id")
        if investment_id in identifiers:
            raise ValueError(f"duplicate investment_id: {investment_id}")
        identifiers.add(investment_id)

        amount = _cost(investment["cost"], f"{field}.cost")
        if amount < 0:
            raise ValueError(f"{field}.cost must be non-negative")
        effectiveness = _number(investment["effectiveness"], f"{field}.effectiveness")
        if not 0 <= effectiveness <= 1:
            raise ValueError(f"{field}.effectiveness must be between 0 and 1")

        covers_assets = [
            _identifier(value, f"{field}.covers_assets")
            for value in _list_field(investment.get("covers_assets", []), f"{field}.covers_assets")
        ]
        covers_gaps = [
            _identifier(value, f"{field}.covers_gaps")
            for value in _list_field(investment.get("covers_gaps", []), f"{field}.covers_gaps")
        ]
        records.append(
            {
                "investment_id": investment_id,
                "cost": amount,
                "effectiveness": effectiveness,
                "covers_assets": covers_assets,
                "covers_gaps": covers_gaps,
            }
        )
    return records


def _optimize_investments_canonical(
    risk_assessments: dict[str, Any],
    investments: list[dict[str, Any]],
    budget: float,
) -> dict[str, Any]:
    """Choose the exact best affordable portfolio for the documented risk model.

    Asset risk is divided evenly among its gaps unless individual gap scores are
    supplied. Selected investments reduce each covered risk atom multiplicatively.
    """
    budget_amount = _cost(budget, "budget")
    atoms = _risk_atoms(risk_assessments)
    records = _investment_records(investments)
    assessed_asset_ids = {asset_id for asset_id, _, _ in atoms}
    assessed_gap_ids = {gap_id for _, gap_id, _ in atoms if gap_id is not None}
    for record in records:
        unknown_assets = set(record["covers_assets"]) - assessed_asset_ids
        if unknown_assets:
            raise ValueError(
                f"investment {record['investment_id']} references unknown assets: "
                f"{', '.join(sorted(unknown_assets))}"
            )
        unknown_gaps = set(record["covers_gaps"]) - assessed_gap_ids
        if unknown_gaps:
            raise ValueError(
                f"investment {record['investment_id']} references unknown gaps: "
                f"{', '.join(sorted(unknown_gaps))}"
            )

    atom_risks = tuple(Fraction.from_float(atom[2]) for atom in atoms)
    baseline_exact = sum(atom_risks, Fraction(0))
    try:
        baseline = float(baseline_exact)
    except OverflowError as error:
        raise ValueError("aggregate baseline risk score must be finite") from error
    if not isfinite(baseline):
        raise ValueError("aggregate baseline risk score must be finite")

    candidates: list[dict[str, Any]] = []
    exclusion_reasons: dict[str, str] = {}
    for record in records:
        effectiveness = Fraction.from_float(record["effectiveness"])
        coverage = tuple(
            effectiveness
            if asset_id in record["covers_assets"]
            or (gap_id is not None and gap_id in record["covers_gaps"])
            else Fraction(0)
            for asset_id, gap_id, _ in atoms
        )
        covered_atoms = tuple(
            (atom_index, effect)
            for atom_index, effect in enumerate(coverage)
            if effect
        )
        potential = sum(
            (atom_risks[atom_index] * effect for atom_index, effect in covered_atoms),
            Fraction(0),
        )
        if potential <= 0:
            exclusion_reasons[record["investment_id"]] = "no_relevant_positive_risk_coverage"
            continue
        if record["cost"] > budget_amount:
            exclusion_reasons[record["investment_id"]] = "cost_exceeds_budget"
            continue
        record["coverage"] = coverage
        record["covered_atoms"] = covered_atoms
        record["potential"] = potential
        candidates.append(record)

    candidates.sort(
        key=lambda record: (
            record["cost"] != 0,
            -(
                record["potential"]
                / (Fraction(record["cost"]) if record["cost"] else Fraction(1))
            ),
            record["investment_id"],
        )
    )

    search_groups: list[dict[str, Any]] = []
    for candidate in candidates:
        signature = (candidate["cost"], candidate["coverage"])
        if search_groups and search_groups[-1]["signature"] == signature:
            search_groups[-1]["members"].append(candidate)
            continue
        search_groups.append(
            {
                "signature": signature,
                "members": [candidate],
                "cost": candidate["cost"],
                "coverage": candidate["coverage"],
                "covered_atoms": candidate["covered_atoms"],
            }
        )

    suffix_factors: list[tuple[Fraction, ...]] = [
        tuple(Fraction(1) for _ in atoms) for _ in range(len(search_groups) + 1)
    ]
    for index in range(len(search_groups) - 1, -1, -1):
        group = search_groups[index]
        suffix_factors[index] = tuple(
            suffix_factors[index + 1][atom_index]
            * (Fraction(1) - group["coverage"][atom_index]) ** len(group["members"])
            for atom_index in range(len(atoms))
        )

    best_reduction = Fraction(0)
    best_cost = Decimal(0)
    best_ids: tuple[str, ...] = ()
    best_records: tuple[dict[str, Any], ...] = ()
    visited_states: set[tuple[int, Decimal, tuple[Fraction, ...]]] = set()

    def visit(
        index: int,
        spent: Decimal,
        residual: tuple[Fraction, ...],
        selected: tuple[dict[str, Any], ...],
    ) -> None:
        nonlocal best_reduction, best_cost, best_ids, best_records

        state = (index, spent, residual)
        if state in visited_states:
            return
        visited_states.add(state)

        reduction = baseline_exact - sum(residual, Fraction(0))
        if (
            reduction > best_reduction
            or (reduction == best_reduction and spent < best_cost)
        ):
            best_reduction = reduction
            best_cost = spent
            best_ids = tuple(sorted(item["investment_id"] for item in selected))
            best_records = selected

        if index == len(search_groups):
            return

        remaining_budget = budget_amount - spent
        marginal_values: list[tuple[Fraction, Fraction, int]] = []
        for group in search_groups[index:]:
            marginal = sum(
                (
                    residual[atom_index] * effect
                    for atom_index, effect in group["covered_atoms"]
                ),
                Fraction(0),
            )
            if marginal > 0:
                marginal_values.append(
                    (marginal, Fraction(group["cost"]), len(group["members"]))
                )

        fractional_gain = Fraction(0)
        free_gain = sum(
            (
                value * count
                for value, cost, count in marginal_values
                if cost == 0
            ),
            Fraction(0),
        )
        fractional_gain += free_gain
        available = Fraction(remaining_budget)
        paid = sorted(
            (
                (value / cost, value, cost, count)
                for value, cost, count in marginal_values
                if cost > 0
            ),
            key=lambda item: (-item[0], item[2]),
        )
        for _, value, cost, count in paid:
            if available <= 0:
                break
            group_cost = cost * count
            group_value = value * count
            if group_cost <= available:
                fractional_gain += group_value
                available -= group_cost
            else:
                fractional_gain += value * available / cost
                break

        fractional_bound = reduction + fractional_gain
        all_remaining_bound = baseline_exact - sum(
            (
                remaining_risk * factor
                for remaining_risk, factor in zip(
                    residual, suffix_factors[index]
                )
            ),
            Fraction(0),
        )
        objective_bound = min(fractional_bound, all_remaining_bound)
        if objective_bound < best_reduction:
            return
        if objective_bound == best_reduction:
            required_gain = best_reduction - reduction
            free_gain = sum(
                (
                    value * count
                    for value, cost, count in marginal_values
                    if cost == 0
                ),
                Fraction(0),
            )
            required_gain = max(Fraction(0), required_gain - free_gain)
            optimistic_cost = Fraction(0)
            paid = sorted(
                (
                    (value / cost, value, cost, count)
                    for value, cost, count in marginal_values
                    if cost > 0
                ),
                key=lambda item: (-item[0], item[2]),
            )
            remaining_gain = required_gain
            for _, value, cost, count in paid:
                if remaining_gain <= 0:
                    break
                group_value = value * count
                group_cost = cost * count
                if group_value <= remaining_gain:
                    optimistic_cost += group_cost
                    remaining_gain -= group_value
                else:
                    optimistic_cost += cost * remaining_gain / value
                    remaining_gain = Fraction(0)
            if (
                remaining_gain > 0
                or Fraction(spent) + optimistic_cost >= Fraction(best_cost)
            ):
                return

        group = search_groups[index]
        group_cost = Fraction(group["cost"])
        if group_cost == 0:
            max_count = len(group["members"])
        else:
            max_count = min(
                len(group["members"]),
                int(Fraction(remaining_budget) // group_cost),
            )
        for selected_count in range(max_count, -1, -1):
            selected_cost = group["cost"] * selected_count
            included_residual = tuple(
                remaining_risk
                * (
                    (Fraction(1) - effect) ** selected_count
                    if effect
                    else Fraction(1)
                )
                for remaining_risk, effect in zip(residual, group["coverage"])
            )
            visit(
                index + 1,
                spent + selected_cost,
                included_residual,
                selected + tuple(group["members"][:selected_count]),
            )

    visit(0, Decimal(0), atom_risks, ())

    selected_by_id = {record["investment_id"]: record for record in best_records}
    selected_output: list[dict[str, Any]] = []
    explanations: list[str] = []
    residual = list(atom_risks)
    for investment_id in best_ids:
        record = selected_by_id[investment_id]
        marginal_reduction = sum(
            (
                risk * effect
                for risk, effect in zip(residual, record["coverage"])
            ),
            Fraction(0),
        )
        residual = [
            risk * (1 - effect)
            for risk, effect in zip(residual, record["coverage"])
        ]
        marginal_reduction_value = float(marginal_reduction)
        selection_explanation = (
            f"Selected {investment_id}: marginal modeled risk-score reduction "
            f"{marginal_reduction_value:.6g} when applied in investment_id order."
        )
        selected_output.append(
            {
                "investment_id": investment_id,
                "cost": float(record["cost"]),
                "effectiveness": record["effectiveness"],
                "covers_assets": list(record["covers_assets"]),
                "covers_gaps": list(record["covers_gaps"]),
                "marginal_risk_reduction": marginal_reduction_value,
                "selection_explanation": selection_explanation,
            }
        )
        explanations.append(selection_explanation)

    total_cost = float(best_cost)
    excluded_output: list[dict[str, str]] = []
    for record in sorted(records, key=lambda item: item["investment_id"]):
        investment_id = record["investment_id"]
        if investment_id in selected_by_id:
            continue
        reason = exclusion_reasons.get(
            investment_id, "not_selected_by_optimal_portfolio"
        )
        if reason == "cost_exceeds_budget":
            explanation = (
                f"Not selected: cost {float(record['cost']):.6g} exceeds the "
                f"original budget {float(budget_amount):.6g}."
            )
        elif reason == "no_relevant_positive_risk_coverage":
            explanation = (
                "Not selected: no covered assessed risk atom has positive modeled "
                "risk reduction."
            )
        else:
            selected_names = ", ".join(best_ids) if best_ids else "no investments"
            explanation = (
                f"Not selected: the globally optimal affordable portfolio "
                f"({selected_names}) yields modeled risk reduction "
                f"{float(best_reduction):.6g} at cost {total_cost:.6g}; the objective "
                "maximizes total portfolio reduction, then minimizes cost, then "
                "uses deterministic investment ordering for remaining ties."
            )
        excluded_output.append(
            {
                "investment_id": investment_id,
                "reason": reason,
                "explanation": explanation,
            }
        )

    residual_risk = float(sum(residual, Fraction(0)))
    if selected_output:
        status = "optimal"
    elif not records:
        status = "no_investments"
    else:
        status = "no_selectable_investments"

    return {
        "optimization_status": status,
        "budget": float(budget_amount),
        "total_cost": total_cost,
        "remaining_budget": float(budget_amount - best_cost),
        "selected_investments": selected_output,
        "excluded_investments": excluded_output,
        "estimated_risk_reduction": float(best_reduction),
        "baseline_risk_score": baseline,
        "residual_risk_score": residual_risk,
        "selection_explanations": explanations,
        "assumptions": [
            "Effectiveness is a modeled fractional reduction from 0 to 1, not a measured guarantee.",
            "Asset risk is split evenly among its gaps unless every gap has an explicit risk_score.",
            "Each selected investment independently reduces the remaining risk on each covered asset-gap atom.",
            "Asset and gap coverage are treated as complete for their listed identifiers.",
        ],
        "limitations": [
            "Risk scores are modeled decision-support indicators, not calibrated breach probabilities.",
            "Effectiveness, coverage, costs, and risk scores are estimates unless supported by validated evidence.",
            "The exact search is exponential in the worst case and is intended for small-to-moderate investment sets.",
        ],
    }


def optimize_investments(
    risk_assessments: dict[str, Any],
    investments: list[dict[str, Any]],
    budget: float,
) -> dict[str, Any]:
    """Optimize canonical records or adapt the dashboard's legacy records.

    Canonical inputs retain the optimizer's strict validation. Compatibility
    conversion is activated only when legacy investment records are detected.
    """
    if not isinstance(risk_assessments, Mapping):
        # Let the canonical implementation raise its established validation error.
        return _optimize_investments_canonical(
            risk_assessments, investments, budget
        )

    assets = risk_assessments.get("assets")
    investment_rows = investments

    # Detect the legacy assessment independently of the investment list.
    # Monitoring may legitimately provide an empty list of investments.
    is_legacy_assessment = (
        isinstance(assets, list)
        and any(
            isinstance(asset, Mapping)
            and "risk_score" not in asset
            and (
                "residual_risk_score" in asset
                or "score" in asset
            )
            for asset in assets
        )
    )

    # Older dashboard and API contracts use risk_reduction or
    # expected_risk_reduction instead of canonical effectiveness.
    is_legacy_investments = (
        isinstance(investment_rows, list)
        and any(
            isinstance(row, Mapping)
            and (
                "investment_id" not in row
                or "effectiveness" not in row
            )
            and "name" in row
            and (
                "expected_risk_reduction" in row
                or "risk_reduction" in row
            )
            for row in investment_rows
        )
    )

    if not is_legacy_assessment and not is_legacy_investments:
        return _optimize_investments_canonical(
            risk_assessments, investments, budget
        )

    if not isinstance(assets, list):
        return _optimize_investments_canonical(
            risk_assessments, investments, budget
        )

    # Build a stable mapping from asset display names to existing IDs.
    # Never mutate the caller's risk assessment or investment records.
    import re
    from copy import deepcopy

    canonical_assessment = deepcopy(dict(risk_assessments))
    canonical_assets = []
    name_to_id: dict[str, str] = {}

    for index, asset in enumerate(assets):
        if not isinstance(asset, Mapping):
            return _optimize_investments_canonical(
                risk_assessments, investments, budget
            )

        asset_copy = dict(asset)
        asset_name = asset_copy.get("asset_name") or asset_copy.get("name") or asset_copy.get("asset")
        asset_id = asset_copy.get("asset_id")

        if not asset_id and isinstance(asset_name, str) and asset_name.strip():
            slug = re.sub(r"[^a-z0-9]+", "-", asset_name.strip().lower()).strip("-")
            asset_id = f"asset-{slug or index}"

        # Only translate the known legacy assessment shape.
        if "risk_score" not in asset_copy:
            if "residual_risk_score" in asset_copy:
                asset_copy["risk_score"] = asset_copy["residual_risk_score"]
            elif "score" in asset_copy:
                asset_copy["risk_score"] = asset_copy["score"]
            else:
                return _optimize_investments_canonical(
                    risk_assessments, investments, budget
                )

        if asset_id:
            asset_copy["asset_id"] = asset_id
            if isinstance(asset_name, str) and asset_name.strip():
                name_to_id[asset_name.strip().casefold()] = asset_id

        canonical_assets.append(asset_copy)

    canonical_assessment["assets"] = canonical_assets

    # Legacy security gaps are not inferred here. The adapter preserves any
    # explicitly supplied canonical gap information but does not invent gaps.
    canonical_investments = []
    original_by_id: dict[str, dict[str, Any]] = {}

    for index, row in enumerate(investment_rows):
        if not isinstance(row, Mapping):
            return _optimize_investments_canonical(
                risk_assessments, investments, budget
            )

        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            return _optimize_investments_canonical(
                risk_assessments, investments, budget
            )

        slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
        investment_id = f"legacy-{index + 1}-{slug or 'investment'}"

        reduction_field = (
            "expected_risk_reduction"
            if "expected_risk_reduction" in row
            else "risk_reduction"
        )
        expected_reduction = _number(
            row.get(reduction_field),
            f"investments[{index}].{reduction_field}",
        )

        # The existing demo expresses expected risk reduction as percentage
        # points (for example 18 means 18%), while the optimizer expects [0, 1].
        effectiveness = expected_reduction / 100.0
        if not 0 <= effectiveness <= 1:
            raise ValueError(
                f"investments[{index}].expected_risk_reduction "
                "must be between 0 and 100 for legacy investment records"
            )

        asset_name = row.get("asset")
        covers_assets = []
        if isinstance(asset_name, str) and asset_name.strip():
            matched_id = name_to_id.get(asset_name.strip().casefold())
            if matched_id is not None:
                covers_assets = [matched_id]

        canonical_row = {
            "investment_id": investment_id,
            "name": name,
            "category": row.get("category"),
            "cost": row.get("cost"),
            "effectiveness": effectiveness,
            "covers_assets": covers_assets,
            "covers_gaps": [],
        }
        canonical_investments.append(canonical_row)
        original_by_id[investment_id] = dict(row)

    result = _optimize_investments_canonical(
        canonical_assessment,
        canonical_investments,
        budget,
    )

    # Keep the canonical output fields, but restore original investment details
    # and the aliases consumed by the existing dashboard and analyst service.
    def restore_investment(item: Any) -> Any:
        if not isinstance(item, Mapping):
            return item
        investment_id = item.get("investment_id")
        original = original_by_id.get(investment_id, {})
        return {**original, **dict(item)}

    selected = [
        restore_investment(item)
        for item in result.get("selected_investments", [])
    ]
    excluded = [
        restore_investment(item)
        for item in result.get("excluded_investments", [])
    ]

    result["selected_investments"] = selected
    result["excluded_investments"] = excluded
    result["unselected_investments"] = excluded
    result["risk_reduction_estimate"] = result.get(
        "estimated_risk_reduction", 0.0
    )
    result["before_risk_score"] = result.get("baseline_risk_score", 0.0)
    result["after_risk_score"] = result.get("residual_risk_score", 0.0)

    return result
