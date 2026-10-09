from copy import deepcopy
from decimal import Decimal
from itertools import combinations
import os
from random import Random
from time import perf_counter

import pytest

from backend.services.investment_optimizer import optimize_investments


def assessment(*assets):
    return {"assets": list(assets)}


def asset(asset_id="asset-a", risk_score=100, security_gaps=None):
    result = {"asset_id": asset_id, "risk_score": risk_score}
    if security_gaps is not None:
        result["security_gaps"] = security_gaps
    return result


def investment(investment_id, cost, effectiveness, assets=None, gaps=None):
    return {
        "investment_id": investment_id,
        "cost": cost,
        "effectiveness": effectiveness,
        "covers_assets": assets or [],
        "covers_gaps": gaps or [],
    }


def brute_force_optimum(risk_assessments, investments, budget):
    """Independent exhaustive solver for the documented risk model."""
    atoms = []
    for assessed_asset in risk_assessments["assets"]:
        asset_id = assessed_asset["asset_id"]
        risk_score = assessed_asset["risk_score"]
        gaps = assessed_asset.get("security_gaps", [])
        if not gaps:
            atoms.append((asset_id, None, risk_score))
        elif all(isinstance(gap, dict) and "risk_score" in gap for gap in gaps):
            atoms.extend(
                (asset_id, gap["gap_id"], gap["risk_score"]) for gap in gaps
            )
        else:
            atoms.extend(
                (
                    asset_id,
                    gap if isinstance(gap, str) else gap["gap_id"],
                    risk_score / len(gaps),
                )
                for gap in gaps
            )

    def modeled_reduction(selected):
        remaining = 0.0
        for asset_id, gap_id, risk_score in atoms:
            residual_fraction = 1.0
            for item in selected:
                if asset_id in item.get("covers_assets", []) or (
                    gap_id is not None and gap_id in item.get("covers_gaps", [])
                ):
                    residual_fraction *= 1.0 - item["effectiveness"]
            remaining += risk_score * residual_fraction
        return sum(atom[2] for atom in atoms) - remaining

    eligible = []
    for item in investments:
        if item["cost"] <= budget and modeled_reduction([item]) > 0:
            eligible.append(item)
    priority = sorted(
        eligible,
        key=lambda item: (
            item["cost"] != 0,
            -Decimal(str(modeled_reduction([item])))
            / (Decimal(str(item["cost"])) or Decimal(1)),
            item["investment_id"],
        ),
    )

    best_ids = ()
    best_cost = 0
    best_reduction = 0.0
    best_priority_bits = ()
    for selected_count in range(len(investments) + 1):
        for selected in combinations(investments, selected_count):
            cost = sum(item["cost"] for item in selected)
            if cost > budget:
                continue
            reduction = modeled_reduction(selected)
            selected_ids = tuple(sorted(item["investment_id"] for item in selected))
            priority_bits = tuple(
                item["investment_id"] in selected_ids for item in priority
            )
            if (
                reduction > best_reduction
                or (reduction == best_reduction and cost < best_cost)
                or (
                    reduction == best_reduction
                    and cost == best_cost
                    and priority_bits > best_priority_bits
                )
            ):
                best_ids = selected_ids
                best_cost = cost
                best_reduction = reduction
                best_priority_bits = priority_bits
    return best_ids, best_cost, best_reduction


def test_budget_feasibility_and_hand_verifiable_optimum():
    result = optimize_investments(
        assessment(asset(security_gaps=["identity", "endpoint"])),
        [
            investment("identity", 4, 0.5, gaps=["identity"]),
            investment("endpoint", 4, 0.5, gaps=["endpoint"]),
            investment("bundle", 10, 0.8, assets=["asset-a"]),
        ],
        10,
    )

    assert [item["investment_id"] for item in result["selected_investments"]] == [
        "bundle"
    ]
    assert result["total_cost"] == 10
    assert result["remaining_budget"] == 0
    assert result["estimated_risk_reduction"] == pytest.approx(80)
    assert result["residual_risk_score"] == pytest.approx(20)


def test_unaffordable_investment_is_explained():
    result = optimize_investments(
        assessment(asset()), [investment("large", 101, 1, assets=["asset-a"])], 100
    )
    assert result["selected_investments"] == []
    assert result["excluded_investments"] == [
        {
            "investment_id": "large",
            "reason": "cost_exceeds_budget",
            "explanation": "Not selected: cost 101 exceeds the original budget 100.",
        }
    ]


def test_selection_and_exclusion_explanations_match_actual_reason():
    result = optimize_investments(
        assessment(asset()),
        [
            investment("winner", 10, 0.8, assets=["asset-a"]),
            investment("affordable-omission", 10, 0.2, assets=["asset-a"]),
            investment("over-budget", 11, 1, assets=["asset-a"]),
            investment("unmapped", 0, 1),
        ],
        10,
    )
    assert "marginal modeled risk-score reduction 80" in result[
        "selected_investments"
    ][0]["selection_explanation"]
    excluded = {
        item["investment_id"]: item for item in result["excluded_investments"]
    }
    assert excluded["affordable-omission"]["reason"] == (
        "not_selected_by_optimal_portfolio"
    )
    assert "globally optimal affordable portfolio (winner)" in excluded[
        "affordable-omission"
    ]["explanation"]
    assert excluded["over-budget"]["reason"] == "cost_exceeds_budget"
    assert "exceeds the original budget 10" in excluded["over-budget"]["explanation"]
    assert excluded["unmapped"]["reason"] == (
        "no_relevant_positive_risk_coverage"
    )
    assert "no covered assessed risk atom" in excluded["unmapped"]["explanation"]


def test_zero_budget_selects_affordable_zero_cost_options_only():
    result = optimize_investments(
        assessment(asset()),
        [
            investment("free", 0, 0.25, assets=["asset-a"]),
            investment("paid", 1, 1, assets=["asset-a"]),
        ],
        0,
    )
    assert [item["investment_id"] for item in result["selected_investments"]] == [
        "free"
    ]
    assert result["total_cost"] == 0
    assert result["estimated_risk_reduction"] == pytest.approx(25)


def test_empty_investment_list_preserves_baseline_risk():
    result = optimize_investments(assessment(asset(risk_score=12)), [], 5)
    assert result["optimization_status"] == "no_investments"
    assert result["baseline_risk_score"] == 12
    assert result["estimated_risk_reduction"] == 0
    assert result["residual_risk_score"] == 12


@pytest.mark.parametrize("budget", [-1, float("nan"), float("inf"), "5"])
def test_invalid_budget_raises_value_error(budget):
    with pytest.raises(ValueError, match="budget"):
        optimize_investments(assessment(), [], budget)


@pytest.mark.parametrize("cost", [-1, float("nan"), float("inf")])
def test_invalid_cost_raises_value_error(cost):
    with pytest.raises(ValueError, match="cost"):
        optimize_investments(
            assessment(), [investment("bad", cost, 0.5)], 10
        )


def test_duplicate_investment_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate investment_id"):
        optimize_investments(
            assessment(), [investment("same", 1, 0.1), investment("same", 2, 0.2)], 10
        )


def test_overlapping_gap_effectiveness_is_multiplicative():
    result = optimize_investments(
        assessment(asset(security_gaps=["identity"])),
        [
            investment("mfa", 1, 0.5, gaps=["identity"]),
            investment("monitoring", 1, 0.5, gaps=["identity"]),
        ],
        2,
    )
    assert result["estimated_risk_reduction"] == pytest.approx(75)
    assert result["residual_risk_score"] == pytest.approx(25)


def test_asset_and_gap_coverage_apply_one_effect_per_investment():
    result = optimize_investments(
        assessment(asset(security_gaps=["identity"])),
        [
            investment(
                "unified-control",
                1,
                0.5,
                assets=["asset-a"],
                gaps=["identity"],
            )
        ],
        1,
    )
    assert result["estimated_risk_reduction"] == pytest.approx(50)
    assert result["residual_risk_score"] == pytest.approx(50)


def test_missing_optional_coverage_is_valid_but_irrelevant():
    result = optimize_investments(
        assessment(asset()),
        [{"investment_id": "unmapped", "cost": 1, "effectiveness": 0.8}],
        10,
    )
    assert result["selected_investments"] == []
    assert result["excluded_investments"][0]["reason"] == (
        "no_relevant_positive_risk_coverage"
    )


@pytest.mark.parametrize(
    "coverage_field, reference, error",
    [
        ("covers_assets", "missing-asset", "unknown assets"),
        ("covers_gaps", "missing-gap", "unknown gaps"),
    ],
)
def test_unknown_coverage_references_raise_value_error(
    coverage_field, reference, error
):
    item = investment("bad-reference", 1, 0.5)
    item[coverage_field] = [reference]
    with pytest.raises(ValueError, match=error):
        optimize_investments(assessment(asset()), [item], 1)


@pytest.mark.parametrize(
    "risk_assessments, investments",
    [
        ({}, []),
        ({"assets": [{"asset_id": "a"}]}, []),
        ({"assets": [{}]}, []),
        (assessment(asset()), [{"investment_id": "i", "cost": 1}]),
        (assessment(asset()), [{"cost": 1, "effectiveness": 0.5}]),
    ],
)
def test_missing_required_fields_raise_value_error(risk_assessments, investments):
    with pytest.raises(ValueError):
        optimize_investments(risk_assessments, investments, 10)


@pytest.mark.parametrize("effectiveness", [-0.1, 1.1, float("nan"), float("inf")])
def test_invalid_effectiveness_raises_value_error(effectiveness):
    with pytest.raises(ValueError, match="effectiveness"):
        optimize_investments(
            assessment(asset()),
            [investment("bad", 1, effectiveness, assets=["asset-a"])],
            10,
        )


def test_output_is_deterministic_and_ties_use_candidate_priority():
    items = [
        investment("zeta", 4, 0.5, assets=["asset-a"]),
        investment("alpha", 4, 0.5, assets=["asset-a"]),
    ]
    first = optimize_investments(assessment(asset()), items, 4)
    second = optimize_investments(assessment(asset()), items, 4)
    assert first == second
    assert [item["investment_id"] for item in first["selected_investments"]] == [
        "alpha"
    ]


def test_investment_reordering_does_not_change_result():
    items = [
        investment("c", 3, 0.4, assets=["asset-a"]),
        investment("a", 4, 0.6, assets=["asset-a"]),
        investment("b", 2, 0.25, assets=["asset-a"]),
    ]
    first = optimize_investments(assessment(asset()), items, 5)
    second = optimize_investments(assessment(asset()), list(reversed(items)), 5)
    assert first == second


def test_explicit_gap_scores_and_risk_boundaries():
    result = optimize_investments(
        assessment(
            asset(
                risk_score=99,
                security_gaps=[
                    {"gap_id": "low", "risk_score": 0},
                    {"gap_id": "high", "risk_score": 9},
                ],
            )
        ),
        [
            investment("low", 1, 1, gaps=["low"]),
            investment("high", 1, 1, gaps=["high"]),
        ],
        1,
    )
    assert result["baseline_risk_score"] == 9
    assert result["estimated_risk_reduction"] == 9
    assert result["residual_risk_score"] == 0
    assert result["selected_investments"][0]["investment_id"] == "high"


def test_no_selectable_investments_and_zero_risk_assets():
    result = optimize_investments(
        assessment(asset(risk_score=0)),
        [investment("no-impact", 0, 1, assets=["asset-a"])],
        0,
    )
    assert result["optimization_status"] == "no_selectable_investments"
    assert result["estimated_risk_reduction"] == 0
    assert result["excluded_investments"][0]["reason"] == (
        "no_relevant_positive_risk_coverage"
    )


def test_cheapest_investment_is_not_necessarily_optimal():
    result = optimize_investments(
        assessment(asset()),
        [
            investment("cheap", 2, 0.2, assets=["asset-a"]),
            investment("effective", 6, 0.9, assets=["asset-a"]),
        ],
        6,
    )
    assert [item["investment_id"] for item in result["selected_investments"]] == [
        "effective"
    ]
    assert result["estimated_risk_reduction"] == pytest.approx(90)


def test_combination_can_outperform_every_single_investment():
    result = optimize_investments(
        assessment(asset()),
        [
            investment("control-a", 5, 0.6, assets=["asset-a"]),
            investment("control-b", 5, 0.6, assets=["asset-a"]),
            investment("single", 10, 0.75, assets=["asset-a"]),
        ],
        10,
    )
    assert [item["investment_id"] for item in result["selected_investments"]] == [
        "control-a",
        "control-b",
    ]
    assert result["estimated_risk_reduction"] == pytest.approx(84)


def test_inputs_are_not_mutated():
    assessments = assessment(asset(security_gaps=["identity"]))
    items = [investment("mfa", 1, 0.5, gaps=["identity"])]
    original_assessments = deepcopy(assessments)
    original_items = deepcopy(items)

    optimize_investments(assessments, items, 1)

    assert assessments == original_assessments
    assert items == original_items


def test_different_asset_risk_levels_are_aggregated_by_risk():
    result = optimize_investments(
        assessment(asset("low", 10), asset("high", 90)),
        [investment("high-asset", 1, 1, assets=["high"])],
        1,
    )
    assert result["baseline_risk_score"] == 100
    assert result["estimated_risk_reduction"] == 90
    assert result["residual_risk_score"] == 10


def test_larger_set_finds_full_coverage_portfolio():
    gaps = [f"gap-{index:02d}" for index in range(24)]
    result = optimize_investments(
        assessment(asset(risk_score=240, security_gaps=gaps)),
        [
            investment(f"investment-{index:02d}", 1, 1, gaps=[gap])
            for index, gap in enumerate(gaps)
        ],
        24,
    )
    assert len(result["selected_investments"]) == 24
    assert result["total_cost"] == 24
    assert result["estimated_risk_reduction"] == pytest.approx(240)
    assert result["residual_risk_score"] == pytest.approx(0)


def test_duplicate_asset_assessments_are_rejected_instead_of_double_counted():
    with pytest.raises(ValueError, match="duplicate asset_id"):
        optimize_investments(assessment(asset(), asset()), [], 0)


def test_duplicate_gap_ids_on_an_asset_are_rejected():
    with pytest.raises(ValueError, match="duplicate gap_id"):
        optimize_investments(
            assessment(asset(security_gaps=["identity", "identity"])), [], 0
        )


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1])
def test_invalid_risk_scores_are_rejected(score):
    with pytest.raises(ValueError, match="risk_score"):
        optimize_investments(assessment(asset(risk_score=score)), [], 0)


def test_unbounded_nonnegative_scores_are_preserved_without_claiming_a_scale():
    score = 1_000_000
    result = optimize_investments(assessment(asset(risk_score=score)), [], 0)
    assert result["baseline_risk_score"] == score
    assert result["residual_risk_score"] == score


def test_numeric_values_outside_float_range_fail_as_value_error():
    with pytest.raises(ValueError, match="finite number"):
        optimize_investments(assessment(), [], 10**10000)


def test_nonzero_values_below_float_range_fail_as_value_error():
    with pytest.raises(ValueError, match="cost.*finite number"):
        optimize_investments(
            assessment(asset()),
            [investment("tiny", Decimal("1e-10000"), 0.5, assets=["asset-a"])],
            1,
        )


def test_extreme_cost_ratios_match_exhaustive_optimum():
    assessments = assessment(
        asset("c", 95),
        asset("a", 1),
        asset("b", 100),
    )
    items = [
        investment("c", Decimal("5e-311"), 1, assets=["c"]),
        investment("a", Decimal("1e-310"), 1, assets=["a"]),
        investment("b", Decimal("1e-309"), 1, assets=["b"]),
    ]
    budget = Decimal("1e-309")

    expected_ids, expected_cost, expected_reduction = brute_force_optimum(
        assessments, items, budget
    )
    result = optimize_investments(assessments, items, budget)

    assert expected_ids == ("b",)
    assert expected_cost == budget
    assert expected_reduction == 100
    assert [item["investment_id"] for item in result["selected_investments"]] == [
        "b"
    ]
    assert result["total_cost"] == float(budget)
    assert result["estimated_risk_reduction"] == 100


def test_finite_asset_scores_with_nonfinite_aggregate_are_rejected():
    with pytest.raises(ValueError, match="aggregate baseline risk score"):
        optimize_investments(
            assessment(asset("a", 1e308), asset("b", 1e308)), [], 0
        )


def test_exhaustive_reference_matches_generated_small_portfolios():
    random = Random(275_901)
    effectiveness_values = [0.0, 0.25, 0.5, 0.75, 1.0]
    for case_number in range(64):
        asset_count = 1 + case_number % 4
        investment_count = 1 + case_number % 8
        assessments = assessment(
            *[
                asset(f"asset-{index}", random.randint(0, 30))
                for index in range(asset_count)
            ]
        )
        items = [
            investment(
            f"investment-{random.randrange(1_000_000):06d}-{index:02d}",
                random.randint(0, 8),
                random.choice(effectiveness_values),
                assets=[
                    f"asset-{asset_index}"
                    for asset_index in range(asset_count)
                    if random.choice([True, False])
                ],
            )
            for index in range(investment_count)
        ]
        random.shuffle(items)
        budget = random.randint(0, 18)
        expected_ids, expected_cost, expected_reduction = brute_force_optimum(
            assessments, items, budget
        )
        result = optimize_investments(assessments, items, budget)
        actual_ids = tuple(
            item["investment_id"] for item in result["selected_investments"]
        )

        assert actual_ids == expected_ids, f"portfolio mismatch in case {case_number}"
        assert result["total_cost"] == expected_cost
        assert result["total_cost"] <= budget
        assert result["estimated_risk_reduction"] == pytest.approx(
            expected_reduction
        )
        assert -1e-12 <= result["residual_risk_score"] <= (
            result["baseline_risk_score"] + 1e-12
        )

        reordered_result = optimize_investments(
            assessments, list(reversed(items)), budget
        )
        assert reordered_result == result, f"order mismatch in case {case_number}"


@pytest.mark.parametrize("investment_count", [20, 50, 100, 200])
@pytest.mark.skipif(
    os.environ.get("RUN_OPTIMIZER_BENCHMARKS") != "1",
    reason="set RUN_OPTIMIZER_BENCHMARKS=1 to run scaling measurements",
)
def test_scaling_benchmark(investment_count, record_property):
    assets = [
        {"asset_id": f"asset-{index:03d}", "risk_score": 1}
        for index in range(investment_count)
    ]
    items = [
        investment(
            f"investment-{index:03d}", 1, 1, assets=[f"asset-{index:03d}"]
        )
        for index in range(investment_count)
    ]

    start = perf_counter()
    result = optimize_investments(
        {"assets": assets}, items, investment_count // 2
    )
    elapsed = perf_counter() - start
    record_property("elapsed_seconds", elapsed)
    print(f"{investment_count} investments: {elapsed:.6f}s")

    assert len(result["selected_investments"]) == investment_count // 2
    assert result["total_cost"] <= investment_count // 2
    assert result["estimated_risk_reduction"] == investment_count // 2


@pytest.mark.parametrize("investment_count", [20, 50, 100, 200])
@pytest.mark.skipif(
    os.environ.get("RUN_OPTIMIZER_BENCHMARKS") != "1",
    reason="set RUN_OPTIMIZER_BENCHMARKS=1 to run scaling measurements",
)
def test_overlapping_scaling_benchmark(investment_count, record_property):
    assessments = {"assets": [{"asset_id": "shared", "risk_score": 100}]}
    items = [
        investment(
            f"investment-{index:03d}",
            1,
            0.02,
            assets=["shared"],
        )
        for index in range(investment_count)
    ]

    start = perf_counter()
    result = optimize_investments(
        assessments, items, investment_count // 2
    )
    elapsed = perf_counter() - start
    record_property("elapsed_seconds", elapsed)
    print(f"{investment_count} overlapping investments: {elapsed:.6f}s")

    selected_count = investment_count // 2
    expected_reduction = 100 * (1 - (1 - 0.02) ** selected_count)
    assert len(result["selected_investments"]) == selected_count
    assert result["total_cost"] == selected_count
    assert result["total_cost"] <= investment_count // 2
    assert result["estimated_risk_reduction"] == pytest.approx(expected_reduction)