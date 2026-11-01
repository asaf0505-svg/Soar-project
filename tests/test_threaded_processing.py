"""Test final state, not nondeterministic thread winner."""
from soc_case_manager.threaded_processing import race_to_claim


def test_only_one_of_two_threads_claims_one_incident():
    results, assignments = race_to_claim("INC-X", ["Gal", "Dana"])
    assert sorted(results) == [False, True]
    assert len(assignments) == 1
    assert "INC-X" in assignments


def test_three_threads_still_allocate_once():
    results, assignments = race_to_claim("INC-Y", ["A", "B", "C"])
    assert sum(results) == 1
    assert len(assignments) == 1
