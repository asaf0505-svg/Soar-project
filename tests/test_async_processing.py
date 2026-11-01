"""Async tests compare both execution models and result order."""
import asyncio
import pytest
from soc_case_manager.async_processing import (
    SimulatedCheck, collect_sequential, collect_concurrent
)


def example_checks():
    return [
        SimulatedCheck("first", 90, 0.015),
        SimulatedCheck("second", 20, 0),
        SimulatedCheck("third", 65, 0.005),
    ]


def test_async_matches_sequential_and_preserves_input_order():
    sequential = asyncio.run(collect_sequential(example_checks()))
    concurrent = asyncio.run(collect_concurrent(example_checks()))
    assert concurrent == sequential == [
        ("first", 90), ("second", 20), ("third", 65)
    ]


def test_async_rejects_duplicate_ids():
    with pytest.raises(ValueError):
        asyncio.run(collect_concurrent([
            SimulatedCheck("a", 1), SimulatedCheck("a", 2), SimulatedCheck("b", 3)
        ]))
