"""Independent, non-network async simulations for identical ordered results."""
import asyncio
from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class SimulatedCheck:
    incident_id: str
    score: int
    delay: float = 0.01


async def _check(item: SimulatedCheck):
    await asyncio.sleep(item.delay)
    return (item.incident_id, item.score)


def _validate_checks(checks: Iterable[SimulatedCheck]) -> List[SimulatedCheck]:
    items = list(checks)
    if len(items) < 3:
        raise ValueError("At least three independent checks are required")
    if len({item.incident_id for item in items}) != len(items):
        raise ValueError("Each check needs a unique incident ID")
    if any(item.delay < 0 for item in items):
        raise ValueError("Delay must be non-negative")
    return items


async def collect_sequential(checks: Iterable[SimulatedCheck]):
    items = _validate_checks(checks)
    results = []
    for item in items:
        results.append(await _check(item))
    return results


async def collect_concurrent(checks: Iterable[SimulatedCheck]):
    items = _validate_checks(checks)
    tasks = [asyncio.create_task(_check(item)) for item in items]
    return list(await asyncio.gather(*tasks))
