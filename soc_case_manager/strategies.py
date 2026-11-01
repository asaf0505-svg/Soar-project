"""Strategy pattern: exchangeable business rules for reputation scores."""
from abc import ABC, abstractmethod


class RiskStrategy(ABC):
    @abstractmethod
    def requires_review(self, score: int) -> bool:
        """Whether a valid external score requires manual investigation."""


class ThresholdRiskStrategy(RiskStrategy):
    """Default policy: review when score is at least 80."""

    def __init__(self, threshold: int = 80):
        if type(threshold) is not int or not 0 <= threshold <= 100:
            raise ValueError("Threshold must be an integer between 0 and 100")
        self.threshold = threshold

    def requires_review(self, score: int) -> bool:
        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError("Score must be between 0 and 100")
        return score >= self.threshold


class StrictRiskStrategy(RiskStrategy):
    """Alternative policy: a lower configurable threshold (default 60)."""

    def __init__(self, threshold: int = 60):
        if type(threshold) is not int or not 0 <= threshold <= 100:
            raise ValueError("Threshold must be an integer between 0 and 100")
        self.threshold = threshold

    def requires_review(self, score: int) -> bool:
        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError("Score must be between 0 and 100")
        return score >= self.threshold
