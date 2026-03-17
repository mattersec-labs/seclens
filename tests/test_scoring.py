"""Tests for per-task scoring."""

from __future__ import annotations

import pytest

from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.task import GroundTruth, Location
from seclens.scoring.grader import _location_iou_and_recall, score_task


class TestScoreVerdict:
    def test_correct_positive(self) -> None:
        pr = ParseResult(status=ParseStatus.FULL, output=ParsedOutput(vulnerable=True), raw_response="")
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.verdict == 1

    def test_incorrect_positive(self) -> None:
        pr = ParseResult(status=ParseStatus.FULL, output=ParsedOutput(vulnerable=False), raw_response="")
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.verdict == 0

    def test_correct_negative(self) -> None:
        pr = ParseResult(status=ParseStatus.FULL, output=ParsedOutput(vulnerable=False), raw_response="")
        gt = GroundTruth(vulnerable=False)
        score = score_task(pr, gt, max_task_points=1)
        assert score.verdict == 1
        assert score.earned == 1.0

    def test_incorrect_negative(self) -> None:
        pr = ParseResult(status=ParseStatus.FULL, output=ParsedOutput(vulnerable=True), raw_response="")
        gt = GroundTruth(vulnerable=False)
        score = score_task(pr, gt, max_task_points=1)
        assert score.verdict == 0
        assert score.earned == 0.0


class TestScoreCwe:
    def test_exact_match(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-89"),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.cwe == 1

    def test_case_insensitive(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="cwe-89"),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.cwe == 1

    def test_wrong_cwe(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-79"),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.cwe == 0

    def test_missing_cwe_in_prediction(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.cwe == 0


class TestScoreLocation:
    def test_exact_match_full_credit(self) -> None:
        loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 1.0

    def test_high_iou_continuous(self) -> None:
        """IoU 0.833 with recall 100% → score = 0.833."""
        pred_loc = Location(file="app.py", line_start=9, line_end=22)  # 14 lines
        gt_loc = Location(file="app.py", line_start=10, line_end=20)   # 11 lines
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        # intersection: 10-20 = 11 lines, union: 9-22 = 14 lines, IoU = 11/14
        assert abs(score.location - 11 / 14) < 1e-9

    def test_broad_prediction_containing_gt(self) -> None:
        """Broad prediction containing narrow GT → low but non-zero score."""
        pred_loc = Location(file="app.py", line_start=1, line_end=100)  # 100 lines
        gt_loc = Location(file="app.py", line_start=50, line_end=50)    # 1 line
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        # recall = 100%, IoU = 1/100 = 0.01
        assert abs(score.location - 0.01) < 1e-9

    def test_partial_overlap_fails_default_recall_gate(self) -> None:
        """Prediction covers only half of GT → recall 50% < threshold 100% → 0."""
        pred_loc = Location(file="app.py", line_start=15, line_end=25)
        gt_loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 0.0

    def test_no_overlap_zero(self) -> None:
        pred_loc = Location(file="app.py", line_start=100, line_end=110)
        gt_loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 0.0

    def test_wrong_file(self) -> None:
        pred_loc = Location(file="other.py", line_start=10, line_end=20)
        gt_loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 0.0

    def test_boundary_iou_0_5_passes(self) -> None:
        """IoU exactly 0.5 should get credit (>= not >)."""
        pred_loc = Location(file="app.py", line_start=10, line_end=13)  # 4 lines
        gt_loc = Location(file="app.py", line_start=10, line_end=11)    # 2 lines
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        # intersection=2, union=4, IoU=0.5, recall=100%
        assert score.location == 0.5


class TestRecallThreshold:
    """Test configurable recall gate."""

    def _make_score(self, pred_loc: Location, gt_loc: Location, threshold: float) -> float:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        return score_task(pr, gt, max_task_points=3, recall_threshold=threshold).location

    def test_threshold_1_0_requires_full_containment(self) -> None:
        """Recall 50% fails at threshold 1.0."""
        pred = Location(file="f.py", line_start=15, line_end=25)
        gt = Location(file="f.py", line_start=10, line_end=20)
        assert self._make_score(pred, gt, 1.0) == 0.0

    def test_threshold_0_5_allows_partial_overlap(self) -> None:
        """Recall ~55% passes at threshold 0.5."""
        pred = Location(file="f.py", line_start=15, line_end=25)  # 11 lines
        gt = Location(file="f.py", line_start=10, line_end=20)    # 11 lines
        # intersection: 15-20 = 6 lines, recall = 6/11 ≈ 0.545
        score = self._make_score(pred, gt, 0.5)
        assert score > 0.0
        assert abs(score - 6 / 16) < 1e-9  # IoU = 6/16

    def test_threshold_0_8_rejects_low_recall(self) -> None:
        """Recall ~55% fails at threshold 0.8."""
        pred = Location(file="f.py", line_start=15, line_end=25)
        gt = Location(file="f.py", line_start=10, line_end=20)
        assert self._make_score(pred, gt, 0.8) == 0.0

    def test_threshold_0_8_accepts_high_recall(self) -> None:
        """Recall ~91% passes at threshold 0.8."""
        pred = Location(file="f.py", line_start=9, line_end=22)   # 14 lines
        gt = Location(file="f.py", line_start=10, line_end=20)    # 11 lines
        # intersection: 10-20 = 11, recall = 11/11 = 100%
        score = self._make_score(pred, gt, 0.8)
        assert score > 0.0

    def test_all_thresholds_same_on_full_containment(self) -> None:
        """When recall = 100%, all thresholds give the same score."""
        pred = Location(file="f.py", line_start=1, line_end=50)
        gt = Location(file="f.py", line_start=10, line_end=20)
        s10 = self._make_score(pred, gt, 1.0)
        s08 = self._make_score(pred, gt, 0.8)
        s05 = self._make_score(pred, gt, 0.5)
        assert s10 == s08 == s05
        assert s10 > 0.0


class TestLocationIoUAndRecall:
    def test_perfect_overlap(self) -> None:
        a = Location(file="f.py", line_start=10, line_end=20)
        iou, recall = _location_iou_and_recall(a, a)
        assert iou == 1.0
        assert recall == 1.0

    def test_no_overlap(self) -> None:
        a = Location(file="f.py", line_start=10, line_end=20)
        b = Location(file="f.py", line_start=30, line_end=40)
        iou, recall = _location_iou_and_recall(a, b)
        assert iou == 0.0
        assert recall == 0.0

    def test_partial_overlap(self) -> None:
        pred = Location(file="f.py", line_start=10, line_end=20)
        gt = Location(file="f.py", line_start=15, line_end=25)
        iou, recall = _location_iou_and_recall(pred, gt)
        # intersection: 15-20 = 6, union: 10-25 = 16, gt_span = 11
        assert abs(iou - 6 / 16) < 1e-9
        assert abs(recall - 6 / 11) < 1e-9

    def test_prediction_contains_gt(self) -> None:
        pred = Location(file="f.py", line_start=1, line_end=100)
        gt = Location(file="f.py", line_start=50, line_end=60)
        iou, recall = _location_iou_and_recall(pred, gt)
        # intersection = 11, union = 100, recall = 11/11 = 1.0
        assert abs(iou - 11 / 100) < 1e-9
        assert recall == 1.0

    def test_gt_contains_prediction(self) -> None:
        pred = Location(file="f.py", line_start=50, line_end=60)
        gt = Location(file="f.py", line_start=1, line_end=100)
        iou, recall = _location_iou_and_recall(pred, gt)
        # intersection = 11, union = 100, recall = 11/100
        assert abs(iou - 11 / 100) < 1e-9
        assert abs(recall - 11 / 100) < 1e-9

    def test_different_file(self) -> None:
        a = Location(file="a.py", line_start=10, line_end=20)
        b = Location(file="b.py", line_start=10, line_end=20)
        iou, recall = _location_iou_and_recall(a, b)
        assert iou == 0.0
        assert recall == 0.0


class TestNegativeTask:
    def test_negative_only_verdict_scored(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=False),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=False)
        score = score_task(pr, gt, max_task_points=1)
        assert score.verdict == 1
        assert score.cwe == 0
        assert score.location == 0.0
        assert score.earned == 1.0
        assert score.max_task_points == 1

    def test_negative_unaffected_by_recall_threshold(self) -> None:
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=False),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=False)
        score = score_task(pr, gt, max_task_points=1, recall_threshold=0.5)
        assert score.earned == 1.0


class TestParseFailure:
    def test_failed_parse_all_zeros(self) -> None:
        pr = ParseResult(status=ParseStatus.FAILED, raw_response="garbage")
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.verdict == 0
        assert score.cwe == 0
        assert score.location == 0.0
        assert score.earned == 0.0


class TestFullScore:
    def test_perfect_positive(self) -> None:
        loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-89", location=loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.verdict == 1
        assert score.cwe == 1
        assert score.location == 1.0
        assert score.earned == 3.0
        assert score.max_task_points == 3

    def test_continuous_earned_is_float(self) -> None:
        """Earned is float when location is partial."""
        pred_loc = Location(file="app.py", line_start=10, line_end=13)  # 4 lines
        gt_loc = Location(file="app.py", line_start=10, line_end=11)    # 2 lines
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-89", location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        # verdict=1, cwe=1, location=0.5 → earned=2.5
        assert score.earned == pytest.approx(2.5)
        assert isinstance(score.earned, float)
