"""Tests for per-task scoring."""

from __future__ import annotations

from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.task import GroundTruth, Location
from seclens.scoring.grader import _location_iou, score_task


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
        assert score.earned == 1

    def test_incorrect_negative(self) -> None:
        pr = ParseResult(status=ParseStatus.FULL, output=ParsedOutput(vulnerable=True), raw_response="")
        gt = GroundTruth(vulnerable=False)
        score = score_task(pr, gt, max_task_points=1)
        assert score.verdict == 0
        assert score.earned == 0


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
    def test_exact_match(self) -> None:
        loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 1

    def test_iou_above_threshold(self) -> None:
        pred_loc = Location(file="app.py", line_start=10, line_end=22)
        gt_loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 1

    def test_iou_below_threshold(self) -> None:
        pred_loc = Location(file="app.py", line_start=10, line_end=50)
        gt_loc = Location(file="app.py", line_start=10, line_end=20)
        pr = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, location=pred_loc),
            raw_response="",
        )
        gt = GroundTruth(vulnerable=True, cwe="CWE-89", location=gt_loc)
        score = score_task(pr, gt, max_task_points=3)
        assert score.location == 0

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
        assert score.location == 0


class TestLocationIoU:
    def test_perfect_overlap(self) -> None:
        a = Location(file="f.py", line_start=10, line_end=20)
        b = Location(file="f.py", line_start=10, line_end=20)
        assert _location_iou(a, b) == 1.0

    def test_no_overlap(self) -> None:
        a = Location(file="f.py", line_start=10, line_end=20)
        b = Location(file="f.py", line_start=30, line_end=40)
        assert _location_iou(a, b) == 0.0

    def test_partial_overlap(self) -> None:
        a = Location(file="f.py", line_start=10, line_end=20)
        b = Location(file="f.py", line_start=15, line_end=25)
        # intersection: 15-20 = 6 lines, union: 10-25 = 16 lines
        assert abs(_location_iou(a, b) - 6 / 16) < 1e-9

    def test_different_file(self) -> None:
        a = Location(file="a.py", line_start=10, line_end=20)
        b = Location(file="b.py", line_start=10, line_end=20)
        assert _location_iou(a, b) == 0.0


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
        assert score.location == 0
        assert score.earned == 1
        assert score.max_task_points == 1


class TestParseFailure:
    def test_failed_parse_all_zeros(self) -> None:
        pr = ParseResult(status=ParseStatus.FAILED, raw_response="garbage")
        gt = GroundTruth(vulnerable=True, cwe="CWE-89")
        score = score_task(pr, gt, max_task_points=3)
        assert score.verdict == 0
        assert score.cwe == 0
        assert score.location == 0
        assert score.earned == 0


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
        assert score.location == 1
        assert score.earned == 3
        assert score.max_task_points == 3
