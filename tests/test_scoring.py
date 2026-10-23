"""Score arithmetic: weights sum, the total is capped, and bands follow the cut points."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jobcheck.engine import RuleFileError, RuleSet, analyze, load_rules, parse_amount, ruleset_from_dict

ROOT = Path(__file__).resolve().parents[1]


def _ruleset(*rules: dict, score_cap: int = 100) -> RuleSet:
    return ruleset_from_dict(
        {
            "score_cap": score_cap,
            "bands": [
                {"name": "Low", "max": 24},
                {"name": "Medium", "max": 54},
                {"name": "High", "max": 100},
            ],
            "next_steps": ["Verify the employer before you reply."],
            "disclaimer": "Heuristic only.",
            "rules": list(rules),
        }
    )


def _rule(rule_id: str, weight: int, pattern: str, name: str | None = None) -> dict:
    return {
        "id": rule_id,
        "name": name or rule_id,
        "weight": weight,
        "explanation": f"Test rule {rule_id}.",
        "patterns": [pattern],
    }


class ScoringTests(unittest.TestCase):
    def test_band_cut_points(self) -> None:
        expected = [("Low", 24), ("Medium", 54), ("High", 100)]
        self.assertEqual([(band.name, band.max) for band in load_rules().bands], expected)
        for weight, band in (
            (1, "Low"),
            (24, "Low"),
            (25, "Medium"),
            (54, "Medium"),
            (55, "High"),
            (100, "High"),
        ):
            with self.subTest(weight=weight):
                report = analyze("marker", _ruleset(_rule("custom_rule", weight, "marker")))
                self.assertEqual(report.score, weight)
                self.assertEqual(report.weight_total, weight)
                self.assertEqual(report.band, band)

    def test_weights_sum_and_cap_at_100(self) -> None:
        ruleset = _ruleset(
            _rule("later_rule", 60, "beta", name="Beta signal"),
            _rule("early_rule", 50, "alpha", name="Alpha signal"),
        )
        report = analyze("alpha then beta", ruleset)
        self.assertEqual(report.weight_total, 110)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.band, "High")
        self.assertEqual([flag.id for flag in report.flags], ["later_rule", "early_rule"])

    def test_equal_weights_sort_by_name(self) -> None:
        ruleset = _ruleset(
            _rule("zeta_rule", 30, "zeta", name="Zeta"),
            _rule("alpha_rule", 30, "alpha", name="Alpha"),
        )
        report = analyze("alpha zeta", ruleset)
        self.assertEqual([flag.name for flag in report.flags], ["Alpha", "Zeta"])

    def test_no_match_and_empty_text(self) -> None:
        ruleset = _ruleset(_rule("custom_rule", 40, "marker"))
        quiet = analyze("nothing to see here", ruleset)
        self.assertEqual(quiet.score, 0)
        self.assertEqual(quiet.band, "Low")
        self.assertEqual(quiet.flags, ())
        self.assertEqual(quiet.warnings, ())

        empty = analyze("  \n", ruleset)
        self.assertEqual(empty.score, 0)
        self.assertIn("empty", empty.warnings[0].lower())

    def test_skip_sentence_suppresses_a_negated_phrase(self) -> None:
        ruleset = ruleset_from_dict(
            {
                "score_cap": 100,
                "bands": [{"name": "Low", "max": 24}, {"name": "High", "max": 100}],
                "next_steps": ["Pause."],
                "disclaimer": "Heuristic only.",
                "rules": [
                    {
                        "id": "fee_rule",
                        "name": "Fee",
                        "weight": 60,
                        "explanation": "A fee was requested.",
                        "patterns": ["(?i)registration fee"],
                        "skip_sentence": "(?i)\\bnever\\b",
                    }
                ],
            }
        )
        self.assertEqual(analyze("Never pay a registration fee.", ruleset).flags, ())
        self.assertEqual(analyze("Pay the registration fee today.", ruleset).score, 60)

    def test_real_scam_sample_is_capped(self) -> None:
        text = (ROOT / "samples" / "scam_upfront_whatsapp.txt").read_text(encoding="utf-8")
        report = analyze(text)
        self.assertEqual(report.score, min(100, report.weight_total))
        self.assertGreater(report.weight_total, report.score)
        self.assertEqual(sum(flag.weight for flag in report.flags), report.weight_total)

    def test_parse_amount(self) -> None:
        self.assertEqual(parse_amount("5 000"), 5000)
        self.assertEqual(parse_amount("5,000"), 5000)
        self.assertEqual(parse_amount("5.000"), 5000)
        self.assertEqual(parse_amount("1,800.50"), 1800)
        self.assertEqual(parse_amount("1.800,50"), 1800)
        self.assertEqual(parse_amount("28.50"), 28)
        self.assertEqual(parse_amount("R500"), None)
        self.assertIsNone(parse_amount(""))
        self.assertIsNone(parse_amount("abc"))

    def test_invalid_rules_are_rejected(self) -> None:
        with self.assertRaises(RuleFileError):
            ruleset_from_dict({"score_cap": 100, "bands": [], "next_steps": [], "disclaimer": "x", "rules": []})

        broken = {
            "score_cap": 100,
            "bands": [{"name": "High", "max": 100}],
            "next_steps": ["Pause."],
            "disclaimer": "Heuristic only.",
            "rules": [
                {
                    "id": "bad_rule",
                    "name": "Bad",
                    "weight": 10,
                    "explanation": "Broken pattern.",
                    "patterns": ["("],
                }
            ],
        }
        with self.assertRaises(RuleFileError):
            ruleset_from_dict(broken)

        duplicate = {
            **broken,
            "rules": [
                _rule("same_rule", 10, "alpha"),
                _rule("same_rule", 10, "beta"),
            ],
        }
        with self.assertRaises(RuleFileError):
            ruleset_from_dict(duplicate)

        with self.assertRaises(RuleFileError):
            load_rules(ROOT / "samples" / "legit_junior_developer.txt")

    def test_rules_file_is_json(self) -> None:
        payload = json.loads((ROOT / "jobcheck" / "rules.json").read_text(encoding="utf-8"))
        self.assertIsInstance(payload["rules"], list)
        self.assertEqual(len(payload["rules"]), 11)


if __name__ == "__main__":
    unittest.main()
