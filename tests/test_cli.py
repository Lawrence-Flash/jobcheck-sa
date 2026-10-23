"""CLI paths: files, stdin, JSON, the demo, and a broken rules file."""

from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from jobcheck.cli import main

ROOT = Path(__file__).resolve().parents[1]
LEGIT = ROOT / "samples" / "legit_junior_developer.txt"
SCAM = ROOT / "samples" / "scam_upfront_whatsapp.txt"


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


class CliTests(unittest.TestCase):
    def test_check_file_human_report(self) -> None:
        stdout = io.StringIO()
        code = main(["check", str(LEGIT)], stdout=stdout)
        text = stdout.getvalue()
        self.assertEqual(code, 0)
        flat = _flat(text)
        self.assertIn("JobCheck SA", flat)
        self.assertIn("Risk score: 0/100", flat)
        self.assertIn("Band: Low", flat)
        self.assertIn("No rules matched.", flat)
        self.assertIn("CIPC", flat)
        self.assertIn("SAPS", flat)
        self.assertIn("SABRIC", flat)
        self.assertIn("not a guarantee", flat.lower())

    def test_check_scam_includes_weight_explanation_and_snippet(self) -> None:
        stdout = io.StringIO()
        code = main(["check", str(SCAM)], stdout=stdout)
        text = stdout.getvalue()
        self.assertEqual(code, 0)
        flat = _flat(text)
        self.assertIn("Risk score: 100/100", flat)
        self.assertIn("Band: High", flat)
        self.assertIn("Upfront fees (weight 60)", flat)
        self.assertIn("A real employer does not charge you to start work.", flat)
        self.assertIn(
            'Matched: "To secure a seat, pay R450 registration fee and R299 uniform fee"',
            flat,
        )
        self.assertIn("capped at 100", flat)

    def test_check_stdin_and_json(self) -> None:
        stdout = io.StringIO()
        code = main(
            ["check", "-", "--json"],
            stdin=io.StringIO("Please pay R450 registration fee.\n"),
            stdout=stdout,
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["tool"], "jobcheck")
        self.assertEqual(payload["source"], "stdin")
        self.assertEqual(payload["score"], 60)
        self.assertEqual(payload["band"], "High")
        self.assertEqual(payload["flags"][0]["id"], "upfront_fees")
        self.assertTrue(payload["flags"][0]["snippets"])
        self.assertIn("CIPC", " ".join(payload["next_steps"]))

    def test_empty_stdin_warns(self) -> None:
        stdout = io.StringIO()
        code = main(["check", "-", "--json"], stdin=io.StringIO("  "), stdout=stdout)
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["score"], 0)
        self.assertEqual(payload["band"], "Low")
        self.assertTrue(payload["warnings"])

    def test_missing_file(self) -> None:
        stderr = io.StringIO()
        code = main(["check", "no-such-ad.txt"], stdout=io.StringIO(), stderr=stderr)
        self.assertEqual(code, 1)
        self.assertIn("not found", stderr.getvalue())

    def test_demo_human_and_json(self) -> None:
        stdout = io.StringIO()
        code = main(["demo"], stdout=stdout)
        text = stdout.getvalue()
        self.assertEqual(code, 0)
        for name in (
            "legit_junior_developer.txt",
            "legit_retail_cashier.txt",
            "scam_upfront_whatsapp.txt",
            "scam_seta_learnership.txt",
            "scam_reshipping.txt",
            "scam_forex_trading.txt",
        ):
            self.assertIn(name, text)
        self.assertIn("0/100", text)
        self.assertIn("100/100", text)
        self.assertIn("Low", text)
        self.assertIn("High", text)

        raw = io.StringIO()
        self.assertEqual(main(["demo", "--json"], stdout=raw), 0)
        payload = json.loads(raw.getvalue())
        self.assertEqual(len(payload["results"]), 6)
        bands = {item["band"] for item in payload["results"]}
        self.assertEqual(bands, {"Low", "High"})

    def test_alternate_rules_file(self) -> None:
        custom = {
            "score_cap": 100,
            "bands": [
                {"name": "Low", "max": 24},
                {"name": "Medium", "max": 54},
                {"name": "High", "max": 100},
            ],
            "next_steps": ["Look up the company."],
            "disclaimer": "Heuristic only.",
            "rules": [
                {
                    "id": "custom_rule",
                    "name": "Custom marker",
                    "weight": 25,
                    "explanation": "The custom marker was present.",
                    "patterns": ["purple elephant"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps(custom), encoding="utf-8")
            stdout = io.StringIO()
            code = main(
                ["check", "-", "--json", "--rules", str(path)],
                stdin=io.StringIO("A purple elephant is not a job."),
                stdout=stdout,
            )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["score"], 25)
        self.assertEqual(payload["band"], "Medium")
        self.assertEqual(payload["flags"][0]["id"], "custom_rule")

    def test_broken_rules_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text("{", encoding="utf-8")
            stderr = io.StringIO()
            code = main(["check", "-", "--rules", str(path)], stdin=io.StringIO("hi"), stderr=stderr)
        self.assertEqual(code, 1)
        self.assertIn("JSON", stderr.getvalue())

    def test_version_and_missing_command(self) -> None:
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("jobcheck", stdout.getvalue())

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 2)

    def test_module_entrypoint(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "jobcheck", "check", str(LEGIT)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Band: Low", completed.stdout)
        self.assertIn("Risk score: 0/100", completed.stdout)


if __name__ == "__main__":
    unittest.main()
