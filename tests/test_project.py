"""Repository constraints: standard library only, MIT licence, and a README that matches the tool."""

from __future__ import annotations

import ast
import io
import os
import sys
import unittest
from pathlib import Path

from jobcheck.cli import main

ROOT = Path(__file__).resolve().parents[1]
NETWORK_MODULES = {
    "socket",
    "http",
    "urllib",
    "ftplib",
    "smtplib",
    "webbrowser",
    "requests",
    "httpx",
    "aiohttp",
}


class ProjectTests(unittest.TestCase):
    def test_package_is_stdlib_only_and_offline(self) -> None:
        for path in (ROOT / "jobcheck").rglob("*"):
            if path.suffix not in {".py", ".json"}:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("http://", text)
            self.assertNotIn("https://", text)
            if path.suffix != ".py":
                continue
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    modules = [node.module.split(".")[0]]
                for name in modules:
                    if name == "jobcheck":
                        continue
                    self.assertIn(name, sys.stdlib_module_names, msg=f"{path.name} imports {name}")
                    self.assertNotIn(name, NETWORK_MODULES)

    def test_readme_and_licence(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        lowered = readme.lower()
        for phrase in (
            "Quick start",
            "How scoring works",
            "How to add a rule",
            "Disclaimer",
            "Lawrence Tshabalala",
            "Lawrence-Flash",
            "Low",
            "Medium",
            "High",
            "CIPC",
            "SAPS",
            "SABRIC",
            "heuristic",
            "not a guarantee",
            "python3 -m jobcheck check",
            "python3 -m jobcheck demo",
            "--json",
        ):
            self.assertIn(phrase, readme)
        for banned in ("certified", "certification", "certificate"):
            self.assertNotIn(banned, lowered)

        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", licence)
        self.assertIn("Lawrence Tshabalala", licence)
        self.assertIn("2026", licence)

    def test_readme_embeds_the_live_demo_and_report(self) -> None:
        previous = Path.cwd()
        os.chdir(ROOT)
        try:
            readme = (ROOT / "README.md").read_text(encoding="utf-8")
            demo = io.StringIO()
            self.assertEqual(main(["demo"], stdout=demo), 0)
            report = io.StringIO()
            code = main(["check", "samples/scam_upfront_whatsapp.txt"], stdout=report)
            self.assertEqual(code, 0)
            self.assertIn(demo.getvalue().rstrip("\n"), readme)
            self.assertIn(report.getvalue().rstrip("\n"), readme)
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
