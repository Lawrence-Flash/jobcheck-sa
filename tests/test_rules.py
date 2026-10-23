"""Every packaged rule has to fire on a known scam phrase and stay quiet on ordinary wording."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from jobcheck.engine import analyze, load_rules

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_WEIGHTS = {
    "upfront_fees": 60,
    "sensitive_documents": 55,
    "reshipping": 60,
    "seta_learnership_fee": 60,
    "crypto_forex": 40,
    "unrealistic_pay": 35,
    "guaranteed_job": 30,
    "messenger_contact": 25,
    "vague_company": 25,
    "free_email": 15,
    "urgency_pressure": 15,
}

# One short advert fragment per rule. Some fragments also trip a related rule.
FIXTURES = {
    "upfront_fees": "Please pay R450 registration fee before we send an offer.",
    "sensitive_documents": "Send a copy of your ID and your bank details before the interview.",
    "reshipping": "Receive parcels at home and reship them to the buyers.",
    "seta_learnership_fee": "Pay R1800 to enrol on this SETA learnership.",
    "crypto_forex": "We are hiring for a forex trading role on our crypto desk.",
    "unrealistic_pay": "Earn R5000 per day from home.",
    "guaranteed_job": "This programme offers 100% placement and a guaranteed job.",
    "messenger_contact": "WhatsApp only on 0715550199 for the details.",
    "vague_company": "The company name is withheld. Location: confidential.",
    "free_email": "The recruiter's address is hiring.team@gmail.com.",
    "urgency_pressure": "Limited spots. Start today.",
}

CLEAN_PHRASES = [
    "Salary: R18 000 per month. We offer medical aid.",
    "We pay R18 000 per month for this role.",
    "Pay rate: R28.50 per hour.",
    "Never pay a registration fee to a recruiter.",
    "You must pay attention to the roster.",
    "Bring your ID to the interview at our office.",
    "The employer pays PAYE over to SARS each month.",
    "Do not send your bank details by email.",
    "Earn R350 per day plus tips.",
    "Earn R1 999 per day.",
    "No experience needed. Stipend R4 000 per month.",
    "No experience needed, salary R22 000 per month.",
    "Apply to careers@naledidigital.co.za.",
    "Call the switchboard on 011 555 0100.",
    "We review applications every Friday.",
    "Strong performers may be offered a permanent role.",
    "This SETA-funded learnership pays a monthly stipend.",
    "The SETA stipend payment is monthly.",
    "SETA learnership with no fee payable by the learner.",
    "You will pack shelves and receive stock deliveries at the store.",
    "You will reconcile card payments for a grocery chain.",
    "Naledi Digital (Pty) Ltd, 12 Rivonia Road, Sandton.",
]

SAMPLE_FLAGS = {
    "legit_junior_developer.txt": set(),
    "legit_retail_cashier.txt": set(),
    "scam_upfront_whatsapp.txt": {
        "upfront_fees",
        "sensitive_documents",
        "unrealistic_pay",
        "vague_company",
        "messenger_contact",
        "urgency_pressure",
    },
    "scam_seta_learnership.txt": {
        "seta_learnership_fee",
        "upfront_fees",
        "guaranteed_job",
        "vague_company",
        "messenger_contact",
        "free_email",
        "urgency_pressure",
    },
    "scam_reshipping.txt": {
        "reshipping",
        "upfront_fees",
        "guaranteed_job",
        "vague_company",
        "messenger_contact",
    },
    "scam_forex_trading.txt": {
        "sensitive_documents",
        "crypto_forex",
        "unrealistic_pay",
        "guaranteed_job",
        "vague_company",
        "messenger_contact",
        "free_email",
    },
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text)


class RuleCatalogTests(unittest.TestCase):
    def test_catalog_matches_the_brief(self) -> None:
        ruleset = load_rules()
        weights = {rule.id: rule.weight for rule in ruleset.rules}
        self.assertEqual(weights, EXPECTED_WEIGHTS)
        self.assertEqual(set(FIXTURES), set(weights))
        for rule in ruleset.rules:
            self.assertTrue(rule.name.strip())
            self.assertGreater(len(rule.explanation), 40)

    def test_every_rule_matches_its_fixture_and_quotes_the_ad(self) -> None:
        for rule_id, text in FIXTURES.items():
            with self.subTest(rule=rule_id):
                report = analyze(text)
                flags = {flag.id: flag for flag in report.flags}
                self.assertIn(rule_id, flags)
                flag = flags[rule_id]
                self.assertEqual(flag.weight, EXPECTED_WEIGHTS[rule_id])
                self.assertTrue(flag.snippets)
                for snippet in flag.snippets:
                    self.assertNotIn("...", snippet)
                    self.assertIn(_norm(snippet), _norm(text))

    def test_ordinary_wording_matches_nothing(self) -> None:
        for text in CLEAN_PHRASES:
            with self.subTest(text=text):
                report = analyze(text)
                self.assertEqual(report.flags, (), msg=report.flags)
                self.assertEqual(report.score, 0)
                self.assertEqual(report.band, "Low")

    def test_amount_thresholds_for_unrealistic_pay(self) -> None:
        self.assertEqual(analyze("Earn R2 000 per day.").flags[0].id, "unrealistic_pay")
        self.assertEqual(analyze("Earn R5,000 per day from home.").band, "Medium")
        high = analyze("No experience needed, salary R45 000 per month.")
        self.assertIn("unrealistic_pay", {flag.id for flag in high.flags})
        self.assertEqual(analyze("No experience needed, salary R24 999 per month.").flags, ())

    def test_free_inboxes_and_company_domains(self) -> None:
        for address in (
            "hiring.team@gmail.com",
            "jobs@yahoo.co.za",
            "recruiter@outlook.com",
            "hr@webmail.co.za",
            "HR@Hotmail.com",
        ):
            with self.subTest(address=address):
                report = analyze(f"Email {address} with your CV.")
                self.assertIn("free_email", {flag.id for flag in report.flags})

    def test_missing_company_and_address(self) -> None:
        vague = (
            "We need several people to type forms on a laptop from wherever they are. "
            "Hours are flexible and the work starts as soon as you reply to this advert. "
            "More detail about the role will be shared after you make contact with the team today."
        )
        self.assertGreaterEqual(len(vague), 180)
        report = analyze(vague)
        self.assertEqual([flag.id for flag in report.flags], ["vague_company"])
        self.assertIn("No registered company", report.flags[0].snippets[0])

        named = vague + " Naledi Digital (Pty) Ltd, 12 Rivonia Road, Sandton."
        self.assertEqual(analyze(named).flags, ())

    def test_sample_ads_and_full_rule_coverage(self) -> None:
        seen: set[str] = set()
        for name, expected in SAMPLE_FLAGS.items():
            with self.subTest(sample=name):
                report = analyze((ROOT / "samples" / name).read_text(encoding="utf-8"))
                found = {flag.id for flag in report.flags}
                self.assertEqual(found, expected)
                seen |= found
                if name.startswith("legit_"):
                    self.assertEqual(report.score, 0)
                    self.assertEqual(report.band, "Low")
                else:
                    self.assertEqual(report.score, 100)
                    self.assertEqual(report.band, "High")
                    self.assertGreater(report.weight_total, 100)
        self.assertEqual(seen, set(EXPECTED_WEIGHTS))

    def test_next_steps_name_the_real_places_to_check(self) -> None:
        ruleset = load_rules()
        steps = " ".join(ruleset.next_steps)
        self.assertIn("CIPC", steps)
        self.assertIn("Never pay", steps)
        self.assertIn("ID number", steps)
        self.assertIn("SAPS", steps)
        self.assertIn("SABRIC", steps)
        self.assertIn("heuristic", ruleset.disclaimer.lower())
        self.assertIn("not a guarantee", ruleset.disclaimer.lower())


if __name__ == "__main__":
    unittest.main()
