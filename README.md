# JobCheck SA

JobCheck SA is a terminal tool that reads a South African job advert and scores it for common scam red flags. It is a local heuristic. It does not browse the web, call a paid API, or decide for you.

**Author:** Lawrence Tshabalala ([Lawrence-Flash](https://github.com/Lawrence-Flash))

Python 3.10 or newer. The standard library only.

## Quick start

Clone the repository and run it from the checkout. There is nothing to install.

```bash
git clone https://github.com/Lawrence-Flash/jobcheck-sa.git
cd jobcheck-sa
python3 -m jobcheck demo
python3 -m jobcheck check samples/scam_upfront_whatsapp.txt
cat samples/legit_junior_developer.txt | python3 -m jobcheck check -
python3 -m jobcheck check --json samples/legit_retail_cashier.txt
```

`check` reads one advert from a file, or from stdin when the path is `-`. `demo` scores the six fictional ads in `samples/`. `--json` prints the same report as JSON. `--rules path/to/rules.json` loads a different rule file.

A finished report exits 0, including when the band is High. Exit code 1 means the advert or the rules file could not be read. Exit code 2 means the command line was not valid.

## Example output

`python3 -m jobcheck demo`

```text
JobCheck SA demo
6 fictional ads

samples/legit_junior_developer.txt
  0/100  Low
  no rules matched

samples/legit_retail_cashier.txt
  0/100  Low
  no rules matched

samples/scam_forex_trading.txt
  100/100  High
  sensitive_documents, crypto_forex, unrealistic_pay, guaranteed_job,
  vague_company, messenger_contact, free_email

samples/scam_reshipping.txt
  100/100  High
  reshipping, upfront_fees, guaranteed_job, vague_company, messenger_contact

samples/scam_seta_learnership.txt
  100/100  High
  seta_learnership_fee, upfront_fees, guaranteed_job, vague_company,
  messenger_contact, free_email, urgency_pressure

samples/scam_upfront_whatsapp.txt
  100/100  High
  upfront_fees, sensitive_documents, unrealistic_pay, vague_company,
  messenger_contact, urgency_pressure

Run `python3 -m jobcheck check <file>` for the full report, including snippets.
JobCheck SA is a heuristic aid. It can miss scams and it can flag legitimate
adverts. A score is not a guarantee that an advert is safe or fraudulent.
```

`python3 -m jobcheck check samples/scam_upfront_whatsapp.txt`

```text
JobCheck SA
Source: samples/scam_upfront_whatsapp.txt
Risk score: 100/100
Band: High
Weight total: 215 (capped at 100)

Flags (6)
---------
1. Upfront fees (weight 60)
   The ad asks you to pay to be hired. Training, admin, registration, uniform,
   medical, or starter-kit fees are a common South African job scam. A real
   employer does not charge you to start work.
   Matched: "To secure a seat, pay R450 registration fee and R299 uniform fee"

2. ID, bank, or SARS details (weight 55)
   The ad asks for an ID number, a copy of your ID, bank details, or a SARS
   tax number. Those details are abused for identity fraud and do not belong
   in an application before you have verified the employer and been
   interviewed.
   Matched: "Send a copy of your ID and your bank details to apply"

3. Unrealistic pay (weight 35)
   The pay on offer is far above a normal wage for the work described, such as
   thousands of rand a day, or a high salary paired with no experience.
   Inflated pay is a common lure. Daily rates for scarce professional locum
   work can also match, so read the rest of the ad.
   Matched: "Earn R5 000 per day from your phone"

4. Vague company or no address (weight 25)
   The ad does not give you a traceable employer. A withheld company name, a
   confidential location, or no street address makes a CIPC search much
   harder.
   Matched: "The company name is withheld until payment is received"
   Matched: "A well-known company is hiring nationwide"

5. WhatsApp or Telegram contact (weight 25)
   The ad uses WhatsApp or Telegram as a contact channel. Scam recruiters
   prefer those apps because a chat is harder to tie to a registered company
   than a switchboard or a company domain. A real employer that also publishes
   a WhatsApp line can match this rule.
   Matched: "WhatsApp only: 071 555 0199"

6. Urgency and pressure (weight 15)
   The ad pushes you to act immediately, for example with limited spots or a
   same-day start. Pressure is used to stop you checking the employer. On its
   own this is a weak signal, because ordinary vacancies can also be urgent.
   Matched: "Limited spots"
   Matched: "Start today"

Safe next steps
---------------
- Verify the employer on the CIPC company search before you share documents or
  money. Look up the registered name, not only a logo, a WhatsApp display
  name, or an email signature. The public search is on CIPC eServices.
- Never pay a fee, deposit, starter-kit cost, or registration charge to be
  hired, interviewed, or placed on a learnership. A legitimate employer pays
  you.
- Do not send your ID number, a copy of your ID, bank details, or a SARS tax
  number before you have verified the company and attended a real interview.
- If you have already paid or shared banking details, contact your bank at
  once and report the matter to the South African Police Service (SAPS).
  Banking-related fraud can also be reported to SABRIC, the South African
  Banking Risk Information Centre.
- Prefer the company's own careers address or a published switchboard. Treat
  WhatsApp-only, Telegram-only, and free-mail recruiters as unverified until
  you can tie them to a registered business.

JobCheck SA is a heuristic aid. It can miss scams and it can flag legitimate
adverts. A score is not a guarantee that an advert is safe or fraudulent.
```

`--json` emits one object with `tool`, `version`, `source`, `score`, `score_cap`, `weight_total`, `band`, `flags` (each with `id`, `name`, `weight`, `explanation`, and `snippets`), `next_steps`, `warnings`, and `disclaimer`. `demo --json` returns those reports under `results`.

## How scoring works

Each rule in [`jobcheck/rules.json`](jobcheck/rules.json) has a weight from 1 to 100. A rule counts once when it matches, even if several of its patterns hit. The score is the sum of the matched weights, capped at 100. `weight_total` in the report is the uncapped sum, so a pile-up of flags stays visible after the cap.

| Band | Score |
| --- | --- |
| Low | 0–24 |
| Medium | 25–54 |
| High | 55–100 |

| Rule | Weight | What it looks for |
| --- | --- | --- |
| Upfront fees | 60 | Training, admin, registration, uniform, medical, or starter-kit fees, including "pay R…" when it is not ordinary monthly, weekly, or hourly pay |
| ID, bank, or SARS details | 55 | An ID number, a copy of an ID, bank details, or a SARS tax number |
| Package reshipping | 60 | Receiving parcels and sending them on (a parcel-mule pattern) |
| SETA learnership fee | 60 | Paying to join a SETA learnership |
| Crypto or forex trading | 40 | Forex, or crypto paired with trading or a hiring pitch |
| Unrealistic pay | 35 | About R2 000 or more per day, or "no experience" next to about R25 000 or more |
| Guaranteed job | 30 | A guaranteed job, income, or "100% placement" |
| WhatsApp or Telegram contact | 25 | WhatsApp, `wa.me`, Telegram, or `t.me` |
| Vague company or no address | 25 | A withheld or "well-known" company, a confidential location, or a long ad with no company name and no street address |
| Free email address | 15 | Gmail, Yahoo, Outlook (including Hotmail and Live), or webmail |
| Urgency and pressure | 15 | Limited spots, start today, act now, and similar pressure |

A single fee, document, reshipping, or SETA-fee hit lands in High because that weight is already 55 or 60. Urgency or a free inbox alone stays Low. WhatsApp alone is Medium. Two weaker rules add up.

The pay thresholds and the phrase lists live in the JSON file, not in Python. A sentence that says the opposite, such as "Never pay a registration fee" or "Do not send your bank details", does not count for the fee, document, or learnership-fee rules.

Ordinary wording still slips through, and legitimate wording can still match. A locum rate of a few thousand rand a day can look like unrealistic pay. A real employer that publishes a WhatsApp number matches the messenger rule. A low score means these rules did not match. It does not mean the advert is safe.

## How to add a rule

Add an object to the `rules` array in `jobcheck/rules.json`. Use a new `id` of lowercase letters, digits, and underscores.

```json
{
  "id": "gift_card_payment",
  "name": "Gift-card payment",
  "weight": 40,
  "explanation": "The ad asks to be paid by gift card. An employer does not collect a hiring fee that way.",
  "patterns": ["(?i)\\bgift\\s+cards?\\b"]
}
```

Optional fields:

- `amount_checks`: objects with `pattern`, `minimum`, and optional `group` (default 1). Write `{amount}` where a rand figure should be parsed (`R5 000`, `R5,000`, `R5000`, `R350.00`). The check matches only when the captured amount is at least `minimum`.
- `skip_sentence`: a regex. A hit is dropped when the same sentence also matches, which is how "never pay" stays quiet.
- `missing`: `{ "patterns": ["..."], "min_length": 180, "snippet": "..." }`. If nothing else matched, the rule fires when the ad is at least `min_length` characters and none of these patterns appear. The vague-company rule uses this for ads with no company name and no street address.

Then add the id and weight to `EXPECTED_WEIGHTS` and a short fixture to `FIXTURES` in `tests/test_rules.py`. The catalog test fails until every rule has a fixture. Run:

```bash
python3 -m unittest discover -s tests -t . -v
```

Patterns are Python regular expressions. Keep quantifiers bounded (`{0,80}`, not open-ended `.*` across long text) so a clumsy rule cannot stall on a large paste.

## Sample ads

`samples/` has six fictional adverts. Two are ordinary vacancies with a named company, a street address, and a company email. Four are scams: an upfront fee over WhatsApp, a paid SETA learnership, a parcel-reshipping task, and a forex/crypto "trading" role. They are not descriptions of real employers.

## Tests

GitHub Actions runs the unit tests on Python 3.10, 3.11, and 3.12, and runs CodeQL on Python. Locally:

```bash
python3 -m unittest discover -s tests -t . -v
```

The suite covers every rule, the ordinary phrases that must stay quiet, the band cut points, the 100-point cap, stdin, JSON, and the demo.

## Disclaimer

JobCheck SA is a heuristic aid. It can miss scams and it can flag legitimate adverts. A score is not a guarantee that an advert is safe or fraudulent. Do not use it as your only check.

The tool never contacts an employer, a bank, CIPC, the South African Police Service (SAPS), or SABRIC. The safe next steps in each report are reminders for you: search the company on CIPC eServices, never pay to be hired, and report money or banking details you have already handed over to your bank, to SAPS, and where it is a banking matter, to SABRIC.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Lawrence Tshabalala.
