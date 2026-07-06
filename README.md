# Distributed Honeynet Analysis

Supporting Python code for the paper:

**Design and Statistical Evaluation of a Distributed Honeynet Model for Early Cyber Attack Detection**

Author: Milan Panić  

## Repository contents

```text
src/
  honeynet_log_parser.py          # Parses and normalizes Cowrie and DDoSPot logs
  paired_honeynet_analysis.py     # Performs paired analysis-time statistical comparison

data/
  paired_observations_example.csv # Scenario-level paired observations used in the manuscript table

outputs/
  .gitkeep                        # Placeholder; generated files should not be committed by default

docs/
  GITHUB_UPLOAD_GUIDE.md          # Step-by-step GitHub upload instructions
  REVIEW_NOTES.md                 # Review notes and recommended improvements before submission
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate          # Windows PowerShell
pip install -r requirements.txt
```

## 1. Parse and normalize honeynet logs

Example:

```bash
python src/honeynet_log_parser.py \
  --cowrie-dir raw_logs/cowrie \
  --ddospot-dir raw_logs/ddospot \
  --output-dir outputs/normalized_output \
  --time-window-min 10
```

Generated files:

- `normalized_events.csv`
- `normalized_events.jsonl`
- `parser_summary.txt`

Raw logs are intentionally excluded from this repository by `.gitignore` because they may contain sensitive or large evidence records.

## 2. Run the paired statistical analysis

```bash
python src/paired_honeynet_analysis.py \
  --input data/paired_observations_example.csv \
  --output-report outputs/paired_ttest_report.txt \
  --output-csv outputs/paired_observations_with_differences.csv
```

The script calculates descriptive statistics, paired differences, a paired t-test, 95% confidence interval and Cohen's dz effect size.

## Data and code availability note

This repository is intended as supplementary material for academic review and reproducibility. If the repository is public, do not commit raw honeypot logs, IP addresses, malware samples, credentials, PCAPs or unpublished manuscript drafts without co-author and journal approval.

## License

No open-source license has been selected yet. Until a license is added, the code is provided for review only and all rights are reserved by the author.
