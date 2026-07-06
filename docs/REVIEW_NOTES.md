# Review notes before submission

## Critical code issue

`paired_honeynet_analysis.py` had an f-string quoting error in the suggested manuscript sentence block. This prepared repository includes a corrected version.

## Manuscript consistency checks

1. Clarify whether the dataset is directly empirical, reconstructed from aggregate values, or anonymized from raw logs. Avoid wording that makes the verification appear circular.
2. Separate `analysis time` from `mean time to detection`. If Table 4 measures analyst work duration, call it `mean analysis time` rather than MTTD.
3. Align the risk-score formula with the Python implementation. The manuscript describes a weighted model, while the parser currently applies additive rule-based points.
4. Explain the correlation algorithm more precisely, including the time window and grouping keys.
5. Because Cowrie alone cannot observe UDP events, frame H1 as broader heterogeneous TCP/UDP coverage, not a completely equivalent sensor-to-sensor comparison.
6. Add effect sizes and confidence intervals to the statistical reporting where possible.
7. Use higher-resolution figures for the workflow and risk-score model.
8. Verify reference dates and access dates before final submission.

## Email consistency checks

- Use the exact script filenames.
- If scripts are attached as `.txt`, say so. If they are attached as `.py`, remove the sentence about `.txt` conversion.
- Remove any blank second page from the email document before sending.
