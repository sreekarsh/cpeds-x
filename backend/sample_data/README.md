# CPEDS-X — Real Training Datasets

Drop a **labeled** dataset here (or upload one from the Model Metrics tab) to
train the model on real data instead of the built-in synthetic generator.

`labeled_dataset_sample.csv` is a ready-to-use example (300 rows, 60 per class)
so you can prove real-data training works in one click.

## What "labeled" means

Every row is one event **plus its true threat class** in a `label` column:

| label | class                   |
|-------|-------------------------|
| 0     | C0 Benign               |
| 1     | C1 Horizontal Escalation|
| 2     | C2 Vertical Escalation  |
| 3     | C3 Data Exfiltration    |
| 4     | C4 Lateral Movement     |

Labels may be written as `0`–`4`, or as class codes like `C2` / `C2: Vertical
Escalation`. The column may instead be named `threat_class`, `class`, or `y`;
the loader tries those automatically, or you can name it explicitly.

## Two accepted shapes (auto-detected per row)

1. **Raw CloudTrail events + a `label`** (what the sample uses, recommended).
   Ordinary CloudTrail-style fields (`eventName`, `userIdentity.arn`,
   `sourceIPAddress`, ...) plus the label. Each event is featurized through the
   **same** 28-feature pipeline used for live inference, so training and
   detection see data identically. In CSV, use dotted headers like
   `userIdentity.arn` — they are un-flattened into nested objects for you.

2. **Pre-computed 28-feature rows + a `label`.** If a row already contains all
   28 canonical feature columns (see `ml_engine/preprocessor.py`
   `feature_names`), they are used directly with no re-featurization.

## Formats

Same as the Log Analysis upload tab: CloudTrail JSON export (`{"Records":[...]}`),
a JSON array, JSON Lines (`.jsonl`), or CSV.

## Validation (why a bad file can't break anything)

Before training, the loader checks the file parses, labels are all 0–4, feature
vectors are length 28, at least two classes are present, there are at least 40
usable rows, and no class has fewer than 10. If any check fails, an **explicit
retrain keeps the previous model** and reports why; at server startup it falls
back to synthetic automatically. Training itself never changes how the model
answers — only what it learned from.

## Using it

- **Dashboard:** Model Metrics tab → switch to *Real* → upload a file → Retrain.
- **Server default:** set `CPEDS_TRAIN_MODE=real` and
  `CPEDS_TRAIN_DATASET=sample_data/labeled_dataset_sample.csv`, then start the
  backend. Leave `CPEDS_TRAIN_MODE` unset for the synthetic default.
