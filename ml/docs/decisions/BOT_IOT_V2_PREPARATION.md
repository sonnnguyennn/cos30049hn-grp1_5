# Decision: Bot-IoT v2 preparation after structural diagnostics

Status: authorized for PREPARED_PENDING_REVIEW preparation, not team verification.
Context: c8d1de7 full scan found one mixed-label exact-X group and valid TEST categories
absent from TRAIN. No classifier/clustering or performance evaluation has occurred.

The user explicitly authorizes two policy changes for a new version:

1. Accept fixed-X representational ambiguity: keep11 benign and3,733 malicious together
   in TRAIN with their original labels. This does not establish annotation error and does
   not authorize dropping, relabelling, regrouping or changing predictors.
2. Replace v1 fail-on-unseen with one typed reserved UNKNOWN slot per categorical field.
   Train vocabularies remain TRAIN-only. Any valid novel source string uses the same
   general mechanism; no TEST category names are added to learned state. Invalid source
   text remains invalid. A reserved object/slot cannot collide with a valid source string.

The timing must be disclosed: these choices follow TEST structural diagnostics and precede
model fitting and model/threshold selection. Frozen v1 is not rewritten or retrospectively
claimed to have used UNKNOWN. Membership, seed1729, labels and13 predictors remain fixed.

Commit this decision, v2 contract and protocol before any v2 preprocessor fitting or package
materialisation. Build only a fresh external namespace, verify relocation independently,
retain TEST default seal and stop at PREPARED_PENDING_REVIEW. Model training is Kaggle-only.
