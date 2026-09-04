# Dependency pinning rationale

Every dependency in `pyproject.toml` is pinned to an exact version (NFR-8).
Two of those pins are not arbitrary and must not be bumped casually.

## `scikit-learn==1.9.0`

The reused V0 artifact (`v0_tfidf_lr.joblib`) was serialised by scikit-learn
**1.9.0**. Note that the LLMShield repository's `requirements-frozen.txt` pins
1.8.0 -- that file predates the Experiment 2 model and does not describe the
environment the artifact was actually written in. The pin here follows the
artifact, established empirically: loading under 1.8.0 raises
`InconsistentVersionWarning` for `TfidfVectorizer`, `TfidfTransformer`,
`FeatureUnion` and `LogisticRegression`. scikit-learn's pickle format is version
sensitive: loading under a different minor version raises
`InconsistentVersionWarning` at best and silently mis-reconstructs estimator
internals at worst. Since V0 is reused rather than retrained, the loader
version is part of the artifact's definition.

Any score produced under a mismatched loader must be treated as unreliable,
so this pin is load-bearing for every V0 number in the project.

## `transformers==5.12.1`

`v3_deberta_base/config.json` records `"transformers_version": "5.12.1"`. The
checkpoint is safetensors with a stable `DebertaV2ForSequenceClassification`
architecture, so a newer transformers would very likely load it. "Very likely"
is not good enough for a reproducibility claim, so the writer version is
pinned.

## What is *not* pinned upstream

The LLMShield repository's `requirements-frozen.txt` pins numpy, scipy and
anthropic (and a stale scikit-learn, see above) but does **not** pin `transformers`, `torch`,
`statsmodels` or `datasketch` -- Experiment 2 was run on rented GPU
infrastructure whose environment was not captured. Reconstructing a working
CPU inference stack for V3 is therefore part of this project rather than
something inherited, and this file is the record of what was chosen.

## Reproducibility without weights

The trained V0/V3 weights are not publishable. To keep the statistical claims
independently checkable anyway, every evaluation run writes a `scores.csv` of
per-item raw scores. Every downstream figure -- matched-FPR calibration,
ASR by threat type, confidence intervals, McNemar, DeLong, leave-one-source-out
-- recomputes from that file with no weights and no inference. Only the forward
pass is unreproducible; the statistics are not.
