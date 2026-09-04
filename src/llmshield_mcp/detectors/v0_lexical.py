"""V0 adapter: reused LLMShield TF-IDF + logistic regression classifier.

The artifact is a joblib dict of {"vectorizer", "classifier", "classes"}
written by evaluation/experiment2/exp2_train.py:65 under scikit-learn 1.9.0,
which pyproject.toml pins exactly.

sklearn unpickling is version-sensitive, and a mismatch surfaces only as a
warning that is trivial to miss in a long evaluation log -- while silently
invalidating every score the detector produces. This adapter therefore
promotes that warning to a hard load failure, which makes the version pin
self-enforcing rather than a comment someone has to remember.

V0 has no token limit: the TF-IDF FeatureUnion vectorises arbitrary-length
input. It is therefore the only reused detector that natively sees a whole
tool result, which makes it the natural control for the V3 truncation
experiment.
"""

from __future__ import annotations

import warnings
from typing import Any, ClassVar

import joblib
from sklearn.exceptions import InconsistentVersionWarning

from llmshield_mcp.config import DETECTOR_CLASSES, V0Config, scalar_from_proba
from llmshield_mcp.detectors.base import Detector, RawScore


class V0LexicalDetector(Detector):
    name: ClassVar[str] = "v0"

    def __init__(self, config: V0Config) -> None:
        self._config = config

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", InconsistentVersionWarning)
            bundle: dict[str, Any] = joblib.load(config.path)

        mismatches = [w for w in caught if issubclass(w.category, InconsistentVersionWarning)]
        if mismatches:
            found = sorted(
                {str(w.message).split("from version ")[-1].split()[0] for w in mismatches}
            )
            raise ValueError(
                f"{config.path} was serialised by scikit-learn {', '.join(found)}, "
                f"but this environment has a different version installed. Scores would be "
                f"unreliable. Pin scikit-learn to match the artifact (see docs/PINNING.md)."
            )

        classes = list(bundle["classes"])
        if tuple(classes) != DETECTOR_CLASSES:
            raise ValueError(
                f"artifact class order {classes} does not match expected "
                f"{list(DETECTOR_CLASSES)}; scores would be silently mislabelled"
            )

        self._vectorizer = bundle["vectorizer"]
        self._classifier = bundle["classifier"]

        # predict_proba columns follow classifier.classes_, not the saved
        # `classes` list. They coincide here (integer labels 0..3), but map
        # explicitly rather than relying on that.
        self._column_of = {int(label): i for i, label in enumerate(self._classifier.classes_)}
        missing = set(range(len(DETECTOR_CLASSES))) - set(self._column_of)
        if missing:
            raise ValueError(f"classifier is missing probability columns for labels {missing}")

    def _score(self, text: str) -> RawScore:
        features = self._vectorizer.transform([text])
        row = self._classifier.predict_proba(features)[0]
        proba = [float(row[self._column_of[i]]) for i in range(len(DETECTOR_CLASSES))]

        return RawScore(
            score=scalar_from_proba(proba, self._config.score_mode),
            detail={name: proba[i] for i, name in enumerate(DETECTOR_CLASSES)},
            truncated=False,
        )
