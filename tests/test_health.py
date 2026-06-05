"""tests/test_health.py — diagnostic de santé dataset."""

import pandas as pd

from ueba.features.health import audit_dataframe, verdict


def test_detects_constant_and_dead_features():
    df = pd.DataFrame({
        "hour": [9, 10, 11, 12, 13],
        "is_night": [0, 0, 0, 0, 0],          # constante
        "nb_files_accessed": [1, 5, 9, 3, 7],
    })
    rep = audit_dataframe(df, ["hour", "is_night", "nb_files_accessed"])
    assert "is_night" in rep["constant_features"]
    assert "is_night" in rep["dead_features"]
    assert "hour" not in rep["constant_features"]


def test_low_volume_and_constant_warnings():
    df = pd.DataFrame({"hour": [9, 10], "is_night": [0, 0]})
    w = " ".join(verdict(audit_dataframe(df, ["hour", "is_night"])))
    assert "VOLUME FAIBLE" in w
    assert "CONSTANTE" in w or "MORTES" in w


def test_separability_reported_with_labels():
    df = pd.DataFrame({
        "nb_files_accessed": [5, 6, 7, 5, 300, 280, 310, 290],
        "label":            [0, 0, 0, 0, 1, 1, 1, 1],
    })
    rep = audit_dataframe(df, ["nb_files_accessed"], label_col="label")
    assert rep["label_counts"] == {"0": 4, "1": 4}
    assert rep["separability_top"][0]["feature"] == "nb_files_accessed"
