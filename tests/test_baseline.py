"""
tests/test_baseline.py
Prouve que la baseline FIGÉE corrige RC-1 : un z-score de session devient
INVARIANT à la composition du lot (contrairement à l'ancien recalcul glissant),
gère l'utilisateur inconnu (repli global) et ne divise jamais par zéro.
Plus : feature_health repère les features mortes (ex. bytes_sent).
"""

import pandas as pd

from ueba.features.baseline import (
    apply_baseline_zscores,
    compute_baseline,
    feature_health,
    load_baseline,
    save_baseline,
)
from ueba.features.parse_logs import add_zscores


def _train():
    return pd.DataFrame({
        "username":          ["u"] * 5,
        "nb_files_accessed": [10, 12, 8, 11, 9],
        "nb_failed_logins":  [0, 0, 1, 0, 0],
    })


def _session(n_files=50):
    return pd.DataFrame({"username": ["u"], "nb_files_accessed": [n_files], "nb_failed_logins": [0]})


def _attack_batch():
    return pd.concat([
        _session(50),
        pd.DataFrame({"username": ["u", "u"], "nb_files_accessed": [300, 250], "nb_failed_logins": [0, 0]}),
    ], ignore_index=True)


class TestFrozenBaselineFixesRC1:
    def test_zscore_invariant_to_batch_composition(self):
        bl = compute_baseline(_train())
        z_alone = apply_baseline_zscores(_session(50), bl)["z_score_files"].iloc[0]
        z_in_batch = apply_baseline_zscores(_attack_batch(), bl)["z_score_files"].iloc[0]
        assert z_alone == z_in_batch          # FIGÉ : le reste du lot n'influe plus

    def test_old_recompute_was_not_invariant(self):
        # Démontre le bug RC-1 que la baseline corrige (l'ancien add_zscores
        # dépend de la population présente dans le DataFrame).
        z_alone = add_zscores(_session(50))["z_score_files"].iloc[0]       # 1 ligne -> 0.0
        z_in_batch = add_zscores(_attack_batch())["z_score_files"].iloc[0]
        assert z_alone != z_in_batch

    def test_unseen_user_falls_back_to_global(self):
        bl = compute_baseline(_train())
        s = pd.DataFrame({"username": ["NEW_USER"], "nb_files_accessed": [10], "nb_failed_logins": [0]})
        z = apply_baseline_zscores(s, bl)["z_score_files"].iloc[0]
        assert isinstance(z, float)           # pas d'erreur, repli global

    def test_std_zero_never_divides(self):
        df = pd.DataFrame({"username": ["u", "u"], "nb_files_accessed": [10, 10], "nb_failed_logins": [0, 0]})
        bl = compute_baseline(df)
        assert (apply_baseline_zscores(df, bl)["z_score_files"] == 0.0).all()

    def test_save_load_roundtrip(self, tmp_path):
        bl = compute_baseline(_train())
        p = tmp_path / "baseline.json"
        save_baseline(bl, p)
        assert load_baseline(p) == bl
        assert load_baseline(tmp_path / "absent.json") is None


class TestFeatureHealth:
    def test_flags_dead_and_present(self):
        df = pd.DataFrame({"bytes_sent": [0, 0, 0, 0], "nb_files_accessed": [1, 5, 9, 3]})
        rep = feature_health(df, ["bytes_sent", "nb_files_accessed", "missing"])
        assert rep["bytes_sent"]["dead"] is True
        assert rep["nb_files_accessed"]["dead"] is False
        assert rep["missing"]["present"] is False
