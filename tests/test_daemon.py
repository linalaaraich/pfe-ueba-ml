"""
tests/test_daemon.py
Tests du daemon : contrat d'ordre des features, robustesse du vote (dégradation
surfacée, pas de crash), et induction réelle sur AlertsWatcher (lignes
partielles, reprise après redémarrage, rotation, lignes malformées).
"""

import json
import types

import numpy as np

from ueba.features.parse_logs import NUMERIC_FEATURES as FEATURES_SRC
import ueba.integration.daemon as dmn
from ueba.integration.daemon import AlertsWatcher, predict


# ---------------------------------------------------------------------------
# Contrat train/serve : une seule source de vérité pour l'ordre des features
# ---------------------------------------------------------------------------

class TestFeatureOrderContract:
    def test_daemon_uses_the_shared_constant(self):
        # Le daemon doit importer EXACTEMENT la liste de parse_logs (même objet
        # logique, même ordre) — sinon scaler/modèles positionnels corrompus.
        assert dmn.NUMERIC_FEATURES == FEATURES_SRC

    def test_feature_count_is_14(self):
        assert len(FEATURES_SRC) == 14
        assert len(FEATURES_SRC) == len(set(FEATURES_SRC))  # pas de doublon

    def test_expected_order(self):
        assert FEATURES_SRC[0] == "hour"
        assert FEATURES_SRC[-1] == "entropy_commands"
        assert "z_score_files" in FEATURES_SRC and "z_score_logins" in FEATURES_SRC


# ---------------------------------------------------------------------------
# Robustesse du vote d'ensemble
# ---------------------------------------------------------------------------

class _Model:
    def __init__(self, pred): self._p = pred
    def predict(self, X): return np.array([self._p])
    def decision_function(self, X): return np.array([0.5])


class _Boom:
    def predict(self, X): raise RuntimeError("boom")
    def decision_function(self, X): raise RuntimeError("boom")


class _AE:
    def __init__(self, recon): self._r = recon
    def predict(self, X, verbose=0): return np.array([self._r])


def _models(**kw):
    base = dict(iso_forest=None, ocsvm=None, autoencoder=None, ae_threshold=1.0)
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestPredictRobustness:
    def test_degraded_is_surfaced_not_masked(self):
        # IF vote anomalie, OCSVM plante → vote dégradé explicite, pas de crash,
        # confidence basée sur les modèles AYANT voté (1), pas sur 2.
        m = _models(iso_forest=_Model(-1), ocsvm=_Boom())
        r = predict(m, np.zeros(14, dtype=np.float32), threshold_votes=2)
        assert r["expected_models"] == 2
        assert r["evaluated_models"] == 1
        assert r["degraded"] is True
        assert r["votes"] == 1
        assert r["confidence"] == 1.0          # 1 vote / 1 modèle évalué
        assert r["is_anomaly"] is False        # 1 < seuil 2

    def test_a_failing_model_does_not_raise(self):
        m = _models(iso_forest=_Boom(), ocsvm=_Boom())
        r = predict(m, np.zeros(14, dtype=np.float32))  # ne doit pas lever
        assert r["evaluated_models"] == 0
        assert r["is_anomaly"] is False

    def test_full_consensus(self):
        m = _models(iso_forest=_Model(-1), ocsvm=_Model(-1), autoencoder=_AE([5.0]))
        r = predict(m, np.zeros(1, dtype=np.float32), threshold_votes=2)
        assert r["degraded"] is False
        assert r["votes"] == 3
        assert r["is_anomaly"] is True
        assert r["confidence"] == 1.0


# ---------------------------------------------------------------------------
# Induction réelle sur AlertsWatcher (fichier temporaire)
# ---------------------------------------------------------------------------

class TestAlertsWatcher:
    def test_first_run_skips_existing_history(self, tmp_path):
        f = tmp_path / "alerts.json"
        f.write_text('{"a":1}\n{"a":2}\n')
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        assert w.read_new() == []                      # historique non rejoué
        with open(f, "a") as fh:
            fh.write('{"a":3}\n')
        assert w.read_new() == [{"a": 3}]
        w.close()

    def test_partial_line_is_held_then_completed(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text("")
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        with open(f, "a") as fh:
            fh.write('{"x":1}\n{"x":2')                 # 2e ligne incomplète
        assert w.read_new() == [{"x": 1}]              # la partielle est retenue
        with open(f, "a") as fh:
            fh.write('}\n')                            # on la complète
        assert w.read_new() == [{"x": 2}]              # plus aucune perte (#8)
        w.close()

    def test_restart_resumes_no_blind_window(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text("")
        sp = str(tmp_path / "s.json")
        w = AlertsWatcher(str(f), state_path=sp); w.open()
        with open(f, "a") as fh:
            fh.write('{"n":1}\n')
        assert w.read_new() == [{"n": 1}]
        w.close()
        # alerte arrivée PENDANT l'arrêt du daemon
        with open(f, "a") as fh:
            fh.write('{"n":2}\n')
        w2 = AlertsWatcher(str(f), state_path=sp); w2.open()
        assert w2.read_new() == [{"n": 2}]             # reprise, pas de saut (#7)
        w2.close()

    def test_rotation_reads_new_file_from_start(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text('{"old":1}\n')
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        assert w.read_new() == []
        f.unlink(); f.write_text('{"new":1}\n')        # rotation → nouvel inode
        assert w.read_new() == [{"new": 1}]
        w.close()

    def test_malformed_line_skipped_not_fatal(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text("")
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        with open(f, "a") as fh:
            fh.write('not-json\n{"ok":1}\n')
        assert w.read_new() == [{"ok": 1}]
        w.close()

    def test_copytruncate_no_blind_window(self, tmp_path):
        # logrotate copytruncate : même inode, fichier tronqué À 0 puis ré-alimenté.
        f = tmp_path / "a.json"; f.write_text("")
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        with open(f, "a") as fh:
            fh.write('{"n":1}\n')
        assert w.read_new() == [{"n": 1}]
        open(f, "w").close()                   # truncate à 0 (taille < _pos)
        assert w.read_new() == []              # rien encore, mais _pos remis à 0
        with open(f, "a") as fh:
            fh.write('{"n":2}\n')              # nouvelle alerte après rotation
        assert w.read_new() == [{"n": 2}]      # lue, pas de fenêtre aveugle
        w.close()


class TestUEBAModelsDegradation:
    def _min_models(self, d):
        import joblib
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import IsolationForest
        X = np.random.RandomState(0).rand(30, len(dmn.NUMERIC_FEATURES))
        joblib.dump(StandardScaler().fit(X), f"{d}/scaler.pkl")
        joblib.dump(IsolationForest(random_state=0).fit(X), f"{d}/isolation_forest.pkl")

    def test_corrupt_ae_threshold_does_not_crash(self, tmp_path):
        import logging
        self._min_models(str(tmp_path))
        (tmp_path / "ae_threshold.json").write_text("{ this is not json")
        m = dmn.UEBAModels(str(tmp_path), logging.getLogger("t"))  # ne doit pas lever
        assert m.is_ready() is True
        assert m.ae_threshold == 0.05          # repli par défaut
        assert m.autoencoder is None

    def test_missing_baseline_is_safe(self, tmp_path):
        import logging
        self._min_models(str(tmp_path))
        m = dmn.UEBAModels(str(tmp_path), logging.getLogger("t"))
        assert m.baseline is None              # absent → repli fenêtre glissante
        assert m.is_ready() is True
