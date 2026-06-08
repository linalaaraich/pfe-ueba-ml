"""
tests/test_reaudit2.py
Régressions trouvées au 2e tour d'audit (audit/reaudit-*.md) :
- perte silencieuse d'alertes sur copytruncate-puis-regrossi / réécriture pendant arrêt ;
- calibrate_ae_threshold qui renvoyait NaN (AE muet) ;
- to_scaled_vector qui laissait passer NaN (vote dégradé silencieux).
"""

import json

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from ueba.integration.daemon import AlertsWatcher, NUMERIC_FEATURES, to_scaled_vector
from ueba.features.baseline import calibrate_ae_threshold


def _write(path, objs, mode="a"):
    with open(path, mode) as fh:
        for o in objs:
            fh.write(json.dumps(o) + "\n")


class TestWatcherRotationDataLoss:
    def test_copytruncate_regrow_past_offset_no_loss(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text("")
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json"))
        w.open()
        _write(f, [{"seed": i} for i in range(20)])      # pos avance bien > 64 octets
        assert len(w.read_new()) == 20
        # copytruncate : tronqué à 0 PUIS regrossi AU-DELÀ de l'ancien offset
        open(f, "w").close()
        _write(f, [{"AA": 11}, {"BB": 22}] + [{"pad": i} for i in range(40)])
        got = w.read_new()
        assert {"AA": 11} in got and {"BB": 22} in got    # rien perdu
        w.close()

    def test_restart_rewritten_during_downtime_no_loss(self, tmp_path):
        f = tmp_path / "a.json"; f.write_text("")
        sp = str(tmp_path / "s.json")
        w = AlertsWatcher(str(f), state_path=sp); w.open()
        _write(f, [{"old": i} for i in range(20)])
        assert len(w.read_new()) == 20
        w.close()
        # réécrit (plus court) pendant l'arrêt du daemon
        f.write_text(json.dumps({"new": 1}) + "\n")
        w2 = AlertsWatcher(str(f), state_path=sp); w2.open()
        assert w2.read_new() == [{"new": 1}]              # nouveau contenu lu
        w2.close()

    def test_normal_growth_not_treated_as_rotation(self, tmp_path):
        # garde-fou anti-régression : une simple extension ne doit PAS relire
        f = tmp_path / "a.json"; f.write_text("")
        w = AlertsWatcher(str(f), state_path=str(tmp_path / "s.json")); w.open()
        _write(f, [{"x": i} for i in range(20)])
        assert len(w.read_new()) == 20
        _write(f, [{"y": 1}])
        assert w.read_new() == [{"y": 1}]                 # pas de double-lecture
        w.close()


class TestCalibrateNonFinite:
    def test_nan_and_inf_ignored(self):
        v = [0.1] * 50 + [np.nan, np.inf, -np.inf]
        t = calibrate_ae_threshold(v, 99.0)
        assert np.isfinite(t)

    def test_all_nonfinite_falls_back(self):
        t = calibrate_ae_threshold([np.nan, np.inf], 99.0,
                                   fallback_mean=0.2, fallback_std=0.05)
        assert abs(t - 0.35) < 1e-9


class TestToScaledVectorNaNSafe:
    def test_nan_feature_yields_finite_vector(self):
        X = np.random.RandomState(0).rand(30, len(NUMERIC_FEATURES))
        scaler = StandardScaler().fit(X)
        feats = {f: 1.0 for f in NUMERIC_FEATURES}
        feats["velocity"] = float("nan")
        out = to_scaled_vector(feats, scaler, pd.DataFrame(),
                               baseline={"per_user": {}, "global": {}})
        assert np.all(np.isfinite(out))
