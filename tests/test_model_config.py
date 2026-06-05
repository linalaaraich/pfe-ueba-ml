"""
tests/test_model_config.py
Verrouille les correctifs de faux positifs : les hyperparamètres de détection
sont lus depuis config.yaml, et avec ces valeurs le FP sur normal hors-échantillon
reste bas (OCSVM gamma réglé, contamination/nu abaissés). Garde-fou de régression.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from ueba.config import get_config
from ueba.features.simulate import simulate_dataset
from ueba.features.parse_logs import NUMERIC_FEATURES as F

DET = get_config().get("detection", {})


def test_config_has_tuned_detection_values():
    assert DET.get("contamination") == 0.01
    assert DET.get("ocsvm_nu") == 0.01
    assert DET.get("ocsvm_gamma") == 0.01


def _attacks(n, seed=3):
    rng = np.random.RandomState(seed)
    rows = []
    for _ in range(n):
        rows.append({
            "hour": 2, "is_night": 1, "is_weekend": 1,
            "nb_files_accessed": rng.randint(60, 300), "nb_sensitive_files": rng.randint(20, 90),
            "nb_failed_logins": rng.randint(0, 3), "nb_processes": rng.randint(20, 90),
            "bytes_sent": rng.randint(200000, 5000000), "new_ip": 1, "sensitive_path_access": 1,
            "z_score_files": rng.uniform(3, 6), "z_score_logins": rng.uniform(0, 5),
            "velocity": rng.uniform(5, 30), "entropy_commands": rng.uniform(3, 5),
        })
    return pd.DataFrame(rows)


def test_low_fp_and_high_detection_with_config_values():
    df = simulate_dataset(n_users=8, days=45, seed=42)
    X = df[F].values.astype(float)
    idx = np.arange(len(X)); np.random.RandomState(0).shuffle(idx)
    tr, te = idx[:int(.7 * len(X))], idx[int(.7 * len(X)):]
    sc = StandardScaler().fit(X[tr])
    Xtr, Xte = sc.transform(X[tr]), sc.transform(X[te])

    iso = IsolationForest(n_estimators=200, contamination=DET["contamination"],
                          random_state=42).fit(Xtr)
    oc = OneClassSVM(kernel="rbf", nu=DET["ocsvm_nu"], gamma=DET["ocsvm_gamma"]).fit(Xtr)

    fp_oc = (oc.predict(Xte) == -1).mean()
    ens_fp = (((iso.predict(Xte) == -1).astype(int) +
               (oc.predict(Xte) == -1).astype(int)) >= 2).mean()
    # OCSVM réglé : FP très inférieur aux ~20% de gamma='scale'
    assert fp_oc < 0.12, f"OCSVM FP trop élevé: {fp_oc:.1%}"
    assert ens_fp < 0.06, f"FP ensemble trop élevé: {ens_fp:.1%}"

    # la détection des attaques (disjointes) reste élevée
    Xa = sc.transform(_attacks(60)[F].values.astype(float))
    det = (((iso.predict(Xa) == -1).astype(int) +
            (oc.predict(Xa) == -1).astype(int)) >= 2).mean()
    assert det > 0.9, f"détection trop basse: {det:.1%}"
