"""
tests/test_simulate.py
Le générateur multi-profils doit produire un normal SAIN : volume suffisant,
plusieurs utilisateurs, et AUCUNE feature constante (le défaut clé de l'ancien
synthétique, cf. audit RC-2 / DATASET_HEALTH.md).
"""

from ueba.features.simulate import simulate_dataset
from ueba.features.health import audit_dataframe
from ueba.features.parse_logs import NUMERIC_FEATURES


def test_volume_and_multi_profile():
    df = simulate_dataset(n_users=8, days=30, seed=1)
    assert len(df) > 200
    assert df["username"].nunique() == 8
    assert (df["label"] == 0).all()


def test_no_constant_features():
    df = simulate_dataset(n_users=8, days=30, seed=1)
    rep = audit_dataframe(df, NUMERIC_FEATURES)
    # Les 4 features jadis constantes doivent désormais varier
    for f in ("is_night", "is_weekend", "new_ip", "sensitive_path_access"):
        assert f not in rep["constant_features"], f"{f} est encore constante"
    assert rep["constant_features"] == [], rep["constant_features"]
    assert rep["dead_features"] == []


def test_realistic_rates_present():
    df = simulate_dataset(n_users=8, days=30, seed=1)
    # un peu de nuit / week-end / accès sensible / nouvelle IP, mais minoritaires
    assert 0.0 < df["is_night"].mean() < 0.3
    assert 0.0 < df["is_weekend"].mean() < 0.3
    assert 0.0 < df["sensitive_path_access"].mean() < 0.6
    assert 0.0 < df["new_ip"].mean() < 0.3


def test_is_night_derived_from_hour():
    # is_night doit être STRICTEMENT dérivé de l'heure (règle canonique de
    # parse_logs : hour<9 ou hour>=18) — sinon skew train/serve (re-audit P1).
    df = simulate_dataset(n_users=8, days=30, seed=1)
    expected = ((df["hour"] < 9) | (df["hour"] >= 18)).astype(int)
    assert (df["is_night"] == expected).all()


def test_reproducible_with_seed():
    a = simulate_dataset(n_users=4, days=10, seed=7)
    b = simulate_dataset(n_users=4, days=10, seed=7)
    assert a.equals(b)
