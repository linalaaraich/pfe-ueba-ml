"""tests/test_config.py — chargement config robuste (ne lève jamais)."""

from ueba.config import load_config


def test_empty_file_returns_defaults(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")                       # yaml.safe_load → None
    cfg = load_config(p)
    assert isinstance(cfg, dict)
    assert cfg["wazuh"]["alerts_path"]      # defaults présents, pas de crash


def test_comments_only_returns_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("# que des commentaires\n")
    assert load_config(p)["detection"]["ensemble_threshold"] == 2


def test_missing_file_returns_defaults(tmp_path):
    assert load_config(tmp_path / "nope.yaml")["daemon"]["poll_seconds"] == 30


def test_returns_independent_copy(tmp_path):
    # muter une config retournée NE DOIT PAS corrompre les défauts globaux
    a = load_config(tmp_path / "nope.yaml")
    a["wazuh"]["alerts_path"] = "/tmp/HACKED"
    b = load_config(tmp_path / "nope.yaml")
    assert b["wazuh"]["alerts_path"] != "/tmp/HACKED"
