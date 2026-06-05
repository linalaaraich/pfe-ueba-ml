"""
tests/test_features.py
Tests unitaires pour ueba.features.parse_logs
"""

import math
from datetime import datetime, timezone

import pandas as pd
import pytest

from ueba.features.parse_logs import (
    _entropy,
    add_zscores,
    build_features,
    extract_raw_fields,
    group_by_session,
    _new_session,
    _update_session,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    ts: str = "2024-01-15T10:00:00+00:00",
    event_id: str = "4624",
    username: str = "user_normal",
    file_path: str = "",
    process_name: str = "chrome.exe",
    command_line: str = "",
    src_ip: str = "192.168.1.10",
) -> dict:
    return {
        "timestamp": ts,
        "data": {
            "win": {
                "system": {"eventID": event_id},
                "eventdata": {
                    "targetUserName":   username,
                    "targetFilename":   file_path,
                    "image":            process_name,
                    "commandLine":      command_line,
                    "ipAddress":        src_ip,
                },
            }
        },
        "rule":  {"id": "60106", "description": "Windows login"},
        "agent": {"name": "DC01"},
    }


# ---------------------------------------------------------------------------
# Tests extract_raw_fields
# ---------------------------------------------------------------------------

class TestExtractRawFields:
    def test_valid_alert_returns_dict(self):
        alert = _make_alert()
        result = extract_raw_fields(alert)
        assert result is not None
        assert result["username"] == "user_normal"
        assert result["event_id"] == "4624"

    def test_missing_timestamp_returns_none(self):
        assert extract_raw_fields({}) is None

    def test_invalid_timestamp_returns_none(self):
        assert extract_raw_fields({"timestamp": "not-a-date"}) is None

    def test_username_lowercased(self):
        alert = _make_alert(username="ADMINISTRATOR")
        result = extract_raw_fields(alert)
        assert result["username"] == "administrator"

    def test_non_dict_data_process_does_not_crash(self):
        # `data.process` non-dict (alerte hostile/malformée) ne doit PAS lever
        # AttributeError (sinon crash de la boucle du daemon = DoS).
        alert = {"timestamp": "2024-01-15T10:00:00+00:00", "data": {"process": "evil"}}
        result = extract_raw_fields(alert)
        assert result is not None
        assert result["process_name"] == ""


# ---------------------------------------------------------------------------
# Tests group_by_session
# ---------------------------------------------------------------------------

class TestGroupBySession:
    def _raw(self, ts: str, user: str = "u1", eid: str = "4624") -> dict:
        return {
            "timestamp":    datetime.fromisoformat(ts),
            "username":     user,
            "event_id":     eid,
            "src_ip":       "192.168.1.1",
            "file_path":    "",
            "process_name": "",
            "command_line": "",
            "bytes_sent":   0,
        }

    def test_single_user_single_session(self):
        events = [
            self._raw("2024-01-15T10:00:00+00:00"),
            self._raw("2024-01-15T10:30:00+00:00"),
        ]
        sessions = group_by_session(events, session_minutes=60)
        assert len(sessions) == 1

    def test_gap_creates_new_session(self):
        events = [
            self._raw("2024-01-15T10:00:00+00:00"),
            self._raw("2024-01-15T12:01:00+00:00"),  # >60 min gap
        ]
        sessions = group_by_session(events, session_minutes=60)
        assert len(sessions) == 2

    def test_two_users_two_sessions(self):
        events = [
            self._raw("2024-01-15T10:00:00+00:00", user="alice"),
            self._raw("2024-01-15T10:05:00+00:00", user="bob"),
        ]
        sessions = group_by_session(events)
        assert len(sessions) == 2
        usernames = {s["username"] for s in sessions}
        assert usernames == {"alice", "bob"}


# ---------------------------------------------------------------------------
# Tests build_features
# ---------------------------------------------------------------------------

class TestBuildFeatures:
    def _session(self, hour: int = 10, weekday_offset: int = 0) -> dict:
        base = datetime(2024, 1, 15 + weekday_offset, hour, 0, tzinfo=timezone.utc)
        s = _new_session("user_normal", base)
        s["last_ts"] = base.replace(minute=30)
        s["file_paths"] = ["C:\\Users\\doc.txt"] * 5
        s["process_names"] = ["chrome.exe"]
        s["command_lines"] = ["chrome.exe --no-sandbox"]
        return s

    def test_work_hours_not_night(self):
        f = build_features(self._session(hour=10))
        assert f["is_night"] == 0

    def test_off_hours_is_night(self):
        f = build_features(self._session(hour=2))
        assert f["is_night"] == 1

    def test_velocity_positive(self):
        f = build_features(self._session())
        assert f["velocity"] > 0

    def test_sensitive_path_detected(self):
        s = self._session()
        s["file_paths"] = [r"C:\Sensitive\secret.docx"]
        f = build_features(s)
        assert f["nb_sensitive_files"] == 1
        assert f["sensitive_path_access"] == 1

    def test_entropy_zero_for_single_command(self):
        s = self._session()
        s["command_lines"] = ["cmd.exe"]
        f = build_features(s)
        assert f["entropy_commands"] == 0.0


# ---------------------------------------------------------------------------
# Tests _entropy
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_empty_list(self):
        assert _entropy([]) == 0.0

    def test_single_element(self):
        assert _entropy(["a"]) == 0.0

    def test_uniform_distribution_max_entropy(self):
        vals = ["a", "b", "c", "d"]
        e = _entropy(vals)
        assert abs(e - 2.0) < 1e-6  # log2(4) = 2

    def test_skewed_lower_entropy(self):
        skewed  = ["a"] * 9 + ["b"]
        uniform = ["a"] * 5 + ["b"] * 5
        assert _entropy(skewed) < _entropy(uniform)


# ---------------------------------------------------------------------------
# Tests add_zscores
# ---------------------------------------------------------------------------

class TestAddZscores:
    def _df(self) -> pd.DataFrame:
        return pd.DataFrame({
            "username":          ["u1"] * 5,
            "nb_files_accessed": [10, 12, 8, 11, 100],
            "nb_failed_logins":  [0, 0, 1, 0, 0],
        })

    def test_columns_created(self):
        df = add_zscores(self._df())
        assert "z_score_files"  in df.columns
        assert "z_score_logins" in df.columns

    def test_outlier_has_high_zscore(self):
        df = add_zscores(self._df())
        z = df["z_score_files"]
        # L'outlier (100) doit être l'écart le plus fort du groupe.
        # NB : avec un z-score d'échantillon (ddof=1) sur n=5, l'outlier gonfle
        # lui-même σ, donc z plafonne ~1.79 — d'où un seuil réaliste (> 1.5),
        # pas > 2.0 (l'ancienne assertion était mathématiquement fausse et le
        # test était rouge). Le vrai enjeu — baseline figée vs fenêtre glissante
        # — est traité dans audit/MASTER_PLAN.md (RC-1).
        assert z.idxmax() == z.index[-1]
        assert z.iloc[-1] > 1.5
        assert z.iloc[-1] > z.iloc[:-1].abs().max()

    def test_single_row_zscore_zero(self):
        df = pd.DataFrame({
            "username": ["u1"],
            "nb_files_accessed": [10],
            "nb_failed_logins": [0],
        })
        df = add_zscores(df)
        assert df["z_score_files"].iloc[0] == 0.0
