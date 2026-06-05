"""
tests/test_otrf.py
Adaptateur OTRF/Mordor : extraction d'événements Windows/Sysmon « à plat » et
pipeline complet vers features UEBA.
"""

import json

from ueba.features.otrf import extract_otrf_event, parse_otrf_to_dataframe


TS = "2024-01-15T10:0{}:00.000Z"


def _events():
    return [
        {"@timestamp": TS.format(0), "EventID": 4624, "Channel": "Security",
         "TargetUserName": "user_normal", "IpAddress": "10.0.0.5"},
        {"@timestamp": TS.format(1), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
         "User": r"UEBA\user_normal"},
        {"@timestamp": TS.format(2), "EventID": 11, "TargetFilename": r"C:\Sensitive\Finance\q.xlsx",
         "Image": r"C:\Windows\explorer.exe", "User": r"UEBA\user_normal"},
        {"@timestamp": TS.format(3), "EventID": 4663, "ObjectName": r"C:\Sensitive\HR\pay.docx",
         "SubjectUserName": "user_normal", "ProcessName": r"C:\Windows\explorer.exe"},
        {"@timestamp": TS.format(4), "EventID": 4625, "TargetUserName": "user_normal",
         "IpAddress": "10.0.0.9"},
        {"@timestamp": TS.format(5), "EventID": 3, "Image": "chrome.exe",
         "DestinationIp": "8.8.8.8", "SourceIp": "10.0.0.5", "User": r"UEBA\user_normal"},
    ]


class TestExtractOtrfEvent:
    def test_sysmon_process_event(self):
        e = extract_otrf_event(_events()[1])
        assert e["event_id"] == "1"
        assert e["username"] == "user_normal"          # domaine retiré + minuscule
        assert e["process_name"].endswith("cmd.exe")
        assert e["command_line"] == "cmd /c whoami"

    def test_security_logon_event(self):
        e = extract_otrf_event(_events()[0])
        assert e["event_id"] == "4624"
        assert e["username"] == "user_normal"
        assert e["src_ip"] == "10.0.0.5"

    def test_file_access_paths(self):
        f11 = extract_otrf_event(_events()[2])
        f4663 = extract_otrf_event(_events()[3])
        assert f11["file_path"].endswith("q.xlsx")
        assert f4663["file_path"].endswith("pay.docx")

    def test_utctime_format_parsed(self):
        e = extract_otrf_event({"EventID": 1, "UtcTime": "2024-01-15 10:05:00.123",
                                "Image": "powershell.exe", "User": r"UEBA\user_normal"})
        assert e is not None and e["timestamp"].year == 2024

    def test_garbage_returns_none(self):
        assert extract_otrf_event({"EventID": 1}) is None        # pas de timestamp
        assert extract_otrf_event([]) is None                    # non-dict


class TestPipeline:
    def test_end_to_end_features(self, tmp_path):
        f = tmp_path / "otrf.json"
        f.write_text("\n".join(json.dumps(e) for e in _events()))   # NDJSON
        df = parse_otrf_to_dataframe(str(f))
        assert len(df) == 1                                          # 1 session (même user, <60min)
        row = df.iloc[0]
        assert row["username"] == "user_normal"
        assert row["nb_files_accessed"] == 2                        # EID 11 + 4663
        assert row["nb_sensitive_files"] == 2                       # 2 fichiers C:\Sensitive
        assert row["sensitive_path_access"] == 1
        assert row["nb_failed_logins"] == 1                         # EID 4625
        assert row["nb_processes"] == 1                             # EID 1

    def test_json_array_format(self, tmp_path):
        f = tmp_path / "otrf_array.json"
        f.write_text(json.dumps(_events()))                         # tableau JSON
        df = parse_otrf_to_dataframe(str(f))
        assert len(df) == 1
