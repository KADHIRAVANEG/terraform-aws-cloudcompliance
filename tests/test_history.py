import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudcompliance.history import get_db, save_score, export_history, show_history


class TestHistory(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_history.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_db_creates_table_with_framework(self):
        conn = get_db(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(compliance_history);")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        self.assertIn("framework", columns)
        self.assertIn("score", columns)
        self.assertIn("report_json", columns)

    def test_save_and_export_score_framework_isolation(self):
        soc2_data = {
            "compliance_score": 100,
            "total_resources": 15,
            "framework": "soc2",
            "controls": {
                "CC6.1": {"status": "PASS"},
                "CC6.2": {"status": "PASS"},
            }
        }
        hipaa_data = {
            "compliance_score": 85,
            "total_resources": 15,
            "framework": "hipaa",
            "controls": {
                "164.312(a)(1)": {"status": "PASS"},
            }
        }
        soc2_path = Path(self.temp_dir.name) / "soc2_report.json"
        hipaa_path = Path(self.temp_dir.name) / "hipaa_report.json"
        with open(soc2_path, "w") as f:
            json.dump(soc2_data, f)
        with open(hipaa_path, "w") as f:
            json.dump(hipaa_data, f)

        save_score(soc2_path, db_path=self.db_path, framework="soc2")
        save_score(hipaa_path, db_path=self.db_path, framework="hipaa")

        # Export all
        all_export_path = Path(self.temp_dir.name) / "export_all.json"
        exported_all = export_history(output_path=all_export_path, db_path=self.db_path)
        self.assertEqual(exported_all["entry_count"], 2)

        # Export only HIPAA
        hipaa_export_path = Path(self.temp_dir.name) / "export_hipaa.json"
        exported_hipaa = export_history(output_path=hipaa_export_path, db_path=self.db_path, framework="hipaa")
        self.assertEqual(exported_hipaa["entry_count"], 1)
        self.assertEqual(exported_hipaa["entries"][0]["framework"], "hipaa")
        self.assertEqual(exported_hipaa["entries"][0]["score"], 85)

        # Export only SOC2
        soc2_export_path = Path(self.temp_dir.name) / "export_soc2.json"
        exported_soc2 = export_history(output_path=soc2_export_path, db_path=self.db_path, framework="soc2")
        self.assertEqual(exported_soc2["entry_count"], 1)
        self.assertEqual(exported_soc2["entries"][0]["framework"], "soc2")
        self.assertEqual(exported_soc2["entries"][0]["score"], 100)

    def test_legacy_database_migration(self):
        # Create legacy table without framework column
        legacy_db = Path(self.temp_dir.name) / "legacy.db"
        conn = sqlite3.connect(str(legacy_db))
        conn.execute("""
            CREATE TABLE compliance_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                controls_passing INTEGER NOT NULL,
                controls_total INTEGER NOT NULL,
                resources_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT INTO compliance_history (timestamp, score, controls_passing, controls_total, resources_count, report_json)
            VALUES ('2026-01-01T00:00:00', 95, 9, 10, 20, '{}')
        """)
        conn.commit()
        conn.close()

        # Opening with get_db should automatically migrate
        migrated_conn = get_db(legacy_db)
        cursor = migrated_conn.cursor()
        cursor.execute("PRAGMA table_info(compliance_history);")
        columns = [row[1] for row in cursor.fetchall()]
        self.assertIn("framework", columns)

        row = cursor.execute("SELECT framework, score FROM compliance_history").fetchone()
        migrated_conn.close()
        self.assertEqual(row[0], "soc2")  # default migration value
        self.assertEqual(row[1], 95)


if __name__ == "__main__":
    unittest.main()
