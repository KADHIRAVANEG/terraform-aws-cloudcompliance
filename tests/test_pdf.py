import os
import tempfile
import unittest
from pathlib import Path

from cloudcompliance.pdf_report import compute_evidence_fingerprint, generate_pdf_report
from cloudcompliance.report import evaluate_controls, load_controls


class TestPDFReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.controls = load_controls("soc2")
        self.resources = [
            {"type": "aws_vpc", "name": "main_vpc"},
            {"type": "aws_kms_key", "name": "main_key"},
            {"type": "aws_s3_bucket", "name": "data_bucket"},
        ]
        self.results = evaluate_controls(self.resources, self.controls, provider="aws")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compute_evidence_fingerprint(self):
        fp1 = compute_evidence_fingerprint(self.results, self.resources)
        fp2 = compute_evidence_fingerprint(self.results, self.resources)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)  # SHA-256 length

    def test_generate_pdf_report(self):
        pdf_path = Path(self.temp_dir.name) / "test_report.pdf"
        generated = generate_pdf_report(
            results=self.results,
            resources=self.resources,
            score=70,
            pass_count=7,
            framework="soc2",
            output_path=pdf_path,
        )
        self.assertTrue(generated.exists())
        self.assertGreater(generated.stat().st_size, 1000)

        with open(generated, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")


if __name__ == "__main__":
    unittest.main()
