import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from app.cli import main


class CLITests(unittest.TestCase):
    def test_missing_path_uses_input_error_exit_code(self):
        output = StringIO()
        with redirect_stdout(output):
            status = main([
                "/definitely/not/a/real/reviewsentinel/path",
                "--json",
                "--static-only",
            ])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 3)
        self.assertTrue(report["analysis_errors"])

    def test_json_report_is_valid(self):
        sample = Path(__file__).resolve().parents[1] / "examples" / "vulnerable.py"
        output = StringIO()
        with redirect_stdout(output):
            status = main([str(sample), "--json", "--static-only"])

        report = json.loads(output.getvalue())
        self.assertEqual(report["decision"], "REJECTED")
        self.assertEqual(status, 2)
        self.assertTrue(report["findings"])
        self.assertTrue(any(
            finding["finding"] == "Potential SQL injection"
            for finding in report["findings"]
        ))
        self.assertTrue(all(
            finding["decision"] == "REJECTED"
            for finding in report["findings"]
        ))


if __name__ == "__main__":
    unittest.main()