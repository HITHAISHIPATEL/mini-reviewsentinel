import unittest

from app.analyzer import analyze_source


class AnalyzerTests(unittest.TestCase):
    def test_real_sql_injection(self):
        source = 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)\n'
        findings, errors = analyze_source(source, "payments.py")
        sql = [f for f in findings if "SQL injection" in f.finding]
        self.assertEqual(errors, [])
        self.assertEqual(len(sql), 1)
        self.assertEqual(sql[0].line, 2)
        self.assertEqual(sql[0].severity.value, "HIGH")

    def test_parameterized_sql_is_safe(self):
        source = 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))\n'
        findings, _ = analyze_source(source, "safe.py")
        self.assertFalse(any("SQL injection" in f.finding for f in findings))

    def test_hard_coded_secret(self):
        findings, _ = analyze_source('api_key = "sk_live_A8f92LmPq7xZ"\n', "settings.py")
        self.assertTrue(any("secret" in f.finding.lower() for f in findings))

    def test_placeholder_and_environment_secret_not_reported(self):
        source = 'api_key = "your_api_key_here"\npassword = os.getenv("APP_PASSWORD")\n'
        findings, _ = analyze_source(source, "settings.py")
        self.assertFalse(any("secret" in f.finding.lower() for f in findings))

    def test_eval_and_exec(self):
        findings, _ = analyze_source('result = eval(user_input)\nexec(payload)\n', "dynamic.py")
        self.assertEqual([f.line for f in findings], [1, 2])
        self.assertTrue(all(f.severity.value == "HIGH" for f in findings))

    def test_multiline_formatted_query(self):
        source = 'query = (\n    f"SELECT * FROM accounts WHERE name = {name}"\n)\ncursor.execute(query)\n'
        findings, _ = analyze_source(source, "multiline.py")
        self.assertTrue(any("SQL injection" in f.finding for f in findings))

    def test_parse_failure_is_reported(self):
        findings, errors = analyze_source("def broken(:\n", "broken.py")
        self.assertEqual(findings, [])
        self.assertEqual(errors[0]["file"], "broken.py")


if __name__ == "__main__":
    unittest.main()
