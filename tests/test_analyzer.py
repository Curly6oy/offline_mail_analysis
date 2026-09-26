import unittest
from analyzer.email_analyzer import analyze_eml

SAMPLE = b"""From: Ivan Petrov <ivan@example.com>
To: office@example.org
Subject: Test
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Ivan Petrov
Phone: +7 999 123-45-67
Passport: 1234 567890
Visit https://example.com/test
"""

class AnalyzerTests(unittest.TestCase):
    def test_pii_categories_are_detected(self):
        result = analyze_eml(SAMPLE)
        kinds = {x["type"] for x in result["pii"]}
        self.assertIn("Email", kinds)
        self.assertIn("Телефон", kinds)
        self.assertIn("Паспорт РФ", kinds)
        self.assertTrue(result["privacy"]["offline"])

    def test_raw_pii_is_not_returned(self):
        result = analyze_eml(SAMPLE)
        serialized = repr(result)
        self.assertNotIn("999 123-45-67", serialized)
        self.assertNotIn("1234 567890", serialized)

    def test_url_is_parsed_without_network_access(self):
        result = analyze_eml(SAMPLE)
        self.assertEqual(result["urls"][0]["host"], "example.com")
        self.assertEqual(result["urls"][0]["path"], "/test")

    def test_attachment_metadata(self):
        sample = (
            b"From: a@example.com\nTo: b@example.com\n"
            b"Subject: attachment\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="x"\n\n'
            b"--x\nContent-Type: text/plain\n\nhello\n"
            b"--x\nContent-Type: application/pdf\n"
            b'Content-Disposition: attachment; filename="doc.pdf"\n\n'
            b"binary-data\n--x--\n"
        )
        result = analyze_eml(sample)
        self.assertEqual(len(result["attachments"]), 1)
        self.assertEqual(result["attachments"][0]["filename"], "doc.pdf")
        self.assertEqual(len(result["attachments"][0]["sha256"]), 64)

if __name__ == "__main__":
    unittest.main()
