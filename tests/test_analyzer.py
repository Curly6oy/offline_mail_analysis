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
IBAN: DE89370400440532013000
Born: 01.02.1990
Visit https://example.com/private-token
"""

class AnalyzerTests(unittest.TestCase):
    def test_detects_categories(self):
        result = analyze_eml(SAMPLE)
        kinds = {x["type"] for x in result["pii"]}
        for expected in ("Email", "Телефон", "Паспорт РФ", "IBAN", "Дата рождения"):
            self.assertIn(expected, kinds)
        self.assertTrue(result["privacy"]["offline"])
        self.assertFalse(result["privacy"]["external_requests"])

    def test_raw_pii_and_url_path_are_not_returned(self):
        result = analyze_eml(SAMPLE)
        serialized = repr(result)
        self.assertNotIn("999 123-45-67", serialized)
        self.assertNotIn("1234 567890", serialized)
        self.assertNotIn("private-token", serialized)
        self.assertEqual(result["urls"][0]["host"], "example.com")

    def test_attachment_filename_is_not_returned(self):
        sample = (
            b"From: a@example.com\nTo: b@example.com\n"
            b"Subject: attachment\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="x"\n\n'
            b"--x\nContent-Type: text/plain\n\nhello\n"
            b"--x\nContent-Type: application/pdf\n"
            b'Content-Disposition: attachment; filename="private-name.pdf"\n\n'
            b"binary-data\n--x--\n"
        )
        result = analyze_eml(sample)
        self.assertEqual(len(result["attachments"]), 1)
        self.assertNotIn("private-name.pdf", repr(result))
        self.assertEqual(len(result["attachments"][0]["sha256"]), 64)

    def test_detects_luhn_valid_card(self):
        sample = SAMPLE.replace(b"Visit", b"Card: 4111 1111 1111 1111\nVisit")
        result = analyze_eml(sample)
        cards = [x for x in result["pii"] if x["type"] == "Банковская карта"]
        self.assertEqual(cards[0]["count"], 1)
        self.assertNotIn("4111 1111 1111 1111", repr(result))

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            analyze_eml(b"x" * (10 * 1024 * 1024 + 1))

if __name__ == "__main__":
    unittest.main()
