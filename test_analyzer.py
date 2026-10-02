import unittest
from analyzer import analyze

class Cases(unittest.TestCase):
    def test_security_behavior(self):
        self.assertEqual(analyze({"before":[{"id":"x","public":False}],"after":[{"id":"x","public":True}]})[0]["severity"], "HIGH")
        self.assertEqual(analyze({"before":[{"id":"x","public":False}],"after":[{"id":"x","public":False}]}), [])
        self.assertEqual(analyze({"before":[{"id":"x"}],"after":[{"id":"x","public":True}]})[0]["severity"], "UNKNOWN")

if __name__ == "__main__":
    unittest.main()

