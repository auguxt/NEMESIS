import unittest

from profiler import detect_attack_type, is_internal_ip


class ProfilerDetectionTests(unittest.TestCase):
    def test_http_honeytoken_access(self):
        attack_type = detect_attack_type("http", ["GET /config.ini HTTP/1.1"])
        self.assertEqual(attack_type, "Honeytoken Access")

    def test_ftp_honeytoken_access(self):
        attack_type = detect_attack_type("ftp", ["USER admin", "PASS pass", "RETR backup.sql"])
        self.assertEqual(attack_type, "Honeytoken Access")

    def test_http_directory_traversal(self):
        attack_type = detect_attack_type("http", ["GET /../../../../etc/passwd HTTP/1.1"])
        self.assertEqual(attack_type, "Directory Traversal")

    def test_http_xss(self):
        attack_type = detect_attack_type("http", ["GET /search?q=<script>alert(1)</script> HTTP/1.1"])
        self.assertEqual(attack_type, "XSS Attempt")


class InternalIpTests(unittest.TestCase):
    def test_rfc1918_ranges_only(self):
        self.assertTrue(is_internal_ip("10.1.2.3"))
        self.assertTrue(is_internal_ip("172.16.5.4"))
        self.assertTrue(is_internal_ip("192.168.1.20"))
        self.assertFalse(is_internal_ip("172.15.0.1"))
        self.assertFalse(is_internal_ip("172.32.0.1"))
        self.assertFalse(is_internal_ip("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
