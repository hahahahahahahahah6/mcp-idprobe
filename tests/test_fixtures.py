"""Tests for the vulnerable / fixed fixture servers themselves."""
import time
import unittest

from mcp_idprobe.client import StreamableHttpClient, response_texts
from mcp_idprobe.fixtures import FixedMcpServer, VulnerableMcpServer


def exchange(url):
    """Two sessions, one colliding tools/call each; return per-session texts."""
    clients = [StreamableHttpClient(url), StreamableHttpClient(url)]
    for c in clients:
        c.initialize()
    clients[0].call_tool("echo", {"text": "secret-ALPHA"}, req_id="0")
    clients[1].call_tool("echo", {"text": "secret-BETA"}, req_id="0")
    time.sleep(0.8)
    texts = []
    for c in clients:
        blob = []
        for resp in c.poll():
            blob.extend(response_texts(resp))
        texts.append(blob)
    return texts


class TestVulnerableFixture(unittest.TestCase):
    def test_crosses_responses(self):
        with VulnerableMcpServer() as fx:
            texts_a, texts_b = exchange(fx.url)
        # session B must have received session A's secret (the leak)
        self.assertIn("secret-ALPHA", texts_b)
        # session A never gets its own response back (misrouted away)
        self.assertNotIn("secret-ALPHA", texts_a)

    def test_crossing_is_deterministic(self):
        for _ in range(3):
            with VulnerableMcpServer() as fx:
                texts_a, texts_b = exchange(fx.url)
            self.assertIn("secret-ALPHA", texts_b)


class TestFixedFixture(unittest.TestCase):
    def test_no_crossing(self):
        with FixedMcpServer() as fx:
            texts_a, texts_b = exchange(fx.url)
        self.assertIn("secret-ALPHA", texts_a)
        self.assertIn("secret-BETA", texts_b)
        self.assertNotIn("secret-BETA", texts_a)
        self.assertNotIn("secret-ALPHA", texts_b)

    def test_unknown_session_rejected(self):
        with FixedMcpServer() as fx:
            client = StreamableHttpClient(fx.url)
            client.session_id = "bogus"
            with self.assertRaises(Exception):
                client.call_tool("echo", {"text": "x"}, req_id="0")


if __name__ == "__main__":
    unittest.main()
