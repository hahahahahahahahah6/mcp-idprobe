"""Tests for the minimal Streamable HTTP client."""
import unittest

from mcp_idprobe.client import StreamableHttpClient, response_texts
from mcp_idprobe.fixtures import FixedMcpServer


class TestParseResponses(unittest.TestCase):
    def test_empty_body(self):
        self.assertEqual(StreamableHttpClient.parse_responses(""), [])
        self.assertEqual(StreamableHttpClient.parse_responses("   "), [])

    def test_single_json_response(self):
        body = '{"jsonrpc": "2.0", "id": "0", "result": {"ok": true}}'
        out = StreamableHttpClient.parse_responses(body)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "0")

    def test_batch(self):
        body = '[{"jsonrpc": "2.0", "id": "0"}, {"jsonrpc": "2.0", "id": "1"}]'
        out = StreamableHttpClient.parse_responses(body)
        self.assertEqual(len(out), 2)

    def test_poll_envelope(self):
        body = '{"responses": [{"jsonrpc": "2.0", "id": "0"}]}'
        out = StreamableHttpClient.parse_responses(body)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "0")

    def test_sse(self):
        body = (
            "event: message\ndata: {\"jsonrpc\": \"2.0\", \"id\": \"0\", \"result\": {}}\n\n"
            "data: [DONE]\n\n"
        )
        out = StreamableHttpClient.parse_responses(body, "text/event-stream")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "0")

    def test_garbage_ignored(self):
        self.assertEqual(StreamableHttpClient.parse_responses("not json"), [])
        self.assertEqual(StreamableHttpClient.parse_responses("{}"), [])

    def test_non_dict_frames_dropped(self):
        out = StreamableHttpClient.parse_responses('[1, "x", null]')
        self.assertEqual(out, [])


class TestResponseTexts(unittest.TestCase):
    def test_tool_result_text(self):
        resp = {
            "jsonrpc": "2.0",
            "id": "0",
            "result": {"content": [{"type": "text", "text": "hello"}]},
        }
        self.assertEqual(response_texts(resp), ["hello"])

    def test_no_result(self):
        self.assertEqual(response_texts({"jsonrpc": "2.0", "id": "0"}), [])


class TestLiveHandshake(unittest.TestCase):
    def test_initialize_captures_session(self):
        with FixedMcpServer() as fx:
            client = StreamableHttpClient(fx.url)
            client.initialize()
            self.assertIsNotNone(client.session_id)
            self.assertEqual(len(client.session_id), 32)


if __name__ == "__main__":
    unittest.main()
