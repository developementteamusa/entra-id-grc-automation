import unittest
from requests import HTTPError
from entra_audit.graph import GraphClient, GRAPH_BASE, collect_snapshot


class DummyResponse:
    def __init__(self, status, payload, headers=None):
        self.status_code = status
        self.payload = payload
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class DummySession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.headers = {}
        self.calls = 0

    def get(self, url, timeout):
        self.calls += 1
        return next(self.responses)


class GraphTests(unittest.TestCase):
    def test_pagination(self):
        second = f"{GRAPH_BASE}/users?$skiptoken=abc"
        sess = DummySession([
            DummyResponse(200, {"value": [{"id": "a"}], "@odata.nextLink": second}),
            DummyResponse(200, {"value": [{"id": "b"}]}),
        ])
        self.assertEqual(len(list(GraphClient("dummy", session=sess).pages(f"{GRAPH_BASE}/users"))), 2)
        self.assertEqual(sess.calls, 2)

    def test_retry_after_429(self):
        delays = []
        sess = DummySession([
            DummyResponse(429, {"error": "throttled"}, {"Retry-After": "2"}),
            DummyResponse(200, {"value": []}),
        ])
        self.assertEqual(list(GraphClient("dummy", session=sess, sleep=delays.append).pages(f"{GRAPH_BASE}/groups")), [])
        self.assertEqual(delays, [2])

    def test_no_token_to_untrusted_nextlink(self):
        sess = DummySession([DummyResponse(200, {"value": [{"id": "a"}], "@odata.nextLink": "https://evil.example/steal"})])
        with self.assertRaises(ValueError):
            list(GraphClient("dummy", session=sess).pages(f"{GRAPH_BASE}/users"))
        self.assertEqual(sess.calls, 1)

    def test_no_partial_success_after_error(self):
        sess = DummySession([DummyResponse(403, {"error": "Forbidden"})])
        with self.assertRaises(HTTPError):
            collect_snapshot(GraphClient("dummy", session=sess), "tenant")


if __name__ == "__main__":
    unittest.main()
