from __future__ import annotations

import unittest

try:
    from pydantic import ValidationError
except ModuleNotFoundError:  # pragma: no cover - depends on optional test environment deps
    ValidationError = None

try:
    from src.web.schemas import StartPipelineRequest
except ModuleNotFoundError:  # pragma: no cover
    StartPipelineRequest = None


@unittest.skipIf(StartPipelineRequest is None, "pydantic is not installed")
class SchemaTest(unittest.TestCase):
    def test_start_request_requires_interface(self) -> None:
        with self.assertRaises(ValidationError):
            StartPipelineRequest(network_interface="")

    def test_start_request_accepts_ignored_ips_default(self) -> None:
        request = StartPipelineRequest(network_interface="eth0")
        self.assertEqual(request.ignored_source_ips, [])


if __name__ == "__main__":
    unittest.main()
