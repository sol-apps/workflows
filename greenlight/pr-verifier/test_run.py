"""Focused tests for release-asset download origin checks."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class Response:
    def __init__(self, final_url):
        self.final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self.final_url

    def read(self, _size):
        return b""


class DownloadOriginTests(unittest.TestCase):
    def test_github_release_asset_redirect_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(run.urllib.request, "urlopen", return_value=Response(
                "https://release-assets.githubusercontent.com/github-production-release-asset/example"
            )):
                run._download("https://github.com/example/release", Path(directory) / "asset")

    def test_unrelated_redirect_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(run.urllib.request, "urlopen", return_value=Response(
                "https://example.com/asset"
            )):
                with self.assertRaisesRegex(run.VerificationSetupError, "untrusted origin"):
                    run._download("https://github.com/example/release", Path(directory) / "asset")


if __name__ == "__main__":
    unittest.main()
