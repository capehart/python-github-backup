"""Tests for GitHub App authentication with an app private key."""

import base64
import json
import shutil
import subprocess
import time
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from github_backup import github_backup

APP_ARGS = ["--app-id", "12345", "--app-private-key", "app.pem"]
APP_ARGS += ["--app-installation-id", "678"]


class MockHTTPResponse:
    def __init__(self, data, link_header=None):
        self._content = json.dumps(data).encode("utf-8")
        self.headers = {"x-ratelimit-remaining": "5000"}
        if link_header:
            self.headers["Link"] = link_header

    def getcode(self):
        return 200

    def read(self):
        return self._content


def b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def expires_in(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


@pytest.fixture
def app_args():
    return github_backup.parse_args(APP_ARGS + ["testorg"])


class TokenEndpoint:
    """Stands in for POST /app/installations/{id}/access_tokens."""

    def __init__(self):
        self.requests = []
        self.expires_at = expires_in(3600)

    def __call__(self, request, *args, **kwargs):
        self.requests.append(request)
        token = "ghs_{0}".format(len(self.requests))
        return MockHTTPResponse({"token": token, "expires_at": self.expires_at})


@pytest.fixture
def token_endpoint():
    endpoint = TokenEndpoint()
    with patch("github_backup.github_backup.build_app_jwt", return_value="app.jwt"):
        with patch("github_backup.github_backup.urlopen", side_effect=endpoint):
            yield endpoint


def test_app_flags_imply_as_app(app_args):
    assert app_args.as_app is True
    assert app_args.app_id == "12345"
    assert app_args.app_installation_id == "678"


def test_app_flags_must_be_used_together(capsys):
    with pytest.raises(SystemExit):
        github_backup.parse_args(["--app-id", "12345", "testorg"])

    assert "must be used together" in capsys.readouterr().err


@pytest.mark.parametrize(
    "token_args",
    [
        ["-t", "ghp_token"],
        ["-f", "github_pat_token"],
        ["--token-from-gh"],
        ["--keychain-name", "name", "--keychain-account", "account"],
    ],
)
def test_app_flags_reject_other_token_sources(token_args, capsys):
    with pytest.raises(SystemExit):
        github_backup.parse_args(APP_ARGS + token_args + ["testorg"])

    assert "cannot be combined" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_build_app_jwt_is_verifiable_rs256(tmp_path):
    private_key = tmp_path / "app.pem"
    public_key = tmp_path / "app.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )

    app_jwt = github_backup.build_app_jwt(str(private_key), {"iss": "12345"})

    header, payload, signature = app_jwt.split(".")
    assert json.loads(b64url_decode(header)) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(b64url_decode(payload)) == {"iss": "12345"}
    (tmp_path / "sig").write_bytes(b64url_decode(signature))
    verify = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key)]
        + ["-signature", str(tmp_path / "sig")],
        input="{0}.{1}".format(header, payload).encode("ascii"),
        capture_output=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr


def test_build_app_jwt_reports_missing_openssl():
    with patch(
        "github_backup.github_backup.subprocess.run", side_effect=FileNotFoundError
    ):
        with pytest.raises(Exception, match="'openssl' executable not found"):
            github_backup.build_app_jwt("app.pem", {})


def test_build_app_jwt_reports_openssl_errors():
    error = subprocess.CalledProcessError(1, "openssl", stderr=b"Could not read key")
    with patch("github_backup.github_backup.subprocess.run", side_effect=error):
        with pytest.raises(Exception, match="Could not read key"):
            github_backup.build_app_jwt("app.pem", {})


def test_jwt_claims_and_private_key_path(app_args):
    app_args.app_private_key = "file:///keys/app.pem"

    with patch(
        "github_backup.github_backup.build_app_jwt", return_value="app.jwt"
    ) as mock_build, patch(
        "github_backup.github_backup.urlopen",
        return_value=MockHTTPResponse(
            {"token": "ghs_1", "expires_at": expires_in(3600)}
        ),
    ):
        now = int(time.time())
        github_backup.get_auth(app_args)

    key_path, claims = mock_build.call_args.args
    assert key_path == "/keys/app.pem"
    assert claims["iss"] == "12345"
    assert now - 61 <= claims["iat"] <= now - 59
    assert now + 539 <= claims["exp"] <= now + 541


def test_get_auth_creates_installation_token(app_args, token_endpoint):
    assert github_backup.get_auth(app_args, encode=False) == "ghs_1"

    request = token_endpoint.requests[0]
    assert request.get_method() == "POST"
    assert (
        request.full_url == "https://api.github.com/app/installations/678/access_tokens"
    )
    assert request.get_header("Authorization") == "Bearer app.jwt"


def test_installation_token_on_enterprise_host(app_args, token_endpoint):
    app_args.github_host = "ghe.example.com"

    github_backup.get_auth(app_args)

    assert token_endpoint.requests[0].full_url == (
        "https://ghe.example.com/api/v3/app/installations/678/access_tokens"
    )


def test_installation_token_is_cached(app_args, token_endpoint):
    assert github_backup.get_auth(app_args, encode=False) == "ghs_1"
    assert github_backup.get_auth(app_args, encode=False) == "ghs_1"

    assert len(token_endpoint.requests) == 1


def test_installation_token_is_refreshed_before_expiry(app_args, token_endpoint):
    token_endpoint.expires_at = expires_in(github_backup.APP_TOKEN_REFRESH_MARGIN - 60)

    assert github_backup.get_auth(app_args, encode=False) == "ghs_1"
    assert github_backup.get_auth(app_args, encode=False) == "ghs_2"


def test_git_url_uses_installation_token(app_args, token_endpoint):
    repository = {"owner": {"login": "testorg"}, "name": "repo"}

    assert github_backup.get_github_repo_url(app_args, repository) == (
        "https://x-access-token:ghs_1@github.com/testorg/repo.git"
    )


def test_installation_token_http_error(app_args):
    error = HTTPError(
        "https://api.github.com",
        401,
        "Unauthorized",
        {},
        BytesIO(b'{"message":"Integration not found"}'),
    )
    with patch("github_backup.github_backup.build_app_jwt", return_value="app.jwt"):
        with patch("github_backup.github_backup.urlopen", side_effect=error):
            with pytest.raises(
                Exception, match="HTTP 401 Unauthorized: .*Integration not found"
            ):
                github_backup.get_auth(app_args)


def test_pagination_picks_up_refreshed_token(app_args):
    """A long paginated listing keeps working across a token refresh."""
    pages = [
        MockHTTPResponse(
            [{"id": 1}],
            link_header='<https://api.github.com/orgs/testorg/repos?page=2>; rel="next"',
        ),
        MockHTTPResponse([{"id": 2}]),
    ]
    tokens = iter(["ghs_1", "ghs_2"])
    page_auth = []

    def mock_urlopen(request, *args, **kwargs):
        page_auth.append(request.get_header("Authorization"))
        return pages[len(page_auth) - 1]

    with patch(
        "github_backup.github_backup.get_app_installation_token",
        side_effect=lambda args: next(tokens),
    ), patch("github_backup.github_backup.urlopen", side_effect=mock_urlopen):
        results = github_backup.retrieve_data(
            app_args, "https://api.github.com/orgs/testorg/repos"
        )

    assert results == [{"id": 1}, {"id": 2}]
    assert page_auth == [b"token ghs_1", b"token ghs_2"]
