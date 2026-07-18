#!/usr/bin/env python3
"""Verify that one dmarcgo release is visible through its public channels."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from urllib.parse import quote

import validate_release_metadata


MODULE_PATH = "github.com/georgestarcher/dmarcgo/v3"
REPOSITORY = "georgestarcher/dmarcgo"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Fail closed instead of forwarding a request or token to another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def publication_urls(tag: str) -> dict[str, str]:
    """Return the bounded first-party publication endpoints for tag."""
    escaped_tag = quote(tag, safe="")
    return {
        "github_release": f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{escaped_tag}",
        "go_proxy_info": f"https://proxy.golang.org/{MODULE_PATH}/@v/{escaped_tag}.info",
        "go_proxy_mod": f"https://proxy.golang.org/{MODULE_PATH}/@v/{escaped_tag}.mod",
        "checksum_database": f"https://sum.golang.org/lookup/{MODULE_PATH}@{escaped_tag}",
        "package_documentation": f"https://pkg.go.dev/{MODULE_PATH}@{escaped_tag}",
    }


def _json_object(
    responses: Mapping[str, bytes], key: str, errors: list[str]
) -> dict[str, object] | None:
    payload = responses.get(key)
    if payload is None:
        errors.append(f"{key}: response is missing")
        return None
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"{key}: response is not valid JSON: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{key}: response must be a JSON object")
        return None
    return value


def validate_publication_responses(
    tag: str, responses: Mapping[str, bytes]
) -> list[str]:
    """Return deterministic errors for fetched public release responses."""
    if not validate_release_metadata.TAG_PATTERN.fullmatch(tag):
        return [f"release tag must be a semantic v3 version, got {tag}"]

    errors: list[str] = []
    release = _json_object(responses, "github_release", errors)
    if release is not None:
        if release.get("tag_name") != tag:
            errors.append("github_release: tag_name does not match the requested tag")
        if release.get("draft") is not False:
            errors.append("github_release: release is missing or still a draft")
        expected_prerelease = "-" in tag
        if release.get("prerelease") is not expected_prerelease:
            errors.append(
                "github_release: prerelease state does not match the tag"
            )

    info = _json_object(responses, "go_proxy_info", errors)
    if info is not None and info.get("Version") != tag:
        errors.append("go_proxy_info: Version does not match the requested tag")

    module_payload = responses.get("go_proxy_mod")
    if module_payload is None:
        errors.append("go_proxy_mod: response is missing")
    else:
        try:
            module_lines = module_payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            errors.append(f"go_proxy_mod: response is not UTF-8: {exc}")
        else:
            module_line = next(
                (line.strip() for line in module_lines if line.startswith("module ")),
                "",
            )
            if module_line != f"module {MODULE_PATH}":
                errors.append("go_proxy_mod: module path does not match the v3 module")

    checksum_payload = responses.get("checksum_database")
    if checksum_payload is None:
        errors.append("checksum_database: response is missing")
    else:
        try:
            checksum_lines = checksum_payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            errors.append(f"checksum_database: response is not UTF-8: {exc}")
        else:
            module_prefix = f"{MODULE_PATH} {tag} h1:"
            go_mod_prefix = f"{MODULE_PATH} {tag}/go.mod h1:"
            if not any(line.startswith(module_prefix) for line in checksum_lines):
                errors.append("checksum_database: module checksum is missing")
            if not any(line.startswith(go_mod_prefix) for line in checksum_lines):
                errors.append("checksum_database: go.mod checksum is missing")

    documentation_payload = responses.get("package_documentation")
    if documentation_payload is None:
        errors.append("package_documentation: response is missing")
    else:
        if MODULE_PATH.encode() not in documentation_payload:
            errors.append("package_documentation: module path is missing from the page")
        if tag.encode() not in documentation_payload:
            errors.append("package_documentation: version is missing from the page")

    return errors


def fetch_response(url: str, timeout: float, github_token: str) -> bytes:
    """Fetch one bounded response without retries or redirects."""
    headers = {
        "Accept": "application/json, text/plain, text/html;q=0.9, */*;q=0.1",
        "User-Agent": f"dmarcgo-release-verifier ({REPOSITORY})",
    }
    if url.startswith("https://api.github.com/") and github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(RejectRedirects)
    with opener.open(request, timeout=timeout) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag including leading v")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    args = parser.parse_args()

    if not validate_release_metadata.TAG_PATTERN.fullmatch(args.tag):
        print(
            f"release tag must be a semantic v3 version, got {args.tag}",
            file=sys.stderr,
        )
        return 2
    if args.timeout <= 0 or args.timeout > 60:
        print("timeout must be greater than zero and at most 60 seconds", file=sys.stderr)
        return 2

    responses: dict[str, bytes] = {}
    errors: list[str] = []
    github_token = os.environ.get("GITHUB_TOKEN", "")
    for name, url in publication_urls(args.tag).items():
        try:
            responses[name] = fetch_response(url, args.timeout, github_token)
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            ValueError,
            OSError,
        ) as exc:
            errors.append(f"{name}: fetch failed: {exc}")

    errors.extend(validate_publication_responses(args.tag, responses))
    if errors:
        for error in dict.fromkeys(errors):
            print(error, file=sys.stderr)
        return 1

    print(f"release publication verified for {args.tag}")
    for name, url in publication_urls(args.tag).items():
        print(f"- {name}: {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
