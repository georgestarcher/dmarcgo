#!/usr/bin/env python3
"""Validate repository documentation links, style, spelling, and sample safety."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = ROOT / "docs"
ALLOWLIST_PATH = ROOT / "scripts" / "docs_spelling_allowlist.txt"
DEFAULT_PROVIDER_CATALOG_PATH = ROOT / "providers" / "default.yaml"
REPOSITORY = "georgestarcher/dmarcgo"

MARKDOWN_FILES = (
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    *(path for path in sorted(DOCS_ROOT.rglob("*.md"))),
)
PUBLIC_SAMPLE_FILES = (
    ROOT / "examples_test.go",
    *(path for path in sorted((ROOT / "testdata" / "portfolio").glob("*.yaml"))),
    *(path for path in sorted((ROOT / "testdata" / "fixtures" / "campaigns").glob("*.yaml"))),
)

LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9_-])")
IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)(?:/\d{1,3})?(?![0-9A-Fa-f:.])")
RESERVED_DOMAIN_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
RESERVED_DOMAIN_ROOTS = ("example.com", "example.net", "example.org")
NON_DNS_SAMPLE_SUFFIXES = (".gz", ".json", ".xmlns")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----|"
    r"github_pat_[A-Za-z0-9_]{8,}|ghp_[A-Za-z0-9]{8,}|"
    r"AKIA[0-9A-Z]{16}|(?i:(?:api[_-]?key|client[_-]?secret|password)\s*[:=]\s*[^\s<{][^\s]*))"
)
PRIVATE_SAMPLE_MARKERS = (
    "/Users/",
    ".codex-tmp",
    "test_dmarc_reports",
    "private-test-domains",
    "private_test_domains",
)
COMMON_MISSPELLINGS = {
    "adress": "address",
    "compatability": "compatibility",
    "dependancy": "dependency",
    "lanugage": "language",
    "occured": "occurred",
    "occurence": "occurrence",
    "priveleged": "privileged",
    "recieve": "receive",
    "seperate": "separate",
    "similiar": "similar",
    "sucess": "success",
    "truely": "truly",
}
REQUIRED_ADOPTION_DOCS = {
    "optional-context-configuration.md": (
        "## Start here",
        "## Configuration forms",
        "## Configure source enrichment",
        "## Configure source activity",
        "## Configure phishing intelligence",
        "## Configure jurisdiction context",
        "## Configure DNS perspectives",
        "## New-adopter checklist",
    ),
    "adoption-guide.md": (
        "## Choose a workflow",
        "## Reference architectures",
        "## Mode and side-effect matrix",
        "## Adoption checklist",
    ),
    "configuration-reference.md": (
        "## Portfolio configuration",
        "## Campaign configuration",
        "## Provider catalog configuration",
        "## Synthetic configuration files",
    ),
    "operations-and-troubleshooting.md": (
        "## Operational ownership",
        "## Safe rollout",
        "## Troubleshooting",
    ),
    "consumer-agent-guide.md": (
        "## Integration decision tree",
        "## Prohibited shortcuts",
        "## Consumer integration checklist",
    ),
}
CONFIGURATION_FIELD_SOURCES = (
    ROOT / "portfolio.go",
    ROOT / "campaign_config.go",
    ROOT / "provider_catalog.go",
)


def report(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}: {message}")


def github_slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value)
    return value.replace(" ", "-")


def anchors(text: str) -> set[str]:
    result: set[str] = set()
    counts: dict[str, int] = {}
    for _, heading in HEADING_RE.findall(text):
        base = github_slug(heading)
        count = counts.get(base, 0)
        counts[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def exact_path(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return False
    current = ROOT
    for part in relative.parts:
        if not current.is_dir() or part not in {entry.name for entry in current.iterdir()}:
            return False
        current /= part
    return current.exists()


def repository_target(target: str) -> tuple[Path, str] | None:
    parsed = urlparse(target)
    prefix = f"/{REPOSITORY}/"
    if parsed.netloc != "github.com" or not parsed.path.startswith(prefix):
        return None
    remainder = parsed.path[len(prefix) :]
    for marker in ("blob/main/", "tree/main/"):
        if remainder.startswith(marker):
            return ROOT / unquote(remainder[len(marker) :]), parsed.fragment
    return None


def local_target(source: Path, target: str) -> tuple[Path, str] | None:
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or target.startswith("mailto:"):
        return None
    plain = unquote(parsed.path)
    if source.parent == DOCS_ROOT / "wiki" and plain and not Path(plain).suffix:
        plain = f"{plain}.md"
    destination = source if not plain else source.parent / plain
    return destination, parsed.fragment


def validate_link(errors: list[str], source: Path, target: str) -> None:
    target = target.strip().split(maxsplit=1)[0].strip("<>")
    resolved = repository_target(target) or local_target(source, target)
    if resolved is None:
        return
    destination, fragment = resolved
    if not exact_path(destination):
        report(errors, source, f"link target does not match an exact repository path: {target}")
        return
    if fragment and destination.is_file() and destination.suffix.lower() == ".md":
        text = destination.read_text(encoding="utf-8")
        if unquote(fragment).casefold() not in {item.casefold() for item in anchors(text)}:
            report(errors, source, f"link anchor does not exist: {target}")


def load_spelling_allowlist(errors: list[str]) -> set[str]:
    if not ALLOWLIST_PATH.is_file():
        report(errors, ALLOWLIST_PATH, "spelling allowlist is missing")
        return set()
    allowed: set[str] = set()
    for number, raw in enumerate(ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", line):
            report(errors, ALLOWLIST_PATH, f"line {number} is not one literal word")
            continue
        allowed.add(line.casefold())
    return allowed


def go_strings_and_comments(text: str) -> str:
    """Return only Go string literals and comments for sample-data checks."""
    retained: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = len(text)
            retained.append(text[index + 2 : end])
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                end = len(text)
                retained.append(text[index + 2 : end])
                index = end
            else:
                retained.append(text[index + 2 : end])
                index = end + 2
            continue

        delimiter = text[index]
        if delimiter == "`":
            end = text.find("`", index + 1)
            if end < 0:
                end = len(text)
            retained.append(text[index + 1 : end])
            index = min(end + 1, len(text))
            continue
        if delimiter == '"':
            value: list[str] = []
            index += 1
            while index < len(text):
                if text[index] == "\\" and index + 1 < len(text):
                    value.extend(text[index : index + 2])
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                value.append(text[index])
                index += 1
            retained.append("".join(value))
            continue
        if delimiter == "'":
            index += 1
            while index < len(text):
                if text[index] == "\\" and index + 1 < len(text):
                    index += 2
                    continue
                index += 1
                if text[index - 1] == "'":
                    break
            continue
        index += 1
    return "\n".join(retained)


def reserved_sample_domain(domain: str) -> bool:
    normalized = domain.casefold().rstrip(".")
    if normalized.endswith(RESERVED_DOMAIN_SUFFIXES):
        return True
    return any(normalized == root or normalized.endswith(f".{root}") for root in RESERVED_DOMAIN_ROOTS)


def domain_sample_candidate(domain: str) -> bool:
    normalized = domain.casefold().rstrip(".")
    if normalized.endswith(NON_DNS_SAMPLE_SUFFIXES):
        return False
    labels = normalized.split(".")
    return not (labels[-1] == "zip" and all(label.isdigit() for label in labels[:-1]))


def reviewed_provider_domains(errors: list[str]) -> set[str]:
    if not DEFAULT_PROVIDER_CATALOG_PATH.is_file():
        report(errors, DEFAULT_PROVIDER_CATALOG_PATH, "reviewed provider catalog is missing")
        return set()
    domains: set[str] = set()
    for line in DEFAULT_PROVIDER_CATALOG_PATH.read_text(encoding="utf-8").splitlines():
        if line.startswith("    official_domains: "):
            domains.update(domain.casefold() for domain in DOMAIN_RE.findall(line))
            continue
        if line.startswith("        - name: "):
            value = line.split(":", maxsplit=1)[1].strip()
            if DOMAIN_RE.fullmatch(value):
                domains.add(value.casefold())
    if not domains:
        report(errors, DEFAULT_PROVIDER_CATALOG_PATH, "contains no reviewed provider DNS names")
    return domains


def documentation_sample_address(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return True
    return any(network.version == reserved.version and network.subnet_of(reserved) for reserved in DOCUMENTATION_NETWORKS)


def sample_network_errors(text: str, allowed_domains: set[str] | None = None) -> list[str]:
    errors: list[str] = []
    allowed = {domain.casefold().rstrip(".") for domain in allowed_domains or set()}
    for domain in DOMAIN_RE.findall(text):
        normalized = domain.casefold().rstrip(".")
        if domain_sample_candidate(domain) and not reserved_sample_domain(domain) and normalized not in allowed:
            errors.append(f"sample domain is not reserved for documentation: {domain}")
    for raw in IP_RE.findall(text):
        if not documentation_sample_address(raw):
            errors.append(f"sample address is not reserved documentation space: {raw}")
    return errors


def validate_markdown(errors: list[str], path: Path, allowed: set[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        report(errors, path, "file must end with one newline")
    prose: list[str] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.rstrip() != line:
            report(errors, path, f"line {number} has trailing whitespace")
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if "\t" in line and not in_fence:
            report(errors, path, f"line {number} contains a tab")
        if not in_fence:
            prose.append(line)
    if text.count("```") % 2:
        report(errors, path, "fenced code blocks are unbalanced")

    for _, target in LINK_RE.findall(text):
        validate_link(errors, path, target)

    words = {word.casefold() for word in re.findall(r"[A-Za-z]+", "\n".join(prose))}
    for misspelling, correction in COMMON_MISSPELLINGS.items():
        if misspelling in words and misspelling not in allowed:
            report(errors, path, f"contains {misspelling!r}; use {correction!r} or add an intentional exception to {ALLOWLIST_PATH.relative_to(ROOT)}")


def validate_sample_safety(errors: list[str], path: Path, provider_domains: set[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if SECRET_RE.search(text):
        report(errors, path, "contains a credential-shaped value")
    folded = text.casefold()
    for marker in PRIVATE_SAMPLE_MARKERS:
        if marker.casefold() in folded:
            report(errors, path, f"contains prohibited private marker {marker!r}")

    is_go = path.suffix == ".go"
    network_text = go_strings_and_comments(text) if is_go else text
    # Only Go examples may demonstrate exact DNS names already reviewed in the
    # embedded catalog. Portfolio/campaign fixtures remain fully synthetic.
    allowed_domains = provider_domains if is_go else set()
    for message in sample_network_errors(network_text, allowed_domains):
        report(errors, path, message)


def validate_index(errors: list[str]) -> None:
    index = (DOCS_ROOT / "README.md").read_text(encoding="utf-8")
    for path in sorted(DOCS_ROOT.glob("*.md")):
        if path.name == "README.md":
            continue
        if f"({path.name})" not in index:
            report(errors, DOCS_ROOT / "README.md", f"does not index {path.name}")

    for name, headings in REQUIRED_ADOPTION_DOCS.items():
        path = DOCS_ROOT / name
        if not path.is_file():
            report(errors, path, "required adoption guide is missing")
            continue
        text = path.read_text(encoding="utf-8")
        for heading in headings:
            if heading not in text:
                report(errors, path, f"required heading is missing: {heading}")


def validate_configuration_reference(errors: list[str]) -> None:
    reference_path = DOCS_ROOT / "configuration-reference.md"
    text = reference_path.read_text(encoding="utf-8")
    documented = re.findall(r"`([^`]+)`", text)
    for source in CONFIGURATION_FIELD_SOURCES:
        fields = set(re.findall(r'yaml:"([^",]+)', source.read_text(encoding="utf-8")))
        for field in sorted(fields - {"-"}):
            if not any(value == field or value.endswith(f".{field}") for value in documented):
                report(errors, reference_path, f"does not document YAML/JSON field {field!r} from {source.name}")


def main() -> int:
    errors: list[str] = []
    allowed = load_spelling_allowlist(errors)
    provider_domains = reviewed_provider_domains(errors)
    for path in MARKDOWN_FILES:
        validate_markdown(errors, path, allowed)
    for path in PUBLIC_SAMPLE_FILES:
        validate_sample_safety(errors, path, provider_domains)
    validate_index(errors)
    validate_configuration_reference(errors)

    if errors:
        print("documentation validation failed:", file=sys.stderr)
        for message in sorted(set(errors)):
            print(f"- {message}", file=sys.stderr)
        return 1

    print(
        f"documentation validation passed: {len(MARKDOWN_FILES)} Markdown files, "
        f"{len(PUBLIC_SAMPLE_FILES)} public sample files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
