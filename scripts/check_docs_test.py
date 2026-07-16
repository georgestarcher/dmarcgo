#!/usr/bin/env python3
"""Regression tests for documentation sample-data validation."""

import unittest

import check_docs


class GoSampleExtractionTests(unittest.TestCase):
    def test_retains_only_strings_and_comments(self) -> None:
        source = '''package sample

import "context"

func example(value context.Context) {
    _ = "mail.example.com"
    _ = `192.0.2.10`
    _ = 'x'
    // 198.51.100.20
}
'''
        retained = check_docs.go_strings_and_comments(source)
        self.assertNotIn("context.Context", retained)
        self.assertIn("mail.example.com", retained)
        self.assertIn("192.0.2.10", retained)
        self.assertIn("198.51.100.20", retained)

    def test_ignores_comment_markers_inside_strings(self) -> None:
        retained = check_docs.go_strings_and_comments('var value = "https://config.example.test/path"\n')
        self.assertIn("https://config.example.test/path", retained)

    def test_exposes_nonreserved_values_in_go_literals(self) -> None:
        source = 'var domain = "mail.public-domain.tld"\nvar address = `100.64.0.1`\n'
        errors = check_docs.sample_network_errors(check_docs.go_strings_and_comments(source))
        self.assertIn("sample domain is not reserved for documentation: mail.public-domain.tld", errors)
        self.assertIn("sample address is not reserved documentation space: 100.64.0.1", errors)


class SampleNetworkTests(unittest.TestCase):
    def test_owner_authorized_sample_exception_requires_exact_content(self) -> None:
        approved = (
            check_docs.ROOT
            / "examples/go/report-directory/samples/georgestarcher.com/google.com!georgestarcher.com!1783382400!1783468799.xml"
        )
        adjacent = approved.with_name("another-real-report.xml")
        payload = approved.read_bytes()
        self.assertTrue(check_docs.owner_authorized_public_sample(approved, payload))
        self.assertFalse(check_docs.owner_authorized_public_sample(approved, payload + b"\n"))
        self.assertFalse(check_docs.owner_authorized_public_sample(adjacent, payload))

    def test_accepts_reserved_domains_and_documentation_addresses(self) -> None:
        sample = """
        example.com sub.example.net example.org service.example.test
        192.0.2.10 198.51.100.0/24 203.0.113.7 2001:db8::10
        """
        self.assertEqual(check_docs.sample_network_errors(sample), [])

    def test_ignores_file_names_and_structured_field_paths(self) -> None:
        sample = "security-simulations.json report.xml.gz 1700086399.zip feedback.xmlns"
        self.assertEqual(check_docs.sample_network_errors(sample), [])

    def test_rejects_nonreserved_domain_and_address(self) -> None:
        errors = check_docs.sample_network_errors("mail.public-domain.tld 100.64.0.1")
        self.assertIn("sample domain is not reserved for documentation: mail.public-domain.tld", errors)
        self.assertIn("sample address is not reserved documentation space: 100.64.0.1", errors)

    def test_allows_only_explicit_reviewed_provider_domains(self) -> None:
        allowed = {"_spf.google.com"}
        self.assertEqual(check_docs.sample_network_errors("_spf.google.com", allowed), [])
        errors = check_docs.sample_network_errors("mail.public-domain.tld", allowed)
        self.assertEqual(errors, ["sample domain is not reserved for documentation: mail.public-domain.tld"])

    def test_provider_domains_come_from_dns_fields_not_documentation_urls(self) -> None:
        errors: list[str] = []
        domains = check_docs.reviewed_provider_domains(errors)
        self.assertEqual(errors, [])
        self.assertIn("google.com", domains)
        self.assertIn("_spf.google.com", domains)
        self.assertNotIn("knowledge.workspace.google.com", domains)

    def test_go_identifiers_do_not_look_like_domains(self) -> None:
        source = "func example(value context.Context) { fmt.Println(value) }\n"
        retained = check_docs.go_strings_and_comments(source)
        self.assertEqual(check_docs.sample_network_errors(retained), [])


if __name__ == "__main__":
    unittest.main()
