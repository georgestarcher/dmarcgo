package dmarcgo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
)

// DKIMKeyRecord is a side-effect-free semantic parse of one DKIM key record.
type DKIMKeyRecord struct {
	Raw            string                     `json:"raw"`
	Status         AuthenticationRecordStatus `json:"status"`
	Selector       string                     `json:"selector,omitempty"`
	Domain         string                     `json:"domain,omitempty"`
	Version        string                     `json:"version"`
	KeyType        string                     `json:"key_type"`
	KeyEncoding    string                     `json:"key_encoding,omitempty"`
	PublicKey      string                     `json:"public_key"`
	KeyBits        int                        `json:"key_bits"`
	Revoked        bool                       `json:"revoked"`
	HashAlgorithms []string                   `json:"hash_algorithms"`
	Services       []string                   `json:"services"`
	Flags          []string                   `json:"flags"`
	Granularity    string                     `json:"granularity,omitempty"`
	Notes          string                     `json:"notes,omitempty"`
	UnknownTags    []string                   `json:"unknown_tags"`
}

// ParseDKIMKeyRecord parses one supplied TXT value without resolving a selector
// or handling private key material.
func ParseDKIMKeyRecord(value string) (DKIMKeyRecord, []AuthenticationDiagnostic) {
	record := DKIMKeyRecord{
		Raw:     value,
		Version: "DKIM1", KeyType: "rsa", HashAlgorithms: []string{}, Services: []string{"*"},
		Flags: []string{}, UnknownTags: []string{},
	}
	if len(value) > maxAuthenticationRecordBytes {
		diagnostic := parserDiagnostic("dkim.malformed_record_size", FindingSeverityHigh, "record", 0, "The DKIM key record exceeds the parser size limit.", dkimStandardReference)
		record.Status = AuthenticationRecordMalformed
		return record, []AuthenticationDiagnostic{diagnostic}
	}
	tags, diagnostics := parseAuthenticationTags(value, dkimStandardReference)
	if len(tags) == 0 {
		diagnostics = append(diagnostics, parserDiagnostic("dkim.missing_required_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM public-key tag is missing.", dkimStandardReference))
		record.Status = statusFromDiagnostics(diagnostics)
		return record, diagnostics
	}
	publicKeyPresent := false
	publicKeyOffset := 0
	for index, tag := range tags {
		switch tag.name {
		case "v":
			if index != 0 || tag.value != "DKIM1" {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.invalid_version", FindingSeverityHigh, "version", tag.offset, "The DKIM version tag must be first and exactly DKIM1.", dkimStandardReference))
			}
			record.Version = tag.value
		case "h":
			var truncated bool
			record.HashAlgorithms, truncated = normalizedColonList(tag.value)
			if truncated {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.malformed_hash_algorithm_limit", FindingSeverityHigh, "hash_algorithms", tag.offset, "The DKIM hash-algorithm list contains too many values.", dkimStandardReference))
			}
			if len(record.HashAlgorithms) == 0 {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.invalid_hash_algorithms", FindingSeverityHigh, "hash_algorithms", tag.offset, "The DKIM hash-algorithm list is empty.", dkimStandardReference))
			}
			for _, algorithm := range record.HashAlgorithms {
				switch algorithm {
				case "sha1":
					diagnostics = append(diagnostics, parserDiagnostic("dkim.weak_sha1", FindingSeverityMedium, "hash_algorithms", tag.offset, "The DKIM key record permits the obsolete SHA-1 hash algorithm.", dkimCryptoReference))
				case "sha256":
				default:
					diagnostics = append(diagnostics, parserDiagnostic("dkim.unsupported_hash_algorithm", FindingSeverityMedium, "hash_algorithms", tag.offset, "The DKIM key record names an unsupported hash algorithm.", dkimStandardReference))
				}
			}
		case "k":
			record.KeyType = strings.ToLower(tag.value)
			if record.KeyType != "rsa" && record.KeyType != "ed25519" {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.unsupported_key_type", FindingSeverityMedium, "key_type", tag.offset, "The DKIM key type is not supported by this parser.", dkimStandardReference))
			}
		case "p":
			publicKeyPresent = true
			publicKeyOffset = tag.offset
			record.PublicKey = removeASCIIWhitespace(tag.value)
		case "s":
			var truncated bool
			record.Services, truncated = normalizedColonList(tag.value)
			if truncated {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.malformed_service_limit", FindingSeverityHigh, "services", tag.offset, "The DKIM service list contains too many values.", dkimStandardReference))
			}
			if len(record.Services) == 0 {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.invalid_services", FindingSeverityHigh, "services", tag.offset, "The DKIM service list is empty.", dkimStandardReference))
			}
			for _, service := range record.Services {
				if service != "*" && service != "email" {
					diagnostics = append(diagnostics, parserDiagnostic("dkim.unsupported_service", FindingSeverityMedium, "services", tag.offset, "The DKIM key record names an unsupported service type.", dkimStandardReference))
				}
			}
		case "t":
			var truncated bool
			record.Flags, truncated = normalizedColonList(tag.value)
			if truncated {
				diagnostics = append(diagnostics, parserDiagnostic("dkim.malformed_flag_limit", FindingSeverityHigh, "flags", tag.offset, "The DKIM flag list contains too many values.", dkimStandardReference))
			}
			for _, flag := range record.Flags {
				if flag != "y" && flag != "s" {
					diagnostics = append(diagnostics, parserDiagnostic("dkim.unsupported_flag", FindingSeverityMedium, "flags", tag.offset, "The DKIM key record contains an unsupported flag.", dkimStandardReference))
				}
			}
		case "g":
			record.Granularity = tag.value
		case "n":
			record.Notes = tag.value
		default:
			record.UnknownTags = append(record.UnknownTags, tag.name)
			diagnostics = append(diagnostics, parserDiagnostic("dkim.unknown_tag", FindingSeverityInfo, "unknown_tags", tag.offset, "An unknown DKIM tag is preserved and ignored.", dkimStandardReference))
		}
	}
	if !publicKeyPresent {
		diagnostics = append(diagnostics, parserDiagnostic("dkim.missing_required_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM public-key tag is missing.", dkimStandardReference))
	} else if record.PublicKey == "" {
		record.Revoked = true
		diagnostics = append(diagnostics, parserDiagnostic("dkim.revoked_key", FindingSeverityMedium, "public_key", 0, "The DKIM selector is explicitly revoked.", dkimStandardReference))
	} else {
		keyDiagnostics := validateDKIMPublicKey(&record)
		for index := range keyDiagnostics {
			keyDiagnostics[index].Offset += publicKeyOffset
		}
		diagnostics = append(diagnostics, keyDiagnostics...)
	}
	record.Status = statusFromDiagnostics(diagnostics)
	return record, diagnostics
}

func validateDKIMPublicKey(record *DKIMKeyRecord) []AuthenticationDiagnostic {
	decoded, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return []AuthenticationDiagnostic{parserDiagnostic("dkim.malformed_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM public key is not valid base64.", dkimStandardReference)}
	}
	switch record.KeyType {
	case "rsa":
		key, err := x509.ParsePKCS1PublicKey(decoded)
		if err != nil {
			parsed, parseErr := x509.ParsePKIXPublicKey(decoded)
			if parseErr != nil {
				return []AuthenticationDiagnostic{parserDiagnostic("dkim.malformed_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM RSA public key is not valid DER.", dkimStandardReference)}
			}
			var ok bool
			key, ok = parsed.(*rsa.PublicKey)
			if !ok {
				return []AuthenticationDiagnostic{parserDiagnostic("dkim.malformed_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM public key does not match its declared RSA key type.", dkimStandardReference)}
			}
			record.KeyEncoding = "subject_public_key_info"
		} else {
			record.KeyEncoding = "pkcs1"
		}
		record.KeyBits = key.N.BitLen()
		switch {
		case record.KeyBits < 1024:
			return []AuthenticationDiagnostic{parserDiagnostic("dkim.invalid_rsa_key_size", FindingSeverityHigh, "key_bits", 0, "The DKIM RSA public key is shorter than the required 1024 bits.", dkimCryptoReference)}
		case record.KeyBits < 2048:
			return []AuthenticationDiagnostic{parserDiagnostic("dkim.weak_rsa_key", FindingSeverityMedium, "key_bits", 0, "The DKIM RSA public key is shorter than the recommended 2048 bits.", dkimCryptoReference)}
		}
	case "ed25519":
		if len(decoded) != 32 {
			return []AuthenticationDiagnostic{parserDiagnostic("dkim.malformed_public_key", FindingSeverityHigh, "public_key", 0, "The DKIM Ed25519 public key must contain exactly 32 decoded bytes.", dkimEd25519Reference)}
		}
		record.KeyBits = 256
	}
	return nil
}

func normalizedColonList(value string) ([]string, bool) {
	parts := strings.SplitN(value, ":", maxAuthenticationListItems+1)
	truncated := len(parts) > maxAuthenticationListItems
	if truncated {
		parts = parts[:maxAuthenticationListItems]
	}
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" && !seen[part] {
			seen[part] = true
			result = append(result, part)
		}
	}
	return result, truncated
}

func removeASCIIWhitespace(value string) string {
	return strings.Map(func(character rune) rune {
		switch character {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return character
		}
	}, value)
}

func cloneDKIMKeyRecord(value DKIMKeyRecord) DKIMKeyRecord {
	value.HashAlgorithms = cloneStrings(value.HashAlgorithms)
	value.Services = cloneStrings(value.Services)
	value.Flags = cloneStrings(value.Flags)
	value.UnknownTags = cloneStrings(value.UnknownTags)
	return value
}
