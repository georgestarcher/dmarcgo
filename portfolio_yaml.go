package dmarcgo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxPortfolioYAMLBytes = 4 << 20

var (
	// ErrInvalidPortfolioYAML identifies malformed, multi-document, or schema-invalid YAML.
	ErrInvalidPortfolioYAML = errors.New("invalid portfolio YAML")
	// ErrPortfolioEnvironmentDisabled identifies an environment placeholder used without opt-in expansion.
	ErrPortfolioEnvironmentDisabled = errors.New("portfolio environment expansion is disabled")
	// ErrPortfolioEnvironmentMissing identifies a missing explicitly requested environment value.
	ErrPortfolioEnvironmentMissing = errors.New("portfolio environment value is missing")
	// ErrPortfolioSecretField identifies a forbidden secret-bearing configuration field.
	ErrPortfolioSecretField = errors.New("portfolio configuration contains a secret-bearing field")
	// ErrPortfolioTooLarge identifies an oversized configuration document.
	ErrPortfolioTooLarge = errors.New("portfolio YAML exceeds the size limit")
)

// EnvironmentLookup resolves one explicitly requested environment variable.
type EnvironmentLookup func(string) (string, bool)

// PortfolioLoadOption controls YAML loading without introducing global state.
type PortfolioLoadOption func(*portfolioLoadConfig) error

type portfolioLoadConfig struct {
	lookup EnvironmentLookup
}

// WithPortfolioEnvironment enables ${NAME} expansion through a caller-owned
// lookup function. The loader never reads process environment variables itself.
func WithPortfolioEnvironment(lookup EnvironmentLookup) PortfolioLoadOption {
	return func(config *portfolioLoadConfig) error {
		if lookup == nil {
			return fmt.Errorf("%w: lookup function is nil", ErrInvalidPortfolioYAML)
		}
		config.lookup = lookup
		return nil
	}
}

// ParsePortfolioYAML strictly decodes one versioned YAML document. It rejects
// unknown fields, aliases, secret-bearing keys, and implicit environment access.
func ParsePortfolioYAML(data []byte, options ...PortfolioLoadOption) (PortfolioConfig, error) {
	if len(data) > maxPortfolioYAMLBytes {
		return PortfolioConfig{}, ErrPortfolioTooLarge
	}
	loadConfig := portfolioLoadConfig{}
	for _, option := range options {
		if option == nil {
			return PortfolioConfig{}, fmt.Errorf("%w: load option is nil", ErrInvalidPortfolioYAML)
		}
		if err := option(&loadConfig); err != nil {
			return PortfolioConfig{}, err
		}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return PortfolioConfig{}, fmt.Errorf("%w: document could not be decoded", ErrInvalidPortfolioYAML)
	}
	if len(document.Content) == 0 {
		return PortfolioConfig{}, fmt.Errorf("%w: document is empty", ErrInvalidPortfolioYAML)
	}
	var additional yaml.Node
	if err := decoder.Decode(&additional); err != io.EOF {
		return PortfolioConfig{}, fmt.Errorf("%w: exactly one document is required", ErrInvalidPortfolioYAML)
	}
	if err := inspectAndExpandYAML(&document, loadConfig.lookup, false); err != nil {
		return PortfolioConfig{}, err
	}

	var normalized bytes.Buffer
	encoder := yaml.NewEncoder(&normalized)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return PortfolioConfig{}, fmt.Errorf("%w: document normalization failed", ErrInvalidPortfolioYAML)
	}
	if err := encoder.Close(); err != nil {
		return PortfolioConfig{}, fmt.Errorf("%w: document normalization failed", ErrInvalidPortfolioYAML)
	}

	strict := yaml.NewDecoder(&normalized)
	strict.KnownFields(true)
	var config PortfolioConfig
	if err := strict.Decode(&config); err != nil {
		return PortfolioConfig{}, fmt.Errorf("%w: syntax or field validation failed", ErrInvalidPortfolioYAML)
	}
	if config.SchemaVersion != PortfolioSchemaVersion {
		return PortfolioConfig{}, ErrUnsupportedPortfolioSchema
	}
	return config, nil
}

// LoadPortfolioYAML strictly decodes and normalizes a portfolio configuration.
func LoadPortfolioYAML(data []byte, options ...PortfolioLoadOption) (Portfolio, error) {
	config, err := ParsePortfolioYAML(data, options...)
	if err != nil {
		return Portfolio{}, err
	}
	return NormalizePortfolio(config)
}

var environmentPlaceholder = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func inspectAndExpandYAML(node *yaml.Node, lookup EnvironmentLookup, mappingKey bool) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%w: aliases are not supported", ErrInvalidPortfolioYAML)
	}
	if mappingKey && node.Kind == yaml.ScalarNode {
		if isSecretBearingKey(node.Value) {
			return ErrPortfolioSecretField
		}
		if environmentPlaceholder.MatchString(node.Value) {
			return fmt.Errorf("%w: mapping keys cannot use environment placeholders", ErrInvalidPortfolioYAML)
		}
	}
	if !mappingKey && node.Kind == yaml.ScalarNode && (node.Tag == "!!str" || node.Tag == "") {
		expanded, err := expandPortfolioEnvironment(node.Value, lookup)
		if err != nil {
			return err
		}
		node.Value = expanded
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if err := inspectAndExpandYAML(node.Content[index], lookup, true); err != nil {
				return err
			}
			if index+1 < len(node.Content) {
				if err := inspectAndExpandYAML(node.Content[index+1], lookup, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := inspectAndExpandYAML(child, lookup, false); err != nil {
			return err
		}
	}
	return nil
}

func expandPortfolioEnvironment(value string, lookup EnvironmentLookup) (string, error) {
	matches := environmentPlaceholder.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, nil
	}
	if lookup == nil {
		return "", ErrPortfolioEnvironmentDisabled
	}
	var builder strings.Builder
	position := 0
	for _, match := range matches {
		builder.WriteString(value[position:match[0]])
		name := value[match[2]:match[3]]
		replacement, ok := lookup(name)
		if !ok {
			return "", ErrPortfolioEnvironmentMissing
		}
		builder.WriteString(replacement)
		position = match[1]
	}
	builder.WriteString(value[position:])
	return builder.String(), nil
}

func isSecretBearingKey(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	if strings.Contains(value, "password") || strings.Contains(value, "secret") || strings.Contains(value, "credential") {
		return true
	}
	switch value {
	case "token", "api_token", "api_key", "private_key", "client_secret", "access_key":
		return true
	default:
		return false
	}
}
