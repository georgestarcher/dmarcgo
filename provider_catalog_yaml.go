package dmarcgo

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

const maxProviderCatalogYAMLBytes = 1 << 20

var (
	// ErrInvalidProviderCatalogYAML identifies malformed, multi-document, or schema-invalid YAML.
	ErrInvalidProviderCatalogYAML = errors.New("invalid provider catalog YAML")
	// ErrProviderCatalogSecretField identifies a forbidden secret-bearing field.
	ErrProviderCatalogSecretField = errors.New("provider catalog contains a secret-bearing field")
	// ErrProviderCatalogTooLarge identifies an oversized provider catalog.
	ErrProviderCatalogTooLarge = errors.New("provider catalog YAML exceeds the size limit")
)

// ParseProviderCatalogYAML strictly decodes one bounded, versioned YAML
// document. It rejects unknown fields, aliases, environment placeholders, and
// secret-bearing keys. It never fetches remote content.
func ParseProviderCatalogYAML(data []byte) (ProviderCatalogConfig, error) {
	if len(data) > maxProviderCatalogYAMLBytes {
		return ProviderCatalogConfig{}, ErrProviderCatalogTooLarge
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return ProviderCatalogConfig{}, fmt.Errorf("%w: document could not be decoded", ErrInvalidProviderCatalogYAML)
	}
	if len(document.Content) == 0 {
		return ProviderCatalogConfig{}, fmt.Errorf("%w: document is empty", ErrInvalidProviderCatalogYAML)
	}
	var additional yaml.Node
	if err := decoder.Decode(&additional); err != io.EOF {
		return ProviderCatalogConfig{}, fmt.Errorf("%w: exactly one document is required", ErrInvalidProviderCatalogYAML)
	}
	if err := inspectProviderCatalogYAML(&document, false); err != nil {
		return ProviderCatalogConfig{}, err
	}

	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	var config ProviderCatalogConfig
	if err := strict.Decode(&config); err != nil {
		return ProviderCatalogConfig{}, fmt.Errorf("%w: syntax or field validation failed", ErrInvalidProviderCatalogYAML)
	}
	if config.SchemaVersion != ProviderCatalogSchemaVersion {
		return ProviderCatalogConfig{}, ErrUnsupportedProviderCatalogSchema
	}
	return config, nil
}

// LoadProviderCatalogYAML strictly decodes and normalizes a caller-owned catalog.
func LoadProviderCatalogYAML(data []byte) (ProviderCatalog, error) {
	config, err := ParseProviderCatalogYAML(data)
	if err != nil {
		return ProviderCatalog{}, err
	}
	return NormalizeProviderCatalog(config)
}

func inspectProviderCatalogYAML(node *yaml.Node, mappingKey bool) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%w: aliases are not supported", ErrInvalidProviderCatalogYAML)
	}
	if mappingKey && node.Kind == yaml.ScalarNode && isSecretBearingKey(node.Value) {
		return ErrProviderCatalogSecretField
	}
	if node.Kind == yaml.ScalarNode && environmentPlaceholder.MatchString(node.Value) {
		return fmt.Errorf("%w: environment placeholders are not supported", ErrInvalidProviderCatalogYAML)
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if err := inspectProviderCatalogYAML(node.Content[index], true); err != nil {
				return err
			}
			if index+1 < len(node.Content) {
				if err := inspectProviderCatalogYAML(node.Content[index+1], false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := inspectProviderCatalogYAML(child, false); err != nil {
			return err
		}
	}
	return nil
}
