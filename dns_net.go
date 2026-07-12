package dmarcgo

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// NetTXTResolver adapts net.Resolver to TXTResolver. The standard library API
// does not expose TTL, RCODE, authority, CNAME, or negative-cache SOA evidence,
// so those fields remain explicitly unavailable in the returned result.
type NetTXTResolver struct {
	Resolver   *net.Resolver
	ResolverID string
}

func (resolver NetTXTResolver) validateTXTResolver() error {
	if resolver.Resolver == nil {
		return fmt.Errorf("%w: net resolver is required", ErrInvalidDNSCollectionOptions)
	}
	return nil
}

// LookupTXT performs one explicit TXT lookup through the configured resolver.
// Resolver is required; callers that want the process default must pass
// net.DefaultResolver explicitly. The lookup name is rooted so platform search
// domains cannot redirect evidence to a different owner name.
func (resolver NetTXTResolver) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	if err := resolver.validateTXTResolver(); err != nil {
		return TXTLookupResult{Name: normalizeDNSDisplayName(name)}, err
	}
	backend := resolver.Resolver
	result := TXTLookupResult{
		Name:         normalizeDNSDisplayName(name),
		Records:      []TXTRecord{},
		Resolver:     strings.TrimSpace(resolver.ResolverID),
		AnswerSource: DNSAnswerSourceUnknown,
		CNAMEPath:    []string{},
	}
	values, err := backend.LookupTXT(ctx, absoluteDNSName(name))
	if err != nil {
		return result, err
	}
	for _, value := range values {
		result.Records = append(result.Records, TXTRecord{Fragments: []string{}, Joined: value})
	}
	if len(result.Records) == 0 {
		result.Status = DNSObservationNoData
	} else {
		result.Status = DNSObservationSuccess
	}
	return result, nil
}
