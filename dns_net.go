package dmarcgo

import (
	"context"
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

// LookupTXT performs one explicit TXT lookup through the configured resolver.
func (resolver NetTXTResolver) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	backend := resolver.Resolver
	if backend == nil {
		backend = net.DefaultResolver
	}
	result := TXTLookupResult{
		Name:         normalizeDNSDisplayName(name),
		Records:      []TXTRecord{},
		Resolver:     strings.TrimSpace(resolver.ResolverID),
		AnswerSource: DNSAnswerSourceUnknown,
		CNAMEPath:    []string{},
	}
	values, err := backend.LookupTXT(ctx, name)
	if err != nil {
		return result, err
	}
	for _, value := range values {
		result.Records = append(result.Records, TXTRecord{Fragments: []string{value}, Joined: value})
	}
	if len(result.Records) == 0 {
		result.Status = DNSObservationNoData
	} else {
		result.Status = DNSObservationSuccess
	}
	return result, nil
}
