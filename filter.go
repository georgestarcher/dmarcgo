package dmarcgo

import (
	"fmt"
	"net/netip"
	"strings"
)

// SourceExclusion matches source IPs that a caller wants to suppress from
// unauthenticated-source review. Pattern may be an exact IP address or CIDR.
type SourceExclusion struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason,omitempty"`
}

// ExcludeUnauthenticatedSources removes sources whose SourceIP matches any
// exact-IP or CIDR exclusion pattern. It is useful for caller-owned allowlists
// without baking policy state into the parser.
func ExcludeUnauthenticatedSources(sources []SuspiciousSource, exclusions []SourceExclusion) ([]SuspiciousSource, error) {
	matchers, err := compileSourceExclusions(exclusions)
	if err != nil {
		return nil, err
	}
	out := make([]SuspiciousSource, 0, len(sources))
	for _, source := range sources {
		if sourceExcluded(source.SourceIP, matchers) {
			continue
		}
		out = append(out, source)
	}
	return out, nil
}

type sourceExclusionMatcher struct {
	addr   netip.Addr
	prefix netip.Prefix
}

func compileSourceExclusions(exclusions []SourceExclusion) ([]sourceExclusionMatcher, error) {
	matchers := make([]sourceExclusionMatcher, 0, len(exclusions))
	for _, exclusion := range exclusions {
		pattern := strings.TrimSpace(exclusion.Pattern)
		if pattern == "" {
			continue
		}
		if strings.Contains(pattern, "/") {
			prefix, err := netip.ParsePrefix(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid source exclusion CIDR %q: %w", pattern, err)
			}
			matchers = append(matchers, sourceExclusionMatcher{prefix: prefix.Masked()})
			continue
		}
		addr, err := netip.ParseAddr(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid source exclusion IP %q: %w", pattern, err)
		}
		matchers = append(matchers, sourceExclusionMatcher{addr: addr})
	}
	return matchers, nil
}

func sourceExcluded(rawIP string, matchers []sourceExclusionMatcher) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	for _, matcher := range matchers {
		if matcher.addr.IsValid() && matcher.addr == addr {
			return true
		}
		if matcher.prefix.IsValid() && matcher.prefix.Contains(addr) {
			return true
		}
	}
	return false
}
