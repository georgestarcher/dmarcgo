package dmarcgo

import "sort"

// CountSummary is a sorted message-count entry.
type CountSummary struct {
	Value    string `json:"value"`
	Messages int    `json:"messages"`
}

// TopSources returns up to n source summaries sorted by message count.
func TopSources(sources []SourceSummary, n int) []SourceSummary {
	if n <= 0 || len(sources) == 0 {
		return nil
	}
	out := append([]SourceSummary(nil), sources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages == out[j].Messages {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Messages > out[j].Messages
	})
	if n < len(out) {
		out = out[:n]
	}
	return out
}

// TopUnauthenticatedSources returns up to n unauthenticated source summaries
// sorted by message count.
func TopUnauthenticatedSources(sources []SuspiciousSource, n int) []SuspiciousSource {
	if n <= 0 || len(sources) == 0 {
		return nil
	}
	out := append([]SuspiciousSource(nil), sources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages == out[j].Messages {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Messages > out[j].Messages
	})
	if n < len(out) {
		out = out[:n]
	}
	return out
}

// TopCounts returns up to n entries from counts sorted by message count.
func TopCounts(counts map[string]int, n int) []CountSummary {
	if n <= 0 || len(counts) == 0 {
		return nil
	}
	out := make([]CountSummary, 0, len(counts))
	for value, messages := range counts {
		out = append(out, CountSummary{Value: value, Messages: messages})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages == out[j].Messages {
			return out[i].Value < out[j].Value
		}
		return out[i].Messages > out[j].Messages
	})
	if n < len(out) {
		out = out[:n]
	}
	return out
}
