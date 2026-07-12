package dmarcgo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSMessageResolver performs explicit DNS-message TXT queries against one
// caller-selected DNS server. Unlike net.Resolver, it preserves TTL, RCODE,
// authority, CNAME, and negative-cache SOA evidence.
type DNSMessageResolver struct {
	Server     string
	Network    string
	ResolverID string
}

func (resolver DNSMessageResolver) validateTXTResolver() error {
	_, _, err := resolver.configuration()
	return err
}

func (resolver DNSMessageResolver) configuration() (string, string, error) {
	network := strings.ToLower(strings.TrimSpace(resolver.Network))
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" {
		return "", "", fmt.Errorf("%w: unsupported DNS network", ErrInvalidDNSCollectionOptions)
	}
	server, err := dnsServerAddress(resolver.Server)
	return network, server, err
}

// LookupTXT performs one DNS-message exchange. Network may be "udp" or "tcp"
// and defaults to UDP with automatic TCP retry for truncated responses.
func (resolver DNSMessageResolver) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	network, server, err := resolver.configuration()
	if err != nil {
		return TXTLookupResult{Name: normalizeDNSDisplayName(name)}, err
	}
	query, id, err := buildTXTQuery(name)
	if err != nil {
		return TXTLookupResult{Name: normalizeDNSDisplayName(name)}, err
	}
	response, err := exchangeDNSMessage(ctx, network, server, query)
	if err != nil {
		return TXTLookupResult{Name: normalizeDNSDisplayName(name)}, err
	}
	result, truncated, err := parseTXTResponse(response, id, name, resolver.ResolverID)
	if truncated && network == "udp" {
		response, err = exchangeDNSMessage(ctx, "tcp", server, query)
		if err != nil {
			return result, err
		}
		result, truncated, err = parseTXTResponse(response, id, name, resolver.ResolverID)
		if err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	if truncated {
		return result, ErrDNSMalformedResponse
	}
	return result, nil
}

func dnsServerAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: DNS server is required", ErrInvalidDNSCollectionOptions)
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("%w: DNS server host is required", ErrInvalidDNSCollectionOptions)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("%w: DNS server port is invalid", ErrInvalidDNSCollectionOptions)
		}
		return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("%w: invalid DNS server address", ErrInvalidDNSCollectionOptions)
	}
	return net.JoinHostPort(value, "53"), nil
}

func buildTXTQuery(value string) ([]byte, uint16, error) {
	name, err := dnsmessage.NewName(absoluteDNSName(value))
	if err != nil {
		return nil, 0, ErrDNSMalformedResponse
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("create DNS query identifier: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, ErrDNSMalformedResponse
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, ErrDNSMalformedResponse
	}
	query, err := builder.Finish()
	if err != nil {
		return nil, 0, ErrDNSMalformedResponse
	}
	return query, id, nil
}

func exchangeDNSMessage(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() {
		// The exchange result is already complete; a close-only error cannot
		// change the DNS evidence returned to the caller.
		_ = connection.Close()
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if network == "tcp" {
		if len(query) > int(^uint16(0)) {
			return nil, ErrDNSMalformedResponse
		}
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		copy(framed[2:], query)
		if err := writeDNSBytes(connection, framed); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return nil, err
		}
		response := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, err
		}
		return response, nil
	}
	if err := writeDNSBytes(connection, query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	count, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:count], nil
}

func writeDNSBytes(writer io.Writer, value []byte) error {
	written, err := io.Copy(writer, bytes.NewReader(value))
	if err != nil {
		return err
	}
	if written != int64(len(value)) {
		return io.ErrShortWrite
	}
	return nil
}

func parseTXTResponse(message []byte, id uint16, queryName, resolverID string) (TXTLookupResult, bool, error) {
	result := TXTLookupResult{
		Name: normalizeDNSDisplayName(queryName), Records: []TXTRecord{}, Resolver: strings.TrimSpace(resolverID),
		AnswerSource: DNSAnswerSourceUnknown, CNAMEPath: []string{},
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil || !header.Response || header.ID != id {
		return result, false, ErrDNSMalformedResponse
	}
	result.RCode = DNSRCodeEvidence{Available: true, Value: int(header.RCode)}
	result.DNSSEC = DNSSECEvidence{Available: true, AuthenticatedData: header.AuthenticData}
	if header.Authoritative {
		result.AnswerSource = DNSAnswerSourceAuthoritative
	} else {
		result.AnswerSource = DNSAnswerSourceRecursive
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Type != dnsmessage.TypeTXT || questions[0].Class != dnsmessage.ClassINET || normalizeDNSDisplayName(questions[0].Name.String()) != result.Name {
		return result, header.Truncated, ErrDNSMalformedResponse
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return result, header.Truncated, ErrDNSMalformedResponse
	}
	authorities, err := parser.AllAuthorities()
	if err != nil {
		return result, header.Truncated, ErrDNSMalformedResponse
	}
	if err := parser.SkipAllAdditionals(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return result, header.Truncated, ErrDNSMalformedResponse
	}

	cnameByOwner := make(map[string]string)
	txtAnswers := make([]dnsmessage.Resource, 0)
	for _, answer := range answers {
		switch body := answer.Body.(type) {
		case *dnsmessage.CNAMEResource:
			owner := normalizeDNSDisplayName(answer.Header.Name.String())
			target := normalizeDNSDisplayName(body.CNAME.String())
			if existing, present := cnameByOwner[owner]; present && existing != target {
				return result, header.Truncated, ErrDNSMalformedResponse
			}
			cnameByOwner[owner] = target
		case *dnsmessage.TXTResource:
			txtAnswers = append(txtAnswers, answer)
		}
	}
	currentName := result.Name
	seenNames := map[string]struct{}{currentName: {}}
	for {
		target, present := cnameByOwner[currentName]
		if !present {
			break
		}
		if _, seen := seenNames[target]; seen {
			return result, header.Truncated, ErrDNSMalformedResponse
		}
		seenNames[target] = struct{}{}
		result.CNAMEPath = append(result.CNAMEPath, target)
		result.CanonicalName = target
		currentName = target
	}
	if len(cnameByOwner) != len(result.CNAMEPath) {
		return result, header.Truncated, ErrDNSMalformedResponse
	}

	var ttl uint32
	ttlSet := false
	for _, answer := range txtAnswers {
		body := answer.Body.(*dnsmessage.TXTResource)
		if normalizeDNSDisplayName(answer.Header.Name.String()) != currentName {
			return result, header.Truncated, ErrDNSMalformedResponse
		}
		if !ttlSet || answer.Header.TTL < ttl {
			ttl = answer.Header.TTL
		}
		ttlSet = true
		fragments := append([]string(nil), body.TXT...)
		if len(fragments) == 0 {
			return result, header.Truncated, ErrDNSMalformedResponse
		}
		result.Records = append(result.Records, TXTRecord{
			Fragments: fragments, FragmentsAvailable: true, Joined: strings.Join(fragments, ""),
			TTL: DNSDurationEvidence{Available: true, Seconds: answer.Header.TTL},
		})
	}
	if ttlSet {
		result.TTL = DNSDurationEvidence{Available: true, Seconds: ttl}
	}
	for _, authority := range authorities {
		body, ok := authority.Body.(*dnsmessage.SOAResource)
		if !ok {
			continue
		}
		result.SOA = &DNSSOAEvidence{
			Name: normalizeDNSDisplayName(authority.Header.Name.String()), MName: normalizeDNSDisplayName(body.NS.String()),
			RName: normalizeDNSDisplayName(body.MBox.String()), Serial: body.Serial, Refresh: body.Refresh,
			Retry: body.Retry, Expire: body.Expire, Minimum: body.MinTTL, TTL: authority.Header.TTL,
		}
		negativeTTL := min(authority.Header.TTL, body.MinTTL)
		result.NegativeTTL = DNSDurationEvidence{Available: true, Seconds: negativeTTL}
		break
	}

	switch header.RCode {
	case dnsmessage.RCodeSuccess:
		if len(result.Records) == 0 {
			result.Status = DNSObservationNoData
		} else {
			result.Status = DNSObservationSuccess
		}
	case dnsmessage.RCodeNameError:
		if len(result.Records) != 0 {
			return result, header.Truncated, ErrDNSMalformedResponse
		}
		result.Status = DNSObservationNXDOMAIN
	default:
		result.Status = DNSObservationTemporaryFailure
	}
	return result, header.Truncated, nil
}

func absoluteDNSName(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasSuffix(value, ".") {
		value += "."
	}
	return value
}
