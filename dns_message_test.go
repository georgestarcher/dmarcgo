package dmarcgo

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseTXTResponsePreservesPositiveEvidence(t *testing.T) {
	for _, test := range []struct {
		name          string
		authoritative bool
		authenticData bool
		wantSource    DNSAnswerSource
		ttl           uint32
	}{
		{name: "authoritative", authoritative: true, wantSource: DNSAnswerSourceAuthoritative, ttl: 3600},
		{name: "recursive remaining cache lifetime", authenticData: true, wantSource: DNSAnswerSourceRecursive, ttl: 215},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := buildDNSResponse(t, dnsResponseFixture{
				id: 42, name: "selector._domainkey.example.test", authoritative: test.authoritative, authenticData: test.authenticData,
				cname: "selector._domainkey.provider.test", txt: [][]string{{"v=DKIM1; p=", "key"}}, ttl: test.ttl,
			})
			result, truncated, err := parseTXTResponse(message, 42, "selector._domainkey.example.test", "fixture")
			if err != nil || truncated {
				t.Fatalf("parse response: truncated=%v error=%v", truncated, err)
			}
			if result.Status != DNSObservationSuccess || result.AnswerSource != test.wantSource || !result.TTL.Available || result.TTL.Seconds != test.ttl || !result.RCode.Available || result.RCode.Value != 0 {
				t.Fatalf("positive evidence = %+v", result)
			}
			if !result.DNSSEC.Available || result.DNSSEC.AuthenticatedData != test.authenticData {
				t.Fatalf("DNSSEC evidence = %+v", result.DNSSEC)
			}
			if len(result.Records) != 1 || result.Records[0].Joined != "v=DKIM1; p=key" || !result.Records[0].FragmentsAvailable || len(result.Records[0].Fragments) != 2 {
				t.Fatalf("TXT fragments = %+v", result.Records)
			}
			if result.CanonicalName != "selector._domainkey.provider.test" || len(result.CNAMEPath) != 1 {
				t.Fatalf("CNAME evidence = %+v", result.CNAMEPath)
			}
		})
	}
}

func TestParseTXTResponsePreservesNegativeEvidence(t *testing.T) {
	for _, test := range []struct {
		name       string
		rcode      dnsmessage.RCode
		wantStatus DNSObservationStatus
	}{
		{name: "nxdomain", rcode: dnsmessage.RCodeNameError, wantStatus: DNSObservationNXDOMAIN},
		{name: "nodata", rcode: dnsmessage.RCodeSuccess, wantStatus: DNSObservationNoData},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := buildDNSResponse(t, dnsResponseFixture{
				id: 9, name: "_dmarc.example.test", authoritative: true, rcode: test.rcode,
				soa: true, soaTTL: 900, soaMinimum: 600,
			})
			result, _, err := parseTXTResponse(message, 9, "_dmarc.example.test", "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus || !result.RCode.Available || result.RCode.Value != int(test.rcode) || !result.NegativeTTL.Available || result.NegativeTTL.Seconds != 600 || result.SOA == nil {
				t.Fatalf("negative evidence = %+v", result)
			}
			if result.TTL.Available || len(result.Records) != 0 {
				t.Fatalf("negative answer invented positive evidence: %+v", result)
			}
		})
	}
}

func TestParseTXTResponseUsesMinimumInconsistentRRSetTTL(t *testing.T) {
	message := buildDNSResponse(t, dnsResponseFixture{
		id: 12, name: "example.test", txt: [][]string{{"first"}, {"second"}}, ttl: 60, secondTTL: 120,
	})
	result, _, err := parseTXTResponse(message, 12, "example.test", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != DNSObservationSuccess || !result.TTL.Available || result.TTL.Seconds != 60 || len(result.Records) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if result.Records[0].TTL.Seconds != 60 || result.Records[1].TTL.Seconds != 120 {
		t.Fatalf("per-record TTL evidence = %+v", result.Records)
	}
}

func TestParseTXTResponseDoesNotDependOnAnswerOrder(t *testing.T) {
	message := buildDNSResponse(t, dnsResponseFixture{
		id: 13, name: "alias.example.test", cname: "target.example.test",
		txt: [][]string{{"value"}}, ttl: 60, reverseAnswers: true,
	})
	result, _, err := parseTXTResponse(message, 13, "alias.example.test", "fixture")
	if err != nil || result.Status != DNSObservationSuccess || result.CanonicalName != "target.example.test" {
		t.Fatalf("result = %+v error=%v", result, err)
	}
}

func TestParseTXTResponseValidatesTransactionAndQuestion(t *testing.T) {
	message := buildDNSResponse(t, dnsResponseFixture{id: 1, name: "example.test", txt: [][]string{{"value"}}, ttl: 60})
	if _, _, err := parseTXTResponse(message, 2, "example.test", "fixture"); !errors.Is(err, ErrDNSMalformedResponse) {
		t.Fatalf("transaction error = %v", err)
	}
	if _, _, err := parseTXTResponse(message, 1, "other.test", "fixture"); !errors.Is(err, ErrDNSMalformedResponse) {
		t.Fatalf("question error = %v", err)
	}
}

func TestDNSMessageResolverRequiresExplicitServer(t *testing.T) {
	_, err := (DNSMessageResolver{}).LookupTXT(t.Context(), "example.test")
	if !errors.Is(err, ErrInvalidDNSCollectionOptions) {
		t.Fatalf("error = %v", err)
	}
}

func TestDNSMessageResolverValidatesNumericServerPort(t *testing.T) {
	for _, server := range []string{
		"127.0.0.1:bad",
		"127.0.0.1:",
		"127.0.0.1:0",
		"127.0.0.1:-1",
		"127.0.0.1:65536",
		":53",
	} {
		t.Run(server, func(t *testing.T) {
			err := (DNSMessageResolver{Server: server}).validateTXTResolver()
			if !errors.Is(err, ErrInvalidDNSCollectionOptions) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDNSMessageResolverAcceptsValidServerPort(t *testing.T) {
	for _, server := range []string{"127.0.0.1:5353", "[::1]:5353"} {
		t.Run(server, func(t *testing.T) {
			if err := (DNSMessageResolver{Server: server}).validateTXTResolver(); err != nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDNSMessageResolverRetriesMalformedTruncatedUDPOverTCP(t *testing.T) {
	tcpListener, udpListener := listenSharedDNSFixturePort(t)
	t.Cleanup(func() {
		if err := tcpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close TCP fixture listener: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := udpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close UDP fixture listener: %v", err)
		}
	})

	udpErrors := make(chan error, 1)
	tcpErrors := make(chan error, 1)
	go serveMalformedTruncatedUDPFixture(udpListener, udpErrors)
	go func() {
		connection, err := tcpListener.Accept()
		if err != nil {
			tcpErrors <- err
			return
		}
		serveNetResolverFixture(connection, tcpErrors)
	}()

	result, err := (DNSMessageResolver{
		Server: tcpListener.Addr().String(), ResolverID: "truncation-fixture",
	}).LookupTXT(t.Context(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-udpErrors; err != nil {
		t.Fatalf("UDP fixture: %v", err)
	}
	if err := <-tcpErrors; err != nil {
		t.Fatalf("TCP fixture: %v", err)
	}
	if result.Status != DNSObservationSuccess || len(result.Records) != 1 || result.Records[0].Joined != "v=spf1 -all" {
		t.Fatalf("TCP fallback result = %+v", result)
	}
}

func listenSharedDNSFixturePort(t *testing.T) (*net.TCPListener, *net.UDPConn) {
	t.Helper()
	const (
		firstCandidatePort = 20000
		maxAttempts        = 128
	)
	loopback := net.IPv4(127, 0, 0, 1)
	var lastErr error
	for attempt := range maxAttempts {
		// Windows chooses dynamic TCP and UDP ports from independently
		// configurable ranges. Use bounded candidates below the default dynamic
		// range instead of asking one protocol to choose a port that the other
		// protocol may reserve or exclude.
		port := firstCandidatePort + attempt
		tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: loopback, Port: port})
		if err != nil {
			lastErr = err
			continue
		}
		udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: port})
		if err == nil {
			return tcpListener, udpListener
		}
		lastErr = err
		if closeErr := tcpListener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Fatalf("close TCP fixture after UDP bind failure: %v", closeErr)
		}
	}
	t.Fatalf("listen TCP and UDP fixtures on one non-dynamic port after %d attempts: %v", maxAttempts, lastErr)
	return nil, nil
}

func serveMalformedTruncatedUDPFixture(connection *net.UDPConn, result chan<- error) {
	message := make([]byte, 65535)
	count, address, err := connection.ReadFromUDP(message)
	if err != nil {
		result <- err
		return
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(message[:count])
	if err != nil {
		result <- err
		return
	}
	question, err := parser.Question()
	if err != nil {
		result <- err
		return
	}
	response, err := buildNetResolverResponse(header.ID, question)
	if err != nil {
		result <- err
		return
	}
	flags := binary.BigEndian.Uint16(response[2:4]) | 0x0200
	binary.BigEndian.PutUint16(response[2:4], flags)
	response = response[:len(response)-3]
	_, err = connection.WriteToUDP(response, address)
	result <- err
}

func FuzzParseTXTResponse(f *testing.F) {
	seed := buildDNSResponse(f, dnsResponseFixture{id: 7, name: "example.test", txt: [][]string{{"v=spf1 ", "-all"}}, ttl: 300})
	f.Add(seed, uint16(7), "example.test")
	f.Add([]byte("not dns"), uint16(1), "example.test")
	f.Fuzz(func(t *testing.T, message []byte, id uint16, name string) {
		_, _, _ = parseTXTResponse(message, id, name, "fuzz")
	})
}

type dnsResponseFixture struct {
	id             uint16
	name           string
	authoritative  bool
	authenticData  bool
	rcode          dnsmessage.RCode
	cname          string
	txt            [][]string
	ttl            uint32
	secondTTL      uint32
	soa            bool
	soaTTL         uint32
	soaMinimum     uint32
	reverseAnswers bool
}

func buildDNSResponse(t testing.TB, fixture dnsResponseFixture) []byte {
	t.Helper()
	name := mustDNSName(t, fixture.name)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: fixture.id, Response: true, Authoritative: fixture.authoritative, RecursionAvailable: !fixture.authoritative, AuthenticData: fixture.authenticData, RCode: fixture.rcode,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if len(fixture.txt) > 0 || fixture.cname != "" {
		if err := builder.StartAnswers(); err != nil {
			t.Fatal(err)
		}
	}
	addCNAME := func() {
		if fixture.cname == "" {
			return
		}
		if err := builder.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: fixture.ttl}, dnsmessage.CNAMEResource{CNAME: mustDNSName(t, fixture.cname)}); err != nil {
			t.Fatal(err)
		}
	}
	addTXT := func() {
		for index, fragments := range fixture.txt {
			ttl := fixture.ttl
			if index == 1 && fixture.secondTTL != 0 {
				ttl = fixture.secondTTL
			}
			answerName := name
			if fixture.cname != "" {
				answerName = mustDNSName(t, fixture.cname)
			}
			if err := builder.TXTResource(dnsmessage.ResourceHeader{Name: answerName, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.TXTResource{TXT: fragments}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if fixture.reverseAnswers {
		addTXT()
		addCNAME()
	} else {
		addCNAME()
		addTXT()
	}
	if fixture.soa {
		if err := builder.StartAuthorities(); err != nil {
			t.Fatal(err)
		}
		if err := builder.SOAResource(dnsmessage.ResourceHeader{Name: mustDNSName(t, "test"), Class: dnsmessage.ClassINET, TTL: fixture.soaTTL}, dnsmessage.SOAResource{
			NS: mustDNSName(t, "ns.test"), MBox: mustDNSName(t, "hostmaster.test"), Serial: 1,
			Refresh: 2, Retry: 3, Expire: 4, MinTTL: fixture.soaMinimum,
		}); err != nil {
			t.Fatal(err)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func mustDNSName(t testing.TB, value string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(absoluteDNSName(value))
	if err != nil {
		t.Fatal(err)
	}
	return name
}
