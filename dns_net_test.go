package dmarcgo

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNetTXTResolverMarksMessageEvidenceUnavailable(t *testing.T) {
	serverErrors := make(chan error, 1)
	backend := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveNetResolverFixture(server, serverErrors)
			return client, nil
		},
	}
	result, err := (NetTXTResolver{Resolver: backend, ResolverID: "stdlib-fixture"}).LookupTXT(t.Context(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErrors; err != nil {
		t.Fatalf("fixture server: %v", err)
	}
	if result.Status != DNSObservationSuccess || len(result.Records) != 1 || result.Records[0].Joined != "v=spf1 -all" {
		t.Fatalf("TXT result = %+v", result)
	}
	if result.Records[0].FragmentsAvailable || len(result.Records[0].Fragments) != 0 {
		t.Fatalf("limited adapter invented TXT fragment boundaries: %+v", result.Records[0])
	}
	if result.TTL.Available || result.NegativeTTL.Available || result.SOA != nil || result.AnswerSource != DNSAnswerSourceUnknown || result.RCode.Available {
		t.Fatalf("limited adapter invented DNS-message evidence: %+v", result)
	}
}

func TestNetTXTResolverRequiresExplicitResolver(t *testing.T) {
	_, err := (NetTXTResolver{}).LookupTXT(t.Context(), "example.test")
	if !errors.Is(err, ErrInvalidDNSCollectionOptions) {
		t.Fatalf("error = %v", err)
	}
}

func serveNetResolverFixture(connection net.Conn, result chan<- error) {
	var operationErr error
	defer func() { result <- errors.Join(operationErr, connection.Close()) }()
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		operationErr = err
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(connection, query); err != nil {
		operationErr = err
		return
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		operationErr = err
		return
	}
	question, err := parser.Question()
	if err != nil {
		operationErr = err
		return
	}
	response, err := buildNetResolverResponse(header.ID, question)
	if err != nil {
		operationErr = err
		return
	}
	framed := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(framed, uint16(len(response)))
	copy(framed[2:], response)
	operationErr = writeDNSBytes(connection, framed)
}

func buildNetResolverResponse(id uint16, question dnsmessage.Question) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if err := builder.TXTResource(
		dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.TXTResource{TXT: []string{"v=spf1 -all"}},
	); err != nil {
		return nil, err
	}
	return builder.Finish()
}
