package localcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeEmitsMutationAuditThroughSocketPath(t *testing.T) {
	socketPath := testSocketPath(t)

	var audit bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveWithAuditWriter(
			ctx,
			socketPath,
			&fakeStore{},
			ready,
			&audit,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf(
			"server exited before ready: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("server did not become ready")
	}

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = connection.Write([]byte(
		`{"version":2,"operation":"write","target":"all",` +
			`"message":"SECRET MESSAGE","audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}` +
			"\n",
	))
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}

	var response Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if !response.OK {
		t.Fatalf(
			"response = %#v; want success",
			response,
		)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	got := audit.String()

	for _, expected := range []string{
		"aamm-ng audit",
		`auth_node="TEST-NODE-A"`,
		`operation="write"`,
		`target="all"`,
		`outcome="success"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"audit output missing %q: %q",
				expected,
				got,
			)
		}
	}

	if strings.Contains(got, "SECRET MESSAGE") {
		t.Fatalf(
			"audit output leaked message: %q",
			got,
		)
	}
}

func TestServeAuditsMutationRejectedBeforeDispatch(t *testing.T) {
	socketPath := testSocketPath(t)

	var audit bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveWithAuditWriter(
			ctx,
			socketPath,
			&fakeStore{},
			ready,
			&audit,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("server exited before ready: %v", err)
	case <-time.After(time.Second):
		t.Fatal("server did not become ready")
	}

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = connection.Write([]byte(
		`{"version":2,"operation":"write","target":"all",` +
			`"message":"SECRET REJECTED MESSAGE",` +
			`"audit":{"auth_node":"TEST-NODE-A\nforged",` +
			`"auth_role":"admin","source_ip":"192.0.2.44"}}` +
			"\n",
	))
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}

	var response Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if response.OK || response.Error == nil {
		t.Fatalf(
			"response = %#v; want validation failure",
			response,
		)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	got := audit.String()

	for _, expected := range []string{
		"aamm-ng audit",
		`operation="write"`,
		`target="all"`,
		`outcome="failure"`,
		`error_code="` + response.Error.Code + `"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"audit output missing %q: %q",
				expected,
				got,
			)
		}
	}

	for _, forbidden := range []string{
		"auth_node=",
		"auth_role=",
		"source_ip=",
		"source_node=",
		"source_host=",
		"TEST-NODE-A",
		"forged",
		"SECRET REJECTED MESSAGE",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf(
				"audit output leaked %q: %q",
				forbidden,
				got,
			)
		}
	}
}
