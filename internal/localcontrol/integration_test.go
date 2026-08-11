package localcontrol

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/alertstore"
)

func TestServeRealStoreLifecycle(t *testing.T) {
	alertRoot := t.TempDir()

	backupRoot := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(alertRoot, "legacy.txt"),
		[]byte("<strong>Legacy</strong>"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	store, err := alertstore.Open(alertstore.Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			store,
			ready,
		)
	}()

	defer func() {
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not stop")
		}
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not become ready")
	}

	listResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"list"}`,
	)

	if !listResponse.OK {
		t.Fatalf(
			"initial list response = %#v; want success",
			listResponse,
		)
	}

	writeResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"write","target":"all","message":"Net open","actor":"K2EXE"}`,
	)

	requireSuccessResult(
		t,
		writeResponse,
		"all",
		"managed",
	)

	readResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"read","target":"all"}`,
	)

	readResult := resultObject(t, readResponse)

	if got := readResult["message"]; got != "Net open" {
		t.Fatalf(
			"read message = %#v; want Net open",
			got,
		)
	}

	convertResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"convert","target":"legacy","message":"Converted","actor":"K2EXE"}`,
	)

	convertResult := resultObject(t, convertResponse)

	if convertResult["target"] != "legacy" {
		t.Fatalf(
			"converted target = %#v; want legacy",
			convertResult["target"],
		)
	}

	if convertResult["kind"] != "managed" {
		t.Fatalf(
			"converted kind = %#v; want managed",
			convertResult["kind"],
		)
	}

	backupName, ok := convertResult["backup_name"].(string)
	if !ok || backupName == "" {
		t.Fatalf(
			"conversion backup_name = %#v; want non-empty string",
			convertResult["backup_name"],
		)
	}

	convertedRead := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"read","target":"legacy"}`,
	)

	convertedResult := resultObject(t, convertedRead)

	if convertedResult["message"] != "Converted" {
		t.Fatalf(
			"converted message = %#v; want Converted",
			convertedResult["message"],
		)
	}

	deleteResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"delete","target":"all","actor":"K2EXE"}`,
	)

	deleteResult := resultObject(t, deleteResponse)

	deleteBackup, ok := deleteResult["backup_name"].(string)
	if !ok || deleteBackup == "" {
		t.Fatalf(
			"delete backup_name = %#v; want non-empty string",
			deleteResult["backup_name"],
		)
	}

	missingResponse := controlRoundTrip(
		t,
		socketPath,
		`{"version":1,"operation":"read","target":"all"}`,
	)

	requireErrorCode(
		t,
		missingResponse,
		ErrorNotFound,
	)

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 2 {
		t.Fatalf(
			"backup count = %d; want 2",
			len(backups),
		)
	}
}

func controlRoundTrip(
	t *testing.T,
	socketPath string,
	request string,
) Response {
	t.Helper()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(
		time.Now().Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}

	if _, err := connection.Write(
		append([]byte(request), '\n'),
	); err != nil {
		t.Fatal(err)
	}

	var response Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}

	return response
}

func resultObject(
	t *testing.T,
	response Response,
) map[string]any {
	t.Helper()

	if !response.OK {
		t.Fatalf(
			"response = %#v; want success",
			response,
		)
	}

	result, ok := response.Result.(map[string]any)
	if !ok {
		t.Fatalf(
			"result type = %T; want JSON object",
			response.Result,
		)
	}

	return result
}

func requireSuccessResult(
	t *testing.T,
	response Response,
	target string,
	kind string,
) {
	t.Helper()

	result := resultObject(t, response)

	if result["target"] != target {
		t.Fatalf(
			"target = %#v; want %q",
			result["target"],
			target,
		)
	}

	if result["kind"] != kind {
		t.Fatalf(
			"kind = %#v; want %q",
			result["kind"],
			kind,
		)
	}
}
