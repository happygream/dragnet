package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/happygream/dragnet/internal/monitor"
	"github.com/happygream/dragnet/internal/scan"
)

func TestDashboard_ServesPageAndAPI(t *testing.T) {
	dir := t.TempDir()
	store, err := monitor.OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mon := monitor.New(scan.Config{Target: "10.0.0.0/24"}, time.Minute, store)
	srv := New(mon, store, "127.0.0.1:8899")

	ctx, cancel := context.WithCancel(context.Background())
	go srv.ListenAndServe(ctx)
	defer cancel()
	time.Sleep(200 * time.Millisecond)

	// Index page.
	resp, err := http.Get("http://127.0.0.1:8899/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "DRAGNET") {
		t.Fatalf("index page missing brand")
	}

	// State API.
	resp2, err := http.Get("http://127.0.0.1:8899/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&st)
	resp2.Body.Close()
	if st["target"] != "10.0.0.0/24" {
		t.Fatalf("state API wrong target: %v", st["target"])
	}
}
