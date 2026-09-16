package monitor

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

func TestStore_SaveAndDiffCycle(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// No snapshot yet.
	prev, err := st.LastSnapshot()
	if err != nil || prev != nil {
		t.Fatalf("expected empty, got %v err %v", prev, err)
	}

	// First scan: one host.
	s1 := []model.Host{host("10.0.0.1", 80)}
	if _, err := st.SaveScan("net", time.Now(), time.Now(), s1); err != nil {
		t.Fatal(err)
	}
	c1 := Diff(nil, s1, time.Now())
	if err := st.RecordChanges(c1); err != nil {
		t.Fatal(err)
	}

	// Round-trip snapshot.
	got, err := st.LastSnapshot()
	if err != nil || len(got) != 1 || got[0].IP != "10.0.0.1" {
		t.Fatalf("snapshot round-trip failed: %+v err %v", got, err)
	}

	// Second scan: port opens.
	s2 := []model.Host{host("10.0.0.1", 80, 443)}
	prev2, _ := st.LastSnapshot()
	c2 := Diff(prev2, s2, time.Now())
	if findChange(c2, PortOpened, "10.0.0.1") == nil {
		t.Fatalf("expected port_opened across persisted scans, got %+v", c2)
	}
	st.SaveScan("net", time.Now(), time.Now(), s2)
	st.RecordChanges(c2)

	// Recent changes should include both events.
	rc, err := st.RecentChanges(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc) < 2 {
		t.Fatalf("expected >=2 recorded changes, got %d", len(rc))
	}

	scans, changes, err := st.Stats()
	if err != nil || scans != 2 {
		t.Fatalf("stats wrong: scans=%d changes=%d err=%v", scans, changes, err)
	}
}
