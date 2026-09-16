package monitor

import (
	"testing"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

func host(ip string, ports ...int) model.Host {
	h := model.Host{IP: ip, Alive: true}
	for _, p := range ports {
		h.OpenPorts = append(h.OpenPorts, model.PortState{Port: p, Open: true})
	}
	return h
}

func findChange(cs []Change, kind ChangeKind, ip string) *Change {
	for i := range cs {
		if cs[i].Kind == kind && cs[i].IP == ip {
			return &cs[i]
		}
	}
	return nil
}

func TestDiff_FirstScanAllAppear(t *testing.T) {
	cur := []model.Host{host("10.0.0.1", 80), host("10.0.0.2", 22)}
	cs := Diff(nil, cur, time.Now())
	if findChange(cs, HostAppeared, "10.0.0.1") == nil || findChange(cs, HostAppeared, "10.0.0.2") == nil {
		t.Fatalf("expected both hosts to appear, got %+v", cs)
	}
}

func TestDiff_PortOpenedAndClosed(t *testing.T) {
	prev := []model.Host{host("10.0.0.1", 80)}
	cur := []model.Host{host("10.0.0.1", 80, 443)}
	cs := Diff(prev, cur, time.Now())
	if findChange(cs, PortOpened, "10.0.0.1") == nil {
		t.Fatalf("expected port_opened, got %+v", cs)
	}

	cur2 := []model.Host{host("10.0.0.1")}
	cs2 := Diff(prev, cur2, time.Now())
	if findChange(cs2, PortClosed, "10.0.0.1") == nil {
		t.Fatalf("expected port_closed, got %+v", cs2)
	}
}

func TestDiff_HostVanished(t *testing.T) {
	prev := []model.Host{host("10.0.0.1", 80), host("10.0.0.2", 22)}
	cur := []model.Host{host("10.0.0.1", 80)}
	cs := Diff(prev, cur, time.Now())
	if findChange(cs, HostVanished, "10.0.0.2") == nil {
		t.Fatalf("expected host_vanished for .2, got %+v", cs)
	}
}

func TestDiff_DecoyAndDevice(t *testing.T) {
	p := host("10.0.0.5", 22)
	p.Device = "Ubuntu Linux"
	c := host("10.0.0.5", 22)
	c.Device = "Windows host"
	c.Honeypot = true
	c.HoneypotReason = "many silent lure ports"
	cs := Diff([]model.Host{p}, []model.Host{c}, time.Now())
	if findChange(cs, DeviceChanged, "10.0.0.5") == nil {
		t.Fatalf("expected device_changed, got %+v", cs)
	}
	if findChange(cs, DecoyDetected, "10.0.0.5") == nil {
		t.Fatalf("expected decoy_detected, got %+v", cs)
	}
}

func TestDiff_CertExpiring(t *testing.T) {
	p := host("10.0.0.6", 443)
	p.TLS = []model.TLSInfo{{Port: 443, DaysUntilExpiry: 90}}
	c := host("10.0.0.6", 443)
	c.TLS = []model.TLSInfo{{Port: 443, DaysUntilExpiry: 10}}
	cs := Diff([]model.Host{p}, []model.Host{c}, time.Now())
	if findChange(cs, CertExpiring, "10.0.0.6") == nil {
		t.Fatalf("expected cert_expiring, got %+v", cs)
	}
}

func TestDiff_NoChangeWhenStable(t *testing.T) {
	prev := []model.Host{host("10.0.0.1", 80, 443)}
	cur := []model.Host{host("10.0.0.1", 80, 443)}
	cs := Diff(prev, cur, time.Now())
	if len(cs) != 0 {
		t.Fatalf("expected no changes on stable scan, got %+v", cs)
	}
}
