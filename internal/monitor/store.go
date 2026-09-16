package monitor

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/happygream/dragnet/internal/model"

	_ "modernc.org/sqlite"
)

// Store persists scan snapshots and detected change events to SQLite.
// The pure-Go modernc driver keeps the binary CGO-free and portable.
type Store struct {
	db *sql.DB
}

// ChangeKind enumerates the kinds of change the diff engine can report.
type ChangeKind string

const (
	HostAppeared  ChangeKind = "host_appeared"
	HostVanished  ChangeKind = "host_vanished"
	PortOpened    ChangeKind = "port_opened"
	PortClosed    ChangeKind = "port_closed"
	CertExpiring  ChangeKind = "cert_expiring"
	DecoyDetected ChangeKind = "decoy_detected"
	DeviceChanged ChangeKind = "device_changed"
)

// Change is a single recorded difference between two scans.
type Change struct {
	ID      int64      `json:"id"`
	At      time.Time  `json:"at"`
	Kind    ChangeKind `json:"kind"`
	IP      string     `json:"ip"`
	Detail  string     `json:"detail"`
}

// OpenStore opens (creating if needed) the SQLite database at path and
// ensures the schema exists.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite: serialize writes, avoid "database is locked"
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS scans (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at TEXT NOT NULL,
	ended_at   TEXT NOT NULL,
	target     TEXT NOT NULL,
	hosts_up   INTEGER NOT NULL,
	snapshot   TEXT NOT NULL          -- JSON array of model.Host
);
CREATE TABLE IF NOT EXISTS changes (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	at      TEXT NOT NULL,
	kind    TEXT NOT NULL,
	ip      TEXT NOT NULL,
	detail  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_at ON changes(at DESC);
`
	_, err := s.db.Exec(schema)
	return err
}

// SaveScan stores a scan snapshot and returns its row id.
func (s *Store) SaveScan(target string, started, ended time.Time, hosts []model.Host) (int64, error) {
	blob, err := json.Marshal(hosts)
	if err != nil {
		return 0, err
	}
	up := 0
	for _, h := range hosts {
		if h.Alive {
			up++
		}
	}
	res, err := s.db.Exec(
		`INSERT INTO scans (started_at, ended_at, target, hosts_up, snapshot) VALUES (?,?,?,?,?)`,
		started.Format(time.RFC3339), ended.Format(time.RFC3339), target, up, string(blob),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LastSnapshot returns the most recent scan's host list, or nil if none.
func (s *Store) LastSnapshot() ([]model.Host, error) {
	row := s.db.QueryRow(`SELECT snapshot FROM scans ORDER BY id DESC LIMIT 1`)
	var blob string
	if err := row.Scan(&blob); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var hosts []model.Host
	if err := json.Unmarshal([]byte(blob), &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// RecordChanges inserts a batch of change events.
func (s *Store) RecordChanges(changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO changes (at, kind, ip, detail) VALUES (?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, c := range changes {
		if _, err := stmt.Exec(c.At.Format(time.RFC3339), string(c.Kind), c.IP, c.Detail); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// RecentChanges returns the most recent change events, newest first.
func (s *Store) RecentChanges(limit int) ([]Change, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, at, kind, ip, detail FROM changes ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Change
	for rows.Next() {
		var c Change
		var atStr string
		if err := rows.Scan(&c.ID, &atStr, &c.Kind, &c.IP, &c.Detail); err != nil {
			return nil, err
		}
		c.At, _ = time.Parse(time.RFC3339, atStr)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Stats returns quick counts for the dashboard header.
func (s *Store) Stats() (scans int, changes int, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&scans); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM changes`).Scan(&changes)
	return
}

