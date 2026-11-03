package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func openStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS usage (kind TEXT NOT NULL, id TEXT NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time TEXT NOT NULL, level TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) load() (*Config, map[string]Usage, []Event, error) {
	c := &Config{Inbounds: []Inbound{}, Outbounds: []Outbound{}, Routes: []Route{}, Users: []User{}, Credentials: []Credential{}, Settings: Settings{Workspace: "我的工作空间"}}
	var body []byte
	err := s.db.QueryRow("SELECT body FROM config WHERE id=1").Scan(&body)
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, nil, err
	}
	if err == nil {
		if err = json.Unmarshal(body, c); err != nil {
			return nil, nil, nil, fmt.Errorf("配置数据损坏: %w", err)
		}
		if err = validateConfig(c); err != nil {
			return nil, nil, nil, err
		}
	}
	usage := map[string]Usage{}
	rows, err := s.db.Query("SELECT kind,id,upload,download FROM usage")
	if err != nil {
		return nil, nil, nil, err
	}
	for rows.Next() {
		var kind, id string
		var u Usage
		if err = rows.Scan(&kind, &id, &u.Upload, &u.Download); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		usage[kind+":"+id] = u
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err = s.db.Query("SELECT time,level,title,detail FROM events ORDER BY id DESC LIMIT 200")
	if err != nil {
		return nil, nil, nil, err
	}
	events := []Event{}
	for rows.Next() {
		var e Event
		var ts string
		if err = rows.Scan(&ts, &e.Level, &e.Title, &e.Detail); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	return c, usage, events, err
}
func (s *Store) saveConfig(c *Config) error {
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO config(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", body)
	return err
}
func (s *Store) saveUsage(usage map[string]Usage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO usage(kind,id,upload,download) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET upload=excluded.upload,download=excluded.download")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for key, u := range usage {
		kind, id, ok := splitUsageKey(key)
		if !ok {
			continue
		}
		if _, err = stmt.Exec(kind, id, u.Upload, u.Download); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func splitUsageKey(key string) (string, string, bool) {
	for i := range key {
		if key[i] == ':' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}
func (s *Store) event(e Event) error {
	_, err := s.db.Exec("INSERT INTO events(time,level,title,detail) VALUES(?,?,?,?)", e.Time.Format(time.RFC3339Nano), e.Level, e.Title, e.Detail)
	if err == nil {
		_, err = s.db.Exec("DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-500 FROM events)")
	}
	return err
}
func (s *Store) hasAdmin() bool {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&n)
	return n > 0
}
