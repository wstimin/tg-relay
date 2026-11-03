package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminBootstrapPreservesExistingAccount(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	for _, password := range []string{"short", strings.Repeat("x", 257), "twelve-chars\nextra"} {
		if initializeAdmin(s, "admin", strings.NewReader(password)) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	if err := initializeAdmin(s, " installer ", strings.NewReader("test-password-12345\r\n")); err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	var username string
	if err := s.db.QueryRow("SELECT username,hash FROM admin WHERE id=1").Scan(&username, &before); err != nil {
		t.Fatal(err)
	}
	if username != "installer" {
		t.Fatal("username was not normalized")
	}
	if err := initializeAdmin(s, "replacement", strings.NewReader("different-password")); !errors.Is(err, errAdminExists) {
		t.Fatalf("existing account: %v", err)
	}
	if err := s.db.QueryRow("SELECT hash FROM admin WHERE id=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing password changed")
	}
}
