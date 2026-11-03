package main

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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
	initializeAdmin := func(s *Store, username string, input *strings.Reader) error {
		password, err := readAdminPassword(input)
		if err != nil {
			return err
		}
		_, err = s.saveAdmin(username, password, false)
		return err
	}
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

func TestLoginWithBrowserCookieJarOverHTTPAndHTTPS(t *testing.T) {
	for _, https := range []bool{false, true} {
		name := "HTTP"
		if https {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			s := testService(t)
			if _, err := s.store.saveAdmin("installer", "123456", false); err != nil {
				t.Fatal(err)
			}
			a := newAPI(s, "", false)
			var server *httptest.Server
			if https {
				server = httptest.NewTLSServer(a)
			} else {
				server = httptest.NewServer(a)
			}
			defer server.Close()
			client := server.Client()
			client.Jar, _ = cookiejar.New(nil)
			response, err := client.Post(server.URL+"/api/login", "application/json", strings.NewReader(`{"username":"installer","password":"123456"}`))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("login failed", response.StatusCode)
			}
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].Secure != https {
				t.Fatal("incorrect session cookie mode")
			}
			response, err = client.Get(server.URL + "/api/state")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("login cookie was not usable", response.StatusCode)
			}
		})
	}
}

func TestSixCharacterPasswordLoginAndReset(t *testing.T) {
	s := testService(t)
	password, err := readAdminPassword(strings.NewReader("123456"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.saveAdmin(" operator ", password, false); err != nil {
		t.Fatal(err)
	}
	a := newAPI(s, "", false)
	login := requestAPI(a, "POST", "/api/login", `{"username":" operator ","password":"123456"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Secure {
		t.Fatal("HTTP session cookie unavailable")
	}
	if got := requestAPI(a, "GET", "/api/state", "", cookies).Code; got != http.StatusOK {
		t.Fatal(got)
	}
	if err := s.store.saveUsage(map[string]Usage{"user:existing": {Upload: 123, Download: 456}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.saveAdmin("", " $ab! ", true); err != nil {
		t.Fatal(err)
	}
	if username, err := s.store.adminUsername(); err != nil || username != "operator" {
		t.Fatal(username, err)
	}
	if got := requestAPI(a, "GET", "/api/state", "", cookies).Code; got != http.StatusUnauthorized {
		t.Fatal("reset left old session active", got)
	}
	if _, err := s.store.authenticateAdmin("operator", "123456"); !errors.Is(err, errAdminCredentials) {
		t.Fatal("old password accepted", err)
	}
	login = requestAPI(a, "POST", "/api/login", `{"username":"operator","password":" $ab! "}`, nil)
	if login.Code != http.StatusOK {
		t.Fatal(login.Body.String())
	}
	if _, err := s.store.authenticateAdmin("operator", "$ab!"); !errors.Is(err, errAdminCredentials) {
		t.Fatal("password whitespace was changed", err)
	}
	_, usage, _, err := s.store.load()
	if err != nil || usage["user:existing"].Upload != 123 || usage["user:existing"].Download != 456 {
		t.Fatal("reset changed traffic", err)
	}
	if _, err := s.store.saveAdmin("renamed", "654321", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.authenticateAdmin("renamed", "654321"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.authenticateAdmin("operator", "654321"); !errors.Is(err, errAdminCredentials) {
		t.Fatal("old username accepted")
	}
	for range 10 {
		requestAPI(a, "POST", "/api/login", `{"username":"renamed","password":"wrong-password"}`, nil)
	}
	if got := requestAPI(a, "POST", "/api/login", `{"username":"renamed","password":"654321"}`, nil).Code; got != 429 {
		t.Fatal("login rate limit did not apply", got)
	}
	if _, err := s.store.saveAdmin("", "112233", true); err != nil {
		t.Fatal(err)
	}
	if got := requestAPI(a, "POST", "/api/login", `{"username":"renamed","password":"112233"}`, nil).Code; got != 200 {
		t.Fatal("password recovery retained old lockout", got)
	}
}
