package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type dcTransport func(*http.Request) (*http.Response, error)

func (f dcTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDCAddressRefreshValidationPersistenceAndFallback(t *testing.T) {
	s := testService(t)
	m, err := parseDCManifest(bundledDCs)
	if err != nil {
		t.Fatal(err)
	}
	m.Generation++
	m.Addresses[-2] = []string{"149.154.167.222:443"}
	m.Addresses[6] = []string{"149.154.175.50:443"}
	data, _ := json.Marshal(m)
	client := &http.Client{Transport: dcTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://raw.githubusercontent.com/wstimin/tg-relay/main/dc-seeds.json" {
			t.Fatal("unexpected DC source", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}
	if err := s.refreshDCs(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if got := s.dcs.addresses(-2); !reflect.DeepEqual(got, m.Addresses[-2]) {
		t.Fatal("media DC not preserved", got)
	}
	if got := newDCDirectory(s.store).addresses(6); !reflect.DeepEqual(got, m.Addresses[6]) {
		t.Fatal("DC cache not persisted", got)
	}
	data = bundledDCs
	if err := s.refreshDCs(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if got := s.dcs.addresses(-2); !reflect.DeepEqual(got, m.Addresses[-2]) {
		t.Fatal("old manifest replaced newer cache")
	}
	data = []byte(`{"generation":99,"addresses":{}}`)
	if err := s.refreshDCs(context.Background(), client); err == nil {
		t.Fatal("empty source accepted")
	}
	client.Transport = dcTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("network unavailable") })
	if err := s.refreshDCs(context.Background(), client); err == nil {
		t.Fatal("network failure hidden")
	}
	if got := s.dcs.addresses(-2); !reflect.DeepEqual(got, m.Addresses[-2]) {
		t.Fatal("network failure discarded usable cache")
	}
	if _, err := s.store.db.Exec("UPDATE dc_cache SET body=? WHERE id=1", []byte("bad cache")); err != nil {
		t.Fatal(err)
	}
	if got := newDCDirectory(s.store).addresses(2); !reflect.DeepEqual(got, dcAddresses(2)) {
		t.Fatal("corrupt cache prevented bundled fallback")
	}
}

func TestDCManifestRejectsUnsafeEndpoints(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "[::1]:443", "[fe80::1%eth0]:443", "100.64.1.2:443", "192.0.2.1:443", "[2001:db8::1]:443", "149.154.167.51:22", "example.com:443"} {
		m, _ := parseDCManifest(bundledDCs)
		m.Addresses[2] = []string{address}
		data, _ := json.Marshal(m)
		if _, err := parseDCManifest(data); err == nil {
			t.Fatal("unsafe endpoint accepted", address)
		}
	}
	if _, err := parseDCManifest([]byte(strings.Repeat(" ", 32769))); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}
