package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPanelCertificateRenewalAndInvalidReplacement(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	notAfter := time.Now().Add(time.Hour)
	writePair := func(serial int64) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "panel.example.com"}, DNSNames: []string{"panel.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if cfg, err := panelTLSConfig("", "", ""); err != nil || cfg != nil {
		t.Fatal("HTTP configuration changed")
	}
	if _, err := panelTLSConfig(certFile, "", "panel.example.com"); err == nil {
		t.Fatal("missing key accepted")
	}
	writePair(1)
	if _, err := panelTLSConfig(certFile, keyFile, "wrong.example.com"); err == nil {
		t.Fatal("mismatched panel domain accepted")
	}
	cfg, err := panelTLSConfig(certFile, keyFile, "panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	writePair(2)
	renewed, err := cfg.GetCertificate(nil)
	if err != nil || renewed.Leaf.SerialNumber.Int64() != 2 || first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("renewal did not replace certificate safely", err)
	}
	if err := os.WriteFile(keyFile, []byte("incomplete key"), 0600); err != nil {
		t.Fatal(err)
	}
	retained, err := cfg.GetCertificate(nil)
	if err != nil || retained.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("invalid renewal replaced valid certificate", err)
	}
	notAfter = time.Now().Add(-time.Minute)
	writePair(3)
	retained, err = cfg.GetCertificate(nil)
	if err != nil || retained.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("expired renewal replaced valid certificate", err)
	}
	if _, err := panelTLSConfig(certFile, keyFile, "panel.example.com"); err == nil {
		t.Fatal("expired certificate accepted on startup")
	}
}
