package main

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

func panelTLSConfig(certFile, keyFile, host string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("HTTPS 证书和私钥必须同时指定")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	validate := func(cert *tls.Certificate) error {
		now := time.Now()
		if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
			return errors.New("面板证书尚未生效或已过期")
		}
		if host != "" {
			return cert.Leaf.VerifyHostname(host)
		}
		return nil
	}
	if err := validate(&certificate); err != nil {
		return nil, err
	}
	current := &certificate
	var mu sync.Mutex
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			// Reload renewed files on handshakes; keep the last valid pair during replacement.
			if renewed, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil && validate(&renewed) == nil {
				current = &renewed
			}
			return current, nil
		},
	}, nil
}
