package fake

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

type fixtureConn struct{ *bytes.Reader }

func (fixtureConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fixtureConn) Close() error                     { return nil }
func (fixtureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (fixtureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (fixtureConn) SetDeadline(time.Time) error      { return nil }
func (fixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (fixtureConn) SetWriteDeadline(time.Time) error { return nil }

func TestIndependentCapturedHelloAndMultipleKeys(t *testing.T) {
	for _, name := range []string{"client-hello-ok-19dfe38384b9884b.json", "client-hello-ok-grease-first.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Full   string `json:"full"`
				Host   string `json:"host"`
				Cipher int    `json:"cipherSuite"`
			}
			if err = json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			packet, _ := base64.StdEncoding.DecodeString(fixture.Full)
			// The public key comes from the upstream capture's serialized ee secret.
			serialized := "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
			key, _ := hex.DecodeString(serialized[2:34])
			bad := bytes.Repeat([]byte{1}, 16)
			hello, index, err := ReadClientHello(fixtureConn{bytes.NewReader(packet)}, [][]byte{bad, key}, fixture.Host, 50*365*24*time.Hour)
			if err != nil || index != 1 {
				t.Fatalf("captured multi-key authentication failed: index=%d err=%v", index, err)
			}
			if int(hello.CipherSuite) != fixture.Cipher {
				t.Fatal("cipher selection differs from independent capture")
			}
			if _, _, err = ReadClientHello(fixtureConn{bytes.NewReader(packet)}, [][]byte{key}, fixture.Host, 5*time.Minute); err == nil {
				t.Fatal("expired captured timestamp accepted")
			}
			if _, _, err = ReadClientHello(fixtureConn{bytes.NewReader(packet)}, [][]byte{key}, "wrong.example", 50*365*24*time.Hour); err == nil {
				t.Fatal("wrong SNI accepted")
			}
		})
	}
}
func FuzzClientHelloBounds(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{0x16, 3, 1, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadClientHello(fixtureConn{bytes.NewReader(data)}, [][]byte{make([]byte, 16)}, "example.com", time.Minute)
	})
}
