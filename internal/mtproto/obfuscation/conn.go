// Adapted from 9seconds/mtg (MIT). See THIRD_PARTY_NOTICES.md.
package obfuscation

import (
	"crypto/cipher"
	"io"
	"net"
	"sync"
)

type conn struct {
	net.Conn

	sendCipher cipher.Stream
	recvCipher cipher.Stream
	readMu     *sync.Mutex
	writeMu    *sync.Mutex
}

func (c conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.recvCipher.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	buf := encryptedBuffers.Get().(*[16384]byte)
	defer encryptedBuffers.Put(buf)
	total := 0
	for len(p) > 0 {
		count := min(len(p), len(buf))
		chunk := buf[:count]
		c.sendCipher.XORKeyStream(chunk, p[:count])
		for len(chunk) > 0 {
			n, err := c.Conn.Write(chunk)
			total += n
			chunk = chunk[n:]
			if err != nil {
				return total, err
			}
			if n == 0 {
				return total, io.ErrShortWrite
			}
		}
		p = p[count:]
	}
	return total, nil
}

var encryptedBuffers = sync.Pool{New: func() any { return new([16384]byte) }}
