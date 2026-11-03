package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func dialOutbound(ctx context.Context, o Outbound, target string) (net.Conn, error) {
	if !o.Enabled {
		return nil, errors.New("出口已停用")
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	if o.Type == "DIRECT" {
		return dialer.DialContext(ctx, "tcp", target)
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(o.Host, strconv.Itoa(o.Port)))
	if err != nil {
		return nil, fmt.Errorf("无法连接落地服务器: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	var tunnel net.Conn = conn
	if o.Type == "HTTPS" {
		secured := tls.Client(conn, &tls.Config{ServerName: o.Host, MinVersion: tls.VersionTLS12})
		if err = secured.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("落地 TLS 验证失败: %w", err)
		}
		tunnel = secured
	}
	switch o.Type {
	case "SOCKS5":
		err = socksConnect(tunnel, o, target)
	case "HTTP", "HTTPS":
		tunnel, err = httpConnect(tunnel, o, target)
	default:
		err = errors.New("不支持的出口协议")
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	if err = tunnel.SetDeadline(time.Time{}); err != nil {
		tunnel.Close()
		return nil, err
	}
	return tunnel, nil
}
func socksConnect(conn net.Conn, o Outbound, target string) error {
	method := byte(0)
	if o.Account != "" {
		method = 2
	}
	if err := writeAll(conn, []byte{5, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != method {
		return errors.New("SOCKS5 认证方式不匹配")
	}
	if method == 2 {
		packet := append([]byte{1, byte(len(o.Account))}, []byte(o.Account)...)
		packet = append(packet, byte(len(o.Password)))
		packet = append(packet, []byte(o.Password)...)
		if err := writeAll(conn, packet); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return errors.New("SOCKS5 账号或密码错误")
		}
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("目标端口无效")
	}
	packet := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		packet = append(packet, 1)
		packet = append(packet, v4...)
	} else if ip != nil {
		packet = append(packet, 4)
		packet = append(packet, ip.To16()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("目标域名无效")
		}
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}
	packet = binary.BigEndian.AppendUint16(packet, uint16(port))
	if err = writeAll(conn, packet); err != nil {
		return err
	}
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return fmt.Errorf("SOCKS5 CONNECT 失败，状态码 %d", header[1])
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var b [1]byte
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			return err
		}
		length = int(b[0])
	default:
		return errors.New("SOCKS5 返回了无效地址类型")
	}
	_, err = io.CopyN(io.Discard, conn, int64(length+2))
	return err
}
func httpConnect(conn net.Conn, o Outbound, target string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if o.Account != "" || o.Password != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(o.Account+":"+o.Password)))
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 4096)
	var headers bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, errors.New("HTTP 代理响应不完整或响应行过长")
		}
		if headers.Len()+len(line) > 32768 {
			return nil, errors.New("HTTP 代理响应头过大")
		}
		headers.Write(line)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headers.Bytes())), req)
	if err != nil {
		return nil, errors.New("HTTP 代理响应无效")
	}
	if resp.StatusCode == 407 {
		return nil, errors.New("HTTP 代理账号或密码错误")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP CONNECT 失败，状态码 %d", resp.StatusCode)
	}
	// Keep bytes read beyond the CONNECT headers; they belong to the target tunnel.
	return &bufferedConn{Conn: conn, reader: reader}, nil
}
