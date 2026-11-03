package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
)

var errAdminExists = errors.New("管理员已创建，请登录；不会覆盖已有账户")

func (s *Store) createAdmin(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 1 || len(username) > 64 || len(password) < 12 || len(password) > 256 || strings.ContainsAny(username+password, "\x00\r\n") {
		return errors.New("用户名为 1–64 字节，密码为 12–256 字节，均不能包含换行或空字符")
	}
	if s.hasAdmin() {
		return errAdminExists
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt[:], 600000, 32)
	if err != nil {
		return err
	}
	result, err := s.db.Exec("INSERT OR IGNORE INTO admin(id,username,salt,hash) VALUES(1,?,?,?)", username, salt[:], hash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errAdminExists
	}
	return nil
}

// Passwords arrive through stdin so they never appear in argv or service configuration.
func initializeAdmin(store *Store, username string, input io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(input, 259))
	if err != nil {
		return err
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	return store.createAdmin(username, password)
}
