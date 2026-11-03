package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"strings"
)

var errAdminExists = errors.New("管理员已创建，请登录；不会覆盖已有账户")
var errAdminCredentials = errors.New("用户名或密码错误；可在服务器运行 tg 重置管理员账号")

func (s *Store) saveAdmin(username, password string, reset bool) ([32]byte, error) {
	if reset && username == "" {
		var err error
		username, err = s.adminUsername()
		if err != nil {
			return [32]byte{}, err
		}
	}
	username = strings.TrimSpace(username)
	if len(username) < 1 || len(username) > 64 || len(password) < 6 || len(password) > 256 || strings.ContainsAny(username+password, "\x00\r\n") {
		return [32]byte{}, errors.New("用户名为 1–64 字节，密码为 6–256 字节，均不能包含换行或空字符")
	}
	if !reset && s.hasAdmin() {
		return [32]byte{}, errAdminExists
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [32]byte{}, err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt[:], 600000, 32)
	if err != nil {
		return [32]byte{}, err
	}
	query := "INSERT OR IGNORE INTO admin(id,username,salt,hash) VALUES(1,?,?,?)"
	if reset {
		query = "UPDATE admin SET username=?,salt=?,hash=? WHERE id=1"
	}
	result, err := s.db.Exec(query, username, salt[:], hash)
	if err != nil {
		return [32]byte{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return [32]byte{}, err
	}
	if n != 1 {
		if reset {
			return [32]byte{}, errors.New("尚未创建管理员，请先安装初始化")
		}
		return [32]byte{}, errAdminExists
	}
	return sha256.Sum256(hash), nil
}

// Passwords arrive through stdin so they never appear in argv or service configuration.
func readAdminPassword(input io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(input, 259))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}
func (s *Store) adminUsername() (string, error) {
	var username string
	err := s.db.QueryRow("SELECT username FROM admin WHERE id=1").Scan(&username)
	return username, err
}
func (s *Store) authenticateAdmin(username, password string) ([32]byte, error) {
	var storedUsername string
	var salt, expected []byte
	err := s.db.QueryRow("SELECT username,salt,hash FROM admin WHERE id=1").Scan(&storedUsername, &salt, &expected)
	if err != nil {
		return [32]byte{}, err
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil || len(password) > 256 || subtle.ConstantTimeCompare(actual, expected) != 1 || subtle.ConstantTimeCompare([]byte(storedUsername), []byte(strings.TrimSpace(username))) != 1 {
		return [32]byte{}, errAdminCredentials
	}
	return sha256.Sum256(expected), nil
}
