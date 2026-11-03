package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

//go:embed web/*
var assets embed.FS

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8765", "管理面板监听地址")
	dataDir := flag.String("data", "data", "SQLite 数据目录")
	adminHost := flag.String("admin-host", "", "允许访问管理面板的额外主机名，例如 panel.example.com")
	secureCookie := flag.Bool("secure-cookie", false, "经 HTTPS 反向代理访问时启用安全 Cookie")
	initAdmin := flag.Bool("init-admin", false, "从标准输入读取密码并首次创建管理员后退出")
	resetAdmin := flag.Bool("reset-admin", false, "从标准输入读取新密码并重置管理员；保留代理配置和流量")
	verifyAdmin := flag.Bool("verify-admin", false, "从标准输入读取密码并验证管理员凭据后退出")
	adminStatus := flag.Bool("admin-status", false, "打印管理员初始化状态后退出")
	showAdmin := flag.Bool("admin-username", false, "打印当前管理员用户名后退出")
	adminUser := flag.String("admin-user", "", "管理员用户名；初始化默认为 admin，重置时留空保留原用户名")
	tlsCert := flag.String("tls-cert", "", "面板 HTTPS PEM 证书路径，与 -tls-key 一起使用")
	tlsKey := flag.String("tls-key", "", "面板 HTTPS 私钥路径")
	flag.Parse()
	adminCommands := 0
	for _, enabled := range []bool{*initAdmin, *resetAdmin, *verifyAdmin, *adminStatus, *showAdmin} {
		if enabled {
			adminCommands++
		}
	}
	if adminCommands > 1 {
		return errors.New("管理员命令不能同时使用")
	}
	if adminCommands == 1 {
		store, err := openStore(filepath.Join(*dataDir, "tg-relay.db"))
		if err != nil {
			return err
		}
		defer store.db.Close()
		if *adminStatus {
			if store.hasAdmin() {
				fmt.Println("initialized")
			} else {
				fmt.Println("uninitialized")
			}
			return nil
		}
		if *showAdmin {
			username, err := store.adminUsername()
			if err != nil {
				return err
			}
			fmt.Println(username)
			return nil
		}
		password, err := readAdminPassword(os.Stdin)
		if err != nil {
			return err
		}
		if *verifyAdmin {
			_, err = store.authenticateAdmin(*adminUser, password)
			return err
		}
		if *initAdmin && *adminUser == "" {
			*adminUser = "admin"
		}
		if _, err := store.saveAdmin(*adminUser, password, *resetAdmin); err != nil {
			return err
		}
		log.Print("管理员账号已保存")
		return nil
	}
	tlsConfig, err := panelTLSConfig(*tlsCert, *tlsKey, *adminHost)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	store, err := openStore(filepath.Join(*dataDir, "tg-relay.db"))
	if err != nil {
		return err
	}
	defer store.db.Close()
	service, err := newService(store)
	if err != nil {
		return err
	}
	api := newAPI(service, *adminHost, *secureCookie)
	web, _ := fs.Sub(assets, "web")
	files := http.FileServer(http.FS(web))
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		files.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: *listen, Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	failed := make(chan error, 1)
	go func() {
		scheme := "http"
		if tlsConfig != nil {
			scheme = "https"
		}
		log.Printf("TG Relay: %s://%s", scheme, *listen)
		var err error
		if tlsConfig == nil {
			err = server.Serve(listener)
		} else {
			err = server.ServeTLS(listener, "", "")
		}
		if err != nil && err != http.ErrServerClosed {
			failed <- err
		}
	}()
	var result error
	select {
	case <-stopped:
	case result = <-failed:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	return errors.Join(result, service.close())
}
