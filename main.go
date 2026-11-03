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
	adminStatus := flag.Bool("admin-status", false, "打印管理员初始化状态后退出")
	adminUser := flag.String("admin-user", "admin", "首次创建的管理员用户名（配合 -init-admin）")
	flag.Parse()
	if *initAdmin || *adminStatus {
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
		if err := initializeAdmin(store, *adminUser, os.Stdin); err != nil {
			return err
		}
		log.Print("管理员已创建")
		return nil
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
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	failed := make(chan error, 1)
	go func() {
		log.Printf("TG Relay: http://%s", *listen)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
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
