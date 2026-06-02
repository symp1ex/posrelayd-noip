package app

import (
	"fmt"
	"net/http"
	"net/url"

	"posrelayd-noip/internal/config"
	"posrelayd-noip/internal/logger"
	"posrelayd-noip/internal/storage"
	"posrelayd-noip/internal/ws"
)

func buildDSN() string {
	dbUser := config.Cfg.Db.User
	dbPass := config.Cfg.Db.Password
	dbHost := config.Cfg.Db.Host
	dbPort := config.Cfg.Db.Port
	dbName := config.Cfg.Db.Db_name

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(dbUser, dbPass),
		Host:   fmt.Sprintf("%s:%d", dbHost, dbPort),
		Path:   dbName,
	}

	return u.String()
}

func Run() error {
	dsn := buildDSN()

	logger.Websocket.Info("Initializing PostgreSQL storage...")

	db, err := storage.NewStorage(dsn)
	if err != nil {
		return err
	}

	defer db.Pool.Close()

	logger.Websocket.Info(
		"The storage has been connected successfully.",
	)

	port := config.Cfg.Service.Port

	server := ws.NewServer(db)

	http.HandleFunc("/ws", server.Handler)

	logger.Websocket.Infof(
		"Server listening on '%d'",
		port,
	)

	return http.ListenAndServe(
		fmt.Sprintf(":%d", port),
		nil,
	)
}
