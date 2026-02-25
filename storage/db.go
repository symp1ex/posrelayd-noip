package storage

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"posrelayd-noip/logger" // Импортируем ваш логгер
)

type ClientEntry struct {
	ID       string
	Password string
	TempPass string
}

type Storage struct {
	Pool *pgxpool.Pool
}

func NewStorage(dsn string) (*Storage, error) {
	ctx := context.Background()

	// 1. Разбор DSN
	u, err := url.Parse(dsn)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to parse DSN: %v", err)
		return nil, err
	}
	targetDB := strings.TrimPrefix(u.Path, "/")

	// Подготовка для системного подключения
	u.Path = "/postgres"
	systemDSN := u.String()

	logger.Websocket.Infof("DB: Checking/Creating database '%s' at %s", targetDB, u.Host)

	// 2. Системное подключение для проверки базы
	sysConn, err := pgx.Connect(ctx, systemDSN)
	if err != nil {
		logger.Websocket.Errorf("DB: System connection failed: %v", err)
		return nil, err
	}

	var exists bool
	err = sysConn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", targetDB).Scan(&exists)
	if err != nil {
		sysConn.Close(ctx)
		return nil, err
	}

	if !exists {
		logger.Websocket.Warnf("DB: Database '%s' does not exist. Creating...", targetDB)
		_, err = sysConn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", targetDB))
		if err != nil {
			sysConn.Close(ctx)
			logger.Websocket.Errorf("DB: Failed to create database: %v", err)
			return nil, err
		}
		logger.Websocket.Infof("DB: Database '%s' created successfully", targetDB)
	}
	sysConn.Close(ctx)

	// 3. Основной пул соединений
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to create connection pool: %v", err)
		return nil, err
	}

	// Проверка связи
	if err := pool.Ping(ctx); err != nil {
		logger.Websocket.Errorf("DB: Ping failed: %v", err)
		return nil, err
	}

	s := &Storage{Pool: pool}

	// 4. Инициализация таблиц
	if err := s.initTables(ctx); err != nil {
		return nil, err
	}

	logger.Websocket.Info("DB: Storage initialized successfully")
	return s, nil
}

func (s *Storage) initTables(ctx context.Context) error {
	logger.Websocket.Debug("DB: Ensuring tables 'clients' and 'blacklist' exist")
	query := `
	CREATE TABLE IF NOT EXISTS clients (
		id TEXT PRIMARY KEY,
		password TEXT DEFAULT '',
		temp_pass TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS blacklist (
		ip TEXT PRIMARY KEY,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := s.Pool.Exec(ctx, query)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to create tables: %v", err)
		return err
	}
	return nil
}

func (s *Storage) GetClient(ctx context.Context, id string) (*ClientEntry, error) {
	logger.Websocket.Debugf("DB: Fetching client data for ID: %s", id)
	var c ClientEntry
	err := s.Pool.QueryRow(ctx, "SELECT id, password, temp_pass FROM clients WHERE id=$1", id).Scan(&c.ID, &c.Password, &c.TempPass)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.Websocket.Debugf("DB: Client %s not found", id)
		} else {
			logger.Websocket.Errorf("DB: Error fetching client %s: %v", id, err)
		}
		return nil, err
	}
	return &c, nil
}

func (s *Storage) UpsertClient(ctx context.Context, id, pass, temp string) error {
	logger.Websocket.Debugf("DB: Upserting client data for ID: %s", id)
	query := `INSERT INTO clients (id, password, temp_pass) VALUES ($1, $2, $3)
              ON CONFLICT (id) DO UPDATE SET 
              password = CASE WHEN EXCLUDED.password != '' THEN EXCLUDED.password ELSE clients.password END,
              temp_pass = CASE WHEN EXCLUDED.temp_pass != '' THEN EXCLUDED.temp_pass ELSE clients.temp_pass END`
	_, err := s.Pool.Exec(ctx, query, id, pass, temp)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to upsert client %s: %v", id, err)
	}
	return err
}

func (s *Storage) IsBlacklisted(ctx context.Context, ip string) bool {
	var exists bool
	err := s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM blacklist WHERE ip=$1)", ip).Scan(&exists)
	if err != nil {
		logger.Websocket.Errorf("DB: Blacklist check error for %s: %v", ip, err)
		return false
	}
	if exists {
		logger.Websocket.Debugf("DB: IP %s found in blacklist", ip)
	}
	return exists
}
