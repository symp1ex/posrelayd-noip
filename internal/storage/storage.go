package storage

import (
	"context"
	"fmt"
	"net/url"
	"posrelayd-noip/internal/logger"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ClientEntry struct {
	ID         string
	Password   string
	TempPass   string
	ClientCode int64
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
	if _, err := s.Pool.Exec(ctx, query); err != nil {
		logger.Websocket.Errorf("DB: Failed to create tables: %v", err)
		return err
	}

	if _, err := s.Pool.Exec(ctx, `
		ALTER TABLE clients
		ADD COLUMN IF NOT EXISTS client_code BIGINT UNIQUE
	`); err != nil {
		logger.Websocket.Errorf("DB: Failed to add client_code column: %v", err)
		return err
	}

	if err := s.migrateClientCodes(ctx); err != nil {
		return err
	}

	return nil
}

func (s *Storage) migrateClientCodes(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `
		SELECT id
		FROM clients
		WHERE client_code IS NULL
	`)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to fetch clients without client_code: %v", err)
		return err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	for _, id := range ids {
		code, err := s.ensureClientCode(ctx, id)
		if err != nil {
			logger.Websocket.Errorf("DB: Failed to migrate client_code for %s: %v", id, err)
			return err
		}

		logger.Websocket.Infof("DB: Migrated client_code for %s: %d", id, code)
	}

	return nil
}
