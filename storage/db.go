package storage

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"posrelayd-noip/logger" // Импортируем ваш логгер
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

func generateClientCode() (int64, error) {
	const min int64 = 10000000
	const max int64 = 99999999

	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return 0, err
	}

	return min + n.Int64(), nil
}

func (s *Storage) ensureClientCode(ctx context.Context, id string) (int64, error) {
	for attempts := 0; attempts < 20; attempts++ {
		code, err := generateClientCode()
		if err != nil {
			return 0, err
		}

		var savedCode int64
		err = s.Pool.QueryRow(ctx, `
			UPDATE clients
			SET client_code = $1
			WHERE id = $2
			  AND client_code IS NULL
			  AND NOT EXISTS (
				  SELECT 1 FROM clients WHERE client_code = $1
			  )
			RETURNING client_code
		`, code, id).Scan(&savedCode)

		if err == nil {
			return savedCode, nil
		}

		if err == pgx.ErrNoRows {
			var existingCode int64
			existingErr := s.Pool.QueryRow(ctx, `
				SELECT client_code
				FROM clients
				WHERE id = $1
				  AND client_code IS NOT NULL
			`, id).Scan(&existingCode)

			if existingErr == nil {
				return existingCode, nil
			}

			continue
		}

		return 0, err
	}

	return 0, fmt.Errorf("failed to generate unique client_code for client %s", id)
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

func (s *Storage) GetClient(ctx context.Context, id string) (*ClientEntry, error) {
	logger.Websocket.Debugf("DB: Fetching client data for ID: %s", id)

	var c ClientEntry
	err := s.Pool.QueryRow(ctx, `
		SELECT id, password, temp_pass, client_code
		FROM clients
		WHERE id = $1
	`, id).Scan(&c.ID, &c.Password, &c.TempPass, &c.ClientCode)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.Websocket.Debugf("DB: Client %s not found", id)
		} else {
			logger.Websocket.Errorf("DB: Error fetching client %s: %v", id, err)
		}
		return nil, err
	}

	if c.ClientCode == 0 {
		code, err := s.ensureClientCode(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		c.ClientCode = code
	}

	return &c, nil
}

func (s *Storage) UpsertClient(ctx context.Context, id, pass, temp string) error {
	logger.Websocket.Debugf("DB: Upserting client data for ID: %s", id)

	query := `
		INSERT INTO clients (id, password, temp_pass)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET
			password = CASE
				WHEN EXCLUDED.password != '' THEN EXCLUDED.password
				ELSE clients.password
			END,
			temp_pass = CASE
				WHEN EXCLUDED.temp_pass != '' THEN EXCLUDED.temp_pass
				ELSE clients.temp_pass
			END
	`

	_, err := s.Pool.Exec(ctx, query, id, pass, temp)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to upsert client %s: %v", id, err)
		return err
	}

	_, err = s.ensureClientCode(ctx, id)
	if err != nil {
		logger.Websocket.Errorf("DB: Failed to ensure client_code for %s: %v", id, err)
		return err
	}

	return nil
}

func (s *Storage) ResolveClientID(ctx context.Context, clientID string) (string, error) {
	var id string

	err := s.Pool.QueryRow(ctx, `
		SELECT id
		FROM clients
		WHERE id = $1
	`, clientID).Scan(&id)

	if err == nil {
		return id, nil
	}

	if err != pgx.ErrNoRows {
		return "", err
	}

	var code int64
	if _, scanErr := fmt.Sscanf(clientID, "%d", &code); scanErr != nil {
		return "", pgx.ErrNoRows
	}

	err = s.Pool.QueryRow(ctx, `
		SELECT id
		FROM clients
		WHERE client_code = $1
	`, code).Scan(&id)

	if err != nil {
		return "", err
	}

	return id, nil
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
