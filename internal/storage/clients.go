package storage

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/jackc/pgx/v5"
	"math/big"

	"posrelayd-noip/internal/logger"
)

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
