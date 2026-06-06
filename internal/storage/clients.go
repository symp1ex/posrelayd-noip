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
		SELECT
			id,
			COALESCE(password, ''),
			COALESCE(temp_pass, ''),
			COALESCE(client_code, 0),
			COALESCE(signature, '')
		FROM clients
		WHERE id = $1
	`, id).Scan(
		&c.ID,
		&c.Password,
		&c.TempPass,
		&c.ClientCode,
		&c.Signature,
	)

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

func (s *Storage) GetClientBySignature(ctx context.Context, sig string) (*ClientEntry, error) {
	logger.Websocket.Debugf("Storage: lookup client by signature, signatureLen=%d", len(sig))

	var c ClientEntry
	err := s.Pool.QueryRow(ctx, `
		SELECT id, password, temp_pass, client_code, signature
		FROM clients
		WHERE signature = $1
	`, sig).Scan(&c.ID, &c.Password, &c.TempPass, &c.ClientCode, &c.Signature)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.Websocket.Debugf("Storage: client by signature not found, signatureLen=%d", len(sig))
		} else {
			logger.Websocket.Errorf("Storage: failed to lookup client by signature, signatureLen=%d: %v", len(sig), err)
		}
		return nil, err
	}
	logger.Websocket.Debugf("Storage: client by signature found, clientID=%s", c.ID)
	return &c, nil
}

func (s *Storage) UpdateClientSignature(ctx context.Context, id, sig string) error {
	_, err := s.Pool.Exec(ctx, "UPDATE clients SET signature = $1 WHERE id = $2", sig, id)
	if err != nil {
		logger.Websocket.Errorf("Storage: failed to update client signature, clientID=%s: %v", id, err)
	} else {
		logger.Websocket.Infof(
			"Storage: client signature updated, clientID=%s, signatureProvided=%t",
			id,
			sig != "",
		)
	}
	return err
}

func (s *Storage) ResolveClientID(ctx context.Context, clientID string) (string, error) {
	logger.Websocket.Debugf("Storage: resolving client ID, input=%s", clientID)

	var id string

	err := s.Pool.QueryRow(ctx, `
		SELECT id
		FROM clients
		WHERE id = $1
	`, clientID).Scan(&id)

	if err == nil {
		logger.Websocket.Infof("Storage: client resolved by ID, clientID=%s", id)
		return id, nil
	}

	if err != pgx.ErrNoRows {
		logger.Websocket.Errorf("Storage: failed to resolve client by ID, input=%s: %v", clientID, err)
		return "", err
	}

	logger.Websocket.Debugf("Storage: client not found by ID, trying client_code, input=%s", clientID)

	var code int64
	if _, scanErr := fmt.Sscanf(clientID, "%d", &code); scanErr != nil {
		logger.Websocket.Debugf("Storage: input is not a numeric client_code, input=%s: %v", clientID, scanErr)
		return "", pgx.ErrNoRows
	}

	err = s.Pool.QueryRow(ctx, `
		SELECT id
		FROM clients
		WHERE client_code = $1
	`, code).Scan(&id)

	if err != nil {
		logger.Websocket.Errorf("Storage: failed to resolve client by client_code, code=%d: %v", code, err)
		return "", err
	}
	logger.Websocket.Infof("Storage: client resolved by client_code, clientID=%s, code=%d", id, code)
	return id, nil
}

func generateClientCode() (int64, error) {
	const min int64 = 10000000
	const max int64 = 99999999

	logger.Websocket.Debugf("Storage: generating client_code")

	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		logger.Websocket.Errorf("Storage: failed to generate client_code: %v", err)
		return 0, err
	}

	return min + n.Int64(), nil
}

func (s *Storage) ensureClientCode(ctx context.Context, id string) (int64, error) {
	logger.Websocket.Debugf("Storage: ensuring client_code, clientID=%s", id)

	for attempts := 0; attempts < 20; attempts++ {
		logger.Websocket.Debugf(
			"Storage: client_code generation attempt, clientID=%s, attempt=%d",
			id,
			attempts+1,
		)

		code, err := generateClientCode()
		if err != nil {
			logger.Websocket.Errorf(
				"Storage: failed to generate client_code for client %s: %v",
				id,
				err,
			)
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
			logger.Websocket.Infof(
				"Storage: client_code assigned, clientID=%s",
				id,
			)
			return savedCode, nil
		}

		if err == pgx.ErrNoRows {
			logger.Websocket.Debugf(
				"Storage: client_code was not assigned, checking existing code, clientID=%s",
				id,
			)

			var existingCode int64
			existingErr := s.Pool.QueryRow(ctx, `
				SELECT client_code
				FROM clients
				WHERE id = $1
				  AND client_code IS NOT NULL
			`, id).Scan(&existingCode)

			if existingErr == nil {
				logger.Websocket.Infof(
					"Storage: existing client_code found, clientID=%s",
					id,
				)
				return existingCode, nil
			}

			if existingErr != pgx.ErrNoRows {
				logger.Websocket.Errorf(
					"Storage: failed to check existing client_code, clientID=%s: %v",
					id,
					existingErr,
				)
			} else {
				logger.Websocket.Debugf(
					"Storage: client_code collision or empty code, retrying, clientID=%s",
					id,
				)
			}
			continue
		}
		logger.Websocket.Errorf(
			"Storage: failed to assign client_code, clientID=%s: %v",
			id,
			err,
		)
		return 0, err
	}
	logger.Websocket.Errorf(
		"Storage: failed to generate unique client_code after attempts, clientID=%s, attempts=%d",
		id,
		20,
	)
	return 0, fmt.Errorf("failed to generate unique client_code for client %s", id)
}
