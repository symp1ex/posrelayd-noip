package storage

import (
	"context"
	"posrelayd-noip/internal/logger"
)

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
