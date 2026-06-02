package storage

import (
	"context"
	"posrelayd-noip/internal/logger"
)

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

// Добавляем IP в blacklist
func (s *Storage) AddToBlacklist(ctx context.Context, ip string) error {
	logger.Websocket.Warnf("Attempt to add IP to blacklist: %s", ip)

	_, err := s.Pool.Exec(context.Background(),
		"INSERT INTO blacklist (ip) VALUES ($1) ON CONFLICT DO NOTHING", ip)

	if err != nil {
		logger.Websocket.Errorf("DB: Error while adding %s in blacklist: %v", ip, err)
		return err
	}
	logger.Websocket.Infof("DB: IP %s successfully locked in the database", ip)
	return nil
}
