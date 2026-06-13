package ws

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"posrelayd-noip/internal/config"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"posrelayd-noip/internal/crypto"
	"posrelayd-noip/internal/logger"
)

const (
	clientStaleAfter             = 90 * time.Second
	duplicateClientCheckAttempts = 10
	duplicateClientCheckDelay    = 15 * time.Second
)

type AuthState struct {
	Attempts int
	Blocked  time.Time
}

type PasswordEntry struct {
	TempPass string `json:"temp_pass"`
	Password any    `json:"password"` // всегда false
}

var (
	authStateMu  sync.Mutex
	authStateMap = make(map[string]*AuthState)

	adminAttempts   = make(map[string]int)
	adminAttemptsMu sync.Mutex

	clientAttempts   = make(map[string]int)
	clientAttemptsMu sync.Mutex

	protocolViolations   = make(map[string]int)
	protocolViolationsMu sync.Mutex
)

func tempPassRotationInterval() time.Duration {
	period := config.Cfg.Service.PassRenewalPeriod

	if period <= 0 {
		period = 60
	}

	return time.Duration(period) * time.Minute
}

func handleClientAuth(remoteIP string, msg Message, conn *websocket.Conn, entry *PasswordEntry) bool {
	authStateMu.Lock()

	logger.Websocket.Debugf(
		"Auth attempt from %s client_id=%s",
		remoteIP, msg.ClientID,
	)

	state, exists := authStateMap[remoteIP]
	if !exists {
		state = &AuthState{}
		authStateMap[remoteIP] = state
	}
	authStateMu.Unlock()

	now := time.Now()
	if state.Blocked.After(now) {
		_ = conn.WriteJSON(Message{
			Type:  "auth_fail",
			Error: fmt.Sprintf("Too many failed attempts. Try again in %d seconds", int(state.Blocked.Sub(now).Seconds())),
		})
		return false
	}

	ok := false
	// проверка паролей
	if entry.Password != false {
		if enc, ok2 := entry.Password.(string); ok2 && crypto.Verify(enc, msg.Password) {
			ok = true
		}
	}
	if entry.TempPass != "" && crypto.Verify(entry.TempPass, msg.Password) {
		ok = true
	}

	if !ok {
		logger.Websocket.Warnf(
			"Auth failed from %s (attempt %d)",
			remoteIP, state.Attempts,
		)

		// неудачная попытка
		authStateMu.Lock()
		state.Attempts++
		if state.Attempts >= 3 {
			logger.Websocket.Warnf(
				"Auth blocked for %s due to too many failures",
				remoteIP,
			)

			state.Blocked = time.Now().Add(1 * time.Minute)
			state.Attempts = 0 // сбрасываем попытки после блокировки
			_ = conn.WriteJSON(Message{
				Type:  "auth_fail",
				Error: "Too many failed attempts. You are blocked for 1 minute",
			})
		} else {
			_ = conn.WriteJSON(Message{
				Type:  "auth_fail",
				Error: fmt.Sprintf("Invalid password (%d/3 attempts)", state.Attempts),
			})
		}
		authStateMu.Unlock()
		return false
	}

	logger.Websocket.Infof(
		"Client authenticated successfully: %s from %s",
		msg.ClientID, remoteIP,
	)

	// успешная авторизация → сброс состояния
	authStateMu.Lock()
	state.Attempts = 0
	state.Blocked = time.Time{}
	authStateMu.Unlock()

	return true
}

func (s *Server) handleAdminAuth(
	r *http.Request,
	conn *websocket.Conn,
	remoteIP string,
	msg Message,
) (string, bool) {
	logger.Websocket.Debugf("Client authorization request for %s from admin", msg.ClientID)

	realClientID, err := db.ResolveClientID(r.Context(), msg.ClientID)
	if err != nil {
		logger.Websocket.Warnf(
			"Auth failed: unknown client id/code=%s from %s",
			msg.ClientID, remoteIP,
		)
		_ = conn.WriteJSON(Message{Type: "auth_fail", Error: "Unknown client"})
		return "", false
	}

	if realClientID != msg.ClientID {
		logger.Websocket.Infof(
			"Resolved client code %s to UUID %s",
			msg.ClientID,
			realClientID,
		)
	}

	msg.ClientID = realClientID

	clientData, err := db.GetClient(r.Context(), msg.ClientID)
	if err != nil {
		logger.Websocket.Warnf(
			"Auth failed: unknown client id=%s from %s",
			msg.ClientID, remoteIP,
		)
		_ = conn.WriteJSON(Message{Type: "auth_fail", Error: "Unknown client"})
		return "", false
	}

	globalMu.Lock()
	_, online := clients[msg.ClientID]
	globalMu.Unlock()

	if !online {
		logger.Websocket.Infof(
			"Auth failed: client %s offline (admin=%s)",
			msg.ClientID, msg.ID,
		)
		_ = conn.WriteJSON(Message{Type: "auth_fail", Error: "Client is offline"})
		return "", false
	}

	// Создаем структуру для совместимости с handleClientAuth
	entry := &PasswordEntry{
		Password: clientData.Password,
		TempPass: clientData.TempPass,
	}
	if clientData.Password == "" {
		entry.Password = false
	}

	if !handleClientAuth(remoteIP, msg, conn, entry) {
		return "", false
	}

	logger.Websocket.Infof(
		"Admin %s authenticated and attached to client %s",
		msg.ID, msg.ClientID,
	)

	return msg.ClientID, true
}

func (s *Server) handleRegister(
	conn *websocket.Conn,
	remoteIP string,
	authenticated bool,
	msg Message,
) (*Peer, bool) {
	logger.Websocket.Debugf(
		"Register peer id=%s role=%s from %s",
		msg.ID, msg.Role, remoteIP,
	)

	if msg.Role == "admin" && !authenticated {
		_ = conn.WriteJSON(Message{
			Type:  "auth_fail",
			Error: "Admin not authenticated",
		})
		return nil, false
	}

	peer := &Peer{
		ID:        msg.ID,
		Role:      msg.Role,
		Conn:      conn,
		sendQueue: make(chan OutboundMessage, 256),
		done:      make(chan struct{}),
		lastSeen:  time.Now(),
	}

	logger.Websocket.Infof(
		"%s registered successfully: %s",
		strings.Title(msg.Role),
		msg.ID,
	)

	peer.StartWriter()
	peer.StartPing(30 * time.Second)

	globalMu.Lock()

	var targetClient *Peer

	if peer.Role == "admin" {
		admins[peer.ID] = peer

		client := sessions[msg.ID]

		if client != "" {
			var ok bool
			targetClient, ok = clients[client]
			if !ok {
				targetClient = nil
			}
		}
	}

	globalMu.Unlock() // <- освободили мьютекс до WriteJSON

	if peer.Role == "admin" {
		logger.Websocket.Infof(
			"Admin connected: %v",
			peer.ID,
		)
	}

	if targetClient != nil {

		targetClient.Enqueue(Message{
			Type: "admin_attach",
			ID:   peer.ID,
		})

	} else if peer.Role == "client" {

		globalMu.Lock()
		clients[peer.ID] = peer
		globalMu.Unlock()

		logger.Websocket.Infof(
			"Client connected: %v",
			peer.ID,
		)
	}
	return peer, true
}

func (s *Server) handleAdminHello(
	conn *websocket.Conn,
	remoteIP string,
	msg Message,
) bool {
	if msg.ApiKey != config.Cfg.Service.AdminKey {

		adminAttemptsMu.Lock()
		adminAttempts[remoteIP]++
		attempts := adminAttempts[remoteIP]
		adminAttemptsMu.Unlock()

		logger.Websocket.Warnf(
			"Invalid admin API key from %s (%d/3)",
			remoteIP, attempts,
		)

		if attempts >= 3 {
			_ = db.AddToBlacklist(context.Background(), remoteIP)
			_ = conn.WriteJSON(Message{
				Type:  "error",
				Error: "Your IP is banned due to too many failed attempts",
			})
			return false
		}

		_ = conn.WriteJSON(Message{
			Type:  "error",
			Error: fmt.Sprintf("Invalid API key (%d/3 attempts)", attempts),
		})
		return false
	}

	logger.Websocket.Infof(
		"Admin authenticated successfully from %s",
		remoteIP,
	)

	// успешная авторизация → сброс счетчика
	adminAttemptsMu.Lock()
	delete(adminAttempts, remoteIP)
	adminAttemptsMu.Unlock()

	protocolViolationsMu.Lock()
	delete(protocolViolations, remoteIP)
	protocolViolationsMu.Unlock()

	return true
}

func (s *Server) validateClientHello(
	conn *websocket.Conn,
	remoteIP string,
	msg Message,
) bool {
	if msg.ApiKey != config.Cfg.Service.ClientKey {
		clientAttemptsMu.Lock()
		clientAttempts[remoteIP]++
		attempts := clientAttempts[remoteIP]
		clientAttemptsMu.Unlock()

		logger.Websocket.Warnf(
			"Invalid API key from client %s (%d/3)",
			remoteIP, attempts,
		)

		if attempts >= 3 {
			_ = db.AddToBlacklist(context.Background(), remoteIP)
			_ = conn.WriteJSON(Message{
				Type:  "error",
				Error: "Your IP is banned due to too many failed API key attempts",
			})
			return false
		}

		_ = conn.WriteJSON(Message{
			Type:  "error",
			Error: fmt.Sprintf("Invalid API key (%d/3 attempts)", attempts),
		})
		return false
	}

	// успешный api_key → сброс счётчиков
	clientAttemptsMu.Lock()
	delete(clientAttempts, remoteIP)
	clientAttemptsMu.Unlock()

	protocolViolationsMu.Lock()
	delete(protocolViolations, remoteIP)
	protocolViolationsMu.Unlock()

	return true
}

func (s *Server) handlePasswordUpdate(
	r *http.Request,
	conn *websocket.Conn,
	msg Message,
) {
	encrypted, err := crypto.Encrypt(msg.Password)
	if err != nil {
		_ = conn.WriteJSON(Message{
			Type:  "error",
			Error: "Password encryption failed",
		})
		return
	}

	err = db.UpsertClient(r.Context(), msg.ID, encrypted, "")
	if err != nil {
		logger.Websocket.Errorf("DB: Error saving persistent client password %s: %v", msg.ID, err)
	} else {
		logger.Websocket.Infof("DB: The client %s permanent password has been updated in the database.", msg.ID)
	}

	logger.Websocket.Infof("Password updated via pass-only connection: %v", msg.ID)

	_ = conn.WriteJSON(Message{
		Type: "password_updated",
	})

	_ = conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "password updated"),
	)

	return
}

func (s *Server) handleClientHello(
	r *http.Request,
	conn *websocket.Conn,
	msg Message,
) (*Peer, bool) {
	peer := &Peer{
		ID:         msg.ID,
		Role:       "client",
		InstanceID: msg.InstanceID,
		Conn:       conn,
		sendQueue:  make(chan OutboundMessage, 256),
		done:       make(chan struct{}),
		lastSeen:   time.Now(),
	}

	peer.StartWriter()
	peer.StartPing(30 * time.Second)

	if !registerClientPeer(conn, peer) {
		peer.Close()
		return nil, false
	}

	logger.Websocket.Infof(
		"Client connected: %s instance_id=%s legacy=%t",
		msg.ID,
		msg.InstanceID,
		msg.InstanceID == "",
	)

	ctx := context.Background()

	if !s.issueTempPass(ctx, msg.ID, peer) {
		globalMu.Lock()
		if clients[peer.ID] == peer {
			delete(clients, peer.ID)
		}
		globalMu.Unlock()

		peer.Close()
		return nil, false
	}

	clientData, _ := db.GetClient(ctx, msg.ID)
	if clientData != nil {
		peer.Enqueue(Message{
			Type:       "client_code",
			ClientCode: clientData.ClientCode,
		})
	}

	go s.startTempPassRotation(ctx, msg.ID, peer)

	return peer, true
}

func registerClientPeer(conn *websocket.Conn, newPeer *Peer) bool {
	for attempt := 1; attempt <= duplicateClientCheckAttempts; attempt++ {
		globalMu.Lock()
		oldPeer := clients[newPeer.ID]

		if oldPeer == nil {
			clients[newPeer.ID] = newPeer
			globalMu.Unlock()

			logger.Websocket.Infof(
				"Client registered: client_id=%s instance_id=%s legacy=%t",
				newPeer.ID,
				newPeer.InstanceID,
				newPeer.InstanceID == "",
			)

			return true
		}

		sameInstance :=
			newPeer.InstanceID != "" &&
				oldPeer.InstanceID != "" &&
				newPeer.InstanceID == oldPeer.InstanceID

		stale := time.Since(oldPeer.LastSeen()) > clientStaleAfter

		if sameInstance || stale {
			clients[newPeer.ID] = newPeer
			globalMu.Unlock()

			logger.Websocket.Warnf(
				"Client takeover: client_id=%s same_instance=%t stale=%t old_instance_id=%s new_instance_id=%s",
				newPeer.ID,
				sameInstance,
				stale,
				oldPeer.InstanceID,
				newPeer.InstanceID,
			)

			oldPeer.Close()
			_ = oldPeer.Conn.Close()

			return true
		}

		oldInstanceID := oldPeer.InstanceID
		newInstanceID := newPeer.InstanceID
		globalMu.Unlock()

		logger.Websocket.Warnf(
			"Duplicate client connection attempt %d/%d: client_id=%s old_instance_id=%s new_instance_id=%s legacy=%t",
			attempt,
			duplicateClientCheckAttempts,
			newPeer.ID,
			oldInstanceID,
			newInstanceID,
			newPeer.InstanceID == "",
		)

		if attempt < duplicateClientCheckAttempts {
			_ = conn.WriteJSON(Message{
				Type: "error",
				Error: fmt.Sprintf(
					"Client with this id is already online, retrying duplicate check (%d/%d)",
					attempt,
					duplicateClientCheckAttempts,
				),
			})

			time.Sleep(duplicateClientCheckDelay)
			continue
		}

		_ = conn.WriteJSON(Message{
			Type:     "error",
			Error:    "Client with this id is already online",
			ExitCode: 1,
		})

		_ = conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(
				websocket.ClosePolicyViolation,
				"client already online",
			),
		)

		return false
	}
	return false
}

func (s *Server) issueTempPass(ctx context.Context, clientID string, peer *Peer) bool {
	plainTemp := generateTempPass()

	encryptedTemp, err := crypto.Encrypt(plainTemp)
	if err != nil {
		peer.Enqueue(Message{
			Type:  "error",
			Error: "Temp password encryption failed",
		})
		return false
	}

	clientData, _ := db.GetClient(ctx, clientID)

	currPass := ""
	if clientData != nil {
		currPass = clientData.Password
	}

	err = db.UpsertClient(ctx, clientID, currPass, encryptedTemp)
	if err != nil {
		logger.Websocket.Errorf(
			"DB: Error saving client temporary password %s: %v",
			clientID,
			err,
		)
		return false
	}

	logger.Websocket.Debugf("DB: Temporary password for %s saved/rotated", clientID)

	peer.Enqueue(Message{
		Type:     "temp_pass",
		TempPass: plainTemp,
	})

	return true
}

func (s *Server) startTempPassRotation(ctx context.Context, clientID string, peer *Peer) {
	ticker := time.NewTicker(tempPassRotationInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.issueTempPass(ctx, clientID, peer)

		case <-peer.done:
			logger.Websocket.Debugf("Temp password rotation stopped for client %s", clientID)
			return

		case <-ctx.Done():
			logger.Websocket.Debugf("Temp password rotation context cancelled for client %s", clientID)
			return
		}
	}
}

func generateTempPass() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	const passLen = 6

	rand.Seed(time.Now().UnixNano())

	pass := make([]byte, passLen)
	for i := range pass {
		pass[i] = chars[rand.Intn(len(chars))]
	}

	logger.Websocket.Debug("Temporary password generated")

	return string(pass)
}
