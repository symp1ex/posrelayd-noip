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
		sendQueue: make(chan OutboundMessage, 32),
		done:      make(chan struct{}),
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
	if msg.ApiKey != config.Cfg.Service.APIKey {

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
	if msg.ApiKey != config.Cfg.Service.APIKey {
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
	globalMu.Lock()
	if oldPeer, ok := clients[msg.ID]; ok {
		logger.Websocket.Infof("Replacing stale session for client ID: %s", msg.ID)
		oldPeer.Close()         // Закрываем старый сокет
		delete(clients, msg.ID) // Удаляем из списка
	}
	globalMu.Unlock()

	plainTemp := generateTempPass()

	encryptedTemp, err := crypto.Encrypt(plainTemp)
	if err != nil {
		_ = conn.WriteJSON(Message{
			Type:  "error",
			Error: "Temp password encryption failed",
		})
		return nil, false
	}

	clientData, _ := db.GetClient(r.Context(), msg.ID)
	currPass := ""
	if clientData != nil {
		currPass = clientData.Password
	}

	err = db.UpsertClient(r.Context(), msg.ID, currPass, encryptedTemp)
	if err != nil {
		logger.Websocket.Errorf("DB: Error saving client temporary password %s: %v", msg.ID, err)
	} else {
		logger.Websocket.Debugf("DB: Temporary password for %s saved", msg.ID)
	}

	peer := &Peer{
		ID:        msg.ID,
		Role:      "client",
		Conn:      conn,
		sendQueue: make(chan OutboundMessage, 32),
		done:      make(chan struct{}),
	}
	peer.StartWriter()
	peer.StartPing(30 * time.Second)

	globalMu.Lock()
	clients[peer.ID] = peer
	globalMu.Unlock()

	logger.Websocket.Infof(
		"Client connected: %s",
		msg.ID,
	)

	clientData, _ = db.GetClient(r.Context(), msg.ID)

	// ОТПРАВЛЯЕМ temp_pass PY-КЛИЕНТУ
	_ = conn.WriteJSON(Message{
		Type:     "temp_pass",
		TempPass: plainTemp,
	})

	if clientData != nil {
		_ = conn.WriteJSON(Message{
			Type:       "client_code",
			ClientCode: clientData.ClientCode,
		})
	}

	return peer, true
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
