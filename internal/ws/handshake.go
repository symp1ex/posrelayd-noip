package ws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/gorilla/websocket"
	"net/http"
	"posrelayd-noip/internal/logger"
)

// Состояние для конкретного соединения во время рукопожатия
type handshakeState struct {
	clientID  string
	publicKey string
	challenge string
	password  string
}

func (s *Server) handleHandshake(r *http.Request, peerState *handshakeState, msg Message) (bool, string) {
	ctx := r.Context()

	// 1. Поиск клиента в базе
	dbClient, _ := db.GetClient(ctx, msg.ID)

	// 2. Проверка коллизии (если прислан новый ключ)
	if msg.PublicKey != "" {
		colClient, _ := db.GetClientBySignature(ctx, msg.PublicKey)
		if colClient != nil && colClient.ID != msg.ID {
			logger.Websocket.Infof("Handshake: Key collision. Moving key from %s to %s", colClient.ID, msg.ID)
			_ = db.UpdateClientSignature(ctx, colClient.ID, "") // Стираем у старого
		}
	}

	// === ЛОГИКА ИЗ ТЗ ===

	// Если ключ прислан
	if msg.PublicKey != "" {
		if dbClient != nil && dbClient.Signature != "" && dbClient.Signature != msg.PublicKey {
			return false, "Public key mismatch"
		}
		// Если записи нет - создаем (UUID + пустые пассы)
		if dbClient == nil {
			_ = db.UpsertClient(ctx, msg.ID, "", "")
		}
	} else {
		// Если ключ НЕ прислан (None)
		if dbClient == nil || dbClient.Signature == "" {
			return false, "Key registration required (no public key provided)"
		}
		msg.PublicKey = dbClient.Signature // Используем ключ из базы
	}

	// Подготовка челленджа
	chal := make([]byte, 32)
	rand.Read(chal)

	peerState.clientID = msg.ID
	peerState.publicKey = msg.PublicKey
	peerState.challenge = hex.EncodeToString(chal)
	peerState.password = msg.Password

	return true, ""
}

func (s *Server) handleHandshakeSign(
	r *http.Request,
	conn *websocket.Conn,
	hState *handshakeState,
	msg Message,
) (*Peer, bool) {
	if hState.challenge == "" || hState.clientID == "" {
		_ = conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Handshake was not initialized",
		})
		return nil, false
	}

	if msg.ID != "" && msg.ID != hState.clientID {
		_ = conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Client ID mismatch",
		})
		return nil, false
	}

	valid, isNew := s.verifyHandshakeSign(hState, msg)
	if !valid {
		_ = conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Invalid signature",
		})
		return nil, false
	}

	msg.ID = hState.clientID
	msg.Password = hState.password

	answer := "ok"
	if isNew {
		answer = "register"
	}

	if err := conn.WriteJSON(Message{
		Type:   "handshake",
		Answer: answer,
	}); err != nil {
		logger.Websocket.Warnf(
			"Handshake: failed to send sign response to client %s: %v",
			hState.clientID,
			err,
		)
		return nil, false
	}

	if msg.Password != "" {
		s.handlePasswordUpdate(
			r,
			conn,
			msg,
		)
		return nil, false
	}

	newPeer, ok := s.handleClientHello(
		r,
		conn,
		msg,
	)

	if !ok {
		return nil, false
	}

	return newPeer, true
}

func (s *Server) verifyHandshakeSign(peerState *handshakeState, msg Message) (bool, bool) {
	if peerState.challenge == "" {
		return false, false
	}

	// 1. Парсим PEM публичного ключа
	block, _ := pem.Decode([]byte(peerState.publicKey))
	if block == nil {
		return false, false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, false
	}

	// 2. Декодируем подпись и челлендж
	sig, _ := base64.StdEncoding.DecodeString(msg.Signature)
	chal, _ := hex.DecodeString(peerState.challenge)

	// 3. Верификация Ed25519
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(edPub, chal, sig) {
		return false, false
	}

	// 4. Успех. Проверяем, был ли ключ в базе до этого (для отправки register vs ok)
	dbClient, _ := db.GetClient(context.Background(), peerState.clientID)
	isNew := dbClient == nil || dbClient.Signature == ""

	if err := db.UpdateClientSignature(context.Background(), peerState.clientID, peerState.publicKey); err != nil {
		logger.Websocket.Errorf(
			"DB: Failed to save public key for client %s: %v",
			peerState.clientID,
			err,
		)
		return false, false
	}

	return true, isNew
}
