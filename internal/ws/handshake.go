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

	logger.Websocket.Infof("Handshake: started for client %s", msg.ID)
	// 1. Поиск клиента в базе
	// 1. Поиск клиента в базе
	dbClient, getClientErr := db.GetClient(ctx, msg.ID)
	if getClientErr != nil {
		logger.Websocket.Errorf(
			"Handshake: failed to get client %s from DB: %v",
			msg.ID,
			getClientErr,
		)
	}

	// 2. Проверка коллизии (если прислан новый ключ)
	if msg.PublicKey != "" {
		logger.Websocket.Debugf("Handshake: checking public key collision for client %s", msg.ID)

		colClient, getClientBySignatureErr := db.GetClientBySignature(ctx, msg.PublicKey)
		if getClientBySignatureErr != nil {
			logger.Websocket.Errorf(
				"Handshake: failed to check key collision for client %s: %v",
				msg.ID,
				getClientBySignatureErr,
			)
		}
		if colClient != nil && colClient.ID != msg.ID {
			logger.Websocket.Infof("Handshake: Key collision. Moving key from %s to %s", colClient.ID, msg.ID)
			if updateSignatureErr := db.UpdateClientSignature(ctx, colClient.ID, ""); updateSignatureErr != nil {
				logger.Websocket.Errorf(
					"Handshake: failed to clear public key for previous client %s while moving key to %s: %v",
					colClient.ID,
					msg.ID,
					updateSignatureErr,
				)
			}
		}
	}

	// Если ключ прислан
	if msg.PublicKey != "" {
		logger.Websocket.Debugf("Handshake: public key provided by client %s", msg.ID)
		if dbClient != nil && dbClient.Signature != "" && dbClient.Signature != msg.PublicKey {
			logger.Websocket.Warnf("Handshake: public key mismatch for client %s", msg.ID)
			return false, "Public key mismatch"
		}
		// Если записи нет - создаем (UUID + пустые пассы)
		if dbClient == nil {
			logger.Websocket.Infof("Handshake: creating DB record for new client %s", msg.ID)
			if upsertClientErr := db.UpsertClient(ctx, msg.ID, "", ""); upsertClientErr != nil {
				logger.Websocket.Errorf(
					"Handshake: failed to create DB record for client %s: %v",
					msg.ID,
					upsertClientErr,
				)
			}
		}
	} else {
		logger.Websocket.Debugf("Handshake: public key was not provided by client %s, trying to use DB signature", msg.ID)
		// Если ключ НЕ прислан (None)
		if dbClient == nil || dbClient.Signature == "" {
			logger.Websocket.Warnf("Handshake: key registration required for client %s, no public key provided", msg.ID)
			return false, "Key registration required (no public key provided)"
		}
		msg.PublicKey = dbClient.Signature // Используем ключ из базы
		logger.Websocket.Debugf("Handshake: using stored public key for client %s", msg.ID)
	}

	// Подготовка челленджа
	chal := make([]byte, 32)
	readBytes, readChallengeErr := rand.Read(chal)
	if readChallengeErr != nil {
		logger.Websocket.Errorf(
			"Handshake: failed to generate challenge for client %s: %v",
			msg.ID,
			readChallengeErr,
		)
	}
	if readBytes != len(chal) {
		logger.Websocket.Warnf(
			"Handshake: generated challenge length mismatch for client %s, expected=%d, actual=%d",
			msg.ID,
			len(chal),
			readBytes,
		)
	}

	peerState.clientID = msg.ID
	peerState.publicKey = msg.PublicKey
	peerState.challenge = hex.EncodeToString(chal)
	peerState.password = msg.Password

	logger.Websocket.Infof("Handshake: challenge prepared for client %s", msg.ID)

	return true, ""
}

func (s *Server) handleHandshakeSign(
	r *http.Request,
	conn *websocket.Conn,
	hState *handshakeState,
	msg Message,
) (*Peer, bool) {
	logger.Websocket.Infof("Handshake: signature step started for client %s", hState.clientID)

	if hState.challenge == "" || hState.clientID == "" {
		logger.Websocket.Warnf(
			"Handshake: signature step rejected because handshake was not initialized, stateClientID=%s",
			hState.clientID,
		)
		if writeErr := conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Handshake was not initialized",
		}); writeErr != nil {
			logger.Websocket.Warnf(
				"Handshake: failed to send not initialized response to client %s: %v",
				hState.clientID,
				writeErr,
			)
		}
		return nil, false
	}

	if msg.ID != "" && msg.ID != hState.clientID {
		logger.Websocket.Warnf(
			"Handshake: client ID mismatch, stateClientID=%s, messageClientID=%s",
			hState.clientID,
			msg.ID,
		)
		if writeErr := conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Client ID mismatch",
		}); writeErr != nil {
			logger.Websocket.Warnf(
				"Handshake: failed to send client ID mismatch response to client %s: %v",
				hState.clientID,
				writeErr,
			)
		}
		return nil, false
	}

	valid, isNew := s.verifyHandshakeSign(hState, msg)
	if !valid {
		logger.Websocket.Warnf("Handshake: invalid signature for client %s", hState.clientID)

		if writeErr := conn.WriteJSON(Message{
			Type:        "handshake",
			Answer:      "fail",
			Description: "Invalid signature",
		}); writeErr != nil {
			logger.Websocket.Warnf(
				"Handshake: failed to send invalid signature response to client %s: %v",
				hState.clientID,
				writeErr,
			)
		}
		return nil, false
	}

	msg.ID = hState.clientID
	msg.Password = hState.password

	if msg.Password != "" {
		logger.Websocket.Debugf("Handshake: password update requested for client %s", msg.ID)
		s.handlePasswordUpdate(
			r,
			conn,
			msg,
		)
		logger.Websocket.Debugf("Handshake: password update handler finished for client %s", msg.ID)
		return nil, false
	}

	if rejectIfClientAlreadyOnline(conn, msg.ID) {
		return nil, false
	}

	answer := "ok"
	if isNew {
		answer = "register"
	}

	logger.Websocket.Infof(
		"Handshake: signature verified for client %s, answer=%s",
		hState.clientID,
		answer,
	)

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

	logger.Websocket.Infof("Handshake: passing client %s to hello handler", msg.ID)

	newPeer, ok := s.handleClientHello(
		r,
		conn,
		msg,
	)

	if !ok {
		logger.Websocket.Warnf("Handshake: client hello handler failed for client %s", msg.ID)
		return nil, false
	}

	logger.Websocket.Infof("Handshake: completed successfully for client %s", msg.ID)

	return newPeer, true
}

func (s *Server) verifyHandshakeSign(peerState *handshakeState, msg Message) (bool, bool) {
	logger.Websocket.Debugf("Handshake: verifying signature for client")

	if peerState.challenge == "" {
		logger.Websocket.Warnf("Handshake: signature verification failed for client %s, empty challenge", peerState.clientID)
		return false, false
	}

	// 1. Парсим PEM публичного ключа
	block, _ := pem.Decode([]byte(peerState.publicKey))
	if block == nil {
		logger.Websocket.Warnf("Handshake: signature verification failed for client %s, invalid PEM public key", peerState.clientID)
		return false, false
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Websocket.Warnf(
			"Handshake: signature verification failed for client %s, failed to parse public key: %v",
			peerState.clientID,
			err,
		)
		return false, false
	}

	// 2. Декодируем подпись и челлендж
	sig, decodeSignatureErr := base64.StdEncoding.DecodeString(msg.Signature)
	if decodeSignatureErr != nil {
		logger.Websocket.Warnf(
			"Handshake: failed to decode signature for client %s: %v",
			peerState.clientID,
			decodeSignatureErr,
		)
	}

	chal, decodeChallengeErr := hex.DecodeString(peerState.challenge)
	if decodeChallengeErr != nil {
		logger.Websocket.Errorf(
			"Handshake: failed to decode challenge for client %s: %v",
			peerState.clientID,
			decodeChallengeErr,
		)
	}

	// 3. Верификация Ed25519
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(edPub, chal, sig) {
		logger.Websocket.Warnf(
			"Handshake: Ed25519 verification failed for client %s, validPublicKeyType=%t",
			peerState.clientID,
			ok,
		)
		return false, false
	}

	logger.Websocket.Debugf("Handshake: Ed25519 signature verified for client %s", peerState.clientID)

	// 4. Успех. Проверяем, был ли ключ в базе до этого (для отправки register vs ok)
	dbClient, getClientErr := db.GetClient(context.Background(), peerState.clientID)
	if getClientErr != nil {
		logger.Websocket.Errorf(
			"Handshake: failed to get client %s from DB after signature verification: %v",
			peerState.clientID,
			getClientErr,
		)
	}

	isNew := dbClient == nil || dbClient.Signature == ""

	if err := db.UpdateClientSignature(context.Background(), peerState.clientID, peerState.publicKey); err != nil {
		logger.Websocket.Errorf(
			"DB: Failed to save public key for client %s: %v",
			peerState.clientID,
			err,
		)
		return false, false
	}

	logger.Websocket.Infof(
		"Handshake: public key saved for client %s, isNew=%t",
		peerState.clientID,
		isNew,
	)
	return true, isNew
}

func rejectIfClientAlreadyOnline(conn *websocket.Conn, clientID string) bool {
	globalMu.Lock()
	_, online := clients[clientID]
	globalMu.Unlock()

	if !online {
		return false
	}

	logger.Websocket.Warnf(
		"Rejected duplicate client connection: client_id=%s already online",
		clientID,
	)

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

	return true
}
