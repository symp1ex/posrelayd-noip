package ws

import (
	"context"
	"fmt"
	"net/http"
	"posrelayd-noip/internal/logger"
	"time"

	"github.com/gorilla/websocket"
)

func writeOrEnqueue(conn *websocket.Conn, peer *Peer, msg Message) {
	if peer != nil {
		peer.Enqueue(msg)
		return
	}

	_ = conn.WriteJSON(msg)
}

func (s *Server) wsHandler(w http.ResponseWriter, r *http.Request) {
	remoteIP := getClientIP(r)

	logger.Websocket.Debugf(
		"Incoming websocket connection from %s (UA=%s)",
		remoteIP,
		r.UserAgent(),
	)

	// ПРОВЕРКА BLACKLIST ДО UPGRADE
	banned := db.IsBlacklisted(r.Context(), remoteIP)
	if banned {
		logger.Websocket.Warnf("Rejected websocket connection from banned IP %s", remoteIP)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("IP_BANNED"))
		return
	}

	// ТОЛЬКО ТЕПЕРЬ UPGRADE
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Websocket.Errorf(
			"Websocket upgrade failed from %s: %v",
			remoteIP, err,
		)
		return
	}
	defer conn.Close()

	waitTimeout := 70 * time.Second

	conn.SetReadLimit(512 * 1024)
	conn.SetReadDeadline(time.Now().Add(waitTimeout))

	// 1. Когда сервер пингует клиента, клиент присылает PONG
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(waitTimeout))
		return nil
	})

	// 2. Когда клиент пингует сервер, сервер получает PING
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(waitTimeout))
		// Обязательно отвечаем клиенту, иначе он подумает, что сервер умер
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	var peer *Peer
	authenticated := false
	hState := &handshakeState{}

	defer func() {
		s.disconnect(peer, conn, remoteIP)
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			logger.Websocket.Warnf(
				"ReadJSON failed from %s: %v",
				remoteIP, err,
			)
			conn.SetReadDeadline(time.Now().Add(waitTimeout))
			return
		}

		conn.SetReadDeadline(time.Now().Add(waitTimeout))

		logger.Websocket.Debugf(
			"Incoming message from %s: type=%s id=%s role=%s client_id=%s",
			remoteIP,
			msg.Type,
			msg.ID,
			msg.Role,
			msg.ClientID,
		)

		if !authenticated {
			switch msg.Type {
			case "admin_hello", "client_hello", "sign":
				// разрешено
			default:
				protocolViolationsMu.Lock()
				protocolViolations[remoteIP]++
				attempts := protocolViolations[remoteIP]
				protocolViolationsMu.Unlock()

				logger.Websocket.Warnf(
					"Protocol violation (unauthenticated) from %s: '%s' (%d/3)",
					remoteIP, msg.Type, attempts,
				)

				if attempts >= 3 {
					_ = db.AddToBlacklist(context.Background(), remoteIP)
					writeOrEnqueue(conn, peer, Message{
						Type:  "error",
						Error: "Your IP is banned due to protocol violations",
					})
					return
				}

				writeOrEnqueue(conn, peer, Message{
					Type:  "error",
					Error: "Authentication required",
				})
				continue
			}
		}

		if authenticated && peer == nil {
			switch msg.Type {
			case "register", "auth":
				// разрешено
			default:
				writeOrEnqueue(conn, peer, Message{
					Type:  "error",
					Error: "Registration required",
				})
				continue
			}
		}

		switch msg.Type {
		case "admin_hello":
			if !s.handleAdminHello(conn, remoteIP, msg) {
				continue
			}

			authenticated = true
			writeOrEnqueue(conn, peer, Message{
				Type: "admin_hello_ok",
			})

		// ================= AUTH =================

		case "auth":
			clientID, ok := s.handleAdminAuth(
				r,
				conn,
				remoteIP,
				msg,
			)

			if !ok {
				continue
			}

			authenticated = true
			sessions[msg.ID] = clientID // сохраняем, чтобы знать, к какому клиенту привязывать админа

			writeOrEnqueue(conn, peer, Message{
				Type:     "auth_ok",
				ClientID: msg.ClientID,
			})

			protocolViolationsMu.Lock()
			delete(protocolViolations, remoteIP)
			protocolViolationsMu.Unlock()

			// ---------------- REGISTER ----------------
		case "register":
			newPeer, ok := s.handleRegister(
				conn,
				remoteIP,
				authenticated,
				msg,
			)

			if !ok {
				return
			}

			peer = newPeer

		// ================= CLIENT HELLO =================

		case "client_hello":
			if !s.validateClientHello(
				conn,
				remoteIP,
				msg,
			) {
				continue
			}

			// Выполняем логику рукопожатия
			ok, reason := s.handleHandshake(r, hState, msg)
			if !ok {
				writeOrEnqueue(conn, peer, Message{Type: "handshake", Answer: "fail", Description: reason})
				return // Закрываем соединение при провале
			}

			writeOrEnqueue(conn, peer, Message{
				Type:      "handshake",
				Answer:    "check",
				Challenge: hState.challenge,
			})

			logger.Websocket.Debugf(
				"Handshake challenge sent to client %s",
				msg.ID,
			)

		case "sign":
			newPeer, ok := s.handleHandshakeSign(
				r,
				conn,
				hState,
				msg,
			)

			if !ok {
				return
			}

			peer = newPeer
			authenticated = true

		// ================= ROUTING =================

		case "command", "control":
			s.handleCommand(msg)

		case "result":
			s.handleResult(msg)

		case "session_closed":
			s.handleSessionClosed(msg)

		default:
			protocolViolationsMu.Lock()
			protocolViolations[remoteIP]++
			attempts := protocolViolations[remoteIP]
			protocolViolationsMu.Unlock()

			logger.Websocket.Warnf(
				"Protocol violation from %s: unknown message type '%s' (%d/3)",
				remoteIP, msg.Type, attempts,
			)

			if attempts >= 3 {
				_ = db.AddToBlacklist(context.Background(), remoteIP)

				writeOrEnqueue(conn, peer, Message{
					Type:  "error",
					Error: "Your IP is banned due to protocol violations",
				})

				return
			}

			writeOrEnqueue(conn, peer, Message{
				Type: "error",
				Error: fmt.Sprintf(
					"Unknown request type '%s' (%d/3)",
					msg.Type, attempts,
				),
			})
		}
	}
}
