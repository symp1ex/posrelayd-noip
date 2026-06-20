package ws

import (
	"github.com/gorilla/websocket"
	"posrelayd-noip/internal/logger"
)

func (s *Server) handleCommand(msg Message) {
	sessionID := msg.ID
	targetClientID := msg.ClientID

	globalMu.Lock()

	if boundClientID, ok := sessions[sessionID]; ok && boundClientID != "" {
		targetClientID = boundClientID
	}

	client := clients[targetClientID]
	admin := admins[sessionID]

	globalMu.Unlock()

	logger.Websocket.Debugf(
		"Routing %s from session_id=%s to client=%s requested_client_id=%s (cmd_id=%s)",
		msg.Type,
		sessionID,
		targetClientID,
		msg.ClientID,
		msg.CommandID,
	)

	if client == nil {
		logger.Websocket.Warnf(
			"Routing dropped: target client not found session_id=%s requested_client_id=%s resolved_client_id=%s cmd_id=%s",
			sessionID,
			msg.ClientID,
			targetClientID,
			msg.CommandID,
		)

		if admin != nil {
			admin.Enqueue(Message{
				Type:      "error",
				ClientID:  targetClientID,
				CommandID: msg.CommandID,
				Error:     "Client is offline or session is not attached",
			})
		}

		return
	}

	client.Enqueue(Message{
		Type:      msg.Type,
		ClientID:  targetClientID,
		CommandID: msg.CommandID,
		Command:   msg.Command,
		ID:        sessionID,
	})
}

func (s *Server) handleResult(msg Message) {
	sessionID := msg.ID

	globalMu.Lock()
	admin := admins[sessionID]
	globalMu.Unlock()

	logger.Websocket.Debugf(
		"Routing %s from session_id=%s to client %s (cmd_id=%s)",
		msg.Type,
		msg.ID,
		msg.ClientID,
		msg.CommandID,
	)

	if admin != nil {
		admin.Enqueue(msg)
	}
}

func (s *Server) handleSessionClosed(msg Message) {
	logger.Websocket.Infof(
		"Session close requested by client: session_id=%s",
		msg.ID,
	)

	sessionID := msg.ID

	globalMu.Lock()
	admin := admins[sessionID]

	if admin == nil {
		logger.Websocket.Warnf(
			"Session close requested, but admin not found: sessionID=%s",
			sessionID,
		)
	} else {
		delete(sessions, sessionID)
	}

	globalMu.Unlock()

	if admin != nil {
		admin.Enqueue(Message{
			Type:  "session_closed",
			Error: "CMD session terminated on client",
		})

		logger.Websocket.Infof(
			"Session closed: session_id=%s (initiated by client)",
			sessionID,
		)
	}
}

func (s *Server) disconnect(
	peer *Peer,
	conn *websocket.Conn,
	remoteIP string,
) {
	defer func() {
		logger.Websocket.Debugf("Connection closing from %s (peer=%v)", remoteIP,
			func() string {
				if peer != nil {
					return peer.ID
				}
				return "nil"
			}())

		if peer != nil {
			peer.Close()
		}

		var notifications []struct {
			peer *Peer
			msg  Message
		}

		if peer != nil && peer.Role == "admin" {
			globalMu.Lock()

			if clientID, ok := sessions[peer.ID]; ok {
				if client, ok := clients[clientID]; ok {
					notifications = append(notifications, struct {
						peer *Peer
						msg  Message
					}{
						peer: client,
						msg:  Message{Type: "admin_detach", ID: peer.ID},
					})
				}

				delete(sessions, peer.ID)
			}

			delete(admins, peer.ID)

			globalMu.Unlock()

			for _, n := range notifications {
				n.peer.Enqueue(n.msg)
			}

			logger.Websocket.Infof("Admin disconnected: %v", peer.ID)
		}

		if peer != nil && peer.Role == "client" {
			globalMu.Lock()

			if clients[peer.ID] == peer {
				delete(clients, peer.ID)
				logger.Websocket.Infof("Client mapping removed: %s", peer.ID)
			}

			for sessionID, clientID := range sessions {
				if clientID == peer.ID {
					if admin, ok := admins[sessionID]; ok {
						notifications = append(notifications, struct {
							peer *Peer
							msg  Message
						}{
							peer: admin,
							msg: Message{
								Type:     "session_closed",
								ClientID: peer.ID,
								Error:    "Client disconnected",
							},
						})
					}

					delete(sessions, sessionID)
				}
			}

			globalMu.Unlock()

			for _, n := range notifications {
				n.peer.Enqueue(n.msg)
			}

			logger.Websocket.Infof("Client disconnected: %v", peer.ID)
		}

		conn.Close()
	}()
}
