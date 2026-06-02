package ws

import (
	"github.com/gorilla/websocket"
	"posrelayd-noip/internal/logger"
)

func (s *Server) handleCommand(msg Message) {
	globalMu.Lock()
	client := clients[msg.ClientID]
	globalMu.Unlock()

	logger.Websocket.Debugf(
		"Routing %s from %s to client %s (cmd_id=%s)",
		msg.Type,
		msg.ID,
		msg.ClientID,
		msg.CommandID,
	)

	if client != nil {
		client.Enqueue(Message{
			Type:      msg.Type,
			ClientID:  msg.ClientID,
			CommandID: msg.CommandID,
			Command:   msg.Command,
			ID:        msg.ID,
		})
	}
}

func (s *Server) handleResult(msg Message) {
	adminID := msg.ID

	globalMu.Lock()
	admin := admins[adminID]
	globalMu.Unlock()

	logger.Websocket.Debugf(
		"Routing %s from %s to client %s (cmd_id=%s)",
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
		"Session close requested by client: admin_id=%s",
		msg.ID,
	)

	adminID := msg.ID

	globalMu.Lock()
	admin := admins[adminID]

	if admin == nil {
		logger.Websocket.Warnf(
			"Session close requested, but admin not found: admin_id=%s",
			adminID,
		)
	}
	globalMu.Unlock()

	if admin != nil {
		admin.Enqueue(Message{
			Type:  "session_closed",
			Error: "CMD session terminated on client",
		})
		delete(sessions, adminID)

		logger.Websocket.Infof(
			"Session closed: admin_id=%s (initiated by client)",
			adminID,
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

		if peer != nil && peer.Role == "admin" {
			globalMu.Lock()
			if clientID, ok := sessions[peer.ID]; ok {
				if client, ok := clients[clientID]; ok {
					client.Enqueue(Message{Type: "admin_detach", ID: peer.ID})
				}
				delete(sessions, peer.ID)
			}
			delete(admins, peer.ID)
			globalMu.Unlock()
			logger.Websocket.Infof("Admin disconnected: %v", peer.ID)
		}

		if peer != nil && peer.Role == "client" {
			globalMu.Lock()
			// КРИТИЧЕСКАЯ ПРАВКА: Удаляем из карты только если там лежит именно ЭТОТ объект
			if clients[peer.ID] == peer {
				delete(clients, peer.ID)
				logger.Websocket.Infof("Client mapping removed: %s", peer.ID)
			}

			for adminID, clientID := range sessions {
				if clientID == peer.ID {
					if admin, ok := admins[adminID]; ok {
						admin.Enqueue(Message{Type: "session_closed", ClientID: peer.ID, Error: "Client disconnected"})
					}
					delete(sessions, adminID)
				}
			}
			globalMu.Unlock()
			logger.Websocket.Infof("Client disconnected: %v", peer.ID)
		}
		conn.Close()
	}()
}
