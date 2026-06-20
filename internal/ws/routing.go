package ws

import (
	"github.com/gorilla/websocket"
	"posrelayd-noip/internal/logger"
)

func (s *Server) handleCommand(msg Message) {
	sessionID := msg.ID
	targetClientID := msg.ClientID

	client, admin, targetClientID := s.sessions.resolveCommandRoute(sessionID, msg.ClientID)

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

	admin := s.sessions.getAdmin(sessionID)

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

	admin := s.sessions.getAdmin(sessionID)

	if admin == nil {
		logger.Websocket.Warnf(
			"Session close requested, but admin not found: sessionID=%s",
			sessionID,
		)
		return
	}

	s.sessions.DetachAdmin(sessionID)

	admin.Enqueue(Message{
		Type:  "session_closed",
		Error: "CMD session terminated on client",
	})

	logger.Websocket.Infof(
		"Session closed: session_id=%s (initiated by client)",
		sessionID,
	)
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

			notifications := s.sessions.RemovePeer(peer)
			for _, n := range notifications {
				n.Peer.Enqueue(n.Msg)
			}
		}

		conn.Close()
	}()
}
