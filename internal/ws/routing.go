package ws

import (
	"github.com/gorilla/websocket"
	"posrelayd-noip/internal/logger"
	"time"
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

	_, clientID, _ := s.sessions.GetAttachedClient(sessionID)
	s.cleanupRDSession(sessionID, clientID, "CMD session terminated on client")

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

func sessionIDFromMessage(msg Message) string {
	if msg.SessionID != "" {
		return msg.SessionID
	}

	return msg.ID
}

func (s *Server) cleanupRDSession(sessionID string, clientID string, reason string) {
	s.sessions.RevokeRDTokensBySession(sessionID)

	rdAdmin, rdAgent := s.sessions.CleanupRDSession(sessionID)

	if clientID == "" {
		_, attachedClientID, ok := s.sessions.GetAttachedClient(sessionID)
		if ok {
			clientID = attachedClientID
		}
	}

	if client, _, ok := s.sessions.GetAttachedClient(sessionID); ok && client != nil {
		client.Enqueue(Message{
			Type:      MessageRDAgentStop,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
		})
	}

	if rdAdmin != nil {
		rdAdmin.Enqueue(Message{
			Type:      MessageRDClosed,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     reason,
		})
	}

	if rdAgent != nil {
		rdAgent.Enqueue(Message{
			Type:      MessageRDClosed,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     reason,
		})
	}
}

func (s *Server) handleRDAdminRegister(
	conn *websocket.Conn,
	msg Message,
) (*Peer, bool) {
	sessionID := sessionIDFromMessage(msg)
	if sessionID == "" {
		_ = conn.WriteJSON(Message{
			Type:  MessageRDError,
			Error: "session_id is required",
		})
		return nil, false
	}

	peerID := msg.ID
	if peerID == "" {
		peerID = sessionID
	}

	peer := &Peer{
		ID:        peerID,
		Role:      RoleRDAdmin,
		Conn:      conn,
		SessionID: sessionID,
		sendQueue: make(chan OutboundMessage, 256),
		done:      make(chan struct{}),
		lastSeen:  time.Now(),
	}

	peer.StartWriter()
	peer.StartPing(30 * time.Second)

	agent := s.sessions.RegisterRDAdmin(sessionID, peer)

	logger.Websocket.Infof(
		"RD admin connected: peer_id=%s session_id=%s",
		peer.ID,
		sessionID,
	)

	peer.Enqueue(Message{
		Type:      MessageRDReady,
		ID:        sessionID,
		SessionID: sessionID,
	})

	if agent != nil {
		agent.Enqueue(Message{
			Type:      MessageRDReady,
			ID:        sessionID,
			SessionID: sessionID,
		})
	}

	return peer, true
}

func (s *Server) handleRDAgentRegister(
	conn *websocket.Conn,
	msg Message,
) (*Peer, bool) {
	sessionID := sessionIDFromMessage(msg)
	if sessionID == "" {
		_ = conn.WriteJSON(Message{
			Type:  MessageRDError,
			Error: "session_id is required",
		})
		return nil, false
	}

	if msg.Token == "" {
		_ = conn.WriteJSON(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			Error:     "rd token is required",
		})
		return nil, false
	}

	_, attachedClientID, ok := s.sessions.GetAttachedClient(sessionID)
	if !ok {
		_ = conn.WriteJSON(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			Error:     "cmd session is not attached or client is offline",
		})
		return nil, false
	}

	clientID := msg.ClientID
	if clientID == "" {
		clientID = msg.ID
	}

	if clientID != attachedClientID {
		_ = conn.WriteJSON(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     "client_id does not match attached cmd session",
		})
		return nil, false
	}

	if !s.sessions.ConsumeRDToken(msg.Token, sessionID, clientID) {
		_ = conn.WriteJSON(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     "invalid, expired, or already consumed rd token",
		})
		return nil, false
	}

	peerID := msg.ID
	if peerID == "" {
		peerID = sessionID
	}

	peer := &Peer{
		ID:         peerID,
		Role:       RoleRDAgent,
		InstanceID: msg.InstanceID,
		Conn:       conn,
		SessionID:  sessionID,
		sendQueue:  make(chan OutboundMessage, 256),
		done:       make(chan struct{}),
		lastSeen:   time.Now(),
	}

	peer.StartWriter()
	peer.StartPing(30 * time.Second)

	rdAdmin := s.sessions.RegisterRDAgent(sessionID, peer)

	logger.Websocket.Infof(
		"RD agent connected: peer_id=%s session_id=%s client_id=%s",
		peer.ID,
		sessionID,
		clientID,
	)

	peer.Enqueue(Message{
		Type:      MessageRDReady,
		ID:        sessionID,
		SessionID: sessionID,
		ClientID:  clientID,
		Target:    RDTargetAgent,
	})

	notifyAdmin := rdAdmin
	if notifyAdmin == nil {
		notifyAdmin = s.sessions.getAdmin(sessionID)
	}

	if notifyAdmin != nil {
		notifyAdmin.Enqueue(Message{
			Type:      MessageRDReady,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Target:    RDTargetAgent,
		})
	}

	return peer, true
}

func (s *Server) handleRDMessage(from *Peer, msg Message) {
	switch msg.Type {
	case MessageRDStart:
		s.handleRDStart(from, msg)
		return

	case MessageRDStop:
		s.handleRDStop(from, msg)
		return
	}
	if from == nil || (from.Role != RoleRDAdmin && from.Role != RoleRDAgent) {
		logger.Websocket.Warnf(
			"RD routing rejected: peer is not registered as RD peer type=%s",
			msg.Type,
		)
		return
	}

	sessionID := sessionIDFromMessage(msg)
	if sessionID == "" {
		sessionID = from.SessionID
	}

	if sessionID == "" {
		from.Enqueue(Message{
			Type:  MessageRDError,
			Error: "session_id is required",
		})
		return
	}

	admin, agent := s.sessions.resolveRDRoute(sessionID)

	if admin == nil {
		admin = s.sessions.getAdmin(sessionID)
	}

	var target *Peer
	switch msg.Target {
	case RDTargetAdmin:
		target = admin
	case RDTargetAgent:
		target = agent
	default:
		if from.Role == RoleRDAdmin {
			target = agent
		} else {
			target = admin
		}
	}

	if target == nil {
		logger.Websocket.Warnf(
			"RD routing dropped: target not found type=%s from_role=%s session_id=%s target=%s",
			msg.Type,
			from.Role,
			sessionID,
			msg.Target,
		)

		from.Enqueue(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			Error:     "RD target is offline or not registered",
		})
		return
	}

	msg.ID = sessionID
	msg.SessionID = sessionID

	target.Enqueue(msg)
}

func (s *Server) handleRDStart(from *Peer, msg Message) {
	if from == nil || (from.Role != RoleRDAdmin && from.Role != RoleAdmin) {
		logger.Websocket.Warnf(
			"RD start rejected: sender role is not allowed role=%v",
			func() string {
				if from == nil {
					return "<nil>"
				}
				return from.Role
			}(),
		)
		return
	}

	sessionID := sessionIDFromMessage(msg)
	if sessionID == "" {
		from.Enqueue(Message{
			Type:  MessageRDError,
			Error: "session_id is required",
		})
		return
	}

	client, attachedClientID, ok := s.sessions.GetAttachedClient(sessionID)
	if !ok || client == nil {
		from.Enqueue(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			Error:     "cmd session is not attached or client is offline",
		})
		return
	}

	clientID := msg.ClientID
	if clientID == "" {
		clientID = attachedClientID
	}

	if clientID != attachedClientID {
		from.Enqueue(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     "client_id does not match attached cmd session",
		})
		return
	}

	if s.sessions.HasActiveRDAgent(sessionID) {
		from.Enqueue(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     "rd-agent is already active for this session",
		})
		return
	}

	token, expiresAt, err := s.sessions.CreateRDToken(sessionID, clientID, rdTokenTTL)
	if err != nil {
		from.Enqueue(Message{
			Type:      MessageRDError,
			ID:        sessionID,
			SessionID: sessionID,
			ClientID:  clientID,
			Error:     err.Error(),
		})
		return
	}

	client.Enqueue(Message{
		Type:      MessageRDAgentStart,
		ID:        sessionID,
		SessionID: sessionID,
		ClientID:  clientID,
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		Display:   msg.Display,
	})

	from.Enqueue(Message{
		Type:      MessageRDStart,
		ID:        sessionID,
		SessionID: sessionID,
		ClientID:  clientID,
		Target:    RDTargetAgent,
		ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		Display:   msg.Display,
	})

	logger.Websocket.Infof(
		"RD agent start requested: session_id=%s client_id=%s expires_at=%s display=%s",
		sessionID,
		clientID,
		expiresAt.Format(time.RFC3339Nano),
		string(msg.Display),
	)
}

func (s *Server) handleRDStop(from *Peer, msg Message) {
	if from == nil || from.Role != RoleRDAdmin {
		logger.Websocket.Warnf(
			"RD stop rejected: sender is not rd_admin",
		)
		return
	}

	sessionID := sessionIDFromMessage(msg)
	if sessionID == "" {
		from.Enqueue(Message{
			Type:  MessageRDError,
			Error: "session_id is required",
		})
		return
	}

	clientID := msg.ClientID
	if _, attachedClientID, ok := s.sessions.GetAttachedClient(sessionID); ok {
		if clientID == "" {
			clientID = attachedClientID
		}
	}

	s.cleanupRDSession(sessionID, clientID, "RD stopped by admin")

	from.Enqueue(Message{
		Type:      MessageRDClosed,
		ID:        sessionID,
		SessionID: sessionID,
		ClientID:  clientID,
		Error:     "RD stopped by admin",
	})

	logger.Websocket.Infof(
		"RD stop requested: session_id=%s client_id=%s",
		sessionID,
		clientID,
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
