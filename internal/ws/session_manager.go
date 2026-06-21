package ws

import (
	"sync"
	"time"

	"posrelayd-noip/internal/logger"
)

type SessionManager struct {
	mu       sync.RWMutex
	clients  map[string]*Peer  // cmd client_id -> client peer
	admins   map[string]*Peer  // cmd session_id -> admin peer
	sessions map[string]string // cmd session_id -> client_id

	rdAdminsBySessionID map[string]*Peer // rd session_id -> rd_admin peer
	rdAgentsBySessionID map[string]*Peer // rd session_id -> rd_agent peer
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		clients:             make(map[string]*Peer),
		admins:              make(map[string]*Peer),
		sessions:            make(map[string]string),
		rdAdminsBySessionID: make(map[string]*Peer),
		rdAgentsBySessionID: make(map[string]*Peer),
	}
}

func (m *SessionManager) RegisterClient(newPeer *Peer) (oldPeer *Peer, takeover bool, registered bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldPeer = m.clients[newPeer.ID]
	if oldPeer == nil {
		m.clients[newPeer.ID] = newPeer

		logger.Websocket.Infof(
			"Client registered: client_id=%s instance_id=%s",
			newPeer.ID,
			newPeer.InstanceID,
		)

		return nil, false, true
	}

	sameInstance :=
		newPeer.InstanceID != "" &&
			oldPeer.InstanceID != "" &&
			newPeer.InstanceID == oldPeer.InstanceID

	stale := time.Since(oldPeer.LastSeen()) > clientStaleAfter

	if sameInstance || stale {
		m.clients[newPeer.ID] = newPeer

		logger.Websocket.Warnf(
			"Client takeover: client_id=%s same_instance=%t stale=%t old_instance_id=%s new_instance_id=%s",
			newPeer.ID,
			sameInstance,
			stale,
			oldPeer.InstanceID,
			newPeer.InstanceID,
		)

		return oldPeer, true, true
	}

	return oldPeer, false, false
}

func (m *SessionManager) RegisterAdmin(peer *Peer) (attachedClient *Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.admins[peer.ID] = peer

	clientID := m.sessions[peer.ID]
	if clientID != "" {
		attachedClient = m.clients[clientID]
	}

	logger.Websocket.Infof(
		"Admin registered successfully, session_id: %s",
		peer.ID,
	)

	return attachedClient
}

func (m *SessionManager) AttachAdminToClient(session_id string, clientID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.clients[clientID] == nil {
		logger.Websocket.Infof(
			"Attach failed: client %s offline (session_id=%s)",
			clientID,
			session_id,
		)
		return false
	}

	m.sessions[session_id] = clientID

	logger.Websocket.Infof(
		"session_id %s attached to client %s",
		session_id,
		clientID,
	)

	return true
}

func (m *SessionManager) DetachAdmin(session_id string) (client *Peer, detached bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clientID, ok := m.sessions[session_id]
	if !ok {
		return nil, false
	}

	client = m.clients[clientID]
	delete(m.sessions, session_id)

	logger.Websocket.Infof(
		"Admin detached: session_id=%s client=%s",
		session_id,
		clientID,
	)

	return client, true
}

func (m *SessionManager) GetAttachedClient(session_id string) (*Peer, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clientID, ok := m.sessions[session_id]
	if !ok || clientID == "" {
		return nil, "", false
	}

	client := m.clients[clientID]
	if client == nil {
		return nil, clientID, false
	}

	return client, clientID, true
}

func (m *SessionManager) RegisterRDAdmin(sessionID string, peer *Peer) (attachedAgent *Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer.SessionID = sessionID
	m.rdAdminsBySessionID[sessionID] = peer

	logger.Websocket.Infof(
		"RD admin registered: session_id=%s peer_id=%s",
		sessionID,
		peer.ID,
	)

	return m.rdAgentsBySessionID[sessionID]
}

func (m *SessionManager) RegisterRDAgent(sessionID string, peer *Peer) (attachedAdmin *Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer.SessionID = sessionID
	m.rdAgentsBySessionID[sessionID] = peer

	logger.Websocket.Infof(
		"RD agent registered: session_id=%s peer_id=%s",
		sessionID,
		peer.ID,
	)

	return m.rdAdminsBySessionID[sessionID]
}

func (m *SessionManager) resolveRDRoute(sessionID string) (*Peer, *Peer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rdAdminsBySessionID[sessionID], m.rdAgentsBySessionID[sessionID]
}

type PeerNotification struct {
	Peer *Peer
	Msg  Message
}

func (m *SessionManager) RemovePeer(peer *Peer) []PeerNotification {
	if peer == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var notifications []PeerNotification

	switch peer.Role {
	case RoleAdmin:
		if clientID, ok := m.sessions[peer.ID]; ok {
			if client := m.clients[clientID]; client != nil {
				notifications = append(notifications, PeerNotification{
					Peer: client,
					Msg:  Message{Type: "admin_detach", ID: peer.ID},
				})
			}

			delete(m.sessions, peer.ID)
		}

		delete(m.admins, peer.ID)

		logger.Websocket.Infof("Admin disconnected: %v", peer.ID)

	case RoleClient:
		if m.clients[peer.ID] == peer {
			delete(m.clients, peer.ID)
			logger.Websocket.Infof("Client mapping removed: %s", peer.ID)
		}

		for sessionID, clientID := range m.sessions {
			if clientID != peer.ID {
				continue
			}

			if admin := m.admins[sessionID]; admin != nil {
				notifications = append(notifications, PeerNotification{
					Peer: admin,
					Msg: Message{
						Type:     "session_closed",
						ClientID: peer.ID,
						Error:    "Client disconnected",
					},
				})
			}

			delete(m.sessions, sessionID)
		}

		logger.Websocket.Infof("Client disconnected: %v", peer.ID)

	case RoleRDAdmin:
		sessionID := peer.SessionID
		if sessionID == "" {
			sessionID = peer.ID
		}

		if m.rdAdminsBySessionID[sessionID] == peer {
			delete(m.rdAdminsBySessionID, sessionID)
		}

		if agent := m.rdAgentsBySessionID[sessionID]; agent != nil {
			notifications = append(notifications, PeerNotification{
				Peer: agent,
				Msg: Message{
					Type:      MessageRDClosed,
					ID:        sessionID,
					SessionID: sessionID,
					Error:     "RD admin disconnected",
				},
			})
		}

		logger.Websocket.Infof("RD admin disconnected: peer_id=%s session_id=%s", peer.ID, sessionID)

	case RoleRDAgent:
		sessionID := peer.SessionID
		if sessionID == "" {
			sessionID = peer.ID
		}

		if m.rdAgentsBySessionID[sessionID] == peer {
			delete(m.rdAgentsBySessionID, sessionID)
		}

		if admin := m.rdAdminsBySessionID[sessionID]; admin != nil {
			notifications = append(notifications, PeerNotification{
				Peer: admin,
				Msg: Message{
					Type:      MessageRDClosed,
					ID:        sessionID,
					SessionID: sessionID,
					Error:     "RD agent disconnected",
				},
			})
		}

		logger.Websocket.Infof("RD agent disconnected: peer_id=%s session_id=%s", peer.ID, sessionID)
	}
	return notifications
}

func (m *SessionManager) resolveCommandRoute(sessionID string, requestedClientID string) (*Peer, *Peer, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resolvedClientID := requestedClientID

	if boundClientID, ok := m.sessions[sessionID]; ok && boundClientID != "" {
		resolvedClientID = boundClientID
	}

	return m.clients[resolvedClientID], m.admins[sessionID], resolvedClientID
}

func (m *SessionManager) getAdmin(sessionID string) *Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.admins[sessionID]
}
