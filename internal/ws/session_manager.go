package ws

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"posrelayd-noip/internal/logger"
)

const rdTokenTTL = 60 * time.Second

type rdTokenEntry struct {
	tokenHash [32]byte
	sessionID string
	clientID  string
	expiresAt time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	clients  map[string]*Peer  // cmd client_id -> client peer
	admins   map[string]*Peer  // cmd session_id -> admin peer
	sessions map[string]string // cmd session_id -> client_id

	rdAdminsBySessionID map[string]*Peer         // rd session_id -> rd_admin peer
	rdAgentsBySessionID map[string]*Peer         // rd session_id -> rd_agent peer
	rdTokensByHash      map[string]*rdTokenEntry // sha256(token) base64url -> token metadata
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		clients:             make(map[string]*Peer),
		admins:              make(map[string]*Peer),
		sessions:            make(map[string]string),
		rdAdminsBySessionID: make(map[string]*Peer),
		rdAgentsBySessionID: make(map[string]*Peer),
		rdTokensByHash:      make(map[string]*rdTokenEntry),
	}
}

func hashRDToken(token string) ([32]byte, string) {
	hash := sha256.Sum256([]byte(token))
	key := base64.RawURLEncoding.EncodeToString(hash[:])
	return hash, key
}

func (m *SessionManager) CreateRDToken(
	sessionID string,
	clientID string,
	ttl time.Duration,
) (plainToken string, expiresAt time.Time, err error) {
	if sessionID == "" {
		return "", time.Time{}, errors.New("session_id is required")
	}

	if clientID == "" {
		return "", time.Time{}, errors.New("client_id is required")
	}

	if ttl <= 0 {
		ttl = rdTokenTTL
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}

	plainToken = base64.RawURLEncoding.EncodeToString(raw)
	tokenHash, tokenKey := hashRDToken(plainToken)
	expiresAt = time.Now().UTC().Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()

	attachedClientID, ok := m.sessions[sessionID]
	if !ok || attachedClientID == "" {
		return "", time.Time{}, errors.New("cmd session is not attached")
	}

	if attachedClientID != clientID {
		return "", time.Time{}, errors.New("client_id does not match attached cmd session")
	}

	if m.clients[clientID] == nil {
		return "", time.Time{}, errors.New("attached client is offline")
	}

	m.rdTokensByHash[tokenKey] = &rdTokenEntry{
		tokenHash: tokenHash,
		sessionID: sessionID,
		clientID:  clientID,
		expiresAt: expiresAt,
	}

	logger.Websocket.Infof(
		"RD token created: session_id=%s client_id=%s expires_at=%s",
		sessionID,
		clientID,
		expiresAt.Format(time.RFC3339Nano),
	)

	return plainToken, expiresAt, nil
}

func (m *SessionManager) ConsumeRDToken(
	token string,
	sessionID string,
	clientID string,
) bool {
	if token == "" || sessionID == "" || clientID == "" {
		return false
	}

	tokenHash, tokenKey := hashRDToken(token)

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.rdTokensByHash[tokenKey]
	if entry == nil {
		return false
	}

	defer delete(m.rdTokensByHash, tokenKey)

	if subtle.ConstantTimeCompare(entry.tokenHash[:], tokenHash[:]) != 1 {
		return false
	}

	if time.Now().UTC().After(entry.expiresAt) {
		logger.Websocket.Warnf(
			"RD token expired: session_id=%s client_id=%s",
			sessionID,
			clientID,
		)
		return false
	}

	if entry.sessionID != sessionID {
		logger.Websocket.Warnf(
			"RD token rejected: wrong session_id requested=%s expected=%s client_id=%s",
			sessionID,
			entry.sessionID,
			clientID,
		)
		return false
	}

	if entry.clientID != clientID {
		logger.Websocket.Warnf(
			"RD token rejected: wrong client_id requested=%s expected=%s session_id=%s",
			clientID,
			entry.clientID,
			sessionID,
		)
		return false
	}

	attachedClientID, ok := m.sessions[sessionID]
	if !ok || attachedClientID != clientID {
		logger.Websocket.Warnf(
			"RD token rejected: cmd session is not attached anymore session_id=%s client_id=%s",
			sessionID,
			clientID,
		)
		return false
	}

	if m.clients[clientID] == nil {
		logger.Websocket.Warnf(
			"RD token rejected: attached client is offline session_id=%s client_id=%s",
			sessionID,
			clientID,
		)
		return false
	}

	logger.Websocket.Infof(
		"RD token consumed: session_id=%s client_id=%s",
		sessionID,
		clientID,
	)

	return true
}

func (m *SessionManager) RevokeRDTokensBySession(sessionID string) {
	if sessionID == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	revoked := 0
	for tokenKey, entry := range m.rdTokensByHash {
		if entry.sessionID == sessionID {
			delete(m.rdTokensByHash, tokenKey)
			revoked++
		}
	}

	if revoked > 0 {
		logger.Websocket.Infof(
			"RD tokens revoked: session_id=%s count=%d",
			sessionID,
			revoked,
		)
	}
}

func (m *SessionManager) HasActiveRDAgent(sessionID string) bool {
	if sessionID == "" {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rdAgentsBySessionID[sessionID] != nil
}

func (m *SessionManager) CleanupRDSession(sessionID string) (admin *Peer, agent *Peer) {
	if sessionID == "" {
		return nil, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	admin = m.rdAdminsBySessionID[sessionID]
	agent = m.rdAgentsBySessionID[sessionID]

	delete(m.rdAdminsBySessionID, sessionID)
	delete(m.rdAgentsBySessionID, sessionID)

	for tokenKey, entry := range m.rdTokensByHash {
		if entry.sessionID == sessionID {
			delete(m.rdTokensByHash, tokenKey)
		}
	}

	logger.Websocket.Infof(
		"RD session cleaned up: session_id=%s",
		sessionID,
	)

	return admin, agent
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

	for tokenKey, entry := range m.rdTokensByHash {
		if entry.sessionID == session_id {
			delete(m.rdTokensByHash, tokenKey)
		}
	}

	delete(m.rdAdminsBySessionID, session_id)
	delete(m.rdAgentsBySessionID, session_id)

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
			for tokenKey, entry := range m.rdTokensByHash {
				if entry.sessionID == peer.ID {
					delete(m.rdTokensByHash, tokenKey)
				}
			}

			if client := m.clients[clientID]; client != nil {
				notifications = append(notifications, PeerNotification{
					Peer: client,
					Msg: Message{
						Type:      MessageRDAgentStop,
						ID:        peer.ID,
						SessionID: peer.ID,
						ClientID:  clientID,
					},
				})
			}

			if rdAdmin := m.rdAdminsBySessionID[peer.ID]; rdAdmin != nil {
				notifications = append(notifications, PeerNotification{
					Peer: rdAdmin,
					Msg: Message{
						Type:      MessageRDClosed,
						ID:        peer.ID,
						SessionID: peer.ID,
						ClientID:  clientID,
						Error:     "CMD admin disconnected",
					},
				})
			}

			if rdAgent := m.rdAgentsBySessionID[peer.ID]; rdAgent != nil {
				notifications = append(notifications, PeerNotification{
					Peer: rdAgent,
					Msg: Message{
						Type:      MessageRDClosed,
						ID:        peer.ID,
						SessionID: peer.ID,
						ClientID:  clientID,
						Error:     "CMD admin disconnected",
					},
				})
			}

			delete(m.rdAdminsBySessionID, peer.ID)
			delete(m.rdAgentsBySessionID, peer.ID)

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

			for tokenKey, entry := range m.rdTokensByHash {
				if entry.sessionID == sessionID {
					delete(m.rdTokensByHash, tokenKey)
				}
			}

			if rdAdmin := m.rdAdminsBySessionID[sessionID]; rdAdmin != nil {
				notifications = append(notifications, PeerNotification{
					Peer: rdAdmin,
					Msg: Message{
						Type:      MessageRDClosed,
						ID:        sessionID,
						SessionID: sessionID,
						ClientID:  peer.ID,
						Error:     "Client disconnected",
					},
				})
			}

			if rdAgent := m.rdAgentsBySessionID[sessionID]; rdAgent != nil {
				notifications = append(notifications, PeerNotification{
					Peer: rdAgent,
					Msg: Message{
						Type:      MessageRDClosed,
						ID:        sessionID,
						SessionID: sessionID,
						ClientID:  peer.ID,
						Error:     "Client disconnected",
					},
				})
			}

			delete(m.rdAdminsBySessionID, sessionID)
			delete(m.rdAgentsBySessionID, sessionID)
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

		for tokenKey, entry := range m.rdTokensByHash {
			if entry.sessionID == sessionID {
				delete(m.rdTokensByHash, tokenKey)
			}
		}

		if clientID := m.sessions[sessionID]; clientID != "" {
			if client := m.clients[clientID]; client != nil {
				notifications = append(notifications, PeerNotification{
					Peer: client,
					Msg: Message{
						Type:      MessageRDAgentStop,
						ID:        sessionID,
						SessionID: sessionID,
						ClientID:  clientID,
					},
				})
			}
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
