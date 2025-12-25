package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Peer struct {
	ID   string
	Role string // "admin" or "client"
	Conn *websocket.Conn
	Mu   sync.Mutex
}

type Message struct {
	Type      string                 `json:"type"`
	ClientID  string                 `json:"client_id,omitempty"`
	CommandID string                 `json:"command_id,omitempty"`
	Command   string                 `json:"command,omitempty"`
	Prompt    string                 `json:"prompt,omitempty"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Role      string                 `json:"role,omitempty"`
	ID        string                 `json:"id,omitempty"`
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	admins   = make(map[string]*Peer)
	clients  = make(map[string]*Peer)
	globalMu sync.Mutex
)

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var peer *Peer

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			if peer != nil {
				globalMu.Lock()
				if peer.Role == "admin" {
					delete(admins, peer.ID)
				} else {
					delete(clients, peer.ID)
				}
				globalMu.Unlock()
			}
			return
		}

		switch msg.Type {

		case "register":
			peer = &Peer{
				ID:   msg.ID,
				Role: msg.Role,
				Conn: conn,
			}

			globalMu.Lock()
			if peer.Role == "admin" {
				admins[peer.ID] = peer
				log.Println("Admin connected:", peer.ID)
			} else {
				clients[peer.ID] = peer
				log.Println("Client connected:", peer.ID)
			}
			globalMu.Unlock()

		case "command", "interactive_response":
			globalMu.Lock()
			client := clients[msg.ClientID]
			globalMu.Unlock()
			if client != nil {
				client.Mu.Lock()
				client.Conn.WriteJSON(msg)
				client.Mu.Unlock()
			}

		case "interactive_prompt", "result":
			globalMu.Lock()
			for _, admin := range admins {
				admin.Mu.Lock()
				admin.Conn.WriteJSON(msg)
				admin.Mu.Unlock()
			}
			globalMu.Unlock()
		}
	}
}

func main() {
	http.HandleFunc("/ws", wsHandler)
	log.Println("Server listening on :22233")
	http.ListenAndServe(":22233", nil)
}
