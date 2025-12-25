package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

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

	// === AUTH ===
	Password string `json:"password,omitempty"`
	Error    string `json:"error,omitempty"`
}

type AuthState struct {
	Attempts int
	Blocked  time.Time
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	admins   = make(map[string]*Peer)
	clients  = make(map[string]*Peer)
	globalMu sync.Mutex

	passwords = map[string]string{}
	authState = map[string]*AuthState{}
	authMu    sync.Mutex
)

func loadPasswords() {
	data, err := os.ReadFile("passwords.json")
	if err != nil {
		log.Fatal("passwords.json not found")
	}
	json.Unmarshal(data, &passwords)
}

func savePasswords() {
	data, _ := json.MarshalIndent(passwords, "", "  ")
	_ = os.WriteFile("passwords.json", data, 0644)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var peer *Peer
	authenticated := false

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

		// === AUTH ===
		case "auth":
			authMu.Lock()
			state := authState[msg.ClientID]
			if state == nil {
				state = &AuthState{}
				authState[msg.ClientID] = state
			}

			if time.Now().Before(state.Blocked) {
				authMu.Unlock()
				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Тайм-аут 1 минута",
				})
				continue
			}

			if passwords[msg.ClientID] != msg.Password {
				state.Attempts++
				if state.Attempts >= 3 {
					state.Blocked = time.Now().Add(time.Minute)
					state.Attempts = 0
				}
				authMu.Unlock()

				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Неверный логин или пароль",
				})
				continue
			}

			state.Attempts = 0
			authMu.Unlock()

			authenticated = true
			conn.WriteJSON(Message{Type: "auth_ok"})

		// === REGISTER ===
		case "register":

			// === AUTH REQUIRED ONLY FOR ADMIN ===
			if msg.Role == "admin" && !authenticated {
				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Admin not authenticated",
				})
				return
			}

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

		case "client_hello":

			authMu.Lock()
			stored, exists := passwords[msg.ID]

			// === NEW CLIENT ===
			if !exists {
				passwords[msg.ID] = msg.Password
				savePasswords()
				log.Println("New client registered:", msg.ID)
			} else {
				// === EXISTING CLIENT ===
				if stored != msg.Password {
					authMu.Unlock()
					log.Println("Client auth failed:", msg.ID)
					return
				}
			}

			authMu.Unlock()

			peer = &Peer{
				ID:   msg.ID,
				Role: "client",
				Conn: conn,
			}

			globalMu.Lock()
			clients[peer.ID] = peer
			globalMu.Unlock()

			log.Println("Client connected:", peer.ID)

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
	loadPasswords()

	http.HandleFunc("/ws", wsHandler)
	log.Println("Server listening on :22233")
	http.ListenAndServe(":22233", nil)
}
