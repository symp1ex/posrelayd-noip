package ws

import (
	"github.com/gorilla/websocket"
	"net/http"

	"posrelayd-noip/internal/storage"
)

var db *storage.Storage

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Server struct {
	sessions *SessionManager
}

func NewServer(storageDB *storage.Storage) *Server {
	db = storageDB

	return &Server{
		sessions: NewSessionManager(),
	}
}

func (s *Server) Handler(
	w http.ResponseWriter,
	r *http.Request,
) {
	s.wsHandler(w, r)
}
