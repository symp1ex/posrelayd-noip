package ws

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"posrelayd-noip/internal/storage"
)

var db *storage.Storage

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var (
	admins   = make(map[string]*Peer)
	clients  = make(map[string]*Peer)
	sessions = make(map[string]string)

	globalMu sync.Mutex
)

type Server struct{}

func NewServer(storageDB *storage.Storage) *Server {
	db = storageDB
	return &Server{}
}

func (s *Server) Handler(
	w http.ResponseWriter,
	r *http.Request,
) {
	s.wsHandler(w, r)
}
