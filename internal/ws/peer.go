package ws

import (
	"time"

	"github.com/gorilla/websocket"
	"posrelayd-noip/internal/logger"
)

type Peer struct {
	ID   string
	Role string // "admin" or "client"
	Conn *websocket.Conn

	sendQueue chan OutboundMessage
	pingDone  chan struct{}

	done chan struct{}
}

func (p *Peer) StartWriter() {
	go func() {
		logger.Websocket.Debugf(
			"StartWriter started for peer=%s role=%s",
			p.ID, p.Role,
		)
		for {
			select {
			case out, ok := <-p.sendQueue:
				if !ok {
					logger.Websocket.Debugf(
						"StartWriter exiting: sendQueue closed (peer=%s)",
						p.ID,
					)
					return
				}

				switch out.Kind {
				case OutboundJSON:
					if out.JSON != nil {
						if err := p.Conn.WriteJSON(out.JSON); err != nil {
							logger.Websocket.Warnf(
								"WriteJSON failed (peer=%s type=%s): %v",
								p.ID,
								out.JSON.Type,
								err,
							)
							return
						}

						logger.Websocket.Debugf(
							"JSON message sent (peer=%s type=%s)",
							p.ID,
							out.JSON.Type,
						)
					}

				case OutboundPing:
					if err := p.Conn.WriteMessage(websocket.PingMessage, out.Ping); err != nil {
						logger.Websocket.Warnf(
							"Ping failed (peer=%s): %v",
							p.ID,
							err,
						)
						return
					}
				}

			case <-p.done:
				logger.Websocket.Debugf(
					"StartWriter stopped by done signal (peer=%s)",
					p.ID,
				)
				return
			}
		}
	}()
}

func (p *Peer) Enqueue(msg Message) {
	logger.Websocket.Debugf(
		"Message enqueued (peer=%s type=%s)",
		p.ID, msg.Type,
	)

	select {
	case p.sendQueue <- OutboundMessage{
		Kind: OutboundJSON,
		JSON: &msg,
	}:
	case <-p.done:
		logger.Websocket.Warnf(
			"Enqueue dropped message (peer=%s type=%s): peer closed",
			p.ID, msg.Type,
		)
	}
}

func (p *Peer) Close() {
	select {
	case <-p.done:
		logger.Websocket.Debugf(
			"Peer already closed: %s",
			p.ID,
		)
		return
	default:
		logger.Websocket.Infof(
			"Closing peer: %s role=%s",
			p.ID, p.Role,
		)
		close(p.done)
		close(p.sendQueue)
	}
}

func (p *Peer) StartPing(interval time.Duration) {
	p.pingDone = make(chan struct{})

	go func() {
		logger.Websocket.Debugf(
			"Ping loop started (peer=%s interval=%s)",
			p.ID, interval,
		)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				select {
				case p.sendQueue <- OutboundMessage{
					Kind: OutboundPing,
					Ping: []byte("ping"),
				}:
				case <-p.done:
					logger.Websocket.Debugf(
						"Ping loop stopped (peer=%s)",
						p.ID,
					)
					return
				}

			case <-p.done:
				logger.Websocket.Debugf(
					"Ping loop stopped (peer=%s)",
					p.ID,
				)
				return
			}
		}
	}()
}
