package ws

type Message struct {
	Type       string                 `json:"type"`
	ClientID   string                 `json:"client_id,omitempty"`
	ClientCode int64                  `json:"client_code,omitempty"`
	CommandID  string                 `json:"command_id,omitempty"`
	Command    string                 `json:"command,omitempty"`
	Prompt     string                 `json:"prompt,omitempty"`
	Result     map[string]interface{} `json:"result,omitempty"`
	Role       string                 `json:"role,omitempty"`
	ID         string                 `json:"id,omitempty"`

	// === AUTH ===
	Password string `json:"password,omitempty"`
	ApiKey   string `json:"api_key,omitempty"`
	TempPass string `json:"temp_pass,omitempty"`
	Error    string `json:"error,omitempty"`

	// === HANDSHAKE ===
	PublicKey   string `json:"public_key,omitempty"`
	Signature   string `json:"signature,omitempty"` // Здесь приходит подпись (sign)
	Challenge   string `json:"challenge,omitempty"`
	Answer      any    `json:"answer,omitempty"` // Может быть string ("ok", "fail" etc)
	Description string `json:"description,omitempty"`
}

type OutboundMessage struct {
	Kind MessageKind
	JSON *Message
	Ping []byte
}

type MessageKind int

const (
	OutboundJSON MessageKind = iota
	OutboundPing
)
