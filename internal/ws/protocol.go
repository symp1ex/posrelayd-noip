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
