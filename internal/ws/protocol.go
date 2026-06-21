package ws

const (
	RoleAdmin   = "admin"
	RoleClient  = "client"
	RoleRDAdmin = "rd_admin"
	RoleRDAgent = "rd_agent"
)

const (
	MessageAdminHello  = "admin_hello"
	MessageClientHello = "client_hello"
	MessageSign        = "sign"
	MessageRegister    = "register"
	MessageAuth        = "auth"
	
	MessageCommand       = "command"
	MessageControl       = "control"
	MessageResult        = "result"
	MessageSessionClosed = "session_closed"

	MessageRDAdminRegister = "rd_admin_register"
	MessageRDAgentRegister = "rd_agent_register"
	MessageRDStart         = "rd_start"
	MessageRDStop          = "rd_stop"
	MessageRDOffer         = "rd_offer"
	MessageRDAnswer        = "rd_answer"
	MessageRDIce           = "rd_ice"
	MessageRDReady         = "rd_ready"
	MessageRDClosed        = "rd_closed"
	MessageRDError         = "rd_error"
)

const (
	RDTargetAdmin = "admin"
	RDTargetAgent = "agent"
)

type Message struct {
	Type       string                 `json:"type"`
	ClientID   string                 `json:"client_id,omitempty"`
	ClientCode int64                  `json:"client_code,omitempty"`
	InstanceID string                 `json:"instance_id,omitempty"`
	CommandID  string                 `json:"command_id,omitempty"`
	Command    string                 `json:"command,omitempty"`
	Prompt     string                 `json:"prompt,omitempty"`
	Result     map[string]interface{} `json:"result,omitempty"`
	Role       string                 `json:"role,omitempty"`
	ID         string                 `json:"id,omitempty"`

	// === RD / WEBRTC ===
	SessionID string `json:"session_id,omitempty"`
	Token     string `json:"token,omitempty"`
	Target    string `json:"target,omitempty"`
	SDP       string `json:"sdp,omitempty"`
	Candidate any    `json:"candidate,omitempty"`

	// === AUTH ===
	Password string `json:"password,omitempty"`
	ApiKey   string `json:"api_key,omitempty"`
	TempPass string `json:"temp_pass,omitempty"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`

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
