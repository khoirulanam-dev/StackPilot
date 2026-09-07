package protocol

// CurrentVersion is the currently supported Agent presence protocol version.
const CurrentVersion = 1

// HeartbeatEndpointPath is the HTTP path for Agent presence heartbeat requests on the remote TLS listener.
const HeartbeatEndpointPath = "/api/v1/agent/heartbeat"

// HeartbeatRequest defines the JSON payload sent by an Agent during presence heartbeats.
type HeartbeatRequest struct {
	ProtocolVersion int `json:"protocol_version"`
}
