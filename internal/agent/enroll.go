package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"stackpilot/internal/enrollment"
)

const (
	MaxStdinTokenBytes     = 128
	MaxHTTPResponseBody    = 4096
	HTTPClientTimeout      = 10 * time.Second
	EnrollmentEndpointPath = "/api/v1/agent/enroll"
)

// ValidateControllerURL ensures that controller URL points to a literal loopback IP and valid port.
func ValidateControllerURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, errors.New("controller URL is required")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid controller URL")
	}

	if u.Scheme != "http" {
		return nil, errors.New("controller URL scheme must be http")
	}

	if u.User != nil {
		return nil, errors.New("controller URL must not contain credentials")
	}

	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("controller URL must not contain query or fragment")
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, errors.New("controller URL missing host")
	}

	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		return nil, errors.New("controller URL host must be a literal loopback IP address")
	}

	if !ip.IsLoopback() {
		return nil, errors.New("controller URL host must be a loopback IP address")
	}

	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("controller URL must specify a port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("controller URL port is invalid")
	}

	return u, nil
}

// ReadAndValidateTokenFromStdin reads a bounded token stream from stdin until EOF or limit.
// It accepts ONLY <token>, <token>\n, or <token>\r\n.
// It rejects oversized input, empty input, multiple lines, embedded newlines, extra whitespace,
// and invalid token format. Token contents are never included in error messages.
func ReadAndValidateTokenFromStdin(r io.Reader) (string, error) {
	limited := io.LimitReader(r, MaxStdinTokenBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", errors.New("failed to read enrollment token from stdin")
	}
	if len(data) > MaxStdinTokenBytes {
		return "", errors.New("enrollment token input exceeds maximum allowed size")
	}
	if len(data) == 0 {
		return "", errors.New("empty enrollment token from stdin")
	}

	raw := string(data)
	var token string
	if strings.HasSuffix(raw, "\r\n") {
		token = raw[:len(raw)-2]
	} else if strings.HasSuffix(raw, "\n") {
		token = raw[:len(raw)-1]
	} else {
		token = raw
	}

	if len(token) == 0 {
		return "", errors.New("empty enrollment token from stdin")
	}

	if strings.ContainsAny(token, "\r\n") {
		return "", errors.New("stdin contains multiple lines or embedded newline")
	}

	if strings.ContainsAny(token, " \t\v\f") {
		return "", errors.New("enrollment token contains invalid whitespace characters")
	}

	if err := enrollment.ValidateToken(token); err != nil {
		return "", fmt.Errorf("invalid enrollment token: %w", err)
	}

	return token, nil
}

// EnrollOptions specifies parameters for agent enrollment.
type EnrollOptions struct {
	ControllerURL string
	StateDir      string
	TokenReader   io.Reader
	EntropyReader io.Reader
}

type enrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
}

type enrollResponse struct {
	AgentID string `json:"agent_id"`
}

// Enroll executes the full Agent enrollment flow:
// 1. Validates controller URL and parameters
// 2. Checks existing identity metadata (fails closed on invalid/insecure metadata)
// 3. Reads and validates token from stdin
// 4. Generates and persists identity.key before network call (or reuses pending key)
// 5. Sends POST /api/v1/agent/enroll to controller via client with unconditional redirect rejection
// 6. Validates response bounds, Content-Type, and strict JSON
// 7. Atomically persists identity.json on success
func Enroll(ctx context.Context, opts EnrollOptions) (string, error) {
	ctrlURL, err := ValidateControllerURL(opts.ControllerURL)
	if err != nil {
		return "", err
	}

	if opts.StateDir == "" {
		return "", errors.New("state directory is required")
	}

	if opts.TokenReader == nil {
		return "", errors.New("token reader is required")
	}

	// 1. Check existing identity metadata: fail closed on errors
	metaPath := filepath.Join(opts.StateDir, IdentityJSONFileName)
	if _, err := os.Lstat(metaPath); err == nil {
		if _, loadErr := LoadIdentityMetadata(opts.StateDir); loadErr == nil {
			return "", ErrAlreadyEnrolled
		} else {
			return "", fmt.Errorf("existing agent identity metadata is invalid: %w", loadErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to inspect existing agent identity metadata: %w", err)
	}

	// 2. Read and validate token from stdin
	token, err := ReadAndValidateTokenFromStdin(opts.TokenReader)
	if err != nil {
		return "", err
	}

	// 3. Generate and persist identity.key before network request (or reuse existing pending key)
	pub, _, err := LoadOrGenerateKey(opts.StateDir, opts.EntropyReader)
	if err != nil {
		return "", fmt.Errorf("failed to prepare agent identity: %w", err)
	}
	pubKeyStr := FormatPublicKeyBase64RawURL(pub)

	// 4. Construct HTTP client with unconditional redirect rejection
	client := &http.Client{
		Timeout: HTTPClientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("http redirects are not permitted")
		},
	}

	reqBody, err := json.Marshal(enrollRequest{
		Token:     token,
		PublicKey: pubKeyStr,
	})
	if err != nil {
		return "", errors.New("failed to marshal enrollment request")
	}

	targetURL := ctrlURL.ResolveReference(&url.URL{Path: EnrollmentEndpointPath}).String()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", errors.New("failed to construct enrollment request")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", errors.New("enrollment request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBody+1))
	if err != nil {
		return "", errors.New("failed to read enrollment response")
	}
	if len(bodyBytes) > MaxHTTPResponseBody {
		return "", errors.New("controller enrollment response exceeds maximum allowed size")
	}

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		ct := resp.Header.Get("Content-Type")
		if ct == "" {
			return "", errors.New("controller returned missing Content-Type in enrollment response")
		}
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil {
			return "", errors.New("controller returned malformed Content-Type in enrollment response")
		}
		if mediaType != "application/json" {
			return "", errors.New("controller returned invalid Content-Type in enrollment response")
		}
		if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
			return "", errors.New("controller returned unsupported charset in enrollment response")
		}

		var respData enrollResponse
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&respData); err != nil {
			return "", errors.New("controller returned malformed JSON in enrollment response")
		}
		if dec.More() {
			return "", errors.New("controller returned trailing data in enrollment response")
		}
		var trailing json.RawMessage
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return "", errors.New("controller returned additional JSON documents in enrollment response")
		}

		if respData.AgentID == "" {
			return "", errors.New("controller returned empty agent_id in enrollment response")
		}

		if err := ValidateUUIDv7(respData.AgentID); err != nil {
			return "", errors.New("controller returned invalid agent_id format in enrollment response")
		}

		// 5. Persist identity.json atomically
		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       respData.AgentID,
			ControllerURL: opts.ControllerURL,
			PublicKey:     pubKeyStr,
		}
		if err := WriteIdentityMetadata(opts.StateDir, meta); err != nil {
			return "", fmt.Errorf("failed to persist agent identity metadata: %w", err)
		}

		return respData.AgentID, nil

	case http.StatusUnauthorized:
		return "", errors.New("enrollment rejected by controller")
	case http.StatusConflict:
		return "", errors.New("agent identity conflict")
	case http.StatusBadRequest:
		return "", errors.New("controller rejected enrollment request")
	default:
		return "", errors.New("controller enrollment failed")
	}
}
