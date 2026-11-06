// Package api exposes the daemon on a root-only Unix socket for the CLI.
// The socket's file permissions are the authentication.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
)

// Request bodies.
type (
	AddEgressRequest struct {
		Name   string               `json:"name"`
		Config string               `json:"config"`
		Opts   daemon.EgressOptions `json:"opts"`
	}
	AddClientRequest struct {
		Name string               `json:"name"`
		Opts daemon.ClientOptions `json:"opts"`
	}
	OrderRequest  struct{ Names []string }
	SwitchRequest struct {
		KillSwitch *bool `json:"kill_switch,omitempty"`
		Fast       *bool `json:"fast,omitempty"`
	}
	ClientSwitchRequest struct {
		Action config.PortalAction `json:"action"`
		On     bool                `json:"on"`
	}
	RouteRequest struct {
		Egress  string   `json:"egress"`
		Domains []string `json:"domains"`
	}
	SetRequest      struct{ Key, Value string }
	PasswordRequest struct{ Password string }
	TLSRequest      struct{ Cert, Key string } // PEM contents; both empty = new self-signed
	TextResponse    struct{ Text string }
)

// Handler routes API calls to the daemon.
func Handler(d *daemon.Daemon) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { reply(w, d.Status(), nil) })
	m.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, _ *http.Request) { reply(w, nil, d.Reload()) })
	m.HandleFunc("POST /v1/egresses", func(w http.ResponseWriter, r *http.Request) {
		var req AddEgressRequest
		if decode(w, r, &req) {
			reply(w, nil, d.AddEgress(req.Name, req.Config, req.Opts))
		}
	})
	m.HandleFunc("PATCH /v1/egresses/{name}", func(w http.ResponseWriter, r *http.Request) {
		var o daemon.EgressOptions
		if decode(w, r, &o) {
			reply(w, nil, d.UpdateEgress(r.PathValue("name"), o))
		}
	})
	m.HandleFunc("DELETE /v1/egresses/{name}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, d.RemoveEgress(r.PathValue("name")))
	})
	m.HandleFunc("POST /v1/egresses/order", func(w http.ResponseWriter, r *http.Request) {
		var req OrderRequest
		if decode(w, r, &req) {
			reply(w, nil, d.OrderEgresses(req.Names))
		}
	})
	m.HandleFunc("POST /v1/clients", func(w http.ResponseWriter, r *http.Request) {
		var req AddClientRequest
		if decode(w, r, &req) {
			text, err := d.AddClient(req.Name, req.Opts)
			reply(w, TextResponse{text}, err)
		}
	})
	m.HandleFunc("PATCH /v1/clients/{name}", func(w http.ResponseWriter, r *http.Request) {
		var o daemon.ClientOptions
		if decode(w, r, &o) {
			reply(w, nil, d.UpdateClient(r.PathValue("name"), o))
		}
	})
	m.HandleFunc("DELETE /v1/clients/{name}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, d.RemoveClient(r.PathValue("name")))
	})
	m.HandleFunc("POST /v1/clients/{name}/renew", func(w http.ResponseWriter, r *http.Request) {
		text, err := d.RenewClient(r.PathValue("name"))
		reply(w, TextResponse{text}, err)
	})
	m.HandleFunc("POST /v1/clients/{name}/switch", func(w http.ResponseWriter, r *http.Request) {
		var req ClientSwitchRequest
		if decode(w, r, &req) {
			reply(w, nil, d.SetClientSwitch(r.PathValue("name"), req.Action, req.On))
		}
	})
	m.HandleFunc("POST /v1/switches", func(w http.ResponseWriter, r *http.Request) {
		var req SwitchRequest
		if decode(w, r, &req) {
			reply(w, nil, d.SetGlobal(req.KillSwitch, req.Fast))
		}
	})
	m.HandleFunc("PUT /v1/routes/{name}", func(w http.ResponseWriter, r *http.Request) {
		var req RouteRequest
		if decode(w, r, &req) {
			reply(w, nil, d.SetRoute(r.PathValue("name"), req.Egress, req.Domains))
		}
	})
	m.HandleFunc("DELETE /v1/routes/{name}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, d.RemoveRoute(r.PathValue("name")))
	})
	m.HandleFunc("POST /v1/settings", func(w http.ResponseWriter, r *http.Request) {
		var req SetRequest
		if decode(w, r, &req) {
			reply(w, nil, d.Set(req.Key, req.Value))
		}
	})
	m.HandleFunc("POST /v1/password", func(w http.ResponseWriter, r *http.Request) {
		var req PasswordRequest
		if decode(w, r, &req) {
			reply(w, nil, d.SetPassword(req.Password))
		}
	})
	m.HandleFunc("POST /v1/tls", func(w http.ResponseWriter, r *http.Request) {
		var req TLSRequest
		if decode(w, r, &req) {
			if req.Cert == "" && req.Key == "" {
				reply(w, nil, d.ResetTLS())
				return
			}
			reply(w, nil, d.InstallTLS([]byte(req.Cert), []byte(req.Key)))
		}
	})
	return m
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		reply(w, nil, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

type errorBody struct {
	Error string `json:"error"`
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errorBody{err.Error()})
		return
	}
	if v == nil {
		v = struct{}{}
	}
	_ = json.NewEncoder(w).Encode(v)
}

// Listen creates the socket with mode 0600.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// Client talks to a running daemon.
type Client struct {
	http *http.Client
}

// NewClient connects via the socket at path.
func NewClient(path string) *Client {
	return &Client{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}}
}

// ErrNotRunning is returned when the socket is unreachable.
var ErrNotRunning = errors.New("vwitch is not running (systemctl start vwitch)")

// Do sends a request; in and out may be nil.
func (c *Client) Do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(json.NewEncoder(pw).Encode(in)) }()
		body = pr
	}
	req, err := http.NewRequest(method, "http://vwitch"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return ErrNotRunning
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e errorBody
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return errors.New(e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
