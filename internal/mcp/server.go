// Package mcpserver exposes asynchronous GVS tasks through Streamable HTTP MCP.
package mcpserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is shared with the REST task handlers; scans must outlive HTTP requests.
type Backend interface {
	StartCallgraph(api.CallgraphRequest, string) (api.TaskSnapshot, error)
	GetTask(string) (api.TaskSnapshot, error)
	CancelTask(string) (api.TaskSnapshot, error)
	ReadTaskResult(string) ([]byte, error)
}

type adapter struct {
	backend   Backend
	cursorKey [32]byte
}

type baseURLKey struct{}
type remoteIPKey struct{}

// NewHandler constructs an MCP endpoint. Its caller controls whether it is enabled.
func NewHandler(version string, backend Backend, allowedOrigins []string, publicURL string) (http.Handler, error) {
	if backend == nil {
		return nil, fmt.Errorf("MCP requires a task backend")
	}
	allowed := make(map[string]bool)
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		normalized, err := parseOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("GVS_MCP_ALLOWED_ORIGINS: %w", err)
		}
		allowed[normalized] = true
	}
	if publicURL != "" {
		u, err := parseHTTPURL(publicURL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("GVS_PUBLIC_URL must be an HTTP(S) URL without credentials, query, or fragment")
		}
		publicURL = strings.TrimRight(publicURL, "/")
	}
	a := &adapter{backend: backend}
	if _, err := rand.Read(a.cursorKey[:]); err != nil {
		return nil, fmt.Errorf("initialize result cursors: %w", err)
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "gvs", Version: version}, &sdk.ServerOptions{
		Instructions: "GVS scans run in the background and may take several minutes. Submit gvs_scan or gvs_manual_scan, then wait pollAfterSeconds and call gvs_status repeatedly until completed, failed, or cancelled. A client disconnect does not cancel a scan. Use gvs_cancel to request cancellation. When result.inline is false and result.available is true, call gvs_read_result, follow nextCursor until eof, and concatenate content to recover the full result JSON. Scanner and AI verdicts are separate assessments; never replace them with a combined safety verdict.",
		Capabilities: &sdk.ServerCapabilities{},
	})
	a.addTools(server)
	server.AddReceivingMiddleware(logToolCalls, boundToolResults)
	transport := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: maxRequestBytes})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if origins, present := r.Header["Origin"]; present {
			if len(origins) != 1 {
				http.Error(w, "MCP origin is not allowed", http.StatusForbidden)
				return
			}
			origin, err := parseOrigin(origins[0])
			if err != nil || !allowed[origin] {
				http.Error(w, "MCP origin is not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origins[0])
			w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version")
		}
		if r.Method == http.MethodOptions {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if method := r.Header.Get("Access-Control-Request-Method"); method != "" && method != http.MethodPost {
				http.Error(w, "MCP method is not allowed", http.StatusMethodNotAllowed)
				return
			}
			for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
				switch strings.ToLower(strings.TrimSpace(header)) {
				case "", "content-type", "accept", "authorization", "mcp-protocol-version", "mcp-session-id", "last-event-id":
				default:
					http.Error(w, "MCP request header is not allowed", http.StatusForbidden)
					return
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-Id")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		baseURL := publicURL
		if baseURL == "" {
			baseURL = api.PublicBaseURL(r)
		}
		r = r.WithContext(context.WithValue(r.Context(), baseURLKey{}, baseURL))
		r = r.WithContext(context.WithValue(r.Context(), remoteIPKey{}, api.RemoteIP(r)))
		transport.ServeHTTP(w, r)
	}), nil
}

func logToolCalls(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		if method != "tools/call" {
			return next(ctx, method, req)
		}
		name := ""
		if params, ok := req.GetParams().(*sdk.CallToolParamsRaw); ok {
			name = params.Name
		}
		started := time.Now()
		result, err := next(ctx, method, req)
		failed := err != nil
		if toolResult, ok := result.(*sdk.CallToolResult); ok {
			failed = failed || toolResult.IsError
		}
		// Arguments and result contents can contain repository credentials or source.
		remoteIP, _ := ctx.Value(remoteIPKey{}).(string)
		log.Printf("[MCP] remote_ip=%.128q tool=%.128q failed=%t duration=%s", remoteIP, name, failed, time.Since(started))
		return result, err
	}
}

func parseHTTPURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || strings.ContainsAny(u.Host, " \t\r\n") || strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("invalid HTTP(S) URL %q", value)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port in URL %q", value)
		}
	}
	return u, nil
}

func parseOrigin(value string) (string, error) {
	u, err := parseHTTPURL(value)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, "#*") {
		return "", fmt.Errorf("invalid browser origin %q (use an explicit HTTP(S) origin without a path)", value)
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}
