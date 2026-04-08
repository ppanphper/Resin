package node

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
)

const semanticHashSchema = "semantic-v1"

var semanticKeyBuilders = map[string]func(map[string]any) (map[string]any, bool){
	"shadowsocks": semanticKeyShadowsocks,
	"vmess":       semanticKeyVMess,
	"vless":       semanticKeyVLESS,
	"trojan":      semanticKeyTrojan,
	"socks":       semanticKeySOCKS,
	"http":        semanticKeyHTTP,
	"hysteria2":   semanticKeyHysteria2,
}

var genericIgnoredRootFields = map[string]struct{}{
	"tag":            {},
	"detour":         {},
	"bind_interface": {},
	"routing_mark":   {},
	"tcp_fast_open":  {},
	"tcp_multi_path": {},
	"udp_fragment":   {},
}

func semanticCanonicalRawOptions(raw map[string]any) ([]byte, bool) {
	nodeType := normalizeNodeType(mapString(raw, "type"))
	if nodeType == "" {
		return nil, false
	}

	// For known protocols, use strict protocol-aware identity extraction.
	if builder, ok := semanticKeyBuilders[nodeType]; ok {
		key, ok := builder(raw)
		if !ok {
			// Known protocol but key extraction failed: fall back to strict hash
			// in caller to avoid accidental over-merge.
			return nil, false
		}
		key["schema"] = semanticHashSchema
		key["type"] = nodeType

		canonical, err := json.Marshal(key)
		if err != nil {
			return nil, false
		}
		return canonical, true
	}

	// For unknown/new protocols, use generic semantic key so adding a new
	// protocol does not require immediate hash-pipeline code changes.
	key, ok := semanticKeyGeneric(raw, nodeType)
	if !ok {
		return nil, false
	}
	key["schema"] = semanticHashSchema
	key["type"] = nodeType

	canonical, err := json.Marshal(key)
	if err != nil {
		return nil, false
	}
	return canonical, true
}

func semanticKeyGeneric(raw map[string]any, nodeType string) (map[string]any, bool) {
	if len(raw) == 0 || nodeType == "" {
		return nil, false
	}

	cloned := cloneMap(raw)

	// Strip presentation/local-dial fields at root level.
	for key := range cloned {
		if _, ignored := genericIgnoredRootFields[strings.ToLower(strings.TrimSpace(key))]; ignored {
			delete(cloned, key)
		}
	}

	normalizeGenericEndpoint(cloned)
	cloned["type"] = nodeType
	return cloned, true
}

func semanticKeyShadowsocks(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}
	method := normalizeShadowsocksMethodForHash(firstNonEmpty(
		mapString(raw, "method"),
		mapString(raw, "cipher"),
	))
	password := mapString(raw, "password")
	if method == "" || password == "" {
		return nil, false
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	if plugin := strings.ToLower(strings.TrimSpace(mapString(raw, "plugin"))); plugin != "" {
		key["plugin"] = plugin
	}
	if pluginOpts := mapString(raw, "plugin_opts", "plugin-opts", "plugin_options", "plugin-options"); pluginOpts != "" {
		key["plugin_opts"] = pluginOpts
	}
	if network := strings.ToLower(strings.TrimSpace(mapString(raw, "network"))); network != "" {
		key["network"] = network
	}
	return key, true
}

func semanticKeyVMess(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}
	uuid := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		mapString(raw, "uuid"),
		mapString(raw, "id"),
	)))
	if uuid == "" {
		return nil, false
	}
	security := strings.ToLower(strings.TrimSpace(mapString(raw, "security")))
	if security == "" {
		security = "auto"
	}
	alterID, ok := mapUint(raw, "alter_id", "alterId", "aid")
	if !ok {
		alterID = 0
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"security":    security,
		"alter_id":    alterID,
	}
	if tls := normalizeTLSForHash(mapAny(raw, "tls"), server, false); len(tls) > 0 {
		key["tls"] = tls
	}
	if transport := normalizeTransportForHash(raw); len(transport) > 0 {
		key["transport"] = transport
	}
	if packetEncoding := strings.ToLower(strings.TrimSpace(mapString(raw, "packet_encoding"))); packetEncoding != "" {
		key["packet_encoding"] = packetEncoding
	}
	return key, true
}

func semanticKeyVLESS(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}
	uuid := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		mapString(raw, "uuid"),
		mapString(raw, "id"),
	)))
	if uuid == "" {
		return nil, false
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
	}
	if flow := strings.ToLower(strings.TrimSpace(mapString(raw, "flow"))); flow != "" {
		key["flow"] = flow
	}
	if tls := normalizeTLSForHash(mapAny(raw, "tls"), server, false); len(tls) > 0 {
		key["tls"] = tls
	}
	if transport := normalizeTransportForHash(raw); len(transport) > 0 {
		key["transport"] = transport
	}
	if packetEncoding := strings.ToLower(strings.TrimSpace(mapString(raw, "packet_encoding"))); packetEncoding != "" {
		key["packet_encoding"] = packetEncoding
	}
	return key, true
}

func semanticKeyTrojan(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}
	password := mapString(raw, "password")
	if password == "" {
		return nil, false
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"password":    password,
	}
	if tls := normalizeTLSForHash(mapAny(raw, "tls"), server, true); len(tls) > 0 {
		key["tls"] = tls
	}
	if transport := normalizeTransportForHash(raw); len(transport) > 0 {
		key["transport"] = transport
	}
	return key, true
}

func semanticKeySOCKS(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}

	version := strings.ToLower(strings.TrimSpace(mapString(raw, "version")))
	if version == "" {
		version = "5"
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"version":     version,
	}
	if username := mapString(raw, "username", "user"); username != "" {
		key["username"] = username
	}
	if password := mapString(raw, "password"); password != "" {
		key["password"] = password
	}
	if network := strings.ToLower(strings.TrimSpace(mapString(raw, "network"))); network != "" {
		key["network"] = network
	}
	return key, true
}

func semanticKeyHTTP(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
	}
	if username := mapString(raw, "username", "user"); username != "" {
		key["username"] = username
	}
	if password := mapString(raw, "password"); password != "" {
		key["password"] = password
	}
	if headers := normalizeHeadersForHash(mapAny(raw, "headers")); len(headers) > 0 {
		key["headers"] = headers
	}
	if tls := normalizeTLSForHash(mapAny(raw, "tls"), server, false); len(tls) > 0 {
		key["tls"] = tls
	}
	return key, true
}

func semanticKeyHysteria2(raw map[string]any) (map[string]any, bool) {
	server, port, ok := semanticServerPort(raw)
	if !ok {
		return nil, false
	}
	password := mapString(raw, "password", "auth")
	if password == "" {
		return nil, false
	}

	key := map[string]any{
		"server":      server,
		"server_port": port,
		"password":    password,
	}
	if tls := normalizeTLSForHash(mapAny(raw, "tls"), server, true); len(tls) > 0 {
		key["tls"] = tls
	}
	if obfs := normalizeHysteria2ObfsForHash(raw); len(obfs) > 0 {
		key["obfs"] = obfs
	}
	if ports := normalizePortListForHash(mapAny(raw, "server_ports", "ports")); len(ports) > 0 {
		key["server_ports"] = ports
	}
	if up, ok := mapUint(raw, "up_mbps"); ok {
		key["up_mbps"] = up
	}
	if down, ok := mapUint(raw, "down_mbps"); ok {
		key["down_mbps"] = down
	}
	if hopInterval := strings.TrimSpace(mapString(raw, "hop_interval", "hop-interval")); hopInterval != "" {
		key["hop_interval"] = hopInterval
	}
	return key, true
}

func semanticServerPort(raw map[string]any) (string, uint64, bool) {
	server := normalizeServerHost(firstNonEmpty(
		mapString(raw, "server"),
		mapString(raw, "address"),
	))
	if server == "" {
		return "", 0, false
	}
	port, ok := mapUint(raw, "server_port", "port")
	if !ok || port == 0 {
		return "", 0, false
	}
	return server, port, true
}

func normalizeTLSForHash(raw any, server string, defaultEnabled bool) map[string]any {
	server = normalizeServerHost(server)
	if raw == nil {
		if !defaultEnabled {
			return nil
		}
		return map[string]any{
			"enabled":     true,
			"server_name": server,
		}
	}

	if enabledBool, ok := raw.(bool); ok {
		if !enabledBool {
			return nil
		}
		out := map[string]any{"enabled": true}
		if defaultEnabled && server != "" {
			out["server_name"] = server
		}
		return out
	}

	tlsMap, ok := toStringMap(raw)
	if !ok {
		if !defaultEnabled {
			return nil
		}
		out := map[string]any{"enabled": true}
		if server != "" {
			out["server_name"] = server
		}
		return out
	}

	enabled := defaultEnabled
	if v, exists := mapBool(tlsMap, "enabled"); exists {
		enabled = v
	} else if !defaultEnabled {
		// When tls object exists but "enabled" is absent, treat as enabled.
		enabled = true
	}
	if !enabled {
		return nil
	}

	out := map[string]any{"enabled": true}
	serverName := normalizeServerHost(firstNonEmpty(
		mapString(tlsMap, "server_name"),
		mapString(tlsMap, "serverName"),
		mapString(tlsMap, "servername"),
		mapString(tlsMap, "sni"),
		mapString(tlsMap, "peer"),
	))
	if serverName == "" && defaultEnabled {
		serverName = server
	}
	if serverName != "" {
		out["server_name"] = serverName
	}

	if insecure, exists := mapBool(
		tlsMap,
		"insecure",
		"allowInsecure",
		"allow_insecure",
		"skip-cert-verify",
		"skip_cert_verify",
	); exists && insecure {
		out["insecure"] = true
	}

	if alpn := normalizeStringListForHash(mapAny(tlsMap, "alpn")); len(alpn) > 0 {
		out["alpn"] = alpn
	}
	if utls := normalizeUTLSForHash(tlsMap); len(utls) > 0 {
		out["utls"] = utls
	}
	if reality := normalizeRealityForHash(tlsMap); len(reality) > 0 {
		out["reality"] = reality
	}
	if certPath := mapString(tlsMap, "certificate_path", "certificate-path"); certPath != "" {
		out["certificate_path"] = certPath
	}
	if cert := normalizeCertificateForHash(mapAny(tlsMap, "certificate")); len(cert) > 0 {
		out["certificate"] = cert
	}
	return out
}

func normalizeTransportForHash(raw map[string]any) map[string]any {
	transportValue := mapAny(raw, "transport")
	if transportValue == nil {
		return nil
	}
	transportMap, ok := toStringMap(transportValue)
	if !ok {
		return nil
	}

	transportType := normalizeTransportType(mapString(transportMap, "type", "network"))
	switch transportType {
	case "", "tcp":
		return nil
	}

	out := map[string]any{"type": transportType}
	switch transportType {
	case "ws":
		path := strings.TrimSpace(mapString(transportMap, "path"))
		if path == "" {
			path = "/"
		}
		out["path"] = path
		if host := normalizeWSHostForHash(transportMap); host != "" {
			out["host"] = host
		}
		if maxEarlyData, ok := mapUint(transportMap, "max_early_data", "maxEarlyData"); ok {
			out["max_early_data"] = maxEarlyData
		}
		if headerName := strings.ToLower(strings.TrimSpace(mapString(
			transportMap,
			"early_data_header_name",
			"earlyDataHeaderName",
		))); headerName != "" {
			out["early_data_header_name"] = headerName
		}
	case "grpc":
		if serviceName := strings.TrimSpace(mapString(
			transportMap,
			"service_name",
			"grpc_service_name",
			"grpc-service-name",
		)); serviceName != "" {
			out["service_name"] = serviceName
		}
	case "http":
		path := strings.TrimSpace(mapString(transportMap, "path"))
		if path == "" {
			path = "/"
		}
		out["path"] = path
		if hosts := normalizeHostListForHash(mapAny(transportMap, "host")); len(hosts) > 0 {
			out["host"] = hosts
		}
	case "httpupgrade":
		if host := normalizeServerHost(mapString(transportMap, "host")); host != "" {
			out["host"] = host
		}
		path := strings.TrimSpace(mapString(transportMap, "path"))
		if path == "" {
			path = "/"
		}
		out["path"] = path
	case "quic":
		if security := strings.ToLower(strings.TrimSpace(mapString(transportMap, "security"))); security != "" {
			out["security"] = security
		}
		if key := strings.TrimSpace(mapString(transportMap, "key")); key != "" {
			out["key"] = key
		}
	case "kcp":
		if seed := strings.TrimSpace(mapString(transportMap, "seed")); seed != "" {
			out["seed"] = seed
		}
	}
	return out
}

func normalizeUTLSForHash(tls map[string]any) map[string]any {
	utlsValue := mapAny(tls, "utls")
	if utlsValue == nil {
		return nil
	}
	utlsMap, ok := toStringMap(utlsValue)
	if !ok {
		return nil
	}

	if enabled, exists := mapBool(utlsMap, "enabled"); exists && !enabled {
		return nil
	}
	fingerprint := strings.ToLower(strings.TrimSpace(mapString(utlsMap, "fingerprint")))
	if fingerprint == "" {
		return nil
	}
	return map[string]any{
		"enabled":     true,
		"fingerprint": fingerprint,
	}
}

func normalizeRealityForHash(tls map[string]any) map[string]any {
	realityValue := mapAny(tls, "reality")
	if realityValue == nil {
		return nil
	}
	realityMap, ok := toStringMap(realityValue)
	if !ok {
		return nil
	}

	if enabled, exists := mapBool(realityMap, "enabled"); exists && !enabled {
		return nil
	}
	out := map[string]any{"enabled": true}
	if publicKey := strings.TrimSpace(firstNonEmpty(
		mapString(realityMap, "public_key"),
		mapString(realityMap, "public-key"),
		mapString(realityMap, "pbk"),
	)); publicKey != "" {
		out["public_key"] = publicKey
	}
	if shortID := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		mapString(realityMap, "short_id"),
		mapString(realityMap, "short-id"),
		mapString(realityMap, "sid"),
	))); shortID != "" {
		out["short_id"] = shortID
	}
	if len(out) == 1 {
		return nil
	}
	return out
}

func normalizeHysteria2ObfsForHash(raw map[string]any) map[string]any {
	obfsValue := mapAny(raw, "obfs")
	if obfsValue == nil {
		return nil
	}

	switch t := obfsValue.(type) {
	case string:
		obfsType := strings.ToLower(strings.TrimSpace(t))
		if obfsType == "" {
			return nil
		}
		out := map[string]any{"type": obfsType}
		if password := mapString(raw, "obfs_password", "obfs-password"); password != "" {
			out["password"] = password
		}
		return out
	default:
		obfsMap, ok := toStringMap(t)
		if !ok {
			return nil
		}
		obfsType := strings.ToLower(strings.TrimSpace(mapString(obfsMap, "type")))
		if obfsType == "" {
			return nil
		}
		out := map[string]any{"type": obfsType}
		if password := mapString(
			obfsMap,
			"password",
			"obfs_password",
			"obfs-password",
		); password != "" {
			out["password"] = password
		}
		return out
	}
}

func normalizePortListForHash(raw any) []string {
	if raw == nil {
		return nil
	}
	var items []string
	switch t := raw.(type) {
	case string:
		for _, part := range strings.Split(t, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				items = append(items, p)
			}
		}
	case []string:
		for _, item := range t {
			item = strings.TrimSpace(item)
			if item != "" {
				items = append(items, item)
			}
		}
	case []any:
		for _, item := range t {
			s := strings.TrimSpace(stringifyAny(item))
			if s != "" {
				items = append(items, s)
			}
		}
	default:
		s := strings.TrimSpace(stringifyAny(raw))
		if s != "" {
			items = append(items, s)
		}
	}
	if len(items) == 0 {
		return nil
	}
	sort.Strings(items)
	return dedupeSortedStrings(items)
}

func normalizeHeadersForHash(raw any) map[string]any {
	headersMap, ok := toStringMap(raw)
	if !ok || len(headersMap) == 0 {
		return nil
	}
	out := make(map[string]any, len(headersMap))
	for key, value := range headersMap {
		headerKey := strings.ToLower(strings.TrimSpace(key))
		headerValue := strings.TrimSpace(stringifyAny(value))
		if headerKey == "" || headerValue == "" {
			continue
		}
		out[headerKey] = headerValue
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeCertificateForHash(raw any) []string {
	values := normalizeStringListForHash(raw)
	if len(values) == 0 {
		return nil
	}
	return values
}

func normalizeWSHostForHash(raw map[string]any) string {
	headersValue := mapAny(raw, "headers")
	if headersValue == nil {
		return ""
	}
	headersMap, ok := toStringMap(headersValue)
	if !ok {
		return ""
	}
	host := firstNonEmpty(
		mapString(headersMap, "Host"),
		mapString(headersMap, "host"),
	)
	return normalizeServerHost(host)
}

func normalizeHostListForHash(raw any) []string {
	values := normalizeStringListForHash(raw)
	if len(values) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(values))
	for _, value := range values {
		host := normalizeServerHost(value)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	sort.Strings(hosts)
	return dedupeSortedStrings(hosts)
}

func normalizeStringListForHash(raw any) []string {
	if raw == nil {
		return nil
	}
	var values []string
	switch t := raw.(type) {
	case string:
		for _, part := range strings.Split(t, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			if p != "" {
				values = append(values, p)
			}
		}
	case []string:
		for _, part := range t {
			p := strings.ToLower(strings.TrimSpace(part))
			if p != "" {
				values = append(values, p)
			}
		}
	case []any:
		for _, part := range t {
			p := strings.ToLower(strings.TrimSpace(stringifyAny(part)))
			if p != "" {
				values = append(values, p)
			}
		}
	default:
		p := strings.ToLower(strings.TrimSpace(stringifyAny(raw)))
		if p != "" {
			values = append(values, p)
		}
	}
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	return dedupeSortedStrings(values)
}

func mapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if m == nil {
			return ""
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		text := strings.TrimSpace(stringifyAny(value))
		if text != "" {
			return text
		}
	}
	return ""
}

func mapUint(m map[string]any, keys ...string) (uint64, bool) {
	for _, key := range keys {
		if m == nil {
			return 0, false
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch t := value.(type) {
		case int:
			if t >= 0 {
				return uint64(t), true
			}
		case int8:
			if t >= 0 {
				return uint64(t), true
			}
		case int16:
			if t >= 0 {
				return uint64(t), true
			}
		case int32:
			if t >= 0 {
				return uint64(t), true
			}
		case int64:
			if t >= 0 {
				return uint64(t), true
			}
		case uint:
			return uint64(t), true
		case uint8:
			return uint64(t), true
		case uint16:
			return uint64(t), true
		case uint32:
			return uint64(t), true
		case uint64:
			return t, true
		case float32:
			if t >= 0 && float32(uint64(t)) == t {
				return uint64(t), true
			}
		case float64:
			if t >= 0 && float64(uint64(t)) == t {
				return uint64(t), true
			}
		case json.Number:
			if parsed, err := strconv.ParseUint(t.String(), 10, 64); err == nil {
				return parsed, true
			}
		case string:
			if parsed, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64); err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func mapBool(m map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if m == nil {
			return false, false
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch t := value.(type) {
		case bool:
			return t, true
		case string:
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "1", "true", "yes", "on":
				return true, true
			case "0", "false", "no", "off":
				return false, true
			}
		}
	}
	return false, false
}

func mapAny(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if m == nil {
			return nil
		}
		if value, ok := m[key]; ok {
			return value
		}
	}
	return nil
}

func toStringMap(raw any) (map[string]any, bool) {
	switch t := raw.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		out := make(map[string]any, len(t))
		for key, value := range t {
			out[stringifyAny(key)] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func cloneMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = cloneAny(value)
	}
	return dst
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMap(t)
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cloneAny(t[i])
		}
		return out
	default:
		return t
	}
}

func normalizeGenericEndpoint(m map[string]any) {
	server := normalizeServerHost(firstNonEmpty(
		mapString(m, "server"),
		mapString(m, "address"),
	))
	if server != "" {
		m["server"] = server
		delete(m, "address")
	}

	if port, ok := mapUint(m, "server_port", "port"); ok && port > 0 {
		m["server_port"] = port
		delete(m, "port")
	}
}

func normalizeNodeType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "socks", "socks4", "socks4a", "socks5", "socks5h":
		return "socks"
	case "http", "https":
		return "http"
	case "hysteria2", "hy2":
		return "hysteria2"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func normalizeTransportType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ws", "websocket":
		return "ws"
	case "grpc":
		return "grpc"
	case "http", "h2":
		return "http"
	case "httpupgrade", "http-upgrade":
		return "httpupgrade"
	case "quic":
		return "quic"
	case "kcp", "mkcp":
		return "kcp"
	case "tcp":
		return "tcp"
	default:
		return ""
	}
}

func normalizeServerHost(raw string) string {
	host := strings.TrimSpace(raw)
	host = strings.Trim(host, "[]")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

func normalizeShadowsocksMethodForHash(raw string) string {
	method := strings.TrimSpace(raw)
	if method == "" {
		return ""
	}
	upper := strings.ToUpper(strings.ReplaceAll(method, "-", "_"))
	switch upper {
	case "AEAD_CHACHA20_POLY1305":
		return "chacha20-ietf-poly1305"
	case "AEAD_AES_128_GCM":
		return "aes-128-gcm"
	case "AEAD_AES_192_GCM":
		return "aes-192-gcm"
	case "AEAD_AES_256_GCM":
		return "aes-256-gcm"
	}
	if strings.HasPrefix(upper, "AEAD_") {
		return strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(upper, "AEAD_"), "_", "-"))
	}
	return strings.ToLower(method)
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			continue
		}
		out = append(out, values[i])
	}
	return out
}

func stringifyAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int8:
		return strconv.FormatInt(int64(t), 10)
	case int16:
		return strconv.FormatInt(int64(t), 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case uint8:
		return strconv.FormatUint(uint64(t), 10)
	case uint16:
		return strconv.FormatUint(uint64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 64)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return strings.TrimSpace(stringifyFallback(v))
	}
}

func stringifyFallback(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
