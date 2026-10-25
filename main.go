package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	WebGUI struct {
		Enabled bool `json:"enabled"`
		Port    int  `json:"port"`
	} `json:"web_gui"`
	Firewall struct {
		Enabled            bool `json:"enabled"`
		MaxFailures        int  `json:"max_failures"`
		FindTimeSeconds    int  `json:"find_time_seconds"`
		BanDurationSeconds int  `json:"ban_duration_seconds"`
	} `json:"firewall"`
	Honeypot struct {
		Enabled bool `json:"enabled"`
		Port    int  `json:"port"`
	} `json:"honeypot"`
	Telegram struct {
		Enabled  bool   `json:"enabled"`
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
	} `json:"telegram"`
	Zalo struct {
		Enabled    bool   `json:"enabled"`
		WebhookURL string `json:"webhook_url"`
	} `json:"zalo"`
	WhitelistCIDRs   []string `json:"whitelist_cidrs"`
	HomeAssistantLog string   `json:"homeassistant_log"`
	NginxAccessLog   string   `json:"nginx_access_log"`
	MonitorSSH       bool     `json:"monitor_ssh"`
	RateLimitSeconds int      `json:"rate_limit_seconds"`
}

type AlertEvent struct {
	ID           string    `json:"id"`
	Source       string    `json:"source"`
	SourceIP     string    `json:"source_ip"`
	AttackType   string    `json:"attack_type"`
	Details      string    `json:"details"`
	Geo          string    `json:"geo"`
	Timestamp    time.Time `json:"timestamp"`
	IsSuspicious bool      `json:"is_suspicious"`
	ReportedTG   bool      `json:"reported_tg"`
	ReportedZalo bool      `json:"reported_zalo"`
	RateLimited  bool      `json:"rate_limited"`
	WasBanned    bool      `json:"was_banned"`
}

type BanRecord struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Geo       string    `json:"geo"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type FailTracker struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type GeoInfo struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	Query   string `json:"query"`
}

var (
	reHAFailedAuth = regexp.MustCompile(`Login attempt (?:or request )?with invalid authentication from ([^ (]+)`)
	reHAFailed     = regexp.MustCompile(`Login attempt failed from ([^ (]+)`)
	reHABanned     = regexp.MustCompile(`Banned IP ([^ (]+)`)

	reSSHFailPass = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port \d+`)
	reSSHInvalid  = regexp.MustCompile(`Invalid user (\S+) from (\S+) port \d+`)
	reSSHAccepted = regexp.MustCompile(`Accepted (?:publickey|password) for (\S+) from (\S+) port \d+`)

	reNginxLine = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]+)" (\d{3})`)
)

type Guardian struct {
	cfg        Config
	configPath string
	whitelist  []*net.IPNet
	alertLock  sync.Mutex
	alertCache map[string]time.Time
	httpClient *http.Client

	// Web GUI stats & events
	startedAt   time.Time
	eventsMu    sync.RWMutex
	events      []AlertEvent
	statsMu     sync.RWMutex
	totalAlerts int
	haAlerts    int
	sshAlerts   int
	nginxAlerts int
	honeypotHits int
	totalBans   int

	// Fail2ban-like jail tracking & active bans
	jailMu       sync.Mutex
	failTracking map[string]*FailTracker
	bannedIPs    map[string]BanRecord

	// SSE subscribers
	sseMu      sync.Mutex
	sseClients map[chan AlertEvent]struct{}
}

func main() {
	configPath := flag.String("config", "/etc/nas-guardian/config.json", "Path to config file")
	flag.Parse()

	guardian, err := NewGuardian(*configPath)
	if err != nil {
		log.Fatalf("Error initializing guardian: %v", err)
	}

	// Initialize Linux iptables firewall bouncer
	if guardian.cfg.Firewall.Enabled {
		if err := guardian.initFirewall(); err != nil {
			log.Printf("Warning: Failed to init iptables firewall: %v", err)
		} else {
			log.Println("Active Firewall Bouncer initialized. Kernel-level DROP enabled.")
		}
	}

	log.Printf("NAS Guardian started. Monitoring security logs (Web GUI port: %d)...", guardian.cfg.WebGUI.Port)
	guardian.SendStartupNotice()

	stopChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if guardian.cfg.WebGUI.Enabled {
		go guardian.startWebGUI()
	}

	// Start auto-unban cleaner routine
	go guardian.autoUnbanWorker(stopChan)

	// Start Honeypot trap
	if guardian.cfg.Honeypot.Enabled {
		go guardian.startHoneypot(stopChan)
	}

	// Start log monitors
	go guardian.monitorHomeAssistant(stopChan)
	if guardian.cfg.MonitorSSH {
		go guardian.monitorSSHJournal(stopChan)
	}
	if guardian.cfg.NginxAccessLog != "" {
		go guardian.monitorNginx(stopChan)
	}

	<-sigChan
	log.Println("Received termination signal. Cleaning up...")
	close(stopChan)
	if guardian.cfg.Firewall.Enabled {
		guardian.cleanupFirewall()
	}
	time.Sleep(1 * time.Second)
}

func NewGuardian(configPath string) (*Guardian, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.RateLimitSeconds <= 0 {
		cfg.RateLimitSeconds = 300
	}
	if cfg.WebGUI.Port <= 0 {
		cfg.WebGUI.Port = 8799
	}
	if !cfg.WebGUI.Enabled && cfg.WebGUI.Port > 0 {
		cfg.WebGUI.Enabled = true
	}
	if cfg.Firewall.MaxFailures <= 0 {
		cfg.Firewall.MaxFailures = 3
	}
	if cfg.Firewall.FindTimeSeconds <= 0 {
		cfg.Firewall.FindTimeSeconds = 600
	}
	if cfg.Firewall.BanDurationSeconds <= 0 {
		cfg.Firewall.BanDurationSeconds = 3600 // 1 hour
	}
	if cfg.Honeypot.Port <= 0 {
		cfg.Honeypot.Port = 2222
	}

	var parsedNets []*net.IPNet
	for _, cidr := range cfg.WhitelistCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedNets = append(parsedNets, ipNet)
		} else {
			log.Printf("Warning: Invalid CIDR %q: %v", cidr, err)
		}
	}

	return &Guardian{
		cfg:          cfg,
		configPath:   configPath,
		whitelist:    parsedNets,
		alertCache:   make(map[string]time.Time),
		httpClient:   &http.Client{Timeout: 8 * time.Second},
		startedAt:    time.Now(),
		events:       make([]AlertEvent, 0, 200),
		failTracking: make(map[string]*FailTracker),
		bannedIPs:    make(map[string]BanRecord),
		sseClients:   make(map[chan AlertEvent]struct{}),
	}, nil
}

func (g *Guardian) isWhitelisted(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, ipNet := range g.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ----------------- Firewall Bouncer (iptables) -----------------

const chainName = "NAS_GUARDIAN_JAIL"

func (g *Guardian) initFirewall() error {
	// Create dedicated chain if not exists
	exec.Command("iptables", "-N", chainName).Run()

	// Link chain to INPUT (host services like SSH)
	if err := exec.Command("iptables", "-C", "INPUT", "-j", chainName).Run(); err != nil {
		if out, err := exec.Command("iptables", "-I", "INPUT", "1", "-j", chainName).CombinedOutput(); err != nil {
			return fmt.Errorf("link to INPUT: %s (%v)", string(out), err)
		}
	}

	// Link chain to DOCKER-USER (container services like Home Assistant, Nginx)
	if err := exec.Command("iptables", "-C", "DOCKER-USER", "-j", chainName).Run(); err != nil {
		exec.Command("iptables", "-I", "DOCKER-USER", "1", "-j", chainName).Run()
	}

	return nil
}

func (g *Guardian) cleanupFirewall() {
	exec.Command("iptables", "-D", "INPUT", "-j", chainName).Run()
	exec.Command("iptables", "-D", "DOCKER-USER", "-j", chainName).Run()
	exec.Command("iptables", "-F", chainName).Run()
	exec.Command("iptables", "-X", chainName).Run()
	log.Println("Firewall cleanup finished. Removed custom iptables rules.")
}

func (g *Guardian) BanIP(ip string, reason string, duration time.Duration) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" || g.isWhitelisted(ip) {
		log.Printf("Cannot ban whitelisted or invalid IP: %s", ip)
		return false
	}

	g.jailMu.Lock()
	if _, alreadyBanned := g.bannedIPs[ip]; alreadyBanned {
		g.jailMu.Unlock()
		return false
	}

	now := time.Now()
	expiresAt := now.Add(duration)
	geo := g.lookupGeo(ip)
	g.bannedIPs[ip] = BanRecord{
		IP:        ip,
		Reason:    reason,
		Geo:       geo,
		BannedAt:  now,
		ExpiresAt: expiresAt,
	}
	g.jailMu.Unlock()

	g.statsMu.Lock()
	g.totalBans++
	g.statsMu.Unlock()

	// Execute iptables kernel-level drop
	exec.Command("iptables", "-I", chainName, "1", "-s", ip, "-j", "DROP").Run()
	log.Printf("[FIREWALL BAN] Successfully blocked IP %s at kernel level for %v. Reason: %s", ip, duration, reason)

	// Send urgent Telegram / Zalo ban alert
	banMsg := fmt.Sprintf("⛔ <b>ĐÃ KHÓA IP TẠI TƯỜNG LỬA (AUTO-BAN)</b>\n\n"+
		"🌐 <b>IP bị chặn:</b> <code>%s</code>\n"+
		"📍 <b>Vị trí/ISP:</b> %s\n"+
		"⚡ <b>Lý do:</b> %s\n"+
		"⏳ <b>Thời hạn:</b> %v (đến %s)\n"+
		"🛡️ <i>Mọi gói tin từ IP này tới NAS và Home Assistant đã bị DROP hoàn toàn.</i>",
		ip, geo, reason, duration.Round(time.Minute), expiresAt.Format("15:04:05 02/01/2006"))

	if g.cfg.Telegram.Enabled {
		go g.sendTelegram(banMsg)
	}
	if g.cfg.Zalo.Enabled && g.cfg.Zalo.WebhookURL != "" {
		go g.sendZalo(banMsg)
	}

	return true
}

func (g *Guardian) UnbanIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	g.jailMu.Lock()
	delete(g.bannedIPs, ip)
	g.jailMu.Unlock()

	exec.Command("iptables", "-D", chainName, "-s", ip, "-j", "DROP").Run()
	log.Printf("[FIREWALL UNBAN] Unbanned IP %s", ip)
	return true
}

func (g *Guardian) autoUnbanWorker(stopChan <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			g.jailMu.Lock()
			for ip, record := range g.bannedIPs {
				if now.After(record.ExpiresAt) {
					delete(g.bannedIPs, ip)
					exec.Command("iptables", "-D", chainName, "-s", ip, "-j", "DROP").Run()
					log.Printf("[AUTO-UNBAN] Ban expired for IP %s. Firewall rule removed.", ip)
				}
			}
			g.jailMu.Unlock()
		}
	}
}

// Check if IP exceeds failure threshold (Fail2ban logic)
func (g *Guardian) registerFailureAndCheckBan(ip string, reason string) bool {
	if !g.cfg.Firewall.Enabled || g.isWhitelisted(ip) {
		return false
	}

	g.jailMu.Lock()
	tracker, exists := g.failTracking[ip]
	now := time.Now()
	findWindow := time.Duration(g.cfg.Firewall.FindTimeSeconds) * time.Second

	if !exists || now.Sub(tracker.FirstSeen) > findWindow {
		tracker = &FailTracker{
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		g.failTracking[ip] = tracker
	} else {
		tracker.Count++
		tracker.LastSeen = now
	}

	currentCount := tracker.Count
	g.jailMu.Unlock()

	if currentCount >= g.cfg.Firewall.MaxFailures {
		banDuration := time.Duration(g.cfg.Firewall.BanDurationSeconds) * time.Second
		banReason := fmt.Sprintf("%s (Vượt ngưỡng %d lần vi phạm trong %v)", reason, currentCount, findWindow)
		return g.BanIP(ip, banReason, banDuration)
	}

	return false
}

// ----------------- Honeypot Trap -----------------

func (g *Guardian) startHoneypot(stopChan <-chan struct{}) {
	addr := fmt.Sprintf(":%d", g.cfg.Honeypot.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Honeypot listen error on port %d: %v", g.cfg.Honeypot.Port, err)
		return
	}
	defer listener.Close()

	log.Printf("🪤 Honeypot trap listening on port %d...", g.cfg.Honeypot.Port)

	go func() {
		<-stopChan
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer c.Close()
			host, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				return
			}

			if g.isWhitelisted(host) {
				return
			}

			g.statsMu.Lock()
			g.honeypotHits++
			g.statsMu.Unlock()

			log.Printf("[HONEYPOT TRAP] Caught unauthorized scan from %s on port %d", host, g.cfg.Honeypot.Port)

			// Immediate ban for 24 hours on honeypot trip!
			g.BanIP(host, fmt.Sprintf("Quét cổng bẫy Honeypot (Port %d)", g.cfg.Honeypot.Port), 24*time.Hour)

			g.handleAlert(AlertEvent{
				Source:       "Honeypot Trap",
				SourceIP:     host,
				AttackType:   fmt.Sprintf("Quét cổng ngầm (Cổng bẫy %d)", g.cfg.Honeypot.Port),
				Details:      "Kẻ rà quét kết nối tới cổng bẫy - Hệ thống đã lập tức KHÓA IP tại tường lửa",
				IsSuspicious: true,
				WasBanned:    true,
			})
		}(conn)
	}
}

// ----------------- Alert Handler -----------------

func (g *Guardian) handleAlert(event AlertEvent) {
	cacheKey := fmt.Sprintf("%s:%s", event.Source, event.SourceIP)
	now := time.Now()
	event.Timestamp = now
	event.ID = fmt.Sprintf("evt-%d", now.UnixNano())

	// Fail2ban evaluation
	wasBanned := g.registerFailureAndCheckBan(event.SourceIP, event.AttackType)
	if wasBanned {
		event.WasBanned = true
	}

	g.alertLock.Lock()
	lastAlert, exists := g.alertCache[cacheKey]
	isRateLimited := exists && now.Sub(lastAlert) < time.Duration(g.cfg.RateLimitSeconds)*time.Second
	if !isRateLimited {
		g.alertCache[cacheKey] = now
	}
	g.alertLock.Unlock()

	event.RateLimited = isRateLimited
	event.Geo = g.lookupGeo(event.SourceIP)

	// Update stats
	g.statsMu.Lock()
	g.totalAlerts++
	switch event.Source {
	case "Home Assistant":
		g.haAlerts++
	case "SSH Service":
		g.sshAlerts++
	case "Nginx / Web GUI":
		g.nginxAlerts++
	}
	g.statsMu.Unlock()

	// Store event (keep last 200)
	g.eventsMu.Lock()
	if len(g.events) >= 200 {
		g.events = g.events[1:]
	}
	g.events = append(g.events, event)
	g.eventsMu.Unlock()

	// Broadcast to SSE clients
	g.broadcastSSE(event)

	if isRateLimited {
		log.Printf("[Rate-limited] Suppressing duplicate alert for %s", cacheKey)
		return
	}

	msg := g.formatMessage(event, event.Geo)
	log.Printf("[ALERT] %s | %s | %s", event.Source, event.SourceIP, event.AttackType)

	if g.cfg.Telegram.Enabled {
		go func() {
			if g.sendTelegram(msg) {
				g.updateEventReportStatus(event.ID, true, false)
			}
		}()
	}
	if g.cfg.Zalo.Enabled && g.cfg.Zalo.WebhookURL != "" {
		go func() {
			if g.sendZalo(msg) {
				g.updateEventReportStatus(event.ID, false, true)
			}
		}()
	}
}

func (g *Guardian) updateEventReportStatus(id string, tg, zalo bool) {
	g.eventsMu.Lock()
	defer g.eventsMu.Unlock()
	for i := len(g.events) - 1; i >= 0; i-- {
		if g.events[i].ID == id {
			if tg {
				g.events[i].ReportedTG = true
			}
			if zalo {
				g.events[i].ReportedZalo = true
			}
			break
		}
	}
}

func (g *Guardian) broadcastSSE(event AlertEvent) {
	g.sseMu.Lock()
	defer g.sseMu.Unlock()
	for ch := range g.sseClients {
		select {
		case ch <- event:
		default:
		}
	}
}

func (g *Guardian) lookupGeo(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "IP không hợp lệ"
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return "Mạng nội bộ (Private / LAN)"
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp,org,query", ipStr)
	resp, err := g.httpClient.Get(url)
	if err != nil {
		return "Không tra cứu được ISP"
	}
	defer resp.Body.Close()

	var geo GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil || geo.Status != "success" {
		return "Không rõ vị trí"
	}

	parts := []string{}
	if geo.City != "" {
		parts = append(parts, geo.City)
	}
	if geo.Country != "" {
		parts = append(parts, geo.Country)
	}
	if geo.ISP != "" {
		parts = append(parts, geo.ISP)
	}
	return strings.Join(parts, ", ")
}

func (g *Guardian) formatMessage(event AlertEvent, geo string) string {
	var icon string
	if event.WasBanned {
		icon = "⛔"
	} else if event.IsSuspicious {
		icon = "🚨"
	} else {
		icon = "⚠️"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s <b>CẢNH BÁO BẢO MẬT HỆ THỐNG NAS</b>\n\n", icon))
	sb.WriteString(fmt.Sprintf("🎯 <b>Mục tiêu:</b> %s\n", event.Source))
	sb.WriteString(fmt.Sprintf("⚡ <b>Loại cảnh báo:</b> %s\n", event.AttackType))
	sb.WriteString(fmt.Sprintf("🌐 <b>IP nguồn:</b> <code>%s</code>\n", event.SourceIP))
	sb.WriteString(fmt.Sprintf("📍 <b>Vị trí/ISP:</b> %s\n", geo))
	if event.Details != "" {
		sb.WriteString(fmt.Sprintf("📝 <b>Chi tiết:</b> %s\n", event.Details))
	}
	if event.WasBanned {
		sb.WriteString("🛡️ <b>Trạng thái:</b> <b>ĐÃ KHÓA IP TẠI TƯỜNG LỬA (KERNEL DROP)</b>\n")
	}
	sb.WriteString(fmt.Sprintf("⏰ <b>Thời gian:</b> %s\n", event.Timestamp.Format("2006-01-02 15:04:05")))

	return sb.String()
}

func (g *Guardian) SendStartupNotice() {
	if !g.cfg.Telegram.Enabled && !g.cfg.Zalo.Enabled {
		return
	}
	msg := fmt.Sprintf("🛡️ <b>NAS Guardian đã kích hoạt</b>\n\n"+
		"Hệ thống đang bảo vệ:\n"+
		"• Home Assistant Auth Logs\n"+
		"• SSH Daemon Journal\n"+
		"• Nginx / Web GUI Logs\n"+
		"• Bẫy rà quét Honeypot (Port %d)\n"+
		"• Tự động khóa IP (Fail2ban Bouncer): %v\n"+
		"• Web GUI Dashboard: <code>http://<nas-ip>:%d</code>\n\n"+
		"⏰ <b>Thời gian:</b> %s",
		g.cfg.Honeypot.Port, g.cfg.Firewall.Enabled, g.cfg.WebGUI.Port, time.Now().Format("2006-01-02 15:04:05"))
	if g.cfg.Telegram.Enabled {
		go g.sendTelegram(msg)
	}
	if g.cfg.Zalo.Enabled && g.cfg.Zalo.WebhookURL != "" {
		go g.sendZalo(msg)
	}
}

func (g *Guardian) sendTelegram(htmlMsg string) bool {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", g.cfg.Telegram.BotToken)
	payload := map[string]interface{}{
		"chat_id":    g.cfg.Telegram.ChatID,
		"text":       htmlMsg,
		"parse_mode": "HTML",
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Telegram req error: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Printf("Telegram send error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Telegram API error (%d): %s", resp.StatusCode, string(body))
		return false
	}
	return true
}

func (g *Guardian) sendZalo(msg string) bool {
	cleanMsg := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(msg, "")
	payload := map[string]interface{}{
		"text":    cleanMsg,
		"message": cleanMsg,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", g.cfg.Zalo.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Zalo req error: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Printf("Zalo send error: %v", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 300
}

// ----------------- Web GUI Server -----------------

func (g *Guardian) startWebGUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleDashboardHTML)
	mux.HandleFunc("/api/stats", g.handleAPIStats)
	mux.HandleFunc("/api/events", g.handleAPIEvents)
	mux.HandleFunc("/api/events/stream", g.handleSSEStream)
	mux.HandleFunc("/api/bans", g.handleAPIBans)
	mux.HandleFunc("/api/bans/unban", g.handleAPIUnban)
	mux.HandleFunc("/api/bans/ban", g.handleAPIManualBan)
	mux.HandleFunc("/api/test-alert", g.handleAPITestAlert)

	addr := fmt.Sprintf(":%d", g.cfg.WebGUI.Port)
	log.Printf("Web GUI available at http://0.0.0.0%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Web GUI error: %v", err)
	}
}

func (g *Guardian) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	g.statsMu.RLock()
	defer g.statsMu.RUnlock()
	g.jailMu.Lock()
	activeBansCount := len(g.bannedIPs)
	g.jailMu.Unlock()

	uptime := time.Since(g.startedAt).Round(time.Second).String()

	resp := map[string]interface{}{
		"status":          "active",
		"started_at":      g.startedAt.Format(time.RFC3339),
		"uptime":          uptime,
		"total_alerts":    g.totalAlerts,
		"ha_alerts":       g.haAlerts,
		"ssh_alerts":      g.sshAlerts,
		"nginx_alerts":    g.nginxAlerts,
		"honeypot_hits":   g.honeypotHits,
		"active_bans":     activeBansCount,
		"total_bans":      g.totalBans,
		"monitors": map[string]bool{
			"home_assistant": g.cfg.HomeAssistantLog != "",
			"ssh":            g.cfg.MonitorSSH,
			"nginx":          g.cfg.NginxAccessLog != "",
			"honeypot":       g.cfg.Honeypot.Enabled,
			"firewall":       g.cfg.Firewall.Enabled,
		},
		"channels": map[string]bool{
			"telegram": g.cfg.Telegram.Enabled,
			"zalo":     g.cfg.Zalo.Enabled,
		},
		"whitelist_count": len(g.whitelist),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *Guardian) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	g.eventsMu.RLock()
	defer g.eventsMu.RUnlock()

	reversed := make([]AlertEvent, len(g.events))
	for i, e := range g.events {
		reversed[len(g.events)-1-i] = e
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reversed)
}

func (g *Guardian) handleAPIBans(w http.ResponseWriter, r *http.Request) {
	g.jailMu.Lock()
	defer g.jailMu.Unlock()

	list := make([]BanRecord, 0, len(g.bannedIPs))
	for _, rec := range g.bannedIPs {
		list = append(list, rec)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (g *Guardian) handleAPIUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	success := g.UnbanIP(req.IP)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": success})
}

func (g *Guardian) handleAPIManualBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	if req.Minutes <= 0 {
		req.Minutes = 60
	}
	if req.Reason == "" {
		req.Reason = "Khóa thủ công từ Web GUI Dashboard"
	}

	success := g.BanIP(req.IP, req.Reason, time.Duration(req.Minutes)*time.Minute)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": success})
}

func (g *Guardian) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan AlertEvent, 20)
	g.sseMu.Lock()
	g.sseClients[ch] = struct{}{}
	g.sseMu.Unlock()

	defer func() {
		g.sseMu.Lock()
		delete(g.sseClients, ch)
		g.sseMu.Unlock()
		close(ch)
	}()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case event := <-ch:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (g *Guardian) handleAPITestAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	testIP := "198.51.100.25" // RFC 5737 dummy documentation/test IP
	testEvent := AlertEvent{
		Source:       "Kiểm thử bảo mật (Test)",
		SourceIP:     testIP,
		AttackType:   "Mô phỏng truy cập trái phép",
		Details:      "Người dùng bấm nút 'Kiểm thử cảnh báo' từ Web GUI Dashboard",
		Timestamp:    time.Now(),
		IsSuspicious: true,
	}

	go g.handleAlert(testEvent)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success": true, "message": "Đã gửi cảnh báo thử nghiệm thành công"}`))
}

func (g *Guardian) handleDashboardHTML(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

// ----------------- Monitors -----------------

func (g *Guardian) monitorHomeAssistant(stopChan <-chan struct{}) {
	logPath := g.cfg.HomeAssistantLog
	if logPath == "" {
		return
	}

	for {
		select {
		case <-stopChan:
			return
		default:
		}

		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			time.Sleep(5 * time.Second)
			continue
		}

		file, err := os.Open(logPath)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		file.Seek(0, io.SeekEnd)
		reader := bufio.NewReader(file)

		for {
			select {
			case <-stopChan:
				file.Close()
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fi, statErr := file.Stat()
					curFi, curErr := os.Stat(logPath)
					if curErr != nil || statErr != nil || curFi.Size() < fi.Size() {
						file.Close()
						break
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}
				file.Close()
				break
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if m := reHAFailedAuth.FindStringSubmatch(line); len(m) > 1 {
				ip := m[1]
				if !g.isWhitelisted(ip) {
					g.handleAlert(AlertEvent{
						Source:       "Home Assistant",
						SourceIP:     ip,
						AttackType:   "Xác thực thất bại / Token không hợp lệ",
						Details:      line,
						IsSuspicious: true,
					})
				}
			} else if m := reHAFailed.FindStringSubmatch(line); len(m) > 1 {
				ip := m[1]
				if !g.isWhitelisted(ip) {
					g.handleAlert(AlertEvent{
						Source:       "Home Assistant",
						SourceIP:     ip,
						AttackType:   "Đăng nhập sai mật khẩu (Login Failed)",
						Details:      line,
						IsSuspicious: true,
					})
				}
			} else if m := reHABanned.FindStringSubmatch(line); len(m) > 1 {
				ip := m[1]
				g.handleAlert(AlertEvent{
					Source:       "Home Assistant",
					SourceIP:     ip,
					AttackType:   "IP bị đưa vào danh sách đen (Auto Banned)",
					Details:      line,
					IsSuspicious: true,
				})
			}
		}
	}
}

func (g *Guardian) monitorSSHJournal(stopChan <-chan struct{}) {
	for {
		select {
		case <-stopChan:
			return
		default:
		}

		cmd := exec.Command("journalctl", "-u", "ssh", "-f", "-n", "0", "-o", "cat")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if m := reSSHFailPass.FindStringSubmatch(line); len(m) > 2 {
				user, ip := m[1], m[2]
				if !g.isWhitelisted(ip) {
					g.handleAlert(AlertEvent{
						Source:       "SSH Service",
						SourceIP:     ip,
						AttackType:   fmt.Sprintf("Dò mật khẩu SSH (User: %s)", user),
						Details:      line,
						IsSuspicious: true,
					})
				}
			} else if m := reSSHInvalid.FindStringSubmatch(line); len(m) > 2 {
				user, ip := m[1], m[2]
				if !g.isWhitelisted(ip) {
					g.handleAlert(AlertEvent{
						Source:       "SSH Service",
						SourceIP:     ip,
						AttackType:   fmt.Sprintf("Thử đăng nhập với user không tồn tại (%s)", user),
						Details:      line,
						IsSuspicious: true,
					})
				}
			} else if m := reSSHAccepted.FindStringSubmatch(line); len(m) > 2 {
				user, ip := m[1], m[2]
				if !g.isWhitelisted(ip) {
					g.handleAlert(AlertEvent{
						Source:       "SSH Service",
						SourceIP:     ip,
						AttackType:   fmt.Sprintf("Đăng nhập SSH THÀNH CÔNG từ IP lạ (User: %s)", user),
						Details:      line,
						IsSuspicious: true,
					})
				}
			}
		}

		cmd.Process.Kill()
		cmd.Wait()
		time.Sleep(3 * time.Second)
	}
}

func (g *Guardian) monitorNginx(stopChan <-chan struct{}) {
	logPath := g.cfg.NginxAccessLog
	if logPath == "" {
		return
	}

	suspiciousKeywords := []string{
		"/.env", "/wp-login", "/wp-admin", "/phpmyadmin", "/setup.cgi",
		"/actuator", "/.git", "/api/v1/pods", "/shell", "/bin/sh",
	}

	for {
		select {
		case <-stopChan:
			return
		default:
		}

		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			time.Sleep(5 * time.Second)
			continue
		}

		file, err := os.Open(logPath)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		file.Seek(0, io.SeekEnd)
		reader := bufio.NewReader(file)

		for {
			select {
			case <-stopChan:
				file.Close()
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fi, statErr := file.Stat()
					curFi, curErr := os.Stat(logPath)
					if curErr != nil || statErr != nil || curFi.Size() < fi.Size() {
						file.Close()
						break
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}
				file.Close()
				break
			}

			line = strings.TrimSpace(line)
			m := reNginxLine.FindStringSubmatch(line)
			if len(m) > 4 {
				ip, req, status := m[1], m[3], m[4]
				if !g.isWhitelisted(ip) {
					isScan := false
					lowerReq := strings.ToLower(req)
					for _, kw := range suspiciousKeywords {
						if strings.Contains(lowerReq, kw) {
							isScan = true
							break
						}
					}
					if isScan || status == "401" || status == "403" {
						g.handleAlert(AlertEvent{
							Source:       "Nginx / Web GUI",
							SourceIP:     ip,
							AttackType:   fmt.Sprintf("Quét cổng / Dò lỗ hổng Web (Status %s)", status),
							Details:      req,
							IsSuspicious: true,
						})
					}
				}
			}
		}
	}
}

// ----------------- Embedded HTML Dashboard -----------------

const dashboardHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NAS Guardian — Trung tâm điều hành an ninh mạng (SOC)</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151d30;
      --card-border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      padding: 24px 20px;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon { font-size: 32px; }
    .brand-title { font-size: 22px; font-weight: 700; color: #fff; }
    .brand-subtitle { font-size: 13px; color: var(--text-muted); }
    .header-actions { display: flex; align-items: center; gap: 12px; }
    .btn {
      background: #1e293b;
      color: #fff;
      border: 1px solid #334155;
      padding: 8px 16px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { background: #334155; border-color: #475569; }
    .btn-primary { background: #0284c7; border-color: #0369a1; }
    .btn-primary:hover { background: #0369a1; }
    .btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border-color: rgba(239, 68, 68, 0.4); }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.3); }
    .btn-sm { padding: 4px 10px; font-size: 11px; border-radius: 6px; }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
      70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      position: relative;
      overflow: hidden;
    }
    .stat-label { font-size: 13px; color: var(--text-muted); font-weight: 500; }
    .stat-value { font-size: 28px; font-weight: 700; margin: 8px 0 4px; color: #fff; }
    .stat-sub { font-size: 12px; color: var(--text-muted); }
    .stat-icon { position: absolute; right: 16px; top: 16px; font-size: 24px; opacity: 0.6; }

    /* Module Status Section */
    .modules-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 18px 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .modules-title { font-size: 14px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .modules-list { display: flex; gap: 20px; flex-wrap: wrap; }
    .module-item { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; }
    .module-dot { width: 8px; height: 8px; border-radius: 50%; }
    .dot-active { background: var(--success); }
    .dot-inactive { background: var(--text-muted); }

    /* Banned IP Section */
    .jail-card {
      background: var(--card-bg);
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 12px;
      margin-bottom: 24px;
      overflow: hidden;
    }
    .jail-header {
      background: rgba(239, 68, 68, 0.1);
      padding: 14px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid rgba(239, 68, 68, 0.2);
    }
    .jail-title { font-size: 15px; font-weight: 700; color: #f87171; display: flex; align-items: center; gap: 8px; }

    /* Main Table Section */
    .table-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      overflow: hidden;
    }
    .table-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .table-title { font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
    .table-count { font-size: 12px; background: #1e293b; padding: 2px 8px; border-radius: 10px; color: var(--text-muted); }

    .table-wrapper { overflow-x: auto; max-height: 500px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th {
      background: rgba(30, 41, 59, 0.5);
      color: var(--text-muted);
      font-weight: 600;
      padding: 12px 16px;
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid rgba(30, 41, 59, 0.4);
      vertical-align: middle;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-ha { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-ssh { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-nginx { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
    .badge-honey { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-test { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
    
    .ip-code {
      font-family: monospace;
      font-size: 12px;
      background: #0f172a;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid #1e293b;
      color: #38bdf8;
    }
    .geo-text { font-size: 12px; color: var(--text-muted); }
    .empty-row { text-align: center; color: var(--text-muted); padding: 36px; }

    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1e293b;
      border: 1px solid #334155;
      padding: 12px 20px;
      border-radius: 8px;
      color: #fff;
      font-size: 14px;
      display: none;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
          <div class="brand-title">NAS Guardian</div>
          <div class="brand-subtitle">Hệ thống Giám sát & Phòng thủ Mạng Chủ động (SOC)</div>
        </div>
      </div>
      <div class="header-actions">
        <div class="status-badge">
          <div class="pulse-dot"></div>
          <span>PHÒNG THỦ CHỦ ĐỘNG (ACTIVE)</span>
        </div>
        <button class="btn btn-primary" onclick="triggerTestAlert()">⚡ Thử gửi cảnh báo</button>
      </div>
    </header>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Tổng sự kiện phát hiện</div>
        <div class="stat-value" id="val-total">0</div>
        <div class="stat-sub">Tính từ khi khởi động</div>
        <div class="stat-icon">🚨</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">IP đang bị khóa (Jail)</div>
        <div class="stat-value" id="val-bans" style="color: #ef4444;">0</div>
        <div class="stat-sub">Đang bị DROP ở tường lửa</div>
        <div class="stat-icon">⛔</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Dò mật khẩu SSH</div>
        <div class="stat-value" id="val-ssh" style="color: #f59e0b;">0</div>
        <div class="stat-sub">Chặn qua journalctl</div>
        <div class="stat-icon">🔑</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Home Assistant & Quét Web</div>
        <div class="stat-value" id="val-ha-web" style="color: #38bdf8;">0</div>
        <div class="stat-sub">Lỗi Auth / Token / 401 / 403</div>
        <div class="stat-icon">🏠</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Sập bẫy Honeypot</div>
        <div class="stat-value" id="val-honey" style="color: #f43f5e;">0</div>
        <div class="stat-sub">Quét cổng ngầm Port 2222</div>
        <div class="stat-icon">🪤</div>
      </div>
    </div>

    <!-- Active Guards Info -->
    <div class="modules-card">
      <div class="modules-title">Phân hệ phòng thủ</div>
      <div class="modules-list">
        <div class="module-item">
          <div class="module-dot dot-active"></div>
          <span>iptables Bouncer (Auto-Ban)</span>
        </div>
        <div class="module-item">
          <div class="module-dot dot-active"></div>
          <span>Honeypot Trap (Port 2222)</span>
        </div>
        <div class="module-item">
          <div class="module-dot dot-active"></div>
          <span>SSH Journal Guard</span>
        </div>
        <div class="module-item">
          <div class="module-dot dot-active"></div>
          <span>Home Assistant Watcher</span>
        </div>
        <div class="module-item">
          <div class="module-dot dot-active"></div>
          <span id="label-tg">Telegram (@duinch_bot)</span>
        </div>
      </div>
    </div>

    <!-- Active Jails / Banned IPs Table -->
    <div class="jail-card" id="jail-container" style="display: none;">
      <div class="jail-header">
        <div class="jail-title">
          <span>⛔ Danh sách IP đang bị khóa tại tường lửa (Kernel-level DROP)</span>
          <span class="table-count" id="jail-count" style="background: rgba(239, 68, 68, 0.2); color: #f87171;">0 IP</span>
        </div>
      </div>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>IP bị cấm</th>
              <th>Vị trí / ISP</th>
              <th>Lý do khóa</th>
              <th>Thời điểm khóa</th>
              <th>Thời hạn còn lại</th>
              <th>Thao tác</th>
            </tr>
          </thead>
          <tbody id="jail-tbody">
          </tbody>
        </table>
      </div>
    </div>

    <!-- Event Table -->
    <div class="table-card">
      <div class="table-header">
        <div class="table-title">
          <span>Nhật ký phát hiện tấn công & IP lạ</span>
          <span class="table-count" id="table-count">0 sự kiện</span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted);" id="uptime-label">Uptime: --</div>
      </div>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Thời gian</th>
              <th>Mục tiêu</th>
              <th>Loại cảnh báo</th>
              <th>IP nguồn</th>
              <th>Vị trí / Nhà mạng (ISP)</th>
              <th>Trạng thái phòng thủ</th>
              <th>Kênh báo cáo</th>
            </tr>
          </thead>
          <tbody id="events-tbody">
            <tr>
              <td colspan="7" class="empty-row">Chưa ghi nhận sự kiện tấn công nào. Hệ thống an toàn!</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    function showToast(text) {
      const t = document.getElementById('toast');
      t.innerText = text;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3500);
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('val-total').innerText = data.total_alerts;
        document.getElementById('val-bans').innerText = data.active_bans;
        document.getElementById('val-ssh').innerText = data.ssh_alerts;
        document.getElementById('val-ha-web').innerText = (data.ha_alerts + data.nginx_alerts);
        document.getElementById('val-honey').innerText = data.honeypot_hits;
        document.getElementById('uptime-label').innerText = 'Hoạt động: ' + data.uptime;
      } catch (e) {
        console.error('Stats error:', e);
      }
    }

    async function loadBans() {
      try {
        const res = await fetch('/api/bans');
        const bans = await res.json();
        const container = document.getElementById('jail-container');
        const tbody = document.getElementById('jail-tbody');
        document.getElementById('jail-count').innerText = bans.length + ' IP';

        if (!bans || bans.length === 0) {
          container.style.display = 'none';
          return;
        }

        container.style.display = 'block';
        let html = '';
        const now = new Date();

        for (const b of bans) {
          const exp = new Date(b.expires_at);
          const diffMs = exp - now;
          const remainingMin = Math.max(0, Math.round(diffMs / 60000));
          const timeBanned = new Date(b.banned_at).toLocaleTimeString('vi-VN');

          html += '<tr>' +
            '<td><span class="ip-code" style="color:#ef4444">' + b.ip + '</span></td>' +
            '<td class="geo-text">' + (b.geo || 'Nội bộ') + '</td>' +
            '<td><b>' + b.reason + '</b></td>' +
            '<td>' + timeBanned + '</td>' +
            '<td><span style="color:#f59e0b; font-weight:600">Còn ' + remainingMin + ' phút</span></td>' +
            '<td><button class="btn btn-danger btn-sm" onclick="unbanIP(\'' + b.ip + '\')">Mở khóa</button></td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      } catch (e) {
        console.error('Bans error:', e);
      }
    }

    async function unbanIP(ip) {
      if (!confirm('Bạn có chắc muốn mở khóa cho IP ' + ip + ' không?')) return;
      try {
        const res = await fetch('/api/bans/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip })
        });
        showToast('Đã mở khóa cho IP: ' + ip);
        loadBans();
        loadStats();
      } catch (e) {
        showToast('Lỗi khi mở khóa: ' + e);
      }
    }

    async function loadEvents() {
      try {
        const res = await fetch('/api/events');
        const events = await res.json();
        renderTable(events);
      } catch (e) {
        console.error('Events error:', e);
      }
    }

    function renderTable(events) {
      const tbody = document.getElementById('events-tbody');
      document.getElementById('table-count').innerText = events.length + ' sự kiện';

      if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Chưa ghi nhận sự kiện tấn công nào. Hệ thống an toàn!</td></tr>';
        return;
      }

      let html = '';
      for (const ev of events) {
        let badgeClass = 'badge-ha';
        if (ev.source.includes('SSH')) badgeClass = 'badge-ssh';
        else if (ev.source.includes('Nginx')) badgeClass = 'badge-nginx';
        else if (ev.source.includes('Honeypot')) badgeClass = 'badge-honey';
        else if (ev.source.includes('Test')) badgeClass = 'badge-test';

        const timeStr = new Date(ev.timestamp).toLocaleTimeString('vi-VN', {
          hour: '2-digit', minute: '2-digit', second: '2-digit', day: '2-digit', month: '2-digit'
        });

        let defenseStatus = '<span style="color:#10b981">Đã phát hiện & ghi nhận</span>';
        if (ev.was_banned) {
          defenseStatus = '<span style="color:#ef4444; font-weight:700">⛔ ĐÃ KHÓA IP (DROP)</span>';
        } else if (ev.rate_limited) {
          defenseStatus = '<span style="color:#f59e0b">Đang theo dõi (Rate-limit)</span>';
        }

        let channels = [];
        if (ev.reported_tg) channels.push('<span style="color:#38bdf8">Telegram ✓</span>');
        if (ev.reported_zalo) channels.push('<span style="color:#10b981">Zalo ✓</span>');
        if (channels.length === 0) channels.push('<span style="color:#94a3b8">Đã ghi log</span>');

        html += '<tr>' +
          '<td>' + timeStr + '</td>' +
          '<td><span class="badge ' + badgeClass + '">' + ev.source + '</span></td>' +
          '<td><b>' + ev.attack_type + '</b></td>' +
          '<td><span class="ip-code">' + ev.source_ip + '</span></td>' +
          '<td class="geo-text">' + (ev.geo || 'Nội bộ') + '</td>' +
          '<td>' + defenseStatus + '</td>' +
          '<td>' + channels.join(' · ') + '</td>' +
          '</tr>';
      }
      tbody.innerHTML = html;
    }

    async function triggerTestAlert() {
      try {
        const res = await fetch('/api/test-alert', { method: 'POST' });
        const data = await res.json();
        showToast('⚡ Đã kích hoạt thử nghiệm cảnh báo!');
        setTimeout(() => { loadStats(); loadEvents(); loadBans(); }, 500);
      } catch (e) {
        showToast('Lỗi khi kích hoạt: ' + e);
      }
    }

    function initSSE() {
      const sse = new EventSource('/api/events/stream');
      sse.onmessage = function() {
        loadStats();
        loadEvents();
        loadBans();
      };
      sse.onerror = function() {
        setTimeout(initSSE, 5000);
      };
    }

    loadStats();
    loadEvents();
    loadBans();
    initSSE();
    setInterval(() => { loadStats(); loadBans(); }, 5000);
  </script>
</body>
</html>
`
