package main
import (
	"bufio"
	"encoding/json"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)
const (
	RATE_LIMIT_SECONDS        = 60
	BASELINE_FILE             = "baseline.json"
	MAX_BASELINE_ENTRIES      = 10000
	FREQ_WINDOW               = 60
	FREQ_THRESHOLD            = 20
	BEACON_MIN_SAMPLES        = 5
	BEACON_VARIANCE_THRESHOLD = 2.0
)
var SUSPICIOUS_PORTS = map[int]bool{
	4444: true, 5555: true, 6666: true, 1337: true, 9001: true,
}
type Alert struct {
	Timestamp float64
	Type      string
	Message   string
}
type NetworkMonitor struct {
	learn         bool
	exportCSV     string
	exportJSON    string
	alerts        []Alert
	alertCache    map[string]float64
	procCache     map[int]string
	lock          sync.Mutex
	AllowedPorts  map[int]bool
	AllowedIPs    []*net.IPNet
	AllowedProcs  map[string]interface{}
	baseline      map[string]map[string]bool
	connHistory   map[string][]float64
	beaconHistory map[string][]float64
	terminal      bool
}
func NewNetworkMonitor(terminal bool, config string, learn bool, exportCSV, exportJSON string) *NetworkMonitor {
	n := &NetworkMonitor{
		learn:      learn,
		exportCSV:  exportCSV,
		exportJSON: exportJSON,
		alertCache: make(map[string]float64),
		procCache:  make(map[int]string),
		AllowedPorts: map[int]bool{
			22: true, 53: true, 80: true, 443: true,
		},
		AllowedProcs: make(map[string]interface{}),
		baseline: map[string]map[string]bool{
			"connections":   {},
			"process_ports": {},
		},
		connHistory:   make(map[string][]float64),
		beaconHistory: make(map[string][]float64),
		terminal:      terminal,
	}
	// Default IP ranges
	for _, cidr := range []string{"127.0.0.0/8", "192.168.1.0/24", "::1/128"} {
		_, netw, _ := net.ParseCIDR(cidr)
		n.AllowedIPs = append(n.AllowedIPs, netw)
	}
	n.loadBaseline()
	if config != "" {
		n.loadConfig(config)
	}
	return n
}
func (n *NetworkMonitor) loadConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	var cfg map[string]interface{}
	json.NewDecoder(file).Decode(&cfg)
	if ports, ok := cfg["ports"].([]interface{}); ok {
		for _, p := range ports {
			n.AllowedPorts[int(p.(float64))] = true
		}
	}
	if ranges, ok := cfg["ip_ranges"].([]interface{}); ok {
		for _, r := range ranges {
			_, netw, err := net.ParseCIDR(r.(string))
			if err == nil {
				n.AllowedIPs = append(n.AllowedIPs, netw)
			}
		}
	}
	if procs, ok := cfg["processes"].(map[string]interface{}); ok {
		n.AllowedProcs = procs
	}
}
func (n *NetworkMonitor) loadBaseline() {
	if _, err := os.Stat(BASELINE_FILE); err != nil {
		return
	}
	file, err := os.Open(BASELINE_FILE)
	if err != nil {
		return
	}
	defer file.Close()
	var data map[string][]string
	json.NewDecoder(file).Decode(&data)
	for _, v := range data["connections"] {
		n.baseline["connections"][v] = true
	}
	for _, v := range data["process_ports"] {
		n.baseline["process_ports"][v] = true
	}
}
func (n *NetworkMonitor) saveBaseline() {
	file, err := os.Create(BASELINE_FILE)
	if err != nil {
		return
	}
	defer file.Close()
	out := map[string][]string{
		"connections":   {},
		"process_ports": {},
	}
	for k := range n.baseline["connections"] {
		out["connections"] = append(out["connections"], k)
		if len(out["connections"]) >= MAX_BASELINE_ENTRIES {
			break
		}
	}
	for k := range n.baseline["process_ports"] {
		out["process_ports"] = append(out["process_ports"], k)
		if len(out["process_ports"]) >= MAX_BASELINE_ENTRIES {
			break
		}
	}
	json.NewEncoder(file).Encode(out)
}
func (n *NetworkMonitor) rateLimited(key string) bool {
	now := float64(time.Now().Unix())
	n.lock.Lock()
	defer n.lock.Unlock()
	last := n.alertCache[key]
	if now-last < RATE_LIMIT_SECONDS {
		return true
	}
	n.alertCache[key] = now
	return false
}
func cleanIP(ip string) string {
	ip = strings.Split(ip, "%")[0]
	ip = strings.Trim(ip, "[]")
	return ip
}
func classifyIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	if parsed.IsLoopback() {
		return "loopback"
	}
	if parsed.IsPrivate() {
		return "private"
	}
	if parsed.IsMulticast() {
		return "multicast"
	}
	return "public"
}
func getContext(ip string) string {
	switch classifyIP(ip) {
	case "loopback":
		return "LOOPBACK"
	case "private":
		return "PRIVATE_LAN"
	case "multicast":
		return "MULTICAST"
	case "public":
		return "PUBLIC"
	default:
		return "UNKNOWN"
	}
}
func (n *NetworkMonitor) recordAlert(typ, msg, key, context string) {
	if n.rateLimited(key) {
		return
	}
	prefix := "[UNKNOWN]"
	if context != "" {
		prefix = "[" + context + "]"
	}
	log.Println(prefix, msg)
	n.lock.Lock()
	defer n.lock.Unlock()
	n.alerts = append(n.alerts, Alert{
		Timestamp: float64(time.Now().Unix()),
		Type:      typ,
		Message:   prefix + " " + msg,
	})
}
func getSS(args ...string) []string {
	cmd := exec.Command("ss", append(args, "-H")...)
	out, err := cmd.Output()
	if err != nil {
		return []string{}
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
func (n *NetworkMonitor) processConnection(line string) {
	cols := strings.Fields(line)
	if len(cols) < 5 {
		return
	}
	proto := cols[0]
	dest := cols[4]
	if !strings.Contains(dest, ":") {
		return
	}
	parts := strings.Split(dest, ":")
	ip := cleanIP(strings.Join(parts[:len(parts)-1], ":"))
	portStr := parts[len(parts)-1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s:%s:%d", proto, ip, port)
	now := float64(time.Now().Unix())
	context := getContext(ip)
	// Learn mode
	if n.learn {
		n.lock.Lock()
		if len(n.baseline["connections"]) < MAX_BASELINE_ENTRIES {
			n.baseline["connections"][key] = true
		}
		n.lock.Unlock()
		return
	}
	if !n.baseline["connections"][key] {
		n.recordAlert("first_seen",
			fmt.Sprintf("First-seen connection %s %s:%d", proto, ip, port),
			key, context)
	}
	// Frequency
	hist := n.connHistory[key]
	hist = append(hist, now)
	var filtered []float64
	for _, t := range hist {
		if now-t <= FREQ_WINDOW {
			filtered = append(filtered, t)
		}
	}
	n.connHistory[key] = filtered
	if len(filtered) > FREQ_THRESHOLD {
		n.recordAlert("frequency",
			fmt.Sprintf("High frequency connection %s:%d (%d/min)", ip, port, len(filtered)),
			key, context)
	}
	// Beaconing
	bh := append(n.beaconHistory[key], now)
	if len(bh) >= BEACON_MIN_SAMPLES {
		var intervals []float64
		for i := 1; i < len(bh); i++ {
			intervals = append(intervals, bh[i]-bh[i-1])
		}
		var sum float64
		for _, v := range intervals {
			sum += v
		}
		avg := sum / float64(len(intervals))
		var variance float64
		for _, v := range intervals {
			if v > avg {
				variance += v - avg
			} else {
				variance += avg - v
			}
		}
		variance /= float64(len(intervals))
		if variance < BEACON_VARIANCE_THRESHOLD {
			n.recordAlert("beaconing",
				fmt.Sprintf("Beaconing detected to %s:%d (~%.1fs)", ip, port, avg),
				key, context)
		}
		if len(bh) > 20 {
			bh = bh[1:]
		}
	}
	n.beaconHistory[key] = bh
	// Geo classification
	if !n.AllowedPorts[port] {
		n.recordAlert("geo",
			fmt.Sprintf("Connection to %s IP %s:%d", context, ip, port),
			key, context)
	}
}
// --- Process Handling ---
func (n *NetworkMonitor) processProcess(line string) {
	if !strings.Contains(line, "pid=") {
		return
	}
	pidPart := strings.Split(line, "pid=")
	if len(pidPart) < 2 {
		return
	}
	pidStr := strings.Split(pidPart[1], ",")[0]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return
	}
	n.lock.Lock()
	pname, ok := n.procCache[pid]
	n.lock.Unlock()
	if !ok {
		// fallback: read from /proc
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		data, err := os.ReadFile(commPath)
		if err != nil {
			return
		}
		pname = strings.TrimSpace(string(data))
		n.lock.Lock()
		n.procCache[pid] = pname
		n.lock.Unlock()
	}
	cols := strings.Fields(line)
	if len(cols) < 5 {
		return
	}
	dest := cols[4]
	if !strings.Contains(dest, ":") {
		return
	}
	portStr := dest[strings.LastIndex(dest, ":")+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s:%d", pname, port)
	// Learn mode
	if n.learn {
		n.lock.Lock()
		if len(n.baseline["process_ports"]) < MAX_BASELINE_ENTRIES {
			n.baseline["process_ports"][key] = true
		}
		n.lock.Unlock()
		return
	}
	if SUSPICIOUS_PORTS[port] {
		n.recordAlert("suspicious_port",
			fmt.Sprintf("Process %s using suspicious port %d", pname, port),
			key, "PROCESS")
	}
	if !n.baseline["process_ports"][key] {
		n.recordAlert("process_anomaly",
			fmt.Sprintf("Process %s new port usage %d", pname, port),
			key, "PROCESS")
	}
}
// --- Scan Loop ---
func (n *NetworkMonitor) onceScan(isRoot bool) {
	conns := getSS("-tun")
	var procs []string
	if isRoot {
		procs = getSS("-tunp")
	}
	if len(conns) < 100 {
		for _, l := range conns {
			n.processConnection(l)
		}
		for _, l := range procs {
			n.processProcess(l)
		}
	} else {
		var wg sync.WaitGroup
		for _, l := range conns {
			wg.Add(1)
			go func(line string) {
				defer wg.Done()
				n.processConnection(line)
			}(l)
		}
		for _, l := range procs {
			wg.Add(1)
			go func(line string) {
				defer wg.Done()
				n.processProcess(line)
			}(l)
		}
		wg.Wait()
	}
}
// --- Run Logic ---
func (n *NetworkMonitor) Run(continuous bool, once bool, duration int) {
	currentUser, _ := user.Current()
	isRoot := currentUser.Uid == "0"
	start := time.Now()
	if once {
		n.onceScan(isRoot)
		n.printSummary()
		if n.learn {
			n.saveBaseline()
		}
		return
	}
	if continuous {
		for {
			n.onceScan(isRoot)

			if duration > 0 && int(time.Since(start).Seconds()) >= duration {
				break
			}
			time.Sleep(10 * time.Second)
		}
	} else {
		n.onceScan(isRoot)
	}
	if n.learn {
		n.saveBaseline()
	}
	// CSV export
	if n.exportCSV != "" {
		file, err := os.Create(n.exportCSV)
		if err == nil {
			defer file.Close()
			writer := csv.NewWriter(file)
			for _, a := range n.alerts {
				writer.Write([]string{
					fmt.Sprintf("%.0f", a.Timestamp),
					a.Type,
					a.Message,
				})
			}
			writer.Flush()
		}
	}
	// JSON export
	if n.exportJSON != "" {
		file, err := os.Create(n.exportJSON)
		if err == nil {
			defer file.Close()
			json.NewEncoder(file).Encode(n.alerts)
		}
	}
}
// --- Terminal Summary ---
func (n *NetworkMonitor) printSummary() {
	if len(n.alerts) == 0 {
		fmt.Println("\nNo alerts detected.")
		return
	}
	fmt.Println("\n=== Network Monitor Alerts Summary ===")
	for i, a := range n.alerts {
		fmt.Printf("%d. %s\n", i+1, a.Message)
	}
	fmt.Println("=====================================\n")
}
// --- Main / CLI ---
func main() {
	continuous := flag.Bool("continuous", false, "")
	terminal := flag.Bool("terminal", false, "")
	config := flag.String("config", "", "")
	learn := flag.Bool("learn", false, "")
	exportCSV := flag.String("export-csv", "", "")
	exportJSON := flag.String("export-json", "", "")
	once := flag.Bool("once", false, "")
	duration := flag.Int("duration", 0, "")

	flag.Parse()

	monitor := NewNetworkMonitor(
		*terminal,
		*config,
		*learn,
		*exportCSV,
		*exportJSON,
	)
	monitor.Run(*continuous, *once, *duration)
}
