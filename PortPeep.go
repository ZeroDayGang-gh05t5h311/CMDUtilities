package main
import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)
const (
	RATE_LIMIT_SECONDS   = 60
	BASELINE_FILE        = "baseline.json"
	DISK_SPACE_THRESHOLD = 1024 * 1024 * 1024 // 1 GB
)
type NetworkMonitor struct {
	learn            bool
	exportCSV        string
	exportJSON       string
	alerts           []string
	allowedPorts     map[int]bool
	allowedIPRanges  []*net.IPNet
	allowedProcesses map[string][]int
	baseline         map[string]map[string]bool
	alertCache       map[string]time.Time
	terminalOutput   bool
}
func NewNetworkMonitor(terminalOutput bool, configFile string, learn bool, exportCSV string, exportJSON string) (*NetworkMonitor, error) {
	nm := &NetworkMonitor{
		learn:            learn,
		exportCSV:        exportCSV,
		exportJSON:       exportJSON,
		alerts:           []string{},
		allowedPorts:     make(map[int]bool),
		allowedIPRanges:  []*net.IPNet{},
		allowedProcesses: make(map[string][]int),
		baseline:         make(map[string]map[string]bool),
		alertCache:       make(map[string]time.Time),
		terminalOutput:   terminalOutput,
	}
	// Initialize nested baseline map
	nm.baseline["connections"] = make(map[string]bool)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if configFile != "" {
		// Config loading skipped - would panic on missing method anyway
		log.Println("Config file provided but loading not implemented")
	}
	nm.loadBaseline()
	return nm, nil
}
func (nm *NetworkMonitor) loadBaseline() {
	if _, err := os.Stat(BASELINE_FILE); err != nil {
		return
	}
	data, err := ioutil.ReadFile(BASELINE_FILE)
	if err != nil {
		log.Println("Error reading baseline:", err)
		return
	}
	if err := json.Unmarshal(data, &nm.baseline); err != nil {
		log.Println("Error parsing baseline:", err)
		return
	}
	// Ensure connections map exists
	if nm.baseline["connections"] == nil {
		nm.baseline["connections"] = make(map[string]bool)
	}
}
func (nm *NetworkMonitor) saveBaseline() {
	data, err := json.MarshalIndent(nm.baseline, "", "  ")
	if err != nil {
		log.Println("Error marshaling baseline:", err)
		return
	}
	if err := ioutil.WriteFile(BASELINE_FILE, data, 0644); err != nil {
		log.Println("Error saving baseline:", err)
	}
}
func (nm *NetworkMonitor) rateLimited(key string) bool {
	now := time.Now()
	if last, ok := nm.alertCache[key]; ok && now.Sub(last) < time.Duration(RATE_LIMIT_SECONDS)*time.Second {
		return true
	}
	nm.alertCache[key] = now
	return false
}
func (nm *NetworkMonitor) cleanIP(ip string) string {
	if i := strings.Index(ip, "%"); i > 0 {
		return ip[:i]
	}
	return ip
}
func (nm *NetworkMonitor) isIPAllowed(ip string) bool {
	parsed := net.ParseIP(nm.cleanIP(ip))
	if parsed == nil {
		return false
	}
	for _, n := range nm.allowedIPRanges {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
func (nm *NetworkMonitor) getSS(args []string) ([]string, error) {
	cmd := exec.Command("ss", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		return lines[1:], nil // skip header
	}
	return nil, nil
}
func (nm *NetworkMonitor) processConnection(line string) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return
	}
	proto := fields[0]
	remote := fields[4]
	if !strings.Contains(remote, ":") {
		return
	}
	host, portStr, _ := strings.Cut(remote, ":")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s:%s:%s", proto, host, portStr)
	if nm.learn {
		nm.baseline["connections"][key] = true
		return
	}
	if _, known := nm.baseline["connections"][key]; known {
		return
	}
	// Alert logic (very basic - adjust as needed)
	if _, allowed := nm.allowedPorts[port]; allowed && !nm.isIPAllowed(host) {
		if nm.rateLimited(key) {
			return
		}
		msg := fmt.Sprintf("Unusual outbound connection %s %s:%s", proto, host, portStr)
		log.Println(msg)
		nm.alerts = append(nm.alerts, msg)
	}
}
func (nm *NetworkMonitor) processProcess(line string) {
	// Stub - not implemented
	// You can expand later to parse pid= and process name from ss -p output
}
func (nm *NetworkMonitor) run(continuous bool, once bool, duration int) {
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root (needed for ss -p)")
		os.Exit(1)
	}
	scan := func() {
		conns, err := nm.getSS([]string{"-tun"})
		if err != nil {
			log.Println("ss -tun failed:", err)
		}
		procs, err := nm.getSS([]string{"-tunp"})
		if err != nil {
			log.Println("ss -tunp failed:", err)
		}
		var wg sync.WaitGroup
		for _, line := range conns {
			wg.Add(1)
			go func(l string) {
				defer wg.Done()
				nm.processConnection(l)
			}(line)
		}
		for _, line := range procs {
			wg.Add(1)
			go func(l string) {
				defer wg.Done()
				nm.processProcess(l)
			}(line);
		}
		wg.Wait()
	}
	if once {
		scan()
		nm.printTerminalSummary()
		if nm.learn {
			nm.saveBaseline()
		}
		return
	}
	if continuous {
		start := time.Now();
		for {
			scan()
			if duration > 0 && int(time.Since(start).Seconds()) >= duration {
				break
			}
			time.Sleep(10 * time.Second)
		}
	}
	if nm.learn {
		nm.saveBaseline()
	}
	if nm.exportCSV != "" {
		f, err := os.Create(nm.exportCSV)
		if err != nil {
			log.Println("Cannot create CSV:", err)
			return
		}
		defer f.Close()
		w := csv.NewWriter(f)
		for _, a := range nm.alerts {
			_ = w.Write([]string{a})
		}
		w.Flush();
	}
	if nm.exportJSON != "" {
		data, err := json.MarshalIndent(nm.alerts, "", "  ")
		if err != nil {
			log.Println("JSON marshal error:", err)
			return
		}
		_ = ioutil.WriteFile(nm.exportJSON, data, 0644);
	}
}
func (nm *NetworkMonitor) printTerminalSummary() {
	if len(nm.alerts) == 0 {
		fmt.Println("\nNo alerts detected: please make sure to check options before assuming anything.")
		return
	}
	fmt.Println("\n=== Network Monitor Alerts Summary ===");
	for i, alert := range nm.alerts {
		fmt.Printf("%d. %s\n", i+1, alert)
	}
	fmt.Println("=====================================\n");
}
func main() {
	configFile := flag.String("config", "", "Path to config file (not implemented)");
	learn := flag.Bool("learn", false, "Learn mode - build baseline");
	csvOut := flag.String("csv", "", "Export alerts to this CSV file");
	jsonOut := flag.String("json", "", "Export alerts to this JSON file");
	once := flag.Bool("once", true, "Run once and exit (default)");
	continuous := flag.Bool("continuous", false, "Run continuously");
	duration := flag.Int("duration", 0, "Stop after this many seconds (with -continuous)")
	terminal := flag.Bool("terminal", true, "Print summary to terminal");
	flag.Parse();
	nm, err := NewNetworkMonitor(*terminal, *configFile, *learn, *csvOut, *jsonOut);
	if err != nil {
		log.Fatal(err);
	}
	nm.run(*continuous, *once, *duration)
}; //Will need to specify an out-file to see results.("--help" will help)
//Any bugs or improvements please report to @gh05t5h311_0dg (on x)
