package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

const domainRegex = `(?m)^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)`

var (
	threshold     = flag.Int("threshold", 50, "Subdomains ab denen per Wildcard geblockt wird")
	sourcesPath   = flag.String("sources", "sources.txt", "Datei mit Blocklisten-Quellen")
	outputPath    = flag.String("output", "blocklist.txt", "Ausgabedatei Blockliste")
	versionPath   = flag.String("version", "version.txt", "Ausgabedatei Versionsinfo")
	whitelistPath = flag.String("whitelist", "whitelist.txt", "Whitelist-Datei")
	allowlistPath = flag.String("allowlist", "allowlist.txt", "Ausgabedatei Allowliste")
	customPath    = flag.String("custom", "blocklist.custom.txt", "Optionale Datei mit eigenen Domains")
)

// cleanAndLoadWhitelist räumt die Whitelist auf und lädt sie in eine Map
func cleanAndLoadWhitelist(filename string) (map[string]bool, []string) {
	uniqueDomains := make(map[string]bool)
	var order []string

	file, err := os.Open(filename)
	if err != nil {
		return uniqueDomains, order
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.Split(line, "#")[0] // Kommentare entfernen
		line = strings.TrimSpace(line)

		if line != "" {
			dom := strings.ToLower(line)
			if !uniqueDomains[dom] {
				uniqueDomains[dom] = true
				order = append(order, dom)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Fehler beim Lesen von %s: %v\n", filename, err)
	}
	// Whitelist alphabetisch sortieren
	sort.Strings(order)
	// Die Datei direkt sauber wieder speichern
	if err := os.WriteFile(filename, []byte(strings.Join(order, "\n")+"\n"), 0644); err != nil {
		fmt.Printf("Warnung: Konnte %s nicht schreiben: %v\n", filename, err)
	}

	return uniqueDomains, order
}

func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

var multiPartTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"me.uk": true, "net.uk": true, "plc.uk": true, "sch.uk": true, "ltd.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.jp": true, "ne.jp": true, "or.jp": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"com.br": true, "org.br": true, "net.br": true,
	"co.kr": true, "or.kr": true, "ne.kr": true,
	"com.cn": true, "net.cn": true, "org.cn": true,
	"co.in": true, "net.in": true, "org.in": true,
	"com.mx": true, "org.mx": true, "net.mx": true,
	"co.za": true, "org.za": true, "net.za": true,
	"co.il": true, "org.il": true, "net.il": true,
	"com.pl": true, "net.pl": true, "org.pl": true,
	"com.pt": true, "net.pt": true, "org.pt": true,
	"com.ru": true, "net.ru": true, "org.ru": true,
	"com.sg": true, "edu.sg": true, "gov.sg": true, "net.sg": true, "org.sg": true,
	"com.tr": true, "net.tr": true, "org.tr": true, "gov.tr": true,
	"com.ar": true,
}

func isValidDomain(domain string) bool {
	if !strings.Contains(domain, ".") {
		return false
	}
	if isIPAddress(domain) {
		return false
	}
	if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".lan") || strings.HasSuffix(domain, ".home.arpa") {
		return false
	}
	return true
}

func isWhitelisted(domain string, whitelist map[string]bool) bool {
	if whitelist[domain] {
		return true
	}
	parts := strings.Split(domain, ".")
	// Prüft hierarchisch (z.B. für cdn.example.com auch example.com)
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if whitelist[parent] {
			return true
		}
	}
	return false
}

func getParent(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	if len(parts) >= 3 {
		lastTwo := strings.Join(parts[len(parts)-2:], ".")
		if multiPartTLDs[lastTwo] {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func main() {
	flag.Parse()
	startTime := time.Now()
	fmt.Println("--- GO OPTIMIZER START (Parallel + Auto-Cleanup) ---")

	// 0. Whitelist laden & säubern
	whitelist, whitelistOrder := cleanAndLoadWhitelist(*whitelistPath)
	var whitelistHitCount int
	var hitMu sync.Mutex

	fmt.Printf("-> %d Domains in Whitelist (bereinigt).\n\n", len(whitelist))

	// 1. Quellen einlesen
	f, err := os.Open(*sourcesPath)
	if err != nil {
		fmt.Printf("Fehler: %s fehlt.\n", *sourcesPath)
		return
	}
	var uniqueSources []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			uniqueSources = append(uniqueSources, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Fehler beim Lesen von %s: %v\n", *sourcesPath, err)
	}
	f.Close()

	allDomains := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	re := regexp.MustCompile(domainRegex)
	prefixRe := regexp.MustCompile(`^(MASTER\||FAILx\d+\|)+`)

	client := resty.New().SetTimeout(60 * time.Second).SetRetryCount(3)

	fmt.Printf("%-8s | %-10s | %s\n", "STATUS", "NEUE", "QUELLE")
	fmt.Println(strings.Repeat("-", 80))

	for _, source := range uniqueSources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			cleanURL := prefixRe.ReplaceAllString(url, "")

			resp, err := client.R().Get(cleanURL)
			if err != nil || resp.IsError() {
				fmt.Printf("%-8s | %-10s | %s\n", "OFFLINE", "Error", cleanURL)
				return
			}

			matches := re.FindAllStringSubmatch(resp.String(), -1)
			localNewCount := 0

			for _, m := range matches {
				dom := strings.ToLower(m[1])
				if !isValidDomain(dom) {
					continue
				}
				if isWhitelisted(dom, whitelist) {
					hitMu.Lock()
					whitelistHitCount++
					hitMu.Unlock()
					continue
				}
				mu.Lock()
				if !allDomains[dom] {
					allDomains[dom] = true
					localNewCount++
				}
				mu.Unlock()
			}
			fmt.Printf("%-8s | %-10d | %s\n", "OK", localNewCount, cleanURL)
		}(source)
	}
	wg.Wait()

	// 1b. Custom lokale Domains mergen
	if custom, err := os.ReadFile(*customPath); err == nil {
		added := 0
		for _, line := range strings.Split(string(custom), "\n") {
			line = strings.TrimSpace(line)
			line = strings.Split(line, "#")[0]
			line = strings.TrimSpace(line)
			if line != "" {
				dom := strings.ToLower(line)
				if isValidDomain(dom) && !allDomains[dom] {
					allDomains[dom] = true
					added++
				}
			}
		}
		if added > 0 {
			fmt.Printf("\n-> %d Domains aus %s übernommen.\n", added, *customPath)
		}
	}

	// 2. Aggregation (Subdomain-Konsolidierung)
	parentCounts := make(map[string]int)
	for dom := range allDomains {
		parentCounts[getParent(dom)]++
	}
	autoWildcards := make(map[string]bool)
	for p, count := range parentCounts {
		if count >= *threshold {
			autoWildcards[p] = true
		}
	}
	finalList := []string{}
	for dom := range allDomains {
		if !autoWildcards[getParent(dom)] {
			finalList = append(finalList, dom)
		}
	}
	for aw := range autoWildcards {
		finalList = append(finalList, aw)
	}
	sort.Strings(finalList)

	// --- DATEIEN SCHREIBEN ---
	out, err := os.Create(*outputPath)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen von %s: %v\n", *outputPath, err)
		return
	}
	fmt.Fprintf(out, "# Optimized Blocklist\n# Total: %d\n", len(finalList))
	for _, d := range finalList {
		out.WriteString(d + "\n")
	}
	out.Close()

	allowOut, err := os.Create(*allowlistPath)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen von %s: %v\n", *allowlistPath, err)
		return
	}
	fmt.Fprint(allowOut, "# Technitium Allow List\n")
	for _, dom := range whitelistOrder {
		allowOut.WriteString(dom + "\n")
	}
	allowOut.Close()

	timestamp := time.Now().Format("2006-01-02 15:04")
	finalCount := len(finalList)
	duration := time.Since(startTime)
	rawTotal := 0
	for _, c := range parentCounts {
		rawTotal += c
	}

	vFile, err := os.Create(*versionPath)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen von %s: %v\n", *versionPath, err)
		return
	}
	fmt.Fprintf(vFile, "Last Update: %s\nTotal: %d\nWhitelist: %d\nEngine: Go (Resty)", timestamp, finalCount, whitelistHitCount)
	vFile.Close()

	jsonFile, err := os.Create("version.json")
	if err != nil {
		fmt.Printf("Fehler beim Erstellen von version.json: %v\n", err)
		return
	}
	fmt.Fprintf(jsonFile, `{"LastUpdate": "%s", "Total": %d, "Whitelist": %d}`, timestamp, finalCount, whitelistHitCount)
	jsonFile.Close()

	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("ZUSAMMENFASSUNG:\n")
	fmt.Printf("Zeit: %v\n", duration)
	fmt.Printf("Whitelist: %d Einträge, %d Hits\n", len(whitelist), whitelistHitCount)
	fmt.Printf("Quellen: %d\n", len(uniqueSources))
	fmt.Printf("Domains extrahiert: %d | Nach Dedup: %d | Wildcards: %d | Final: %d\n", rawTotal, len(allDomains), len(autoWildcards), finalCount)
}
