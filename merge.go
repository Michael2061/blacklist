package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	sourcesFile   = "sources.txt"
	outputFile    = "blocklist.txt"
	versionFile   = "version.txt"
	whitelistFile = "whitelist.txt"
	allowListFile = "allowlist.txt"
	subThresh     = 50 // Erhöht auf 50, um Overblocking/Ladeprobleme zu reduzieren
	domainRegex   = `(?m)^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)`
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

	// Whitelist alphabetisch sortieren
	sort.Strings(order)
	// Die Datei direkt sauber wieder speichern
	os.WriteFile(filename, []byte(strings.Join(order, "\n")+"\n"), 0644)

	return uniqueDomains, order
}

func isValidDomain(domain string) bool {
	if !strings.Contains(domain, ".") {
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
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

func main() {
	startTime := time.Now()
	fmt.Println("--- GO OPTIMIZER START (Parallel + Auto-Cleanup) ---")

	// 0. Whitelist laden & säubern
	whitelist, whitelistOrder := cleanAndLoadWhitelist(whitelistFile)
	var whitelistHitCount int
	var hitMu sync.Mutex

	fmt.Printf("-> %d Domains in Whitelist (bereinigt).\n\n", len(whitelist))

	// 1. Quellen einlesen
	f, err := os.Open(sourcesFile)
	if err != nil {
		fmt.Printf("Fehler: %s fehlt.\n", sourcesFile)
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
	f.Close()

	allDomains := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	re := regexp.MustCompile(domainRegex)

	client := resty.New().SetTimeout(45 * time.Second).SetRetryCount(3)

	fmt.Printf("%-8s | %-10s | %s\n", "STATUS", "NEUE", "QUELLE")
	fmt.Println(strings.Repeat("-", 80))

	for _, source := range uniqueSources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			cleanURL := regexp.MustCompile(`^(MASTER\||FAILx\d+\|)+`).ReplaceAllString(url, "")

			resp, err := client.R().Get(cleanURL)
			if err != nil || resp.IsError() {
				fmt.Printf("%-8s | %-10s | %s\n", "OFFLINE", "Error", cleanURL)
				return
			}

			matches := re.FindAllStringSubmatch(resp.String(), -1)
			localNewCount := 0

			for _, m := range matches {
				dom := strings.ToLower(m[1])
				if !isValidDomain(dom) || isWhitelisted(dom, whitelist) {
					if isWhitelisted(dom, whitelist) {
						hitMu.Lock()
						whitelistHitCount++
						hitMu.Unlock()
					}
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

	// 2. Aggregation (Subdomain-Konsolidierung)
	parentCounts := make(map[string]int)
	for dom := range allDomains {
		parentCounts[getParent(dom)]++
	}
	autoWildcards := make(map[string]bool)
	for p, count := range parentCounts {
		if count >= subThresh {
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
	out, _ := os.Create(outputFile)
	out.WriteString(fmt.Sprintf("# Optimized Blocklist\n# Total: %d\n", len(finalList)))
	for _, d := range finalList {
		out.WriteString(d + "\n")
	}
	out.Close()

	allowOut, _ := os.Create(allowListFile)
	allowOut.WriteString("# Technitium Allow List\n")
	for _, dom := range whitelistOrder {
		allowOut.WriteString(dom + "\n")
	}
	allowOut.Close()

	timestamp := time.Now().Format("2006-01-02 15:04")
	finalCount := len(finalList)
	duration := time.Since(startTime)

	vFile, _ := os.Create(versionFile)
	vFile.WriteString(fmt.Sprintf("Last Update: %s\nTotal: %d\nWhitelist: %d\nEngine: Go (Resty)", timestamp, finalCount, whitelistHitCount))
	vFile.Close()

	jsonFile, _ := os.Create("version.json")
	jsonFile.WriteString(fmt.Sprintf(`{"LastUpdate": "%s", "Total": %d, "Whitelist": %d}`, timestamp, finalCount, whitelistHitCount))
	jsonFile.Close()

	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("ZUSAMMENFASSUNG:\n")
	fmt.Printf("Zeit: %v | Blockliste: %d | Whitelist-Treffer: %d\n", duration, finalCount, whitelistHitCount)
}
