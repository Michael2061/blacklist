package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	sourcesFile    = "sources.txt"
	outputFile     = "blocklist.txt"
	versionFile    = "version.txt"
	whitelistFile  = "whitelist.txt"
	allowListFile  = "allowlist.txt"
	subThresh      = 10
	domainRegex    = `(?m)^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)`
)

func isWhitelisted(domain string, whitelist map[string]bool) bool {
	if whitelist[domain] {
		return true
	}
	parts := strings.Split(domain, ".")
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
	startTime := time.Now() // Wird jetzt unten verwendet!
	fmt.Println("--- GO OPTIMIZER START ---")

	whitelist := make(map[string]bool)
	var whitelistOrder []string
	whitelistHitCount := 0

	if f, err := os.Open(whitelistFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				dom := strings.ToLower(line)
				whitelist[dom] = true
				whitelistOrder = append(whitelistOrder, dom)
			}
		}
		f.Close()
	}
	fmt.Printf("-> %d Domains von Whitelist geladen.\n", len(whitelist))

	f, _ := os.Open(sourcesFile)
	scanner := bufio.NewScanner(f)
	var uniqueSources []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			uniqueSources = append(uniqueSources, line)
		}
	}
	f.Close()

	allDomains := make(map[string]bool)
	re := regexp.MustCompile(domainRegex)
	totalRaw := 0

	client := &http.Client{Timeout: 45 * time.Second}
	for _, source := range uniqueSources {
		cleanURL := regexp.MustCompile(`^(MASTER\||FAILx\d+\|)+`).ReplaceAllString(source, "")
		resp, err := client.Get(cleanURL)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllStringSubmatch(string(body), -1)
		for _, m := range matches {
			dom := strings.ToLower(m[1])
			if isWhitelisted(dom, whitelist) {
				whitelistHitCount++
				continue
			}
			allDomains[dom] = true
		}
		totalRaw += len(matches)
	}

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

	out, _ := os.Create(outputFile)
	out.WriteString(fmt.Sprintf("# Optimized Blocklist\n# Total: %d\n", len(finalList)))
	for _, d := range finalList {
		out.WriteString(d + "\n")
	}
	out.Close()

	allowOut, _ := os.Create(allowListFile)
	allowOut.WriteString("# Technitium Allow List\n")
	for _, dom := range whitelistOrder {
		allowOut.WriteString("!" + dom + "\n")
	}
	allowOut.Close()

	timestamp := time.Now().Format("2006-01-02 15:04")
	finalCount := len(finalList)
	duration := time.Since(startTime) // Hier wird startTime benutzt

	vFile, _ := os.Create(versionFile)
	vFile.WriteString(fmt.Sprintf("Last Update: %s\nTotal: %d\nWhitelist: %d\nEngine: Go", timestamp, finalCount, whitelistHitCount))
	vFile.Close()

	jsonFile, _ := os.Create("version.json")
	jsonFile.WriteString(fmt.Sprintf(`{"LastUpdate": "%s", "Total": %d, "Whitelist": %d}`, timestamp, finalCount, whitelistHitCount))
	jsonFile.Close()

	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Fertig in: %v\nBlockliste: %d\nAllowliste: %d\n", duration, finalCount, len(whitelistOrder))
	fmt.Println(strings.Repeat("-", 40))
}