package main

import (
	"bufio"
	"crypto/md5"
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
	subThresh      = 10
	maxFails       = 3
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
	startTime := time.Now()
	fmt.Println("--- GO OPTIMIZER START ---")

	// 0. Whitelist laden
	whitelist := make(map[string]bool)
	whitelistHitCount := 0
	if f, err := os.Open(whitelistFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line != "" && !strings.HasPrefix(line, "#") {
				whitelist[line] = true
			}
		}
		f.Close()
	}
	fmt.Printf("-> %d Domains von Whitelist geladen.\n", len(whitelist))

	// 1. Quellen einlesen
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

	fmt.Printf("\n%-8s | %-10s | %s\n", "STATUS", "NEUE", "QUELLE")
	fmt.Println(strings.Repeat("-", 100))

	client := &http.Client{Timeout: 45 * time.Second}

	for _, source := range uniqueSources {
		cleanURL := regexp.MustCompile(`^(MASTER\||FAILx\d+\|)+`).ReplaceAllString(source, "")
		
		resp, err := client.Get(cleanURL)
		if err != nil || resp.StatusCode != 200 {
			fmt.Printf("%-8s | %-10s | %s\n", "OFFLINE", "Error", cleanURL)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		matches := re.FindAllStringSubmatch(string(body), -1)
		newCount := 0
		for _, m := range matches {
			dom := strings.ToLower(m[1])
			if isWhitelisted(dom, whitelist) {
				whitelistHitCount++
				continue
			}
			if !allDomains[dom] {
				allDomains[dom] = true
				newCount++
			}
		}
		totalRaw += len(matches)
		fmt.Printf("%-8s | %-10d | %s\n", "OK", newCount, cleanURL)
	}

	// 2. Aggregation (Subdomains)
	fmt.Println("\nOptimiere Subdomains...")
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

	// 3. Speichern & Statistik
	out, _ := os.Create(outputFile)
	out.WriteString(fmt.Sprintf("# Optimized by Go\n# Total: %d\n", len(finalList)))
	for _, d := range finalList {
		out.WriteString(d + "\n")
	}
	out.Close()

	duration := time.Since(startTime)
	finalCount := len(finalList)
	savings := totalRaw - finalCount - whitelistHitCount

	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("ZUSAMMENFASSUNG (Go-Engine):\n")
	fmt.Printf("  - Brutto-Domains:       %d\n", totalRaw)
	fmt.Printf("  - Whitelist-Treffer:    %d\n", whitelistHitCount)
	fmt.Printf("  - Netto-Blocklist:      %d\n", finalCount)
	fmt.Printf("  - Zeit gesamt:          %v\n", duration)
	fmt.Println(strings.Repeat("-", 100))

	// Version.txt schreiben
	vFile, _ := os.Create(versionFile)
	vFile.WriteString(fmt.Sprintf("Last Update: %s\nTotal: %d\nWhitelist: %d\nEngine: Go", 
		time.Now().Format("2006-01-02 15:04"), finalCount, whitelistHitCount))
	vFile.Close()
}