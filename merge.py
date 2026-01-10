import requests
import re
import os

# Konfiguration
SOURCES_FILE = "sources.txt"
WHITELIST_FILE = "whitelist.txt"
OUTPUT_FILE = "blocklist.txt"
PROTECTED_KEYWORDS = ["oisd", "hagezi", "stevenblack", "firebog", "adaway"]
DOMAIN_REGEX = r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"

def is_subdomain(domain, domain_set):
    """Prüft, ob eine übergeordnete Domain bereits im Set ist."""
    parts = domain.split('.')
    for i in range(len(parts) - 1, 1, -1):
        parent = ".".join(parts[len(parts)-i:])
        if parent in domain_set:
            return True
    return False

def main():
    if not os.path.exists(SOURCES_FILE): return

    # 1. Whitelist laden
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            whitelist = {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}

    # 2. Quellen einlesen
    with open(SOURCES_FILE, "r") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    unique_urls = list(dict.fromkeys(raw_lines))
    unique_urls.sort(key=lambda x: (not x.startswith("MASTER|"), x.lower()))

    all_domains = set()
    cleaned_sources = []
    
    print(f"Starte High-End Optimierung...")
    print("-" * 95)

    for line in unique_urls:
        url = line.replace("MASTER|", "")
        display_name = url.split('/')[-1][:50]
        is_protected = any(k in url.lower() for k in PROTECTED_KEYWORDS)

        try:
            r = requests.get(url, timeout=15, headers={'User-Agent': 'DNS-Optimizer'})
            if r.status_code == 200 and "<html>" not in r.text[:500].lower():
                current_list = set()
                for d_line in r.text.splitlines():
                    match = re.search(DOMAIN_REGEX, d_line)
                    if match:
                        domain = match.group(1).lower()
                        if domain not in whitelist:
                            current_list.add(domain)
                
                # Wildcard-Deduplizierung: Nur Domains hinzufügen, deren Parent NICHT drin ist
                new_added = 0
                for d in current_list:
                    if d not in all_domains and not is_subdomain(d, all_domains):
                        all_domains.add(d)
                        new_added += 1
                
                if new_added > 0 or is_protected:
                    print(f"OK      | {new_added:>10} neue | {display_name}")
                    cleaned_sources.append(line)
                else:
                    print(f"REDUND. | {0:>10} neue | {display_name} -> ENTFERNT")
            else: raise Exception()
        except:
            if is_protected:
                print(f"OFFLINE | {'-':>10}      | {display_name} (BEHALTEN)")
                cleaned_sources.append(line)
            else:
                print(f"ERROR   | {'-':>10}      | {display_name} -> ENTFERNT")

    # 3. Finaler Cleanup (entfernt Subdomains, falls sie durch spätere Listen unnötig wurden)
    print("\nFinaler Wildcard-Check...")
    final_domains = sorted(list(all_domains), key=len)
    optimized_set = set()
    for d in final_domains:
        if not is_subdomain(d, optimized_set):
            optimized_set.add(d)

    # 4. Speichern
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# Optimized Blocklist\n# Total Domains: {len(optimized_set)}\n")
        for d in sorted(optimized_set): f.write(f"{d}\n")

    with open(SOURCES_FILE, "w") as f:
        f.write("# Ultimate Sources\n")
        for s in cleaned_sources: f.write(f"{s}\n")

    print(f"\nFERTIG! Reduziert auf {len(optimized_set)} hochrelevante Domains.")

if __name__ == "__main__":
    main()