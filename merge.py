import requests
import re
import os
import time

# --- KONFIGURATION ---
SOURCES_FILE = "sources.txt"
WHITELIST_FILE = "whitelist.txt"
OUTPUT_FILE = "blocklist.txt"
MAX_RETRIES = 3

# Diese Wörter im URL-Pfad schützen die Liste vor dem automatischen Löschen
PROTECTED_KEYWORDS = ["oisd", "hagezi", "stevenblack", "firebog", "adaway", "1hosts"]

DOMAIN_REGEX = r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"

def is_subdomain(domain, domain_set):
    """Prüft auf Wildcard-Redundanz (Subdomains)."""
    parts = domain.split('.')
    for i in range(len(parts) - 1, 1, -1):
        parent = ".".join(parts[len(parts)-i:])
        if parent in domain_set:
            return True
    return False

def main():
    start_time = time.time()
    if not os.path.exists(SOURCES_FILE):
        print(f"ERROR: {SOURCES_FILE} nicht gefunden!")
        return

    # 1. Whitelist laden
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            whitelist = {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}

    # 2. Quellen einlesen
    with open(SOURCES_FILE, "r") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    unique_urls = list(dict.fromkeys(raw_lines))
    
    # DEBUG-INFO am Anfang
    print(f"DEBUG: {len(unique_urls)} Quellen in {SOURCES_FILE} gefunden.")
    
    # Sortierung: MASTER-Listen zuerst
    unique_urls.sort(key=lambda x: (
        not ("MASTER|" in x), 
        x.replace("FAILx1|", "").replace("FAILx2|", "").replace("MASTER|", "").lower()
    ))

    all_domains = set()
    cleaned_sources = []
    total_raw_domains = 0
    master_finished = False
    
    print(f"\n{'STATUS':<8} | {'NEUE':>10} | {'QUELLE / URL'}")
    print("-" * 110)

    for line in unique_urls:
        # Trenner nach Master-Listen
        if not master_finished and "MASTER|" not in line:
            if any("MASTER|" in l for l in unique_urls):
                print(f"{'INFO':<8} | {'-'*10} | --- ENDE DER MASTER-QUELLEN ---")
            master_finished = True

        fail_count = 0
        current_line = line
        
        # FAIL-Zähler verarbeiten
        if current_line.startswith("FAILx"):
            match = re.match(r"FAILx(\d+)\|(.+)", current_line)
            if match:
                fail_count = int(match.group(1))
                current_line = match.group(2)

        url_to_fetch = current_line.replace("MASTER|", "")
        is_protected = any(k in url_to_fetch.lower() for k in PROTECTED_KEYWORDS) or "MASTER|" in line

        try:
            r = requests.get(url_to_fetch, timeout=25, headers={'User-Agent': 'Mozilla/5.0 DNS-Optimizer'})
            
            if r.status_code == 200 and "<html>" not in r.text[:500].lower():
                current_list = set()
                for d_line in r.text.splitlines():
                    d_match = re.search(DOMAIN_REGEX, d_line)
                    if d_match:
                        domain = d_match.group(1).lower()
                        if domain not in whitelist:
                            current_list.add(domain)
                
                total_raw_domains += len(current_list)
                new_added = 0
                temp_domains = []
                for d in current_list:
                    # Dubletten und Subdomain-Check
                    if d not in all_domains and not is_subdomain(d, all_domains):
                        temp_domains.append(d)
                        new_added += 1
                
                # Schutz-Logik
                if is_protected:
                    all_domains.update(temp_domains)
                    status = "MASTER" if "MASTER|" in line else "PROTECT"
                    print(f"{status:<8} | {new_added:>10} | {url_to_fetch}")
                    cleaned_sources.append(line)
                elif new_added > 0:
                    all_domains.update(temp_domains)
                    print(f"{'OK':<8} | {new_added:>10} | {url_to_fetch}")
                    cleaned_sources.append(current_line)
                else:
                    print(f"{'REDUND.':<8} | {0:>10} | {url_to_fetch} -> ENTFERNT")
            else: 
                raise Exception()

        except:
            if is_protected:
                print(f"{'OFFLINE':<8} | {'-':>10} | {url_to_fetch} (BEHALTEN)")
                cleaned_sources.append(line)
            else:
                fail_count += 1
                if fail_count < MAX_RETRIES:
                    print(f"{'WARN':<8} | {fail_count:>3}/{MAX_RETRIES}  | {url_to_fetch}")
                    cleaned_sources.append(f"FAILx{fail_count}|{current_line}")
                else:
                    print(f"{'ERROR':<8} | {'REMOVED':>10} | {url_to_fetch}")

    # 3. Finaler Wildcard-Check (Optimierung)
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

    # --- STATISTIK-AUSGABE ---
    duration = time.time() - start_time
    final_count = len(optimized_set)
    removed_count = total_raw_domains - final_count
    reduction_pct = (removed_count / total_raw_domains * 100) if total_raw_domains > 0 else 0

    print("-" * 110)
    print(f"ZUSAMMENFASSUNG:")
    print(f"  - Brutto-Domains (alle Listen):   {total_raw_domains:,}".replace(",", "."))
    print(f"  - Netto-Domains (blocklist.txt):  {final_count:,}".replace(",", "."))
    print(f"  - Ersparnis (Duplikate/Wildcards): {removed_count:,}".replace(",", "."))
    print(f"  - Effizienz:                      {reduction_pct:.2f}%")
    print(f"  - Dauer:                          {duration:.2f} Sekunden")
    print("-" * 110)

if __name__ == "__main__":
    main()