import requests
import re
import os
import time
import hashlib

# --- KONFIGURATION ---
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "blocklist.txt"

# Keywords für den Offline-Schutz (behält wichtige Quellen bei Serverfehlern)
PROTECTED_KEYWORDS = ["oisd", "hagezi", "stevenblack", "firebog", "adaway"]

# Regex zur Erkennung von Domains (filtert 0.0.0.0 etc. automatisch weg)
DOMAIN_REGEX = r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"

def is_subdomain(domain, domain_set):
    """Prüft, ob eine Domain bereits durch eine übergeordnete Domain abgedeckt ist."""
    parts = domain.split('.')
    for i in range(len(parts) - 1, 1, -1):
        parent = ".".join(parts[len(parts)-i:])
        if parent in domain_set: return True
    return False

def main():
    start_time = time.time()
    print("--- OPTIMIZER START (No Whitelist Mode) ---")

    if not os.path.exists(SOURCES_FILE):
        print(f"ERROR: {SOURCES_FILE} nicht gefunden.")
        return

    # 1. Quellen einlesen & URL-Deduplizierung
    with open(SOURCES_FILE, "r") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    url_map = {}
    for line in raw_lines:
        clean_url = line.replace("MASTER|", "").replace("FAILx1|", "").replace("FAILx2|", "").lower().strip("/")
        if clean_url not in url_map or "MASTER|" in line:
            url_map[clean_url] = line
    
    unique_urls = list(url_map.values())
    # MASTER-Quellen nach oben sortieren
    unique_urls.sort(key=lambda x: (not ("MASTER|" in x), x.lower()))

    all_domains = set()
    content_hashes = {}
    source_history = []
    cleaned_sources = []
    total_raw_domains = 0 
    
    print(f"\n{'STATUS':<8} | {'NEUE':>10} | {'QUELLE'}")
    print("-" * 110)

    for line in unique_urls:
        url_to_fetch = line.replace("MASTER|", "").replace("FAILx1|", "").replace("FAILx2|", "")
        file_name = url_to_fetch.split('/')[-1] or url_to_fetch
        
        try:
            r = requests.get(url_to_fetch, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                # Mirror-Check via MD5 Hash
                m = hashlib.md5(r.text.encode('utf-8')).hexdigest()
                if m in content_hashes and "MASTER|" not in line:
                    print(f"{'MIRROR':<8} | {0:>10} | {url_to_fetch} (Identisch mit {content_hashes[m]})")
                    continue

                current_list = set()
                for d_line in r.text.splitlines():
                    d_match = re.search(DOMAIN_REGEX, d_line)
                    if d_match:
                        current_list.add(d_match.group(1).lower())
                
                total_raw_domains += len(current_list)
                
                # Nur Domains hinzufügen, die noch nicht bekannt oder durch Wildcards abgedeckt sind
                temp_new = [d for d in current_list if d not in all_domains and not is_subdomain(d, all_domains)]
                new_count = len(temp_new)

                if new_count > 0 or "MASTER|" in line:
                    all_domains.update(temp_new)
                    content_hashes[m] = file_name
                    source_history.append((file_name, current_list))
                    status = "MASTER" if "MASTER|" in line else "OK"
                    print(f"{status:<8} | {new_count:>10} | {url_to_fetch}")
                    cleaned_sources.append(line)
                else:
                    print(f"{'REDUND.':<8} | {0:>10} | {url_to_fetch} -> ENTFERNT")
            else: raise Exception()
        except:
            if "MASTER|" in line or any(k in url_to_fetch.lower() for k in PROTECTED_KEYWORDS):
                print(f"{'OFFLINE':<8} | {'-':>10} | {url_to_fetch} (BEHALTEN)")
                cleaned_sources.append(line)
            else:
                print(f"{'ERROR':<8} | {'REMOVED':>10} | {url_to_fetch}")

    # 2. Finaler Optimierungslauf (Subdomains entfernen)
    final_raw_list = sorted(list(all_domains), key=len)
    optimized_set = set()
    for d in final_raw_list:
        if not is_subdomain(d, optimized_set):
            optimized_set.add(d)

    # 3. Dateien speichern
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# Optimized Blocklist\n# Total Domains: {len(optimized_set)}\n")
        for d in sorted(optimized_set): f.write(d + "\n")

    with open(SOURCES_FILE, "w") as f:
        f.write("# Cleaned Sources\n")
        for s in cleaned_sources: f.write(s + "\n")

    # --- STATISTIK-AUSGABE ---
    final_count = len(optimized_set)
    removed_count = total_raw_domains - final_count
    reduction_pct = (removed_count / total_raw_domains * 100) if total_raw_domains > 0 else 0
    duration = time.time() - start_time

    print("-" * 110)
    print(f"ZUSAMMENFASSUNG:")
    print(f"  - Brutto-Domains (Rohdaten):      {total_raw_domains:,}".replace(",", "."))
    print(f"  - Netto-Domains (blocklist.txt):  {final_count:,}".replace(",", "."))
    print(f"  - Ersparnis (Müll entfernt):      {removed_count:,}".replace(",", "."))
    print(f"  - Effizienz-Steigerung:           {reduction_pct:.2f}%")
    print(f"  - Bearbeitungszeit:               {duration:.2f} Sekunden")
    print("-" * 110)
    print("--- OPTIMIZER BEENDET ---")

if __name__ == "__main__":
    main()