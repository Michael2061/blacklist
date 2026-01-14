import requests
import re
import os
import time
import hashlib
from collections import Counter

# --- KONFIGURATION ---
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "blocklist.txt"
VERSION_FILE = "version.txt"
PROTECTED_KEYWORDS = ["oisd", "hagezi", "stevenblack", "firebog", "adaway", "badmojr"]
DOMAIN_REGEX = r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"

SUBDOMAIN_THRESHOLD = 10 
MAX_FAILS = 3 

def is_subdomain(domain, domain_set):
    parts = domain.split('.')
    for i in range(len(parts) - 1, 1, -1):
        parent = ".".join(parts[len(parts)-i:])
        if parent in domain_set: return True
    return False

def get_parent_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-2:]) if len(parts) > 2 else domain

def main():
    start_time = time.time()
    print("--- OPTIMIZER START (Full Mode) ---")

    if not os.path.exists(SOURCES_FILE):
        print(f"ERROR: {SOURCES_FILE} nicht gefunden.")
        return

    # 1. Quellen einlesen
    with open(SOURCES_FILE, "r") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    url_map = {}
    for line in raw_lines:
        clean_url = re.sub(r"^(MASTER\||FAILx\d+\|)+", "", line).lower().strip("/")
        if clean_url not in url_map or "MASTER|" in line:
            url_map[clean_url] = line
    
    unique_urls = list(url_map.values())
    unique_urls.sort(key=lambda x: (not ("MASTER|" in x), x.lower()))

    all_domains = set()
    content_hashes = {}
    cleaned_sources = []
    total_raw_domains = 0 
    
    print(f"\n{'STATUS':<8} | {'NEUE':>10} | {'QUELLE'}")
    print("-" * 110)

    for line in unique_urls:
        is_master = "MASTER|" in line
        fail_match = re.search(r"FAILx(\d+)\|", line)
        current_fails = int(fail_match.group(1)) if fail_match else 0
        
        url_to_fetch = re.sub(r"^(MASTER\||FAILx\d+\|)+", "", line)
        
        # Kleine Pause um Server zu schonen
        time.sleep(0.5)

        try:
            r = requests.get(url_to_fetch, timeout=60, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                m = hashlib.md5(r.text.encode('utf-8')).hexdigest()
                if m in content_hashes and not is_master:
                    print(f"{'MIRROR':<8} | {0:>10} | {url_to_fetch}")
                    continue

                current_list = set()
                for d_line in r.text.splitlines():
                    d_match = re.search(DOMAIN_REGEX, d_line)
                    if d_match:
                        current_list.add(d_match.group(1).lower())
                
                total_raw_domains += len(current_list)
                temp_new = [d for d in current_list if d not in all_domains and not is_subdomain(d, all_domains)]
                
                if len(temp_new) > 0 or is_master:
                    all_domains.update(temp_new)
                    content_hashes[m] = url_to_fetch
                    cleaned_sources.append(f"MASTER|{url_to_fetch}" if is_master else url_to_fetch)
                    status = "MASTER" if is_master else "OK"
                    print(f"{status:<8} | {len(temp_new):>10} | {url_to_fetch}")
                else:
                    print(f"{'REDUND.':<8} | {0:>10} | {url_to_fetch}")
            else: raise Exception()

        except Exception:
            new_fails = current_fails + 1
            is_protected = any(k in url_to_fetch.lower() for k in PROTECTED_KEYWORDS)
            if new_fails < MAX_FAILS or is_master or is_protected:
                prefix = "MASTER|" if is_master else ""
                cleaned_sources.append(f"{prefix}FAILx{new_fails}|{url_to_fetch}")
                print(f"{'OFFLINE':<8} | {'Try ' + str(new_fails):>10} | {url_to_fetch}")
            else:
                print(f"{'DEAD':<8} | {'REMOVED':>10} | {url_to_fetch}")

    # 2. TLD-AGGREGATION
    print("\nOptimiere Subdomains (Aggregation)...")
    parent_counts = Counter(get_parent_domain(d) for d in all_domains)
    auto_wildcards = {dom for dom, count in parent_counts.items() if count >= SUBDOMAIN_THRESHOLD}
    
    final_set = set()
    final_set.update(auto_wildcards)
    for d in all_domains:
        if get_parent_domain(d) not in auto_wildcards:
            if not is_subdomain(d, final_set):
                final_set.add(d)

    # 3. Speichern der Blockliste
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# Optimized Blocklist\n# Total Domains: {len(final_set)}\n")
        for d in sorted(final_set): f.write(d + "\n")

    # 4. Speichern der gesäuberten Quellen
    with open(SOURCES_FILE, "w") as f:
        f.write("# Cleaned Sources\n")
        for s in cleaned_sources: f.write(s + "\n")

    # --- DETAILLIERTE STATISTIK ---
    final_count = len(final_set)
    removed_count = total_raw_domains - final_count
    reduction_pct = (removed_count / total_raw_domains * 100) if total_raw_domains > 0 else 0
    duration = time.time() - start_time

    print("-" * 110)
    print(f"ZUSAMMENFASSUNG:")
    print(f"  - Brutto-Domains (Rohdaten):      {total_raw_domains:,}".replace(",", "."))
    print(f"  - Netto-Domains (blocklist.txt):  {final_count:,}".replace(",", "."))
    print(f"  - Davon Auto-Wildcards (TLDs):    {len(auto_wildcards):,}".replace(",", "."))
    print(f"  - Ersparnis (Müll & Aggregation): {removed_count:,}".replace(",", "."))
    print(f"  - Effizienz-Steigerung:           {reduction_pct:.2f}%")
    print(f"  - Bearbeitungszeit:               {duration:.2f} Sekunden")
    print("-" * 110)

    # --- NEU: VERSION.TXT FÜR GITHUB ACTIONS EXPORTIEREN ---
    try:
        with open(VERSION_FILE, "w") as f:
            f.write(f"Last Update: {time.strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"Total Domains: {final_count}\n")
        print(f"Statistik in {VERSION_FILE} gespeichert.")
    except Exception as e:
        print(f"Fehler beim Schreiben der version.txt: {e}")

    print("--- OPTIMIZER BEENDET ---")

if __name__ == "__main__":
    main()