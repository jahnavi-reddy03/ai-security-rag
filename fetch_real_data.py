import requests
import json
import time

def fetch_nvd_cves():
    """Fetch recent 2023-2024 CVEs with CVSS v3 scores"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": "remote code execution",
        "pubStartDate": "2023-01-01T00:00:00.000",
        "pubEndDate": "2024-12-31T23:59:59.000",
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 20
    }
    
    print("Fetching recent CVEs from NVD (2023-2024, CRITICAL severity)...")
    response = requests.get(url, params=params, headers={"User-Agent": "security-rag-research/1.0"})
    
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text[:200]}")
        return []
    
    data = response.json()
    cves = data.get("vulnerabilities", [])
    print(f"Got {len(cves)} CVEs")
    return cves

def fetch_mitre_techniques():
    """Fetch MITRE ATT&CK techniques"""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print("Fetching MITRE ATT&CK techniques...")
    response = requests.get(url)
    data = response.json()
    
    techniques = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            techniques.append(obj)
    return techniques[:50]

def save_data(cves, techniques):
    output = []
    
    output.append("=== SECURITY THREAT INTELLIGENCE DATABASE ===\n")
    output.append("Source: National Vulnerability Database (NVD) - Real CVE Data\n\n")
    
    valid_cves = 0
    for vuln in cves:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        
        # Get description
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        
        # Get CVSS v3 score — this is the key part
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = None
        
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]["cvssData"]
                cvss_score = m.get("baseScore")
                cvss_vector = m.get("vectorString", "")
                severity = m.get("baseSeverity", "")
                break
        
        if not cvss_score:
            continue  # Skip CVEs without CVSS v3 score
        
        # Get affected products
        configs = cve_data.get("configurations", [])
        affected = []
        for config in configs[:1]:
            for node in config.get("nodes", [])[:1]:
                for cpe in node.get("cpeMatch", [])[:2]:
                    affected.append(cpe.get("criteria", "").split(":")[4] if ":" in cpe.get("criteria", "") else "")
        affected_str = ", ".join(filter(None, affected[:2])) or "multiple products"
        
        output.append(f"CVE ID: {cve_id}")
        output.append(f"CVSS v3 Score: {cvss_score}")
        output.append(f"CVSS Severity: {severity}")
        output.append(f"CVSS Vector: {cvss_vector}")
        output.append(f"Affected Products: {affected_str}")
        output.append(f"Description: {desc[:300]}")
        output.append("")
        
        valid_cves += 1
    
    print(f"Saved {valid_cves} CVEs with CVSS v3 scores")
    
    output.append("\n=== MITRE ATT&CK TECHNIQUES ===\n")
    for tech in techniques:
        name = tech.get("name", "")
        ext_id = ""
        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
        tactic = tech.get("kill_chain_phases", [{}])[0].get("phase_name", "unknown") if tech.get("kill_chain_phases") else "unknown"
        desc = tech.get("description", "")[:200]
        
        output.append(f"MITRE Technique: {ext_id} - {name}")
        output.append(f"Tactic: {tactic}")
        output.append(f"Description: {desc}")
        output.append("")
    
    with open("data/real_security_data.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    
    print("Saved to data/real_security_data.txt")

if __name__ == "__main__":
    cves = fetch_nvd_cves()
    time.sleep(1)
    techniques = fetch_mitre_techniques()
    save_data(cves, techniques)
    print("Done! Now re-run: py ingest.py")