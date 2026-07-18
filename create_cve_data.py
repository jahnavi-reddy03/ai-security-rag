# create_cve_data.py
# Hardcoded real CVEs with verified CVSS v3 scores

cve_data = """=== SECURITY THREAT INTELLIGENCE DATABASE ===

CVE ID: CVE-2023-20198
CVSS v3 Score: 10.0
CVSS Severity: CRITICAL
Affected Products: Cisco IOS XE Web UI
Description: Cisco IOS XE Software Web UI privilege escalation vulnerability allowing unauthenticated remote attacker to create an account with privilege level 15 access. Actively exploited in the wild.

CVE ID: CVE-2023-22515
CVSS v3 Score: 10.0
CVSS Severity: CRITICAL
Affected Products: Atlassian Confluence Data Center and Server
Description: Broken access control vulnerability in Atlassian Confluence allowing unauthenticated attacker to create unauthorized Confluence administrator accounts and access Confluence instances.

CVE ID: CVE-2024-3400
CVSS v3 Score: 10.0
CVSS Severity: CRITICAL
Affected Products: Palo Alto Networks PAN-OS GlobalProtect
Description: OS command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect feature allowing unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

CVE ID: CVE-2023-44487
CVSS v3 Score: 7.5
CVSS Severity: HIGH
Affected Products: HTTP/2 protocol implementations (nginx, Apache, Tomcat)
Description: HTTP/2 Rapid Reset Attack enabling distributed denial of service by exploiting stream cancellation feature. Caused record-breaking DDoS attacks exceeding 398 million requests per second.

CVE ID: CVE-2023-23397
CVSS v3 Score: 9.8
CVSS Severity: CRITICAL
Affected Products: Microsoft Outlook for Windows
Description: Microsoft Outlook privilege escalation zero-click vulnerability. Attacker sends specially crafted email causing victim's NTLM hash to be sent to attacker-controlled server without any user interaction.

CVE ID: CVE-2023-4863
CVSS v3 Score: 8.8
CVSS Severity: HIGH
Affected Products: Google Chrome, Mozilla Firefox, Microsoft Edge, libwebp
Description: Heap buffer overflow in WebP codec library (libwebp) allowing remote attacker to perform out-of-bounds memory write via crafted HTML page. Exploited in the wild as zero-day.

CVE ID: CVE-2024-21762
CVSS v3 Score: 9.6
CVSS Severity: CRITICAL
Affected Products: Fortinet FortiOS SSL VPN
Description: Out-of-bounds write vulnerability in Fortinet FortiOS allowing unauthenticated remote code execution via specially crafted HTTP requests. Actively exploited against government and enterprise targets.

CVE ID: CVE-2023-38831
CVSS v3 Score: 7.8
CVSS Severity: HIGH
Affected Products: RARLAB WinRAR before version 6.23
Description: WinRAR spoofing vulnerability allowing attacker to execute arbitrary code when victim opens a crafted ZIP archive. Exploited by multiple APT groups to deliver malware via phishing campaigns.

"""

# Append MITRE ATT&CK data
import requests
print("Fetching MITRE ATT&CK data...")
try:
    response = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    mitre_data = response.json()
    techniques = [o for o in mitre_data["objects"] if o.get("type") == "attack-pattern" and not o.get("revoked", False)][:50]
    
    cve_data += "\n=== MITRE ATT&CK TECHNIQUES ===\n\n"
    for tech in techniques:
        name = tech.get("name", "")
        ext_id = next((r["external_id"] for r in tech.get("external_references", []) if r.get("source_name") == "mitre-attack"), "")
        tactic = tech.get("kill_chain_phases", [{}])[0].get("phase_name", "unknown") if tech.get("kill_chain_phases") else "unknown"
        desc = tech.get("description", "")[:200]
        cve_data += f"MITRE Technique: {ext_id} - {name}\nTactic: {tactic}\nDescription: {desc}\n\n"
    print(f"Added {len(techniques)} MITRE techniques")
except Exception as e:
    print(f"MITRE fetch failed: {e}")

with open("data/real_security_data.txt", "w", encoding="utf-8") as f:
    f.write(cve_data)

print("Done! data/real_security_data.txt created with 8 real CVEs + MITRE techniques")
print("Now run: py ingest.py")