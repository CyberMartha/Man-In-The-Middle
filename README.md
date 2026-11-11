# Network Security Monitoring Case Study: Multi-Stage Man-in-the-Middle (MITM) Detection

## Objective
The primary objective of this investigation was to detect, correlate, and reconstruct a multi-stage **Man-in-the-Middle (MITM)** attack inside a simulated corporate LAN (*Acme Corp*). By combining deep packet inspection in **Wireshark** with SIEM log analysis in **Splunk** (`index="network_logs"`), this project demonstrates Tier-1/Tier-2 Security Operations Center (SOC) incident response—tracing an adversary's complete kill chain across **ARP Spoofing (interception)**, **DNS Spoofing (redirection)**, and **SSL Stripping (cleartext credential harvesting)**.

---

## Skills Learned & Core Competencies
* **Layer-2 Anomaly Detection (ARP Spoofing):** Identifying duplicate ARP replies, gratuitous ARP floods, and MAC-to-IP binding conflicts that indicate network interception between a victim host and the default gateway.
* **DNS Cache Poisoning & Redirection Analysis:** Correlating forged DNS `A`-record responses in Wireshark and Splunk to uncover rogue internal IP redirection (`corp-login.acme-corp.local`).
* **SSL Stripping & Protocol Downgrade Forensics:** Detecting HTTPS-to-HTTP downgrade attacks, inspecting anomalous HTTP `301`/`302` redirects, and reconstructing cleartext `POST` login streams.
* **SIEM & PCAP Cross-Correlation:** Pivoting between Splunk SPL queries and raw packet captures (`pcapng`) to validate alerts, quantify attack scope, and attribute malicious activity.
* **MITRE ATT&CK Mapping:** Aligning observed adversary behaviors with **TA0006 (Credential Access)** and **TA0009 (Collection)** techniques (`T1557.002` — ARP Cache Poisoning, `T1557` — Adversary-in-the-Middle).

---

## Tools & Frameworks Used

 <img src="https://img.shields.io/badge/-Splunk-000000?&style=for-the-badge&logo=Splunk&logoColor=white" />
 <img src="https://img.shields.io/badge/-Wireshark-1679A7?&style=for-the-badge&logo=Wireshark&logoColor=white" /> 
 <img src="https://img.shields.io/badge/-TryHackMe-222831?&style=for-the-badge&logo=TryHackMe&logoColor=white" /> 

---

## Executive Summary

A routine network monitoring alert at *Acme Corp* flagged anomalous traffic patterns inside the corporate LAN, suggesting an active **Man-in-the-Middle (MITM)** compromise. Rather than occurring as an isolated event, forensic analysis revealed a **three-stage chained attack** designed to quietly intercept user sessions and steal corporate login credentials:

1. **Network Interception (`ARP Spoofing`):** The attacker poisoned the local ARP cache to position their host between the victim workstation and the network gateway.
2. **Traffic Redirection (`DNS Spoofing`):** Once inline, the attacker forged DNS responses for an internal authentication portal (`corp-login.acme-corp.local`), pointing the victim to a rogue IP (`192.168.10.55`).
3. **Credential Harvesting (`SSL Stripping`):** The attacker downgraded the victim's encrypted HTTPS session to cleartext HTTP, capturing submitted login credentials in plaintext.

---

## Investigation Walkthrough & Technical Analysis

### 1. Stage 1: Detecting ARP Spoofing & Layer-2 Interception (`MITRE T1557.002`)
Address Resolution Protocol (ARP) lacks built-in authentication, allowing an attacker on the local subnet to send forged ARP replies (`is-at`) that associate the attacker's MAC address with the IP address of the default gateway.

#### Investigation Methodology & Filters
* **Step 1 — Isolate ARP Traffic:** Opened the incident packet capture in **Wireshark** and applied the `arp` display filter to separate Layer-2 address resolution frames from higher-layer noise.
* **Step 2 — Filter Unsolicited ARP Replies:** Narrowed the capture to ARP responses using `arp.opcode == 2` and checked Wireshark's built-in expert warnings (`arp.duplicate-address-detected` / `arp.duplicate-address-frame`) to spot conflicting MAC-to-IP mappings.
* **Step 3 — Quantify Spoofed Frames:** Filtered by the rogue MAC address (`eth.src == <ATTACKER_MAC> && arp.opcode == 2`) to measure the exact volume of poisoning packets sent during the interception window.

#### Key Findings
* **Gateway Impersonation:** Detected conflicting ARP replies claiming ownership of the corporate gateway IP, confirming active ARP cache poisoning on the LAN.
* **Attack Scope:** Isolated **14 spoofed ARP packets** originating from the attacker's MAC address to maintain a persistent Man-in-the-Middle position.

<img width="1302" height="664" alt="image" src="https://github.com/user-attachments/assets/11b784a1-33e5-49c9-a724-bf1b4fb51b57" />

<img width="1310" height="672" alt="image" src="https://github.com/user-attachments/assets/e5ce53d5-da7e-4910-893f-c03b371747e4" />
<img width="1312" height="674" alt="image" src="https://github.com/user-attachments/assets/de5abffa-1a06-4b54-af7d-922a72657084" />
<img width="1309" height="669" alt="image" src="https://github.com/user-attachments/assets/0384e1fd-3050-47a1-9296-7c6d63d6db5d" />
<img width="1301" height="651" alt="image" src="https://github.com/user-attachments/assets/79bc1860-36ef-41dc-863f-9491d33991af" />



---

### 2. Stage 2: Unmasking DNS Spoofing & Traffic Redirection (`MITRE T1557`)
After intercepting traffic via ARP spoofing, the adversary manipulated DNS name resolution to silently redirect the victim's browser away from the legitimate corporate portal to an attacker-controlled phishing/proxy server.

#### Investigation Methodology & Queries
* **Step 1 — Inspect DNS Query/Response Pairs (Wireshark):** Applied `dns` and `dns.flags.response == 1` to examine resolution replies, looking for multiple conflicting `A`-record answers or abnormally fast replies arriving ahead of the legitimate internal DNS server.
* **Step 2 — Target Corporate Authentication Domain:** Filtered specifically for the targeted internal login portal using `dns.qry.name contains "corp-login.acme-corp.local"`.
* **Step 3 — Correlate Volume in Splunk:** Queried ingested network logs (`index="network_logs"`) to count spoofed DNS responses and verify every internal host affected by the poisoned records:
  ```spl
  index="network_logs" "corp-login.acme-corp.local" | stats count by src_ip, dest_ip, answer
  ```

#### Key Findings
* **Poisoned DNS Records:** Observed **211 DNS responses** for `corp-login.acme-corp.local` during the incident window.
* **Malicious Redirection Target:** Confirmed the attacker's forged DNS replies resolved `corp-login.acme-corp.local` to the rogue IP address **`192.168.10.55`** instead of the legitimate internal server.

<img width="1300" height="644" alt="image" src="https://github.com/user-attachments/assets/ec8159c1-6a13-42a2-b5c2-56668319b7c8" />
<img width="1291" height="656" alt="image" src="https://github.com/user-attachments/assets/1cfcf253-5ce8-4c39-a9ac-d6a5e66d995d" />
<img width="1307" height="673" alt="image" src="https://github.com/user-attachments/assets/b3688531-8b08-4473-a40e-4853aee7c79f" />
<img width="1310" height="643" alt="image" src="https://github.com/user-attachments/assets/8b529a7f-0033-4ae1-b160-5e24045ded39" />

---

### 3. Stage 3: Spotting SSL Stripping & Cleartext Credential Theft (`MITRE T1557`)
Even when redirected to a rogue server, modern browsers expect HTTPS encryption. Through **SSL Stripping**, the attacker terminates the HTTPS connection with the legitimate server while serving an unencrypted HTTP version of the login page to the victim, capturing submitted credentials in cleartext.

#### Investigation Methodology & Filters
* **Step 1 — Isolate Unencrypted Web Traffic:** Applied `http` and `http.request.method == "POST"` in Wireshark to hunt for authentication submissions transmitted without TLS encryption.
* **Step 2 — Inspect Downgrade Indicators:** Checked HTTP response headers (`http.response.code == 301 || http.response.code == 302`) and external links rewritten from `https://` to `http://`.
* **Step 3 — Reconstruct Login Stream:** Used **Right-Click -> Follow -> HTTP Stream** on the victim's `POST` login request to examine the raw form payload.

#### Key Findings
* **Protocol Downgrade Confirmed:** Identified the victim's login session to `corp-login.acme-corp.local` occurring entirely over cleartext HTTP (`TCP/80`) rather than HTTPS (`TCP/443`).
* **Credential Compromise:** Reconstructing the HTTP `POST` stream exposed the victim's username and plaintext password transmitted directly to the rogue host (`192.168.10.55`).

<img width="1303" height="604" alt="image" src="https://github.com/user-attachments/assets/23395f27-82ad-476a-9f57-0ef96a945a21" />
<img width="1300" height="615" alt="image" src="https://github.com/user-attachments/assets/bbc605b4-d7c4-4df8-8fee-1d3f181cacf0" />
<img width="1307" height="613" alt="image" src="https://github.com/user-attachments/assets/010f5ce3-9583-497b-8898-8662778d19f2" />
<img width="1297" height="616" alt="image" src="https://github.com/user-attachments/assets/52dbdfca-f9ea-47f7-8029-c2de07ca3a1c" />


## Summary of Indicators of Compromise (IoCs) & Attack Chain

| Attack Stage | Protocol / Layer | Detection Filter / SPL Logic | Confirmed Lab Indicators | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| **1. ARP Spoofing** | ARP (`Layer 2`) | `arp.opcode == 2` / `arp.duplicate-address-frame` | **14 spoofed ARP reply packets** impersonating the gateway MAC | `T1557.002` |
| **2. DNS Spoofing** | DNS (`UDP/53`) | `dns.qry.name contains "corp-login.acme-corp.local"` | **211 DNS responses** redirecting `corp-login.acme-corp.local` -> **`192.168.10.55`** | `T1557` |
| **3. SSL Stripping** | HTTP (`TCP/80`) | `http.request.method == "POST"` (Follow HTTP Stream) | HTTPS downgraded to cleartext HTTP; victim login credentials exposed | `T1557` |

---

## Defensive Recommendations & SOC Remediation
To prevent and detect chained MITM attacks across enterprise networks, I recommend implementing layered Layer-2 through Layer-7 defenses:

1. **Enable Dynamic ARP Inspection (DAI) & DHCP Snooping:** Configure enterprise switches to drop untrusted ARP packets with invalid MAC-to-IP bindings, neutralizing ARP spoofing at the access layer.
2. **Enforce DNSSEC & Internal DNS Egress Controls:** Sign internal/external zones with DNSSEC to prevent cache poisoning and restrict endpoint DNS queries strictly to authorized internal resolvers.
3. **Mandate HSTS (HTTP Strict Transport Security):** Configure web servers (`corp-login.acme-corp.local`) with HSTS headers and preload lists so browsers refuse cleartext HTTP connections and block SSL stripping downgrades.
