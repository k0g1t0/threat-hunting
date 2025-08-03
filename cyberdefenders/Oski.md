# 🧪 CyberDefenders – **Oski**

## 📌 Hypothesis

A phishing email containing a PowerPoint (.ppt) attachment with a fake invoice was used to lure the recipient into opening the file.  
The `.ppt` file likely contained embedded malicious content or scripts that initiated the download of a second-stage payload.  
This activity triggered a SIEM alert and likely resulted in the execution of infostealer malware, specifically **Oski**, which is known for targeting browser-stored credentials and exfiltrating sensitive data to a remote server.

---

## 🔍 Data Sources Reviewed

- A `.txt` file containing the hash of the suspicious file  
- File metadata and scan results from **VirusTotal**  
- Behavioral logs and process tree from the **ANY.RUN** sandbox  

---

## 🧰 Tools Used

- [**VirusTotal**](https://www.virustotal.com/gui/home/upload) — Hash and IP analysis  
- [**ANY.RUN**](https://any.run/) — Malware behavior analysis  

---

## 🧠 Key Queries / Actions

The challenge provides a `.zip` archive which, when extracted, contains a `.txt` file.  
Inside is a single MD5 hash: `12c1842c3ccafe7408c23ebf292ee3d9`.  
Using this hash, several questions can be investigated and answered.  
Let’s begin!

---

### ❓ Q1: What was the time of malware creation?

> **Answer:** `2022-09-28 17:40`

- ✅ Dropped the MD5 hash into **VirusTotal** to begin static analysis  
- 🔍 Navigated to the **Details** tab to examine metadata  
- 📆 Located the **creation date** field under the **History** subsection — confirming the malware’s compilation timestamp

---

### ❓ Q2: Which C2 server does the malware in the PPT file communicate with?

> **Answer:** `hxxp[://]171[.]22[.]28[.]221/5c06c05b7b34e8e6[.]php`

- 🌐 Switched to the **Relations** tab in VirusTotal to trace outbound connections  
- 🧭 Observed the **Contacted URLs** section to uncover external callbacks  
- 🔗 Identified the command-and-control (C2) endpoint used for exfiltration or second-stage payload retrieval

---

### ❓ Q3: What is the first library that the malware requests post-infection?

> **Answer:** `sqlite3.dll`

- 🧬 Moved into the **Behavior** tab of VirusTotal to monitor runtime activity  
- 🧾 Under **Files Dropped**, noted the first DLL accessed or downloaded post-infection  
- 📦 Recognized `sqlite3.dll`, often associated with attempts to access or manipulate browser-stored credentials

---

### ❓ Q4: What RC4 key is used by the malware to decrypt its base64-encoded string?

> **Answer:** `5329514621441247975720749009`

- 🧪 Used the ANY.RUN sandbox to examine dynamic behavior  
- 🔐 In the **Malware Configuration** section, searched for encryption/decryption logic  
- 🔎 Found the RC4 key embedded within the malware's configuration data, used to decrypt encoded strings in memory

---

### ❓ Q5: What is the main MITRE technique the malware uses to steal the user’s password?

> **Answer:** `T1555` — *Credentials from Password Stores*

- 🧰 Within the ANY.RUN report, accessed the **ATT&CK** tab  
- 🧠 Analyzed the technique mappings to identify credential harvesting activity  
- 🛠️ Confirmed the malware targets local storage of browser credentials — matching MITRE technique **T1555**

---

### ❓ Q6: Which directory does the malware target for the deletion of all DLL files?

> **Answer:** `C:\ProgramData`

- 🧵 Followed the **Process Tree** in ANY.RUN to track command execution  
- 💻 Observed that `cmd.exe`, spawned by `VPN.exe`, issues a deletion command  
- 🗂️ The command specifically targets `.dll` files in the `C:\ProgramData` directory — indicating an effort to cover tracks or disable dependencies

---

### ❓ Q7: After exfiltrating data, how many seconds does it take for the malware to self-delete?

> **Answer:** `5`

- 🕵️ Navigated to the final entry in the **Process Tree**  
- ⏱️ Noted a `timeout` instruction before executing deletion logic  
- ⛓️ This delay is set to **5 seconds**, giving the malware a brief window to complete its operations before self-destructing

---

## ⚠️ Indicators and Findings

| Type               | Value                                                       |
|--------------------|-------------------------------------------------------------|
| File Name          | `VPN.exe`                                                   |
| MD5 Hash           | `12c1842c3ccafe7408c23ebf292ee3d9`                          |
| SHA-1 Hash         | `4b1af84cc11a8b1e290a18a4222a49526eeadd10`                  |
| SHA-256 Hash       | `a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb` |
| C2 IP              | `171[.]22[.]28[.]221`                                       |
| C2 Endpoint        | `hxxp[://]171[.]22[.]28[.]221/5c06c05b7b34e8e6[.]php`       |
| Dropped DLL        | `hxxp[://]171[.]22[.]28[.]221/9e226a84ec50246d/sqlite3.dll` |

---

## 🧪 Detection Ideas

- 🚩 Alert when Office documents spawn suspicious child processes (e.g., `.ppt` → `cmd.exe`, `powershell.exe`)  
- 🌐 Monitor outbound HTTP connections to recently registered or low-reputation domains  
- 🔐 Watch for file or memory access to browser credential stores (e.g., `Login Data`, `Web Data`)  
- 📜 Apply Sigma or custom detection rules focused on common infostealer behavior patterns

---

## 🧾 Lessons Learned

- 📂 Trusted file formats like PowerPoint can be weaponized for initial infection  
- 📧 Email attachments must be treated with caution, especially when mimicking legitimate business workflows  
- 🌍 Outbound traffic should be continuously profiled to spot exfiltration attempts  
- 🔄 Regular sandbox analysis of attachments can uncover stealthy behaviors not caught by static detection

