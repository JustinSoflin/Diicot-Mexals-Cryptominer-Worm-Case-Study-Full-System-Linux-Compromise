# Linux Miner Infection  
## Root-Level Persistence via /etc/init.d

---

## Report Information

- **Analyst:** Justin Soflin  
- **Date Completed:** Feb. 04, 2026  
- **Environment Investigated:** Cyber Range at LOG(N) Pacific  
- **Hosts Investigated:**  
  - `linux-programmatic-fix-michael`  
  - `linuxprogrammaticpabon`  
- **User Context:** root | Unauthorized miner installation & persistence  
- **Tools & Data Sources:** Microsoft Defender for Endpoint, Log Analytics Workspaces, KQL (Kusto Query Language), Linux audit logs  
- **Scope:** SYSTEM-level execution, persistence analysis, malware delivery chain reconstruction, log tampering assessment  

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Investigation](#investigation)
  - [Initial Detection: Malware or PUA Observed](#initial-detection-malware-or-pua-observed)
  - [Authentication Context and Lab Configuration](#authentication-context-and-lab-configuration)
  - [Malicious Binary Download Detected](#malicious-binary-download-detected)
  - [Multiple Download Methods Observed](#multiple-download-methods-observed)
  - [Binary Relocation and Renaming](#binary-relocation-and-renaming)
  - [Persistence via /etc/init.d](#persistence-via-etcinitd)
  - [Log Tampering via cat /dev/null](#log-tampering-via-cat-devnull)
  - [SSH Key Implantation](#ssh-key-implantation)
  - [Malware Validation and Classification](#malware-validation-and-classification)
- [Recommended Actions](#recommended-actions)
- [Conclusion](#conclusion)

---

## Executive Summary

The student Linux virtual machine `linux-programmatic-fix-michael` was compromised by an automated cryptocurrency mining malware campaign. The investigation was initiated following a Microsoft Defender for Endpoint alert indicating **Malware or  PUA (Potentially Unwanted Application) Observed**.

This incident occurred during an active **student lab exercise** in which the **root account password was intentionally set to `root`** to generate alerts during Tenable vulnerability scanning exercises. While expected in a controlled instructional environment, this configuration significantly weakened the system’s security posture and exposed the VM to real-world internet scanning and brute-force activity.

Telemetry confirms that an external actor successfully authenticated as `root`, downloaded and executed a malicious ELF binary, established persistence using legacy init scripts, renamed system utilities to evade detection, implanted SSH keys for long-term access, and deliberately destroyed forensic artifacts.

VirusTotal analysis of the recovered binary returned a **46 / 63 detection score**, classifying the file as a **Trojan**, confirming the activity was malicious and not the result of student experimentation or administrative automation.

---

## Investigation

### Initial Detection: Malware or PUA Observed

The investigation began after Microsoft Defender for Endpoint generated an alert indicating **Malware or Potentially Unwanted Application (PUA)** activity on the Linux host. The alert correlated with suspicious file creation and execution behavior occurring under the `root` user context.

This detection prompted analysis of:

- File creation events  
- Process execution telemetry  
- Authentication and logon activity  
- Network-based download behavior  

---

### Authentication Context and Lab Configuration

At the time of compromise, the VM was actively being used for a **student lab exercise** designed to demonstrate insecure authentication practices.

Lab configuration included:

- SSH access intentionally exposed  
- **Root password set to `root`**  
- Expected vulnerability and alert generation  

This configuration mirrors conditions exploited by real-world automated attack campaigns. Multiple external IP addresses attempted authentication across multiple lab VMs, consistent with **opportunistic brute-force activity**.

The successful `root` authentication observed during this investigation is attributed to **external automated intrusion**, not legitimate student activity.

---

### Malicious Binary Download Detected

Defender for Endpoint file telemetry revealed suspicious binaries written directly to `/usr/bin`:

DeviceFileEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where FileName startswith "ygljglkjgfg"  
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine  
| order by TimeGenerated asc  

Observed artifacts included:

- `ygljglkjgfg0`  
- `ygljglkjgfg1`  
- `ygljglkjgfg2`  

All were written within seconds of each other.

---

### Multiple Download Methods Observed

Process telemetry revealed redundant payload retrieval attempts:

DeviceProcessEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where ProcessCommandLine has_any ("curl", "wget", "good")  
| project TimeGenerated, FileName, ProcessCommandLine  
| order by TimeGenerated asc  

The same payload was retrieved using:

- `curl`  
- `wget`  
- `good` (a renamed system utility)  

This behavior strongly indicates **automated malware execution**, not manual user activity.

---

### Binary Relocation and Renaming

The attacker deliberately renamed trusted system binaries:

mv /usr/bin/wget /usr/bin/good  
mv /bin/wget /bin/good  

Renaming trusted utilities allows continued payload delivery while bypassing simplistic detections that rely on binary names.

---

### Persistence via /etc/init.d

Persistence was established by creating an init script:

DeviceFileEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where FolderPath startswith "/etc/init.d"  
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine  
| order by TimeGenerated desc  

Why this is significant:

- `/etc/init.d` scripts execute automatically on boot  
- Execution occurs as `root`  
- Persistence survives reboots and user logouts  

This confirms **intentional long-term persistence**.

---

### Log Tampering via cat /dev/null

The attacker deliberately destroyed forensic evidence by truncating multiple logs:

cat /dev/null >/root/.bash_history  
cat /dev/null >/var/log/wtmp  
cat /dev/null >/var/log/btmp  
cat /dev/null >/var/log/lastlog  
cat /dev/null >/var/log/secure  
cat /dev/null >/var/log/syslog  

Because these logs were cleared on the host, historical entries no longer existed for ingestion into Log Analytics, significantly limiting post-incident visibility.

---

### SSH Key Implantation

A persistent SSH backdoor was implanted:

chattr -ia ~/.ssh/authorized_keys  
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." > ~/.ssh/authorized_keys  
chattr +ai ~/.ssh/authorized_keys  

Setting the immutable attribute (`+i`) prevents easy removal and ensures continued access even if credentials are rotated.

---

### Malware Validation and Classification

The malicious ELF binary was validated using VirusTotal:

- **Detection score:** 46 / 63  
- **Classification:** Trojan  
- **Observed behaviors:**  
  - Cryptocurrency mining  
  - Process termination of competing miners  
  - Persistence installation  
  - Log destruction  

This confirms the activity represents a **real-world malware compromise**.

---

## Recommended Actions

### Immediate Recovery

- Redeploy affected virtual machines  
- Remove unauthorized init scripts  
- Rotate all credentials and SSH keys  
- Rebuild systems from trusted images  

### Monitoring Improvements

- Alert on writes to `/etc/init.d`  
- Monitor renaming of binaries in `/bin` and `/usr/bin`  
- Detect log truncation behavior  
- Alert on modifications to `authorized_keys`  
- Flag repeated download attempts from single external IPs  

---

## Conclusion

This incident represents a **complete Linux system compromise** performed by automated malware exploiting weak authentication during a student lab exercise. While the insecure configuration was intentional for instructional purposes, it created conditions identical to real-world attack surfaces.

Microsoft Defender for Endpoint successfully detected the malicious activity, enabling investigation and confirmation of compromise. This case highlights how quickly exposed Linux systems can be compromised and reinforces the importance of monitoring persistence mechanisms, binary integrity, and log tampering — even in educational or non-production environments.
