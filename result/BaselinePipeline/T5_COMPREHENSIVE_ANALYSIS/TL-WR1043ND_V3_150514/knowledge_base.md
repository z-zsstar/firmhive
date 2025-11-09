# TL-WR1043ND_V3_150514 (8 alerts)

---

### shadow-file-permissions

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow`
- **Risk Score:** 10.0
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER file has global read-write permissions (rwxrwxrwx), exposing REDACTED_PASSWORD_PLACEHOLDER hashes to potential theft and modification. Any user can read hashes for offline cracking, modify the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER, or remove passwords entirely. This vulnerability is directly exploitable through low-privilege user accounts or web services, providing complete system compromise.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/bash
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration

---
### netusb-kernel-exploit

- **File/Directory Path:** `lib/modules/2.6.31/kernel/NetUSB.ko`
- **Location:** `lib/modules/2.6.31/kernel/NetUSB.ko`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** KCodes NetUSB kernel module contains known stack buffer overflow (CVE-2015-3036) via crafted USB packets. Vulnerable functions (REDACTED_SECRET_KEY_PLACEHOLDER) copy user input to fixed buffers without bounds checking. Also exposes insecure TCP/IP stack and privilege escalation via ioctl.
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, bulkXfer, tcpV6Main, kernel_ioctl
- **Notes:** hardware_input

---
### httpd-privilege-escalation

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x0044493c`
- **Risk Score:** 9.0
- **Confidence:** 6.75
- **Description:** The HTTP server maps privileged paths (/userRpm/*) without strict authentication. The system contains hardcoded credentials and employs dangerous string operations (strcpy). When combined with an authentication bypass vulnerability, files uploaded to the /incoming/ directory (mapped to /rc_filesys/) could potentially achieve arbitrary code execution.
- **Keywords:** sym.httpCtrlConfAdd, str._userRpm_, sym.REDACTED_SECRET_KEY_PLACEHOLDER, sym.imp.strcpy
- **Notes:** Full exploit chain requires auth bypass or session hijacking. Analyze sym.httpDispatcher for request handling flaws.

---
### wireless-default-config

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_wsc_cfg.txt`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_wsc_cfg.txt`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** WSC configurations in /etc/ath use default credentials (SSID=WscAtherosAP), open authentication (KEY_MGMT=OPEN), and enabled UPnP. Exposes detailed device info (MAC, serial) facilitating targeted attacks. No network encryption (NW_KEY empty) allows MITM attacks.
- **Keywords:** SSID=WscAtherosAP, KEY_MGMT=OPEN, USE_UPNP=1, NW_KEY=
- **Notes:** configuration

---
### wpa-supplicant-eapol

- **File/Directory Path:** `usr/sbin/wpa_supplicant`
- **Location:** `usr/sbin/wpa_supplicant:wpa_sm_rx_eapol`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** wpa_supplicant contains critical vulnerabilities in EAPOL frame processing: 1) Insufficient length validation (continues processing frames smaller than 99 bytes); 2) Weak error handling during decryption failures; 3) Inadequate replay counter checks; 4) Missing proper validation during GTK installation. These vulnerabilities may lead to buffer overflow, encryption downgrade, or group REDACTED_PASSWORD_PLACEHOLDER leakage.
- **Keywords:** wpa_sm_rx_eapol, EAPOL frame too short, AES_unwrap_failed, install_GTK
- **Notes:** Requires MITM position or authenticated client access. Check ASLR effectiveness as mitigation.

---
### libupnp-vulnerabilities

- **File/Directory Path:** `lib/libupnp.so.3.0.5`
- **Location:** `lib/libupnp.so.3.0.5`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** libupnp.so contains multiple high-risk flaws: 1) Buffer overflows via strcpy in REDACTED_PASSWORD_PLACEHOLDER; 2) Incomplete validation in UpnpSendAction; 3) Known CVEs (CVE-2016-8863, CVE-2020-13848) for SSDP NULL dereference and SOAP exploits. Compiled with outdated GCC 3.3.2 lacking modern protections.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, strcpy, CVE-2020-13848, GCC: (GNU) 3.3.2
- **Notes:** network_input

---
### dropbear-ssh-vulnerabilities

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Dropbear SSH server (2012.55) contains multiple high-risk issues: 1) REDACTED_PASSWORD_PLACEHOLDER authentication via REDACTED_PASSWORD_PLACEHOLDER environment variable; 2) Hardcoded paths for REDACTED_PASSWORD_PLACEHOLDER files; 3) Dangerous memory operations in cryptographic functions. Attackers could exploit through brute force, path traversal, or memory corruption attacks.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER_rsa_host_key, buf_getwriteptr, mp_read_unsigned_bin
- **Notes:** network_input

---
### init-script-issues

- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `etc/rc.d/rcS`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Init scripts mount /tmp as ramfs (clearing on reboot but potentially leaking sensitive data). Start httpd without binary integrity checks, allowing REDACTED_PASSWORD_PLACEHOLDER compromise if binary is replaced. Modify kernel network params (nf_conntrack_tcp_be_liberal) weakening firewall protections.
- **Keywords:** mount -t ramfs, /usr/bin/httpd, nf_conntrack_tcp_be_liberal
- **Notes:** configuration

---
