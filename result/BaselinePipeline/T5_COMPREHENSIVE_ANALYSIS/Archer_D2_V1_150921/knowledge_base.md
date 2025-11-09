# Archer_D2_V1_150921 (9 alerts)

---

### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-hash-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 10.0
- **Confidence:** 9.5
- **Description:** The `etc/REDACTED_PASSWORD_PLACEHOLDER.bak` file contains a hardcoded REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER hash (REDACTED_PASSWORD_PLACEHOLDER user) using the crackable MD5 algorithm. Attackers could obtain REDACTED_PASSWORD_PLACEHOLDER privileges by cracking this hash.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** Change all default passwords immediately

---
### attack-scenario-REDACTED_PASSWORD_PLACEHOLDER-hash-cracking

- **File/Directory Path:** `Multiple`
- **Location:** `Multiple files`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** attack_scenario
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/, telnet, ssh
- **Notes:** attack_scenario

---
### telnet-default-enabled-rcS

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:52`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** In the `etc/init.d/rcS` file, the telnet service is found to be enabled by default without any authentication restrictions configured. This allows attackers direct access to the device shell. Combined with the hardcoded REDACTED_PASSWORD_PLACEHOLDER in `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`, attackers can easily obtain REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** telnetd, REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** High-risk configuration, it is recommended to disable immediately or configure strong authentication.

---
### attack-scenario-ftp-telnet-privesc

- **File/Directory Path:** `Multiple`
- **Location:** `Multiple files`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** An attacker can log in via FTP using weak credentials (REDACTED_PASSWORD_PLACEHOLDER:1234), upload malicious files to a world-writable directory, and then execute these files with REDACTED_PASSWORD_PLACEHOLDER privileges by exploiting the telnet service.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** ftp, telnet, /var/tmp, REDACTED_PASSWORD_PLACEHOLDER:1234
- **Notes:** attack_scenario

---
### setPwd-insecure-REDACTED_PASSWORD_PLACEHOLDER-transmission

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `web/frame/setPwd.htm`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** vulnerability
- **Code Snippet:**
  ```
  xmlHttpObj.open("POST", "http://" + window.location.hostname + "/cgi/setPwd?pwd=" + Base64Encoding("REDACTED_PASSWORD_PLACEHOLDER"), true);
  ```
- **Keywords:** setPwd.htm, xmlHttpObj.open, setPwd?pwd=, Base64Encoding
- **Notes:** vulnerability

---
### httpd-buffer-overflow-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 6.75
- **Description:** The HTTP request processing contains unsafe string operations (strcpy/strcat), which may lead to buffer overflow. Attackers can exploit this vulnerability by crafting specially designed HTTP requests to execute arbitrary code. The trigger condition is sending specially crafted oversized HTTP requests.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, strcpy, strcat, http_init_main
- **Notes:** Dynamic analysis is required to confirm actual exploitability.

---
### ftp-weak-credentials-vsftpd

- **File/Directory Path:** `etc/vsftpd.conf`
- **Location:** `etc/vsftpd.conf:3`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** FTP service configuration (`etc/vsftpd.conf`) allows local users to write files, and `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER` contains multiple weak passwords (REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest). Attackers can exploit these credentials to upload malicious files.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** write_enable=YES, local_enable=YES, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest
- **Notes:** It is recommended to disable FTP write permissions or configure a strong REDACTED_PASSWORD_PLACEHOLDER policy.

---
### world-writable-directories-rcS

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:5-15`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The startup script creates multiple world-writable directories (/var/tmp, /var/usbdisk, etc.), which could be exploited by attackers to store malicious files or perform privilege escalation.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** /bin/mkdir -m 0777, /var/tmp, /var/usbdisk
- **Notes:** Restrict directory permissions to avoid world-writable access.

---
### httpd-recv-overflow-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 5.75
- **Description:** The recv() system call lacks buffer size checking, which may lead to heap/stack overflow. Attackers can trigger this by sending excessively long HTTP requests.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, recv, socket, http_inetd.c
- **Notes:** need to check the specific buffer size in the calling context

---
