# R6400v2-V1.0.2.46_1.0.36 (8 alerts)

---

### NVRAM-REDACTED_SECRET_KEY_PLACEHOLDER-sbin-init

- **File/Directory Path:** `sbin/init`
- **Location:** `sbin/init:fcn.0000ed80`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Multiple command injection vulnerabilities were discovered in sbin/init, where NVRAM values were directly used in system() calls without proper sanitization. Attackers could execute arbitrary commands during system initialization by tampering with NVRAM values. This vulnerability is triggered when the rc process reads and executes malicious NVRAM values, potentially leading to complete system compromise.
- **Code Snippet:**
  ```
  system(nvram_get("malicious_config"));
  ```
- **Keywords:** system, nvram_get, nvram_set, strcmp, eval
- **Notes:** command_injection

---
### REDACTED_SECRET_KEY_PLACEHOLDER-genie.cgi-www-cgi-bin

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:fcn.0000ac68`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** command_injection
- **Code Snippet:**
  ```
  popen(nvram_get("remote_command"), "r");
  ```
- **Keywords:** popen, nvram_get, QUERY_STRING, system
- **Notes:** command_injection

---
### System-Command-Injection-sbin-system

- **File/Directory Path:** `sbin/system`
- **Location:** `sbin/system:0xd1b8`
- **Risk Score:** 9.0
- **Confidence:** 7.25
- **Description:** command_injection
- **Code Snippet:**
  ```
  system("nvram set gbsd_msglevel=0x800003ff");
  ```
- **Keywords:** system, nvram set gbsd_msglevel=0x800003ff, libnvram.so
- **Notes:** command_injection

---
### RouterRemote-Service-etc-init.d-remote

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:50-58`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** network_service
- **Code Snippet:**
  ```
  nvram set leafp2p_service_0="RouterRemote,0,1,1,1,1,6:135,6:136,6:137,6:138,6:139,6:445,6:548,17:135,17:136,17:137,17:138,17:139,17:445,17:548"
  ```
- **Keywords:** leafp2p_services, leafp2p_service_0, RouterRemote,0,1,1,1,1,6:135,6:136,6:137,6:138,6:139,6:445,6:548,17:135,17:136,17:137,17:138,17:139,17:445,17:548
- **Notes:** network_service

---
### SSRF-genie.cgi-www-cgi-bin

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:fcn.0000a764`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** Server-Side Request Forgery (SSRF) vulnerability in www/cgi-bin/genie.cgi where the script makes HTTP requests using curl with potentially user-controlled data from QUERY_STRING. This could be exploited to make arbitrary HTTP requests from the server, potentially accessing internal services or bypassing firewall restrictions.
- **Code Snippet:**
  ```
  curl_easy_setopt(curl, CURLOPT_URL, nvram_get("proxy_url"));
  ```
- **Keywords:** curl_easy_perform, curl_easy_setopt, QUERY_STRING, nvram_get
- **Notes:** ssrf

---
### NVRAM-Injection-libnvram

- **File/Directory Path:** `usr/lib/libnvram.so`
- **Location:** `usr/lib/libnvram.so`
- **Risk Score:** 8.5
- **Confidence:** 6.75
- **Description:** nvram_injection
- **Code Snippet:**
  ```
  nvram_set(REDACTED_PASSWORD_PLACEHOLDER, value); // No length validation
  ```
- **Keywords:** nvram_set, nvram_get, acosNvramConfig_set, acosNvramConfig_get, /dev/nvram
- **Notes:** nvram_injection

---
### BufferOverflow-nvram-sbin

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `usr/sbin/nvram:0x000088e8`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** buffer_overflow
- **Code Snippet:**
  ```
  strncpy(buffer, nvram_value, 0x20000);
  ```
- **Keywords:** strncpy, nvram_set, 0x20000
- **Notes:** buffer_overflow

---
### SymbolicLink-etc-init.d-remote

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:10-18`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** directory_traversal
- **Code Snippet:**
  ```
  ln -s REDACTED_PASSWORD_PLACEHOLDER.htm REDACTED_PASSWORD_PLACEHOLDER.htm
  ```
- **Keywords:** ln -s REDACTED_PASSWORD_PLACEHOLDER.htm, ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.htm, ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.cgi, ln -s REDACTED_PASSWORD_PLACEHOLDER.sh
- **Notes:** directory_traversal

---
