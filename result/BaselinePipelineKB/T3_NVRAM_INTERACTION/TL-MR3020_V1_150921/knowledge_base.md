# TL-MR3020_V1_150921 (4 alerts)

---

### env_get-httpd-QUERY_STRING

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00402e2c`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** env_get
- **Keywords:** getenv, QUERY_STRING, command_injection, system_command
- **Notes:** env_get

---
### security-rcS-telnetd

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** The rcS script starts the telnetd service, posing a security risk due to plaintext transmission.
- **Keywords:** telnetd, insecure_protocol
- **Notes:** It is recommended to disable telnetd or switch to encrypted protocols such as SSH.

---
### env_script-rc.wlan-wifi_params

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rc.wlan`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The rc.wlan script configures wireless module parameters using multiple environment variables, including DFS_domainoverride, DFS_usenol, and ATH_countrycode. These variables are directly used to construct kernel module parameters without validation, which could be exploited for parameter injection attacks.
- **Keywords:** DFS_domainoverride, DFS_usenol, ATH_countrycode, ATH_outdoor, ATH_xchanmode, ATH_use_eeprom, ATH_debug, PCI_ARGS, DFS_ARGS, wifi_config
- **Notes:** Validate and filter the values of these environment variables to prevent command injection.

---
### env_get-httpd-NVRAM_SESSION_ID

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00402d58`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Detected a call to 'getenv' accessing the 'NVRAM_SESSION_ID' environment variable. This value is used for session management but lacks proper validation, potentially leading to session fixation attacks.
- **Keywords:** getenv, NVRAM_SESSION_ID, session_management, session_fixation
- **Notes:** Session management may be vulnerable to session fixation.

---
