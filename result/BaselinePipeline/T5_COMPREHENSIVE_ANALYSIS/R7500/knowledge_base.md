# R7500 (10 alerts)

---

### insecure-file-permissions-firewall

- **File/Directory Path:** `etc/config/firewall`
- **Location:** `etc/config/firewall`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** configuration
- **Keywords:** firewall, permissions 777
- **Notes:** configuration

---
### command-injection-ntgr_sw_api

- **File/Directory Path:** `usr/bin/redis-server`
- **Location:** `usr/bin/redis-server:0x44eac`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The Redis Sentinel component in usr/bin/redis-server contains a command injection vulnerability in the REDACTED_PASSWORD_PLACEHOLDER function. The function uses execve to execute external scripts without proper validation of script parameters. An attacker could control script parameters to achieve arbitrary command execution.
- **Code Snippet:**
  ```
  0x00044eac      db4bffeb       bl sym.imp.execve
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, execve, SENTINEL_SCRIPT_MAX_QUEUE
- **Notes:** vulnerability

---
### attack-path-nvram-to-rce

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.0
- **Confidence:** 7.25
- **Description:** attack_path
- **Keywords:** nvram, config_set, command_injection, buffer_overflow
- **Notes:** attack_path

---
### xss-REDACTED_SECRET_KEY_PLACEHOLDER.cgi

- **File/Directory Path:** `www/cgi-REDACTED_PASSWORD_PLACEHOLDER.cgi`
- **Location:** `www/cgi-REDACTED_PASSWORD_PLACEHOLDER.cgi (JavaScript section)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** vulnerability
- **Keywords:** eval, quest1_, PWD_question1, cfg_sed_xss
- **Notes:** vulnerability

---
### buffer-overflow-nvram-config_set

- **File/Directory Path:** `bin/config`
- **Location:** `bin/config:0x8760 (function fcn.000086cc)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The 'config set' command in bin/nvram (symlinked to bin/config) uses strcpy to copy user-controlled input into a stack buffer without bounds checking, leading to a potential stack-based buffer overflow. This can be triggered by executing 'config set name=value' with a long value parameter. The vulnerability is located in the config_set function and has a high risk of arbitrary code execution if exploited.
- **Code Snippet:**
  ```
  0x0000875c      0d00a0e1       mov r0, sp
  0xREDACTED_PASSWORD_PLACEHOLDER      a0ffffeb       bl sym.imp.strcpy
  ```
- **Keywords:** config_set, strcpy, argv, stack_buffer
- **Notes:** vulnerability

---
### path-traversal-func.sh

- **File/Directory Path:** `www/cgi-bin/func.sh`
- **Location:** `www/cgi-bin/func.sh:10-18`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The print_language_js function in www/cgi-bin/func.sh dynamically includes JavaScript files based on the GUI_Region value from NVRAM. If an attacker can control the GUI_Region value, it could lead to path traversal or arbitrary file inclusion vulnerabilities.
- **Code Snippet:**
  ```
  GUI_Region=$($nvram get GUI_Region)
  lang_file="language/$GUI_Region.js"
  path="/www/$lang_file"
  ```
- **Keywords:** print_language_js, GUI_Region, lang_file, path
- **Notes:** It is necessary to verify the method of setting the GUI_Region value and whether it may be influenced by external inputs.

---
### attack-path-ssrf-to-internal

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** attack_path
- **Keywords:** ozker, SSRF, 127.0.0.1:9000, lateral_movement
- **Notes:** attack_path

---
### ssrf-ozker

- **File/Directory Path:** `www/cgi-bin/ozker`
- **Location:** `www/cgi-bin/ozker`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** vulnerability
- **Keywords:** ozker, cgi-fcgi, 127.0.0.1:9000, SSRF
- **Notes:** vulnerability

---
### weak-crypto-uhttpd

- **File/Directory Path:** `etc/config/uhttpd`
- **Location:** `etc/config/uhttpd`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** configuration
- **Keywords:** uhttpd.crt, uhttpd.REDACTED_PASSWORD_PLACEHOLDER, px5g, bits 1024
- **Notes:** It is recommended to upgrade to a 2048-bit or higher strength REDACTED_PASSWORD_PLACEHOLDER and use a properly signed certificate.

---
### open-redirect-func.sh

- **File/Directory Path:** `www/cgi-bin/func.sh`
- **Location:** `www/cgi-bin/func.sh:60-85`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The print_http_refresh function in www/cgi-bin/func.sh directly uses unvalidated URL parameters to construct Refresh headers, potentially leading to open redirect vulnerabilities. Attackers could craft malicious URLs for phishing attacks.
- **Code Snippet:**
  ```
  local url="$1"
  print_http_header
  echo "<HEAD><meta http-equiv=\"Refresh\" content=\"$delay_time; url=$url\">"
  ```
- **Keywords:** print_http_refresh, url=$1, Refresh header
- **Notes:** It is necessary to verify whether the URL parameters are filtered when calling this function.

---
