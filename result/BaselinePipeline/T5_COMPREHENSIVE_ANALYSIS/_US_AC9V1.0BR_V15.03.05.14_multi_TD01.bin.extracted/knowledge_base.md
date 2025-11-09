# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (7 alerts)

---

### web-cmd-injection-dhttpd

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `bin/dhttpd:0x00034da8`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** A command injection vulnerability was discovered in dhttpd. The REDACTED_PASSWORD_PLACEHOLDER function executes the 'killall -9 dhttpd' command via doSystemCmd without proper input validation during command construction. Attackers could potentially inject additional commands through carefully crafted HTTP requests. Combined with nginx's configuration running with REDACTED_PASSWORD_PLACEHOLDER privileges, this could form a complete attack chain for remote REDACTED_PASSWORD_PLACEHOLDER privilege escalation.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER() {
    ...
    doSystemCmd("killall -9 dhttpd");
    ...
  }
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, doSystemCmd, killall -9 dhttpd, user REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is necessary to verify whether command execution can be controlled through web request parameters. Combined with nginx's REDACTED_PASSWORD_PLACEHOLDER privilege operation configuration, this may form a high-risk attack chain.

---
### nginx-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `etc_ro/nginx/conf/nginx.conf`
- **Location:** `etc_ro/nginx/conf/nginx.conf:1`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The web server is running with REDACTED_PASSWORD_PLACEHOLDER privileges (user REDACTED_PASSWORD_PLACEHOLDER), which violates the principle of least privilege. If an attacker exploits an Nginx vulnerability or a web application vulnerability, they would directly gain REDACTED_PASSWORD_PLACEHOLDER access.
- **Code Snippet:**
  ```
  user REDACTED_PASSWORD_PLACEHOLDER;
  ```
- **Keywords:** user REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Combining the command injection vulnerability in dhttpd, this could form a complete remote REDACTED_PASSWORD_PLACEHOLDER privilege escalation attack chain.

---
### var-directory-permissions

- **File/Directory Path:** `etc_ro/init.d/rcS`
- **Location:** `N/A`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The /var directory and all its subdirectories (etc, home, REDACTED_PASSWORD_PLACEHOLDER, webroot) have global read-write-execute permissions (rwxrwxrwx). This allows any user to modify files within these directories, potentially leading to privilege escalation or configuration tampering. Attackers could alter files in webroot to deface websites, or modify configuration files in etc to change system behavior.
- **Keywords:** /var, rwxrwxrwx, webroot, etc
- **Notes:** This loose permission configuration could be exploited for persistence attacks or privilege escalation.

---
### unsafe-libc-functions

- **File/Directory Path:** `lib/libc.so.0`
- **Location:** `lib/libc.so.0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** libc.so.0 contains implementations of multiple known unsafe functions (such as gets, strcpy, etc.), which may be called by other components in the firmware, creating potential attack surfaces. In particular, the gets and strcpy functions can lead to buffer overflow vulnerabilities.
- **Keywords:** libc.so.0, gets, strcpy, sprintf, system
- **Notes:** All programs that call these dangerous functions must be audited.

---
### web-config-tampering-dhttpd

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `bin/dhttpd:0x00034d9c`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Detection of insufficiently validated configuration modification operations. The REDACTED_PASSWORD_PLACEHOLDER function modifies critical configurations such as wan.dnsredirect.flag through SetValue without adequate permission verification. Attackers could potentially alter system behavior by tampering with these configurations, such as enabling DNS redirection.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, SetValue, wan.dnsredirect.flag
- **Notes:** Further analysis is required to assess the specific impact scope of these configuration items and to validate the modification permission mechanisms.

---
### nginx-insecure-config

- **File/Directory Path:** `etc_ro/nginx/conf/nginx.conf`
- **Location:** `etc_ro/nginx/conf/nginx.conf:26-29`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** An insecure file service configuration (location /) was discovered, which sets the /etc/nginx/conf directory as the web REDACTED_PASSWORD_PLACEHOLDER directory. This may expose sensitive configuration files. Combined with the nginx configuration running with REDACTED_PASSWORD_PLACEHOLDER privileges, this could increase the risk of information disclosure.
- **Keywords:** location /, REDACTED_PASSWORD_PLACEHOLDER /etc/nginx/conf
- **Notes:** It is necessary to verify whether these configuration files are truly accessible via the web.

---
### goahead-vulnerable-version

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `N/A`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** vulnerable_component
- **Keywords:** GoAhead, 3.3.0
- **Notes:** vulnerable_component

---
