# Archer_C2_V1_170228 (9 alerts)

---

### attack-path-telnet-to-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS, etc/shadow`
- **Risk Score:** 9.5
- **Confidence:** 9.25
- **Description:** authentication_bypass
- **Keywords:** telnetd, REDACTED_PASSWORD_PLACEHOLDER, $1$, /bin/sh
- **Notes:** authentication_bypass

---
### web-cgi-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/js/lib.js, usr/bin/httpd`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** command_injection
- **Keywords:** ACT_OP, http_cgi_main, strcpy, ACT_REBOOT
- **Notes:** command_injection

---
### permissive-directories-privesc

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS, usr/bin/cos`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Multiple world-writable directories (/var/lock, /var/tmp/dropbear, etc.) created with 0777 permissions in etc/init.d/rcS. Combined with the insecure dropbear configuration (var/tmp/dropbear) and potential symlink attacks, this could lead to privilege escalation. The cos service (usr/bin/cos) also creates insecure /var/tmp/dconf directory.
- **Keywords:** /bin/mkdir -m 0777, /var/tmp/dropbear, /var/tmp/dconf
- **Notes:** privilege_escalation

---
### kernel-module-vulnerabilities

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** Multiple third-party kernel modules loaded (rt_rdm.ko, tp_domain.ko) without version verification. The custom tp_domain.ko module supporting tplinklogin.net functionality is particularly suspicious and could contain backdoors or vulnerabilities.
- **Keywords:** insmod, tp_domain.ko, tplinklogin.net, rt_rdm.ko
- **Notes:** kernel_vulnerability

---
### ftp-service-exploitation

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf, etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** FTP service (vsftpd) configured with write access enabled and weak security settings. Combined with the weak REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER hash found in etc/REDACTED_PASSWORD_PLACEHOLDER.bak, this could allow attackers to upload malicious files or modify system configurations.
- **Keywords:** vsftpd.conf, write_enable, REDACTED_PASSWORD_PLACEHOLDER, $1$
- **Notes:** service_vulnerability

---
### http-request-parsing-vulnerabilities

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** web_vulnerability
- **Keywords:** sym.http_parser_main, sym.http_tool_argUnEscape, str._._, cVar1 == '%'
- **Notes:** web_vulnerability

---
### REDACTED_PASSWORD_PLACEHOLDER-file-exposure

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Backup REDACTED_PASSWORD_PLACEHOLDER file (REDACTED_PASSWORD_PLACEHOLDER.bak) copied to insecure location (/var/REDACTED_PASSWORD_PLACEHOLDER) in etc/init.d/rcS. This exposes REDACTED_PASSWORD_PLACEHOLDER information in a world-writable directory, potentially allowing attackers to read or modify REDACTED_PASSWORD_PLACEHOLDER hashes.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, /var/REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** information_disclosure

---
### dropbear-ssh-vulnerabilities

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Dropbear SSH server has potential path traversal in authorized_keys handling (svr_auth_pubkey) and weak REDACTED_PASSWORD_PLACEHOLDER authentication without account locking. The service account uses /bin/sh shell, increasing risk if compromised.
- **Keywords:** svr_auth_pubkey, dropbear, /bin/sh, buf_getstring
- **Notes:** service_vulnerability

---
### cos-service-risks

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The 'cos' service (usr/bin/cos) uses multiple dangerous functions (strcpy, system) without proper input validation. It also handles privileged operations (process killing) and creates insecure directories (/var/tmp/dconf). The service's purpose is unclear, increasing suspicion.
- **Keywords:** cos, strcpy, system, /var/tmp/dconf
- **Notes:** service_vulnerability

---
