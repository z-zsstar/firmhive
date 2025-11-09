# _DWR-118_V1.01b01.bin.extracted (3 alerts)

---

### nvram-http_REDACTED_PASSWORD_PLACEHOLDER-clear_text

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x00405c88 (sym.check_auth)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Plaintext access to the administrative REDACTED_PASSWORD_PLACEHOLDER variable 'http_REDACTED_PASSWORD_PLACEHOLDER' was detected. This value is used for authentication but lacks security hardening.
- **Keywords:** http_REDACTED_PASSWORD_PLACEHOLDER, getenv
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is stored in plaintext in memory, posing a risk of leakage.

---
### nvram-lan_ipaddr-command_injection

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x00402a10 (sym.get_lan_ip)`
- **Risk Score:** 7.2
- **Confidence:** 7.65
- **Description:** Detection of access to NVRAM variable 'lan_ipaddr', where the value is directly used to construct network configurations. Lack of input validation may lead to command injection risks.
- **Keywords:** lan_ipaddr, getenv
- **Notes:** The variable value is directly concatenated into the system() call. It is recommended to check the calling context.

---
### nvram-remote_mgt_enable-auth_bypass

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER (sym.check_remote_access)`
- **Risk Score:** 6.8
- **Confidence:** 6.75
- **Description:** Access to the 'remote_mgt_enable' flag was detected, which controls the remote management functionality but lacks permission verification.
- **Keywords:** remote_mgt_enable, getenv
- **Notes:** Critical security flags require additional verification

---
