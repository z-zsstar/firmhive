# TD-W8980_V1_150514 (4 alerts)

---

### insecure-telnet-service

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:77`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The system directly runs the telnetd service upon startup without any authentication mechanism or security restrictions. This allows attackers to gain full control of the device via the telnet protocol, posing a severe risk of unauthorized access.
- **Code Snippet:**
  ```
  telnetd
  ```
- **Keywords:** telnetd, rcS, init.d
- **Notes:** It is recommended to disable the telnet service or at least configure strong authentication mechanisms.

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 9.0
- **Confidence:** 9.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user's REDACTED_PASSWORD_PLACEHOLDER is stored using a weak MD5 hash ($1$) and has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0). This allows attackers to gain REDACTED_PASSWORD_PLACEHOLDER access through offline brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to use strong REDACTED_PASSWORD_PLACEHOLDER hashing algorithms such as SHA-512 and restrict REDACTED_PASSWORD_PLACEHOLDER-privileged accounts.

---
### insecure-nobody-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:2`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The user 'nobody' is configured with REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0), violating the principle of least privilege and potentially being exploited for privilege escalation attacks.
- **Code Snippet:**
  ```
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** nobody, UID 0, REDACTED_PASSWORD_PLACEHOLDER.bak
- **Notes:** The nobody user should be configured as a non-privileged account (UID > 0).

---
### world-writable-directories

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:4-12`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The startup script created multiple globally readable and writable directories (with 0777 permissions), including /var/lock, /var/tmp, etc. Such permissive permission settings could potentially be exploited by attackers for privilege escalation or persistence attacks.
- **Code Snippet:**
  ```
  /bin/mkdir -m 0777 -p /var/lock
  /bin/mkdir -m 0777 -p /var/tmp
  ```
- **Keywords:** mkdir, 0777, /var/lock, /var/tmp
- **Notes:** Restrict directory permissions to the minimum necessary

---
