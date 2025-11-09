# Archer_C50 (7 alerts)

---

### unauthenticated-telnet-service-rcS

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:64`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The system starts an unauthenticated telnetd service in the rcS startup script, providing direct REDACTED_PASSWORD_PLACEHOLDER access without any credentials. This is a critical vulnerability as it allows complete system compromise with minimal effort. The telnet protocol is also unencrypted, exposing all session data.
- **Code Snippet:**
  ```
  telnetd
  ```
- **Keywords:** telnetd, rcS, busybox
- **Notes:** vulnerability

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hashing-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The backup REDACTED_PASSWORD_PLACEHOLDER file (REDACTED_PASSWORD_PLACEHOLDER.bak) contains REDACTED_PASSWORD_PLACEHOLDER credentials using weak MD5 hashing ($1$ prefix). This hash can be easily cracked with modern hardware, potentially granting attackers REDACTED_PASSWORD_PLACEHOLDER access. The file's existence also violates security best practices by storing credentials in a backup.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$, MD5
- **Notes:** Delete backup files and upgrade to a stronger hashing algorithm (SHA-256/512 or bcrypt).

---
### insecure-symbolic-link-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:10`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration
- **Code Snippet:**
  ```
  Symbolic link to /var/REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, /var/REDACTED_PASSWORD_PLACEHOLDER, symbolic link
- **Notes:** Verify /var permissions and consider using the standard REDACTED_PASSWORD_PLACEHOLDER location.

---
### buffer-overflow-bpalogin

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `usr/sbin/bpalogin:0x40286c sym.login`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The bpalogin application contains multiple unsafe string operations (strcpy, strcat) without proper length checks, particularly in the login function. This could lead to buffer overflow vulnerabilities, potentially allowing remote code execution. The vulnerability is especially dangerous as it handles authentication data.
- **Code Snippet:**
  ```
  0x0040286c      e080828f       lw v0, -sym.imp.strncpy(gp)
  ```
- **Keywords:** strcpy, strcat, handle_heartbeats, receive_transaction, login
- **Notes:** vulnerability

---
### insecure-kernel-modules-rcS

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 8.0
- **Confidence:** 6.0
- **Description:** configuration
- **Code Snippet:**
  ```
  insmod REDACTED_PASSWORD_PLACEHOLDER_rdm/rt_rdm.ko
  ```
- **Keywords:** insmod, rt_rdm.ko, raeth.ko, usb-storage.ko
- **Notes:** configuration

---
### world-writable-directories-rcS

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The rcS script creates multiple directories (/var/lock, /var/log, etc.) with 0777 permissions. This excessive permission allows any user to modify critical system files, potentially leading to privilege escalation or system manipulation. Particularly concerning are wireless configuration directories that could affect network security.
- **Code Snippet:**
  ```
  /bin/mkdir -m 0777 /var/lock /var/log /var/run
  ```
- **Keywords:** /bin/mkdir -m 0777, /var/lock, /var/log, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration

---
### weak-md5-hashing-bpalogin

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `usr/sbin/bpalogin:0x405060 sym.MD5Init`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The bpalogin application uses MD5 for REDACTED_PASSWORD_PLACEHOLDER hashing, which is REDACTED_SECRET_KEY_PLACEHOLDER weak and vulnerable to rainbow table attacks. This could allow attackers to recover passwords if they obtain the hash values.
- **Code Snippet:**
  ```
  MD5 hash function calls
  ```
- **Keywords:** MD5Init, MD5Update, MD5Final, authserver, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** vulnerability

---
