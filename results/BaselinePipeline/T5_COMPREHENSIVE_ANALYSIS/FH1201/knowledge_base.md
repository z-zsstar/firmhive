# FH1201 (6 alerts)

---

### etc-REDACTED_PASSWORD_PLACEHOLDER-weak-hashes

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER, etc/shadow`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER, etc/shadow`
- **Risk Score:** 10.0
- **Confidence:** 9.75
- **Description:** In `etc/REDACTED_PASSWORD_PLACEHOLDER` and `etc/shadow`, weak REDACTED_PASSWORD_PLACEHOLDER hashes encrypted with DES (such as 6HgsSsJIEOc2U) were found for all users, and the REDACTED_PASSWORD_PLACEHOLDER user was using the weaker MD5 hash (starting with $1$). More critically, all users (including regular users) had REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0), meaning that once an attacker cracks any user's REDACTED_PASSWORD_PLACEHOLDER, they gain complete system control. This is an extremely high-risk configuration issue.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, shadow, REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody, REDACTED_PASSWORD_PLACEHOLDER, UID 0
- **Notes:** The attack path is straightforward: 1) Obtain any user credentials through brute force 2) Immediately gain REDACTED_PASSWORD_PLACEHOLDER privileges 3) Gain full control of the system. Immediate remediation is required.

---
### var-etc-insecure-permissions

- **File/Directory Path:** `var/etc`
- **Location:** `varREDACTED_PASSWORD_PLACEHOLDER, varREDACTED_PASSWORD_PLACEHOLDER, varREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Sensitive configuration files (`REDACTED_PASSWORD_PLACEHOLDER`, `shadow`, `group`, etc.) with global read-write permissions (rwxrwxrwx) were discovered in the `var/etc` directory. These files could be modified by non-privileged users, potentially leading to privilege escalation attacks. Combined with the UID 0 configuration in `etc/REDACTED_PASSWORD_PLACEHOLDER`, this creates an extremely dangerous attack vector.
- **Keywords:** varREDACTED_PASSWORD_PLACEHOLDER, varREDACTED_PASSWORD_PLACEHOLDER, varREDACTED_PASSWORD_PLACEHOLDER, rwxrwxrwx
- **Notes:** Attack Path: 1) Non-privileged user modifies `varREDACTED_PASSWORD_PLACEHOLDER` or `shadow` 2) Adds or modifies a user with UID 0 3) Uses new credentials to log in and gain REDACTED_PASSWORD_PLACEHOLDER privileges. File permissions must be fixed immediately.

---
### nvram-set-buffer-overflow

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0x400a80-0x400a8c`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A potential buffer overflow vulnerability was discovered in the `set` operation of `bin/nvram`. The program uses `strncpy` to copy user-supplied values to a stack buffer (sp+0x1c) but fails to properly validate input length. An attacker could craft an excessively long parameter to trigger stack overflow, potentially gaining control of program execution flow. This is a high-risk vulnerability as `nvram` typically operates with elevated privileges, and this operation can be triggered either via command line or network interface.
- **Code Snippet:**
  ```
  0x00400a80      6480998f       lw t9, -sym.imp.strncpy(gp)
  0x00400a84      REDACTED_PASSWORD_PLACEHOLDER       move a0, s3
  0x00400a88      09f82003       jalr t9
  0x00400a8c      1800b3af       sw s3, (arg_18h)
  ```
- **Keywords:** nvram_set, strncpy, sp+0x1c, main
- **Notes:** Further confirmation is required regarding the buffer size and the maximum possible length of user input. Potential attack vectors may include: 1) Direct execution via command line 2) Indirect invocation through web interfaces 3) Indirect invocation via other services.

---
### usr-sbin-acs-cli-format-string

- **File/Directory Path:** `usr/sbin/acs_cli`
- **Location:** `usr/sbin/acs_cli:multiple locations`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Multiple format string vulnerabilities were identified in `usr/sbin/acs_cli`, particularly within error message handling paths. The program directly outputs user-controllable or NVRAM-retrieved data using `printf`/`fprintf`, which may lead to information disclosure or memory corruption. When combined with NVRAM operation vulnerabilities, this could potentially form a complete attack chain.
- **Keywords:** printf, fprintf, ACSD >>%s(%d), Invalid IPADDR: %s, nvram_get
- **Notes:** The attack path may include: 1) Setting a malicious format string via NVRAM 2) Triggering an error condition to cause the program to output this string 3) Exploiting the format string vulnerability to obtain memory information or control execution flow.

---
### www-directory-potential-vectors

- **File/Directory Path:** `www`
- **Location:** `www directory`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Potential web attack vectors were detected in the `www` directory, but their contents could not be automatically analyzed due to access restrictions. These directories may contain high-risk components such as web server executables, configuration files, authentication scripts, and file upload handlers. Manual inspection of these files is required to identify potential vulnerabilities.
- **Keywords:** www, web, cgi-bin, htaccess
- **Notes:** Further analysis is required: 1) Obtain the exact www directory path 2) Check file permissions 3) Analyze web server configuration 4) Inspect known vulnerable components.

---
### var-webroot-writable-configs

- **File/Directory Path:** `var/webroot`
- **Location:** `var/webroot`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the `var/webroot` directory, web configuration files (`default.cfg`, `nvram_default.cfg`) and upgrade pages (`system_upgrade.asp`, `upgrading.asp`) were found to have global write permissions. These files could potentially be exploited for web service injection attacks or firmware upgrade hijacking, especially if the web server is running with elevated privileges.
- **Keywords:** var/webroot/default.cfg, var/webroot/nvram_default.cfg, var/webroot/system_upgrade.asp, upgrading.asp
- **Notes:** The attack path may include: 1) Uploading malicious configuration files through web vulnerabilities 2) Modifying the upgrade page to inject malicious code 3) Waiting for administrator access to trigger the attack. It is necessary to check whether these files are actually used by the web server.

---
