# TD-W8980_V1_150514 (38 alerts)

---

### telnet-service-exposure

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:50`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The insecure telnet service (telnetd) is enabled by default, making it vulnerable to man-in-the-middle attacks and REDACTED_PASSWORD_PLACEHOLDER sniffing, providing direct unencrypted system access.
- **Keywords:** telnetd
- **Notes:** It is strongly recommended to disable telnet and switch to SSH.

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** MD5 encrypted REDACTED_PASSWORD_PLACEHOLDER of the REDACTED_PASSWORD_PLACEHOLDER user with REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0) was found in `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`. The MD5 encryption method is vulnerable to brute-force attacks, especially when REDACTED_PASSWORD_PLACEHOLDER strength is insufficient.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** etc/REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$, MD5
- **Notes:** Verify whether the credentials from this backup file are still in use in the current system

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER.bak file revealed that the REDACTED_PASSWORD_PLACEHOLDER account has a weak REDACTED_PASSWORD_PLACEHOLDER hash (MD5 hash starting with $1$) and possesses REDACTED_PASSWORD_PLACEHOLDER privileges (UID=0). Attackers could potentially obtain REDACTED_PASSWORD_PLACEHOLDER access through REDACTED_PASSWORD_PLACEHOLDER cracking.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/, REDACTED_PASSWORD_PLACEHOLDER.bak
- **Notes:** It is recommended to check whether the system is still using this backup file as an authentication basis and enforce changing the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER to a strong one.

---
### ftp-plaintext-creds

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.5
- **Confidence:** 9.25
- **Description:** Plaintext FTP credentials were found in `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`, including weak passwords such as REDACTED_PASSWORD_PLACEHOLDER(1234), guest(guest), and test(test). These credentials could potentially be used directly for FTP service authentication.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** plaintext REDACTED_PASSWORD_PLACEHOLDER storage is a serious security violation, immediate change is recommended

---
### telnetd-service-exposure

- **File/Directory Path:** `N/A`
- **Location:** `System services`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The system initiates the telnetd service, exposing an unencrypted management interface, which poses a severe security risk.
- **Keywords:** telnetd
- **Notes:** should be considered a high-risk exposure point and is recommended to be disabled immediately

---
### WPS-REDACTED_PASSWORD_PLACEHOLDER-validation-rate-limiting

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** WPS REDACTED_PASSWORD_PLACEHOLDER validation lacks proper rate limiting mechanisms, making brute-force attacks feasible. The checksum validation (fcn.004350f8) uses simple modulo 10 operation without attempt counters or lockout periods. This vulnerability could allow attackers to brute-force the WPS REDACTED_PASSWORD_PLACEHOLDER, leading to unauthorized access to the network.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** fcn.004350f8, strtoul, modulo 10, wps_lock_pin
- **Notes:** network_input

---
### unverified-file-upload

- **File/Directory Path:** `N/A`
- **Location:** `web/main/softup.htm, REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple unverified file upload endpoints have been identified, including firmware upgrade (/cgi/softup) and 3G configuration file upload (/cgi/usb3gup), which utilize multipart/form-data encoding and may potentially allow attackers to upload malicious files.
- **Keywords:** /cgi/softup, /cgi/usb3gup, enctype="multipart/form-data"
- **Notes:** Need to confirm the permission verification mechanism of the CGI program

---
### telnetd-REDACTED_PASSWORD_PLACEHOLDER-env

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x004411f8`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The telnetd service uses a hardcoded 'USER=REDACTED_PASSWORD_PLACEHOLDER' environment variable, which may lead to authentication bypass. When telnetd starts, it automatically sets the user to REDACTED_PASSWORD_PLACEHOLDER, potentially bypassing the normal authentication process.
- **Keywords:** USER=REDACTED_PASSWORD_PLACEHOLDER, telnetd_main
- **Notes:** authentication_bypass

---
### hardcoded-3g-passwords

- **File/Directory Path:** `N/A`
- **Location:** `web/js/3g.js`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The web/js/3g.js file contains numerous hardcoded 3G network authentication credentials. These passwords are stored in plaintext within client-side JavaScript, potentially allowing attackers to gain unauthorized access to 3G network services.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, 3g.js, clarogprs999, gprs, internet, web, 1234
- **Notes:** These credentials appear to be preset 3G connection credentials for different carriers. It is recommended to remove the hardcoded passwords and require user input.

---
### httpd-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x401ca0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple unvalidated strcpy calls were identified in the fcn.00401ca0 function, potentially leading to buffer overflow vulnerabilities. This function handles device information retrieval requests, using a fixed-size stack buffer (0xfa0 bytes) without performing input length validation.
- **Keywords:** fcn.00401ca0, sym.imp.strcpy, var_fd0h, 0x401cf4, 0x401d4c, 0x401d78
- **Notes:** Verify whether the buffer size is sufficient and whether these strcpy calls could be influenced by user input

---
### httpd-unsafe-string-ops

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple unsafe strcpy calls were detected, lacking boundary checks when handling global variables, which may lead to buffer overflow vulnerabilities.
- **Keywords:** strcpy, 0x41e8f0, 0x41e9f0
- **Notes:** Need to confirm whether these operations handle user-controllable input

---
### telnet-service-enabled

- **File/Directory Path:** `N/A`
- **Location:** `Startup scripts`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** The script enables the telnet service (telnetd) by default, which is an insecure plaintext protocol that may lead to REDACTED_PASSWORD_PLACEHOLDER leakage.
- **Keywords:** telnetd
- **Notes:** It is recommended to disable telnet or replace it with SSH.

---
### device-info-leakage

- **File/Directory Path:** `N/A`
- **Location:** `XML config files`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The XML configuration file exposes detailed device information, including manufacturer, model, and firmware version. Attackers can exploit this information to conduct targeted attacks.
- **Keywords:** default_config.xml, reduced_data_model.xml, Manufacturer, ModelName, SoftwareVersion
- **Notes:** It is recommended to restrict access to these configuration files

---
### command-injection-fcn.00401ad8

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos:0x401ad8`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** A command injection vulnerability was discovered in the fcn.00401ad8 function. The unvalidated output of the ps command is executed via system() and written to the temporary file /var/tmp/pslist. Attackers could potentially influence command execution by controlling process names or environment variables.
- **Code Snippet:**
  ```
  system("ps > /var/tmp/pslist");
  ...
  system("rm /var/tmp/pslist");
  ```
- **Keywords:** system, ps > /var/tmp/pslist, rm /var/tmp/pslist
- **Notes:** It is necessary to examine the context in which this function is called to determine whether user-controllable input affects command execution.

---
### REDACTED_PASSWORD_PLACEHOLDER-mgmt-issues

- **File/Directory Path:** `N/A`
- **Location:** `Multiple locations`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The system has issues with improper REDACTED_PASSWORD_PLACEHOLDER management, including the use of backup REDACTED_PASSWORD_PLACEHOLDER files and storing service passwords in plaintext. These files could be exploited by attackers to gain system access.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, vsftpd_REDACTED_PASSWORD_PLACEHOLDER, HIDDEN
- **Notes:** Review all REDACTED_PASSWORD_PLACEHOLDER storage mechanisms

---
### REDACTED_PASSWORD_PLACEHOLDER-file-exposure

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:14`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Directly copying REDACTED_PASSWORD_PLACEHOLDER.bak to /var/REDACTED_PASSWORD_PLACEHOLDER may lead to REDACTED_PASSWORD_PLACEHOLDER file disclosure. If REDACTED_PASSWORD_PLACEHOLDER.bak contains sensitive information, it could be exploited by attackers for privilege escalation.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to check the contents of REDACTED_PASSWORD_PLACEHOLDER.bak and delete this operation

---
### httpd-format-string

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Multiple sprintf calls were found using user-controllable format parameters, which may lead to format string vulnerabilities or buffer overflows.
- **Keywords:** sprintf, auStack_218, auStack_418
- **Notes:** Analyze the source of the formatted string

---
### wps-property-parser

- **File/Directory Path:** `N/A`
- **Location:** `0x0040925c (fcn.0040333c)`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The WPS property parser lacks proper validation when processing configurations, and fails to perform explicit boundary checks for quoted strings and attribute values, thereby posing potential injection vulnerability risks.
- **Keywords:** fcn.0040333c, wps_property, puVar4, uStack_240
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER vulnerabilities related to WPS in network authentication

---
### insecure-directory-permissions

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:4-8`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The script creates multiple directories (/var/lock, /var/log, etc.) with 0777 permissions, potentially introducing privilege escalation risks. Attackers could exploit these overly permissive permissions for file tampering or persistence attacks.
- **Keywords:** /bin/mkdir -m 0777, /var/lock, /var/log, /var/run, /var/tmp
- **Notes:** Set directory permissions to a more restrictive mode, such as 0755.

---
### default-usb-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The default REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' was found hardcoded in REDACTED_PASSWORD_PLACEHOLDER.htm, potentially allowing unauthorized access to USB sharing functionality.
- **Keywords:** userList[0].REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Enforce users to change default passwords upon first use.

---
### insecure-directory-permissions

- **File/Directory Path:** `N/A`
- **Location:** `Startup scripts`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The startup script created multiple directories (/var/lock, /var/log, etc.) with 0777 permissions, potentially introducing privilege escalation risks. Attackers could create or modify files within these directories, compromising system stability or security.
- **Keywords:** /bin/mkdir -m 0777, /var/lock, /var/log, /var/run, /var/tmp
- **Notes:** Set directory permissions to a more restrictive mode, such as 0755.

---
### WPS-REDACTED_PASSWORD_PLACEHOLDER-checksum-bypass

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** REDACTED_PASSWORD_PLACEHOLDER checksum validation vulnerable to predictable checksum bypass. The checksum calculation at 0x0043516c-0xREDACTED_PASSWORD_PLACEHOLDER doesn't use cryptographic operations. This makes the WPS REDACTED_PASSWORD_PLACEHOLDER vulnerable to offline attacks, similar to known WPS offline REDACTED_PASSWORD_PLACEHOLDER attacks.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** checksum validation, modulo operation, fcn.004350f8
- **Notes:** Similar to known WPS offline REDACTED_PASSWORD_PLACEHOLDER attacks

---
### config-backup-restore

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The configuration backup/restore endpoints (/cgi/conf.bin and /cgi/confup) may allow attackers to obtain or modify device configurations, and the restore functionality could potentially be exploited to inject malicious configurations.
- **Keywords:** /cgi/conf.bin, /cgi/confup, backNRestore.htm
- **Notes:** Configuration backups may contain sensitive information such as passwords.

---
### buffer-overflow-fcn.00401ad8

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos:0x401b7c`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** A buffer overflow vulnerability was identified in the function fcn.00401ad8. The strcpy function copies the process name into a fixed-size stack buffer (auStack_320[256]) without performing length validation.
- **Code Snippet:**
  ```
  strcpy(auStack_320,*piVar5);
  ```
- **Keywords:** strcpy, auStack_320, fgets
- **Notes:** Verify whether the source of piVar5 is controllable and its maximum possible length

---
### config-parser-input-validation

- **File/Directory Path:** `N/A`
- **Location:** `0xREDACTED_PASSWORD_PLACEHOLDER (fcn.0040405c)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** configuration_load
- **Keywords:** fcn.0040405c, fcn.REDACTED_PASSWORD_PLACEHOLDER, auStack_13c, auStack_23c
- **Notes:** configuration_load

---
### route-config-injection

- **File/Directory Path:** `N/A`
- **Location:** `etc/hotplug.d/iface/10-routes`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The script handles route configuration through direct `config_get` calls without proper input validation, allowing potential injection of malicious route configurations if an attacker controls the configuration source. Parameters like target, netmask, gateway are processed without sanitization before being passed to `/sbin/route`.
- **Keywords:** add_route, config_get, target, netmask, gateway, metric, mtu, /sbin/route
- **Notes:** configuration_load

---
### httpd-external-data

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** The critical function rdp_getObj retrieves data from external sources but lacks sufficient validation, potentially introducing untrusted data that could compromise program logic.
- **Keywords:** rdp_getObj, IGD_DEV_INFO
- **Notes:** track data flow paths

---
### ftp-service-risks

- **File/Directory Path:** `N/A`
- **Location:** `vsftpd.conf`
- **Risk Score:** 7.0
- **Confidence:** 8.25
- **Description:** The FTP service configuration poses potential security risks: 1) Allows local users to write (write_enable=YES) 2) Enables ASCII mode transfer (ascii_upload_enable=YES) 3) Limits maximum connections to only 2 (max_clients=2), which may lead to DoS attacks.
- **Keywords:** vsftpd.conf, write_enable, ascii_upload_enable, max_clients
- **Notes:** It is recommended to disable ASCII mode transfer and restrict write permissions

---
### missing-csrf-protection

- **File/Directory Path:** `N/A`
- **Location:** `web/js/lib.js`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The generic AJAX call implementation lacks an apparent CSRF protection mechanism, potentially exposing all endpoints to CSRF attack risks.
- **Keywords:** $.ajax(, hook(data)
- **Notes:** It is recommended to check for the presence of other CSRF protection mechanisms such as REDACTED_PASSWORD_PLACEHOLDER verification.

---
### cos-httpd-integration

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The system integrates web service functionality through a COS binary program, replacing the traditional cgi-bin directory architecture. This program includes HTTPD service capabilities and may be a primary target for attacks.
- **Keywords:** cos, httpd, /var/tmp/pc/
- **Notes:** Reverse engineer the COS binary to identify potential web service vulnerabilities.

---
### base64-auth-cookie

- **File/Directory Path:** `N/A`
- **Location:** `web/frame/login.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** In web/frame/login.htm, HTTP basic authentication credentials encoded in Base64 were found stored in cookies, which may lead to session hijacking risks.
- **Keywords:** auth, Base64Encoding, document.cookie, Authorization
- **Notes:** Base64 is not encryption, merely encoding; it is recommended to use more secure session management methods.

---
### vsftpd-local-access

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The configuration of vsftpd enabling local user access (local_enable=YES) and write permissions (write_enable=YES), combined with chroot restrictions, may still lead to privilege escalation or filesystem access risks.
- **Keywords:** local_enable, write_enable, chroot_local_user
- **Notes:** Check the system for local accounts with weak passwords or default credentials

---
### WPS-push-button-abuse

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Push button mode can be abused for unauthorized access when combined with other weaknesses. The function at 0x00435d78 shows push-button restrictions but lacks proper state verification. This could lead to WPS registrar impersonation attacks.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** fcn.0043583c, WPS_push_button, configme
- **Notes:** may lead to WPS registrar emulation attacks

---
### kernel-module-loading

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:28-43`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Multiple kernel modules (such as usb-storage.ko, nf_conntrack_pptp.ko, etc.) were loaded, increasing the kernel attack surface. Vulnerabilities in these modules could be exploited for privilege escalation.
- **Keywords:** insmod, usb-storage.ko, nf_conntrack_pptp.ko, ifxusb_host.ko
- **Notes:** Evaluate the necessity of module loading

---
### busybox-login-analysis

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Initial analysis of BusyBox login functionality reveals multiple security points requiring in-depth validation: 1) REDACTED_PASSWORD_PLACEHOLDER handling in authentication logic 2) Input validation for REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER fields 3) Session management mechanism 4) Potential privilege escalation paths. Multiple critical string references identified but require further cross-analysis.
- **Keywords:** /bin/login, /etc/issue, /etc/motd, REDACTED_PASSWORD_PLACEHOLDER login, Login incorrect
- **Notes:** The specific functions that reference these strings need to be analyzed to confirm the actual vulnerability. Hardcoded paths suggest potential configuration issues.

---
### telnetd-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Potential buffer overflow risks were identified due to the use of unsafe string functions such as strcpy. Overflow may be triggered when processing long REDACTED_PASSWORD_PLACEHOLDERs or passwords.
- **Keywords:** strcpy, malloc
- **Notes:** Further analysis of the input point is required to confirm exploitability.

---
### unverified-cgi-handlers

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** During HTTPd initialization, multiple CGI processing paths (such as /cgi/softup, /cgi/conf.bin, etc.) were registered, but the specific handler functions could not be located. These paths may handle sensitive operations such as firmware updates.
- **Keywords:** sym.http_init_main, /cgi/softup, /cgi/conf.bin, fcn.004056cc
- **Notes:** Dynamic analysis or more in-depth disassembly is required to determine these CGI handling functions.

---
### blob-base64-processing

- **File/Directory Path:** `N/A`
- **Location:** `0x00408a48`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** configuration_load
- **Keywords:** blob-base64-, fcn.004026d0, iVar7, iVar2
- **Notes:** Memory handling vulnerabilities in binary data processing

---
