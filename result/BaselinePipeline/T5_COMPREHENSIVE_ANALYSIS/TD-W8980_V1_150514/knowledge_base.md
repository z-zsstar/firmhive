# TD-W8980_V1_150514 (6 alerts)

---

### ftp-vsftpd-weak-creds

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf and etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The `vsftpd.conf` configuration allows local user write permissions (write_enable=YES) with chroot restrictions, but combined with weak credentials in `vsftpd_REDACTED_PASSWORD_PLACEHOLDER` (guest/guest, test/test, REDACTED_PASSWORD_PLACEHOLDER/1234), it forms a complete attack chain. Attackers can exploit these weak credentials via FTP to upload malicious files or gain system access.
- **Keywords:** vsftpd.conf, write_enable, chroot_local_user, vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** It is recommended to disable FTP write permissions or implement strict REDACTED_PASSWORD_PLACEHOLDER policies. Monitor unauthorized FTP logins.

---
### httpd-firmware-upload-vuln

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x406430`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The `/cgi/softup` handler in `usr/bin/httpd` utilizes a fixed-size stack buffer (0xa48 bytes) for upload data without proper length validation, creating a risk of stack overflow. Furthermore, the file name handling lacks sanitization, which could enable path traversal attacks to write files to arbitrary locations.
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, addiu sp, sp, -0xa48, cmem_REDACTED_SECRET_KEY_PLACEHOLDER, cmem_REDACTED_PASSWORD_PLACEHOLDER, sprintf, fcn.00403a2c
- **Notes:** This vulnerability could allow remote code execution via crafted firmware uploads. Recommend implementing strict size checks and file name sanitization.

---
### REDACTED_PASSWORD_PLACEHOLDER-etc-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The `etc/REDACTED_PASSWORD_PLACEHOLDER.bak` file contains REDACTED_PASSWORD_PLACEHOLDER user (REDACTED_PASSWORD_PLACEHOLDER) REDACTED_PASSWORD_PLACEHOLDER hashes using weak MD5 encryption ($1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/). This backup file can be used for offline brute-force attacks to gain administrative access. The presence of such weak hashes significantly lowers the barrier for privilege escalation.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** It is recommended to immediately delete this backup file and enforce a strong REDACTED_PASSWORD_PLACEHOLDER policy for all accounts.

---
### web-js-system-commands

- **File/Directory Path:** `N/A`
- **Location:** `web/js/err.js`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  e_str[CMM_USB_3G_TOO_MANY_ENTRIES] = "Too many entries for USB 3G uploaded commands! max is 4.";
  ```
- **Keywords:** CMM_USB_3G_TOO_MANY_ENTRIES, CMM_ARP_BIND_ADD_SYS_ENTRY_FAILED, err.js
- **Notes:** It is recommended to audit all system command interfaces to ensure the accuracy of input validation and implement strict permission controls.

---
### telnet-unsecured

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The startup script `rcS` enables telnet service (telnetd) without authentication restrictions. Combined with weak credentials found elsewhere, this provides attackers with a direct path to system compromise via unauthenticated remote access.
- **Keywords:** rcS, telnetd
- **Notes:** It is recommended to disable the Telnet service or implement strong authentication mechanisms.

---
### wps-vulnerabilities

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wpa_supplicant`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** vulnerability
- **Keywords:** wps_set_value, wps_get_value, wps_write_wps_data, wps_parse_wps_data, WPS Error: Invalid REDACTED_PASSWORD_PLACEHOLDER, wps_enable: Bad checksum on REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to disable WPS in device configuration and switch to WPA2/3 with a strong REDACTED_PASSWORD_PLACEHOLDER set.

---
