# TL-WA701ND_V2_140324 (26 alerts)

---

### file_permission-etc_REDACTED_PASSWORD_PLACEHOLDER-777

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Insecure permissions detected on REDACTED_PASSWORD_PLACEHOLDER file - set to 777 (rwxrwxrwx). This allows any user to modify this critical system file, potentially enabling privilege escalation attacks. Attackers could add or modify user accounts, particularly by creating accounts with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Keywords:** etc/REDACTED_PASSWORD_PLACEHOLDER, rwxrwxrwx
- **Notes:** The file permissions should be immediately changed to 644 (rw-r--r--).

---
### eapol_vulnerability-wpa_sm_rx_eapol

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wpa_supplicant:0x0041fbdc`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Multiple security vulnerabilities were identified in the EAPOL frame processing within the `wpa_sm_rx_eapol` function. This function handles EAPOL REDACTED_PASSWORD_PLACEHOLDER frames during 802.1X authentication and contains potential integer overflow, buffer overflow, and improper encryption REDACTED_PASSWORD_PLACEHOLDER handling issues. Particularly noteworthy is the insecure processing of the `key_data` field.
- **Keywords:** wpa_sm_rx_eapol, EAPOL, key_data, memcpy, memcmp
- **Notes:** authentication_vulnerability

---
### privilege_escalation-multiple_root_accounts

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.75
- **Description:** The system has been found to contain multiple accounts with UID 0 (REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER), and a custom user ap71 also possesses REDACTED_PASSWORD_PLACEHOLDER privileges. This violates the principle of least privilege and expands the attack surface. Attackers could leverage these accounts for lateral movement and privilege escalation.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:x:0:0, REDACTED_PASSWORD_PLACEHOLDER:x:0:0, ap71:x:500:0
- **Notes:** Remove unnecessary REDACTED_PASSWORD_PLACEHOLDER privilege accounts and assign regular user permissions to the ap71 account.

---
### service-privilege-rcS-httpd

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The rcS script contains potential security issues: 1) Starting the httpd service with REDACTED_PASSWORD_PLACEHOLDER privileges (/usr/bin/httpd &), which could lead to complete system compromise if httpd has vulnerabilities; 2) Mounting /tmp and /var as ramfs may result in sensitive information leakage or denial of service; 3) Network interface configuration lacks security restrictions (ifconfig lo 127.0.0.1 up).
- **Keywords:** mount -t ramfs, /usr/bin/httpd, ifconfig lo
- **Notes:** The HTTP service should be started using a non-privileged user, and the ramfs mount should be configured with appropriate permission restrictions.

---
### authentication-weak_password_hash-root_admin

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1-2`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** It was discovered that both the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER users share the same weak MD5 hashed REDACTED_PASSWORD_PLACEHOLDER (prefixed with $1$). MD5 hashing is known to be vulnerable to collision and rainbow table attacks. Attackers could obtain plaintext passwords through offline cracking. The use of identical passwords for two privileged accounts increases the risk of lateral movement.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$
- **Notes:** It is recommended to enforce the use of strong passwords and switch to SHA-512 hashing (prefix $6$)

---
### web-xss-menujs-document.write

- **File/Directory Path:** `N/A`
- **Location:** `web/dynaform/menu.js`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** Reflected XSS vulnerability in menu.js via unescaped document.write using user-controllable menuList parameters
- **Keywords:** menuList, document.write, menuDisplay
- **Notes:** It is necessary to verify whether the menuList parameter comes directly from HTTP request parameters and whether there are other similar patterns of document.write usage.

---
### command_execution-BusyBox-fcn.0041ad5c

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x41ad5c`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The function fcn.0041ad5c in BusyBox contains critical command execution paths through execve system calls. Multiple execve calls are made with user-controlled arguments (0x41ae58, 0x41aec4). Error conditions are checked including E2BIG (argument list too long), ENOMEM (memory exhausted), ENOEXEC (cannot execute), and ENOENT (not found). Fallback to default shell (/bin/sh) is implemented when initial execution fails. The function handles path manipulation and argument processing. Potential security implications include command injection risks if arguments are not properly sanitized, path traversal vulnerabilities if path handling is insecure, memory corruption risks in argument processing, and shell injection if default shell fallback is triggered with untrusted input.
- **Code Snippet:**
  ```
  0x0041ae50      8f9985c0       lw t9, -sym.imp.execve(gp)
  0x0041ae58      0320f809       jalr t9
  0x0041aebc      8c440000       lw a0, (v0)
  0x0041aec4      0320f809       jalr t9
  ```
- **Keywords:** fcn.0041ad5c, sym.imp.execve, bb_default_login_shell, bb_msg_memory_exhausted, argument_list_too_long, no_Shell, cannot_execute, not_found
- **Notes:** command_execution

---
### web-xss-commonjs-innerHTML

- **File/Directory Path:** `N/A`
- **Location:** `web/dynaform/common.js:HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Multiple instances of unvalidated innerHTML usage were found in the web/dynaform/common.js file, directly inserting the content of str_pages[page][tag] into the DOM. Attackers could potentially inject malicious scripts by controlling the page or tag parameters, leading to cross-site scripting (XSS) vulnerabilities. These operations occur in dynamic content loading functions, affecting all pages that utilize these functions.
- **Code Snippet:**
  ```
  items[i].innerHTML = str_pages[page][tag];
  obj.getElementById(tag).innerHTML = str_pages[page][tag];
  ```
- **Keywords:** innerHTML, str_pages, getElementById, common.js
- **Notes:** Further analysis is required to determine the source of the str_pages data and how the page/tag parameters are controlled, verifying whether they can be influenced by external input. It is recommended to inspect all pages that call these functions.

---
### service-httpd_root_privilege

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS:24`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Starting the httpd service directly in the rcS script without specifying user privileges may cause the service to run with REDACTED_PASSWORD_PLACEHOLDER permissions. If vulnerabilities exist in httpd, attackers could potentially gain REDACTED_PASSWORD_PLACEHOLDER access.
- **Keywords:** /usr/bin/httpd
- **Notes:** It is recommended to run the httpd service using a non-privileged user.

---
### buffer_overflow-wlanconfig-strncpy

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wlanconfig:0x0040254c`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The program uses unsafe string manipulation functions such as strncpy, which may lead to buffer overflow. Specifically, when handling the device name (wlandev) and mode parameter (wlanmode), there is no validation of the destination buffer size.
- **Keywords:** strncpy, wlandev, wlanmode, var_68h, var_4ch
- **Notes:** Attackers may trigger a buffer overflow by providing excessively long device names or mode parameters.

---
### wps_vulnerability-wps_parse_wps_ie

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wpa_supplicant:0x0042c360`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** A potential vulnerability was identified in the `wps_parse_wps_ie` function regarding the parsing of WPS information. This function processes WPS information elements in wireless networks but fails to adequately validate the length and format of input data, which may lead to memory corruption or information leakage.
- **Keywords:** wps_parse_wps_ie, WPS, ie, memcpy
- **Notes:** The WPS protocol is known to have security vulnerabilities, and it is recommended to disable the WPS feature.

---
### attack-path-web-to-wireless

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Attack path analysis: Injecting malicious environment variables through the web interface (httpd) → affecting wireless module configuration (rc.wlan) → bypassing wireless security restrictions or enabling illegal channels. Alternatively, exploiting the temporary network window opened by iptables-stop to conduct attacks.
- **Keywords:** /usr/bin/httpd, ATH_countrycode, iptables-stop
- **Notes:** The complete attack path requires further validation of the actual interaction methods between components.

---
### kernel-modules-wireless-drivers

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/2.6.31/net`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** In the directory `lib/modules/2.6.31/net`, Atheros wireless network drivers and protocol stack modules were discovered, including: adf.ko, ag7240_mod.ko, art.ko, asf.ko, ath_dev.ko, ath_hal.ko, ath_pktlog.ko, ath_rate_atheros.ko, and umac.ko. These modules handle critical functions of wireless network communication and may include network protocol implementations and hardware interface drivers. Further analysis of these modules is required to identify potential security vulnerabilities, particularly in REDACTED_PASSWORD_PLACEHOLDER functionalities such as network packet processing, rate control, and hardware abstraction layer interfaces.
- **Keywords:** adf.ko, ag7240_mod.ko, art.ko, asf.ko, ath_dev.ko, ath_hal.ko, ath_pktlog.ko, ath_rate_atheros.ko, umac.ko
- **Notes:** It is recommended to subsequently use binary analysis tools (such as Radare2) to reverse engineer these kernel modules, with a focus on critical functionalities such as network packet processing, rate control, and hardware abstraction layer interfaces. Particular attention should be paid to checking for common vulnerability types such as buffer overflows, integer overflows, and insufficiently validated input handling.

---
### command_execution-BusyBox-path_traversal

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x41ae50,0x41aec4`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** Two execve calls were identified in function 0x41ad5c, which handles path concatenation and execution logic. There is a potential path traversal risk, where user-controlled path parameters could lead to arbitrary command execution through specially crafted paths.
- **Keywords:** execve, fcn.0041ad5c, path concatenation
- **Notes:** Further verification is required to ensure the parameter source is fully controllable. Check if there are any unfiltered user inputs in the call chain.

---
### filesystem-ramfs_mount_issue

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS:8-9`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Mounting ramfs directly to /tmp and /var directories in the rcS script may lead to sensitive data leakage. ramfs does not utilize swap space and has no size limit, which could be exploited to exhaust system memory. Attackers may cause system crashes by writing large amounts of data to /tmp or /var.
- **Keywords:** mount -t ramfs, /tmp, /var
- **Notes:** It is recommended to use tmpfs instead of ramfs and set an appropriate size limit

---
### wireless-config-rc.wlan

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rc.wlan`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The rc.wlan script controls wireless module parameters through environment variables (DFS_domainoverride, ATH_countrycode, etc.). If these variables can be externally manipulated (e.g., via web interface), it may lead to bypassing wireless security configurations. Special attention should be paid to: 1) Support for demo channels (country code 0x1ff); 2) Ability to override regulatory domain settings (DFS_domainoverride).
- **Keywords:** DFS_domainoverride, ATH_countrycode, countrycode=0x1ff
- **Notes:** It is necessary to verify the input sources and filtering mechanisms of all wireless-related environment variables.

---
### account-suspicious_ap71_account

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:13`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** A non-standard user account 'ap71' exists without a REDACTED_PASSWORD_PLACEHOLDER set. This unknown account could be a backdoor or a leftover test account, posing a potential exploitation risk.
- **Keywords:** ap71
- **Notes:** backdoor_suspicion

---
### buffer_overflow-wpa_config_read

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wpa_supplicant:0x00408e28`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the `wpa_config_read` function, unsafe string handling operations were identified during configuration file parsing. Potential buffer overflow risks exist, particularly when processing configuration items such as `network={` and `blob-base64-`, due to insufficient boundary checks. Attackers could trigger overflows by crafting malicious configuration files.
- **Keywords:** wpa_config_read, network={, blob-base64-, strcpy, strncpy
- **Notes:** Further verification is required to confirm whether all configuration items have undergone appropriate boundary checks.

---
### input_validation-wlanconfig-commands

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wlanconfig:0x004024b0 main`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Multiple potential input validation vulnerabilities were identified in the wlanconfig program. The program processes user-input commands and parameters using strncasecmp and strcmp functions, but fails to perform adequate boundary checking. Particularly when handling commands such as 'create', 'destroy', and 'list', it may be vulnerable to command injection attacks.
- **Keywords:** strncasecmp, strcmp, create, destroy, list, wlanmode, wlandev
- **Notes:** Further validation is required to determine whether buffer overflow or other memory corruption vulnerabilities can be triggered through carefully crafted input parameters.

---
### environment_variable-BusyBox-PATH_injection

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** It was discovered that BusyBox poses a risk of environment variable injection when processing shell commands, particularly where the PATH environment variable could be tampered with, potentially leading to the execution of malicious binaries.
- **Keywords:** PATH, execve, environment variables
- **Notes:** It is recommended to inspect all environment variable handling logic, particularly the cleanup of environment variables during privileged operations.

---
### httpd-privilege-issue

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS:25`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** service_configuration
- **Keywords:** /usr/bin/httpd
- **Notes:** service_configuration

---
### web-xss-commonjs-innerHTML

- **File/Directory Path:** `N/A`
- **Location:** `web/dynaform/common.js`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** web_vulnerability
- **Keywords:** innerHTML, str_pages, setTagStr
- **Notes:** The text requires analyzing the data source of str_pages and the calling context of the setTagStr function.

---
### crypto_weakness-md5_rc4

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wpa_supplicant:0x0042cb50, 0x0042c8b0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The code employs insecure cryptographic operations, including the direct use of MD5 and RC4 algorithms, which are known to have security vulnerabilities. This is particularly evident in the `md5_vector` and `rc4` function calls, potentially compromising overall security.
- **Keywords:** md5_vector, rc4, aes_encrypt, aes_decrypt
- **Notes:** Consider upgrading to more secure encryption algorithms, such as SHA-256 and AES-GCM.

---
### kernel-modules-rc.modules

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rc.modules`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The rc.modules script loads a large number of kernel modules, including network filtering (iptables), QoS, and VPN-related modules. There are module dependency risks: 1) If any module contains vulnerabilities, it could lead to privilege escalation; 2) Non-standard modules such as harmony.ko are loaded, potentially introducing unknown risks; 3) Support for outdated VPN protocols like PPTP/L2TP may expose known vulnerabilities.
- **Keywords:** insmod, harmony.ko, pptp.ko, pppol2tp.ko
- **Notes:** Audit all loaded kernel module versions and check for known CVEs

---
### kernel-suspicious_modules

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rc.modules:multiple`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The rc.modules script loads a large number of kernel modules, including network filtering, QoS, and others. If these modules contain vulnerabilities, attackers could potentially exploit them for privilege escalation or network attacks. In particular, non-standard modules such as harmony.ko and wlan_warn.ko may have unknown vulnerabilities.
- **Keywords:** insmod, harmony.ko, wlan_warn.ko
- **Notes:** Review all loaded kernel modules, especially non-standard ones

---
### ioctl-vulnerability-wlanconfig

- **File/Directory Path:** `N/A`
- **Location:** `sbin/wlanconfig:0x004028f4`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The program uses the ioctl system call to interact with the wireless driver but fails to adequately validate the ioctl return values and parameters. Certain ioctl operations (such as 0x89f7, 0x89f8, 0x89fe) may be susceptible to misuse.
- **Keywords:** ioctl, 0x89f7, 0x89f8, 0x89fe, IEEE80211_IOCTL_GETPARAM
- **Notes:** It is necessary to check whether the driver has implemented adequate security checks for these ioctl commands.

---
