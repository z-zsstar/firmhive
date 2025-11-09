# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (31 alerts)

---

### command-injection-dhttpd-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `bin/dhttpd:0x34ca0`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The function `REDACTED_PASSWORD_PLACEHOLDER` contains a direct system command execution path through `doSystemCmd` without proper input validation. Attackers could potentially inject malicious commands through WAN error check parameters. This represents a direct command injection vulnerability with high exploit potential.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, doSystemCmd, SetValue, CommitCfm
- **Notes:** command_execution

---
### auth-bypass-cfm-nvram

- **File/Directory Path:** `N/A`
- **Location:** `bin/cfm (multiple locations)`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** The program exposes multiple sensitive operation interfaces (SetValue/GetValue), but no obvious permission check mechanism was found, which may lead to unauthorized access to configuration data.
- **Keywords:** SetValue, GetValue, bcm_nvram_restore
- **Notes:** further analysis of the call chain and parameter validation is required

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hash-shadow

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** authentication
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** etc_ro/shadow, REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** authentication

---
### command-injection-vpn-down

- **File/Directory Path:** `N/A`
- **Location:** `bin/upgrade:0x00008bd0 (sym.vpn_down_connect)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** command_injection
- **Keywords:** doSystemCmd, vpn_down_connect, killall, pptp_callmgr, pptpd, strcmp, GetValue
- **Notes:** This could lead to command injection if NVRAM values used in command construction are attacker-controllable. Further analysis of NVRAM set/get operations is recommended.

---
### goform-interface-risks

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/js/ multiple files`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** A large number of JavaScript files interacting with goform interfaces were discovered in the webroot_ro/js/ directory. These interfaces handle various system operations, including device configuration, system reboots, firmware upgrades, etc. REDACTED_PASSWORD_PLACEHOLDER findings include: 1) Multiple unvalidated user input points were identified; 2) REDACTED_PASSWORD_PLACEHOLDER modification interface (SysToolpassword) and system reboot interface (SysToolReboot) were found potentially exploitable; 3) Direct USB device manipulation interface (setUsbUnload) was detected; 4) Beamforming configuration interface (REDACTED_SECRET_KEY_PLACEHOLDER) was identified as potentially usable for denial-of-service attacks.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, goform/setUsbUnload, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, goform/SetSpeedWan, REDACTED_PASSWORD_PLACEHOLDER, goform/InsertWhite
- **Notes:** It is recommended to further analyze the backend processing logic of the goform interface to verify the existence of vulnerabilities such as command injection. Pay special attention to the security of system reboot and REDACTED_PASSWORD_PLACEHOLDER modification interfaces.

---
### nvram-access-control-dhttpd

- **File/Directory Path:** `N/A`
- **Location:** `bin/dhttpd (multiple locations)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** nvram_set/nvram_get
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** SetValue, GetValue, CommitCfm
- **Notes:** nvram_set/nvram_get

---
### buffer-overflow-cfm-strncpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/cfm:0xa66c-0xa670 (ConnectServer), bin/cfm:0xa4c4-0xa4c8 (InitServer)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the ConnectServer and InitServer functions, an insecure use of strncpy was identified where the destination buffer size is fixed at 0x6b (107 bytes) without checking the length of the source string. An attacker could potentially cause a buffer overflow by supplying an excessively long pathname.
- **Keywords:** strncpy, ConnectServer, InitServer, /var/cfm_socket
- **Notes:** buffer_overflow

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hash-md5

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER account was found to use the MD5 hash algorithm for REDACTED_PASSWORD_PLACEHOLDER storage (indicated by the $1$ identifier), which has been proven insecure and vulnerable to brute-force attacks. If attackers obtain this file, they could retrieve the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER through rainbow tables or brute-force methods.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow
- **Notes:** It is recommended to upgrade the REDACTED_PASSWORD_PLACEHOLDER hashing algorithm to a more secure option such as SHA-512 (identified by $6$). If this is the default REDACTED_PASSWORD_PLACEHOLDER, the risk is even higher and mandatory modification is required.

---
### nginx-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/nginx/conf/nginx.conf:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The nginx service runs with REDACTED_PASSWORD_PLACEHOLDER privileges, posing a privilege escalation risk. Attackers could potentially gain REDACTED_PASSWORD_PLACEHOLDER access by exploiting vulnerabilities in nginx.
- **Keywords:** user REDACTED_PASSWORD_PLACEHOLDER;
- **Notes:** run as a non-privileged user

---
### command-injection-busybox

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:fcn.0002ece0`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A potential **command injection REDACTED_PASSWORD_PLACEHOLDER was identified in the function `fcn.0002ece0`. This function executes the user-controllable string `puVar6` via the `system` function without proper input filtering or validation. Attackers could craft malicious input to inject arbitrary commands, enabling the execution of malicious operations on the system.
- **Code Snippet:**
  ```
  iVar2 = sym.imp.system(puVar6);
  ```
- **Keywords:** system, puVar6, fcn.0002ece0, strcpy, getenv
- **Notes:** Further verification is required to determine whether the source of `puVar6` is entirely user-controlled and whether other filtering mechanisms exist. It is recommended to examine all contexts where `fcn.0002ece0` is called to confirm the feasibility of the attack path.

---
### usb-autorun-mdev

- **File/Directory Path:** `N/A`
- **Location:** `etc/mdev.conf`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The mdev configuration rules define automatic execution scripts (/usr/sbin/usb_up.sh and /usr/sbin/usb_down.sh) for USB device insertion and removal. Improper handling of these scripts may allow code execution triggered by malicious USB devices. Trigger condition: when inserting/removing a USB device.
- **Keywords:** mdev.conf, usb_up.sh, usb_down.sh, autoUsb.sh, DelUsb.sh
- **Notes:** Need to check the security of these USB processing scripts

---
### command-injection-usb_up-cfm_post

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/usb_up.sh:5`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The script accepts a user-supplied parameter `$1` and directly uses it in the `cfm post` command without any validation or filtering. An attacker could potentially inject malicious commands or special characters by controlling the input parameter.
- **Code Snippet:**
  ```
  cfm post netctrl 51?op=1,string_info=$1
  ```
- **Keywords:** $1, cfm post, netctrl, string_info
- **Notes:** Further analysis of the functionalities of `cfm` and `netctrl` is required to determine injection possibilities.

---
### etc_ro-configuration-files

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Multiple critical configuration files were discovered in the etc_ro directory, including system startup scripts (rcS, inittab), user authentication files (REDACTED_PASSWORD_PLACEHOLDER, shadow, group), web server configuration (nginx), device management configuration (udev), and network-related configurations (ppp, iproute2). These files may contain sensitive information or configuration vulnerabilities.
- **Keywords:** etc_ro/REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow, etc_ro/nginx/conf/nginx.conf, etc_ro/init.d/rcS, etc_ro/udev/rules.d/udev.rules, etc_ro/fireversion.cfg, etc_ro/inittab
- **Notes:** Further analysis of specific file contents is required to confirm actual risks. Focus areas include:
1. Default accounts in REDACTED_PASSWORD_PLACEHOLDER/shadow
2. Directory traversal vulnerabilities in nginx configurations
3. Potential command injection in rcS scripts
4. Privilege escalation paths in udev rules

---
### buffer-overflow-nvram-bcm_nvram_set

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x000089b8`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A potential buffer overflow vulnerability was identified in the NVRAM set operation. The program uses strncpy to copy data from user input into a fixed-size buffer (0x10000 bytes) but fails to properly null-terminate the string. An attacker could exploit this by crafting an excessively long parameter to trigger buffer overflow.
- **Code Snippet:**
  ```
  strncpy(dest, src, 0x10000)
  ```
- **Keywords:** bcm_nvram_set, strncpy, 0x10000
- **Notes:** Verify whether the target system has stack protection enabled.

---
### weak-REDACTED_PASSWORD_PLACEHOLDER-hashes-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The `etc_ro/REDACTED_PASSWORD_PLACEHOLDER` file contains multiple user accounts along with their REDACTED_PASSWORD_PLACEHOLDER hashes. These hashes may be vulnerable to brute-force attacks, especially if weak passwords are used. The users listed in the file include REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, and nobody, with the REDACTED_PASSWORD_PLACEHOLDER account possessing the highest privileges.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1, REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U, support:Ead09Ca6IhzZY, user:tGqcT.qjxbEik, nobody:VBcCXSNG7zBAY
- **Notes:** It is recommended to further analyze the strength of these REDACTED_PASSWORD_PLACEHOLDER hashes and check whether any other configuration files or scripts directly reference these accounts. Additionally, verify whether these accounts are actually in use within the system and identify any unnecessary privileged accounts that may exist.

---
### command-injection-formexeCommand

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd (formexeCommand function)`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** command_injection
- **Keywords:** formexeCommand, strcmp, command execution, whitelist validation
- **Notes:** A thorough review of the whitelist validation implementation is required to confirm the possibility of bypass.

---
### auth-bypass-dhttpd-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `bin/dhttpd:0xbc98`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER verification in `REDACTED_PASSWORD_PLACEHOLDER` contains a potential authentication bypass vulnerability through file operations or timing attacks. This function employs multiple conditional checks that could potentially be exploited to circumvent the authentication mechanism.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, fcn.0002bc54
- **Notes:** file_read

---
### privilege-issue-nvram-commit

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x00008ab4`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The NVRAM commit operation does not perform any permission checks or validation, allowing any user to submit NVRAM changes.
- **Code Snippet:**
  ```
  bcm_nvram_commit();
  ```
- **Keywords:** bcm_nvram_commit
- **Notes:** nvram_set

---
### kernel-module-loading-rcS

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The rcS script contains operations for dynamically loading kernel modules, including several network-related modules (fastnat, bm, mac_filter, etc.). Vulnerabilities in these modules could potentially be exploited to escalate privileges or bypass security restrictions. Trigger condition: Automatically executed during system startup.
- **Keywords:** insmod, fastnat.ko, bm.ko, mac_filter.ko, privilege_ip.ko
- **Notes:** Further analysis is required to determine whether these kernel modules contain known vulnerabilities.

---
### nvram-validation-vpn

- **File/Directory Path:** `N/A`
- **Location:** `bin/upgrade:0x00008b30 (sym.vpn_down_connect)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The binary contains multiple NVRAM operations (GetValue, bcm_nvram_match, bcm_nvram_unset) which are used to make security-critical decisions. These operations lack proper validation of the returned values, potentially leading to security bypasses if NVRAM values can be manipulated.
- **Keywords:** GetValue, bcm_nvram_match, bcm_nvram_unset, vpn.cli.type, vpn.cli.l2tpEnable, vpn.cli.pptpEnable, vpn.ser.pptpdEnable
- **Notes:** nvram_get

---
### insecure-firmware-upgrade-cloudv2

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/goform/cloudv2`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The firmware upgrade configuration file (cloudv2) contains version information and upgrade status, but lacks obvious authentication or encryption mechanisms. Attackers could potentially exploit this by spoofing upgrade servers or tampering with upgrade files.
- **Keywords:** cloudv2, ver_info, up_info, newest_ver
- **Notes:** It is recommended to verify the integrity and authentication mechanisms of the firmware upgrade process

---
### cgi-handler-dhttpd-webs_Tenda_CGI_BIN_Handler

- **File/Directory Path:** `N/A`
- **Location:** `bin/dhttpd:0x34a18`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** The CGI handler `webs_Tenda_CGI_BIN_Handler` appears to be a potential attack surface, though decompilation was incomplete. CGI handlers often contain command injection or path traversal vulnerabilities that could be exploited by attackers.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** webs_Tenda_CGI_BIN_Handler, cgi-bin
- **Notes:** Further binary analysis is required to confirm the vulnerability. It may serve as a potential entry point for network-based attacks.

---
### luci-fastcgi-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/nginx/conf/nginx.conf:27-31`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** The path `/cgi-bin/luci/` is configured with FastCGI processing and listens on `127.0.0.1:8188`, which may pose risks of unauthorized access or command injection.
- **Keywords:** location /cgi-bin/luci/, fastcgi_pass 127.0.0.1:8188
- **Notes:** check the security of the FastCGI backend service

---
### busybox-command-execution

- **File/Directory Path:** `N/A`
- **Location:** `Multiple functions including fcn.0001e684, fcn.000238a4, fcn.00021fbc`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** binary_analysis
- **Keywords:** sym.imp.execve, fcn.0001e684, fcn.000238a4, fcn.00021fbc, sym.imp.strcpy, sym.imp.memcpy, /proc/self/exe, ash
- **Notes:** binary_analysis

---
### info-leak-nvram-dump

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x00008b24-0x00008b84`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** dump/show operations expose the complete NVRAM content, potentially leaking sensitive system information.
- **Code Snippet:**
  ```
  bcm_nvram_getall(buffer, 0x10000); puts(buffer);
  ```
- **Keywords:** bcm_nvram_getall, dump, show
- **Notes:** nvram_get

---
### symlink-attack-cfm-socket

- **File/Directory Path:** `N/A`
- **Location:** `bin/cfm:0xa658 (ConnectServer), bin/cfm:0xa4b0 (InitServer)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The program uses a hardcoded socket path '/var/cfm_socket', which may be vulnerable to symlink attacks or path hijacking. Attackers could create malicious socket files to perform man-in-the-middle attacks.
- **Keywords:** /var/cfm_socket, ConnectServer, InitServer
- **Notes:** privilege_escalation

---
### nginx-init-script

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_init.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The nginx initialization script (REDACTED_PASSWORD_PLACEHOLDER_init.sh) is conditionally executed, potentially exposing web interface vulnerabilities if nginx is improperly configured. Trigger condition: when the nginx_init.sh file exists.
- **Keywords:** nginx_init.sh, nginx/conf
- **Notes:** Need to check the nginx configuration and initialization script

---
### web-interface-functions

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The `bin/httpd` binary contains multiple web interface handler functions and CGI paths, primarily involving authentication, system configuration, and network settings. REDACTED_PASSWORD_PLACEHOLDER findings include: 1) Form processing endpoints prefixed with `/goform/` for handling various system configuration operations; 2) Authentication-related functions such as `LoginCheck` and REDACTED_PASSWORD_PLACEHOLDER processing logic; 3) Identification of multiple system command execution points potentially triggered through the web interface. These findings indicate a complete functional chain for system configuration and management via the web interface.
- **Keywords:** LoginCheck, goform, SetSysTimeCfg, SetMacFilterCfg, WifiBasicSet, REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_SECRET_KEY_PLACEHOLDER, formSetIptv
- **Notes:** Further analysis of the specific form processing function implementation is required, particularly focusing on input validation and command execution sections, to determine whether command injection or other security vulnerabilities exist.

---
### fastcgi-path-traversal

- **File/Directory Path:** `N/A`
- **Location:** `etc_REDACTED_PASSWORD_PLACEHOLDER.conf:1`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The FastCGI configuration directly passes user-controllable $document_root and $fastcgi_script_name to the backend, posing a path traversal risk.
- **Keywords:** SCRIPT_FILENAME, $document_root$fastcgi_script_name
- **Notes:** Need to verify how the backend processes these parameters

---
### vpn-service-privilege-issue

- **File/Directory Path:** `N/A`
- **Location:** `bin/upgrade:0x00008c2c (sym.vpn_down_connect)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** privilege_escalation
- **Keywords:** check_app, xl2tpd-server, xl2tpd-clent, REDACTED_PASSWORD_PLACEHOLDER-control, do_file_cmd
- **Notes:** privilege_escalation

---
### command-injection-nvram-strsep

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x000089c0-0x000089e4`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The program uses strsep to parse user input in the 'name=value' format, but fails to validate the length or content of the value after the delimiter, which may lead to command injection.
- **Code Snippet:**
  ```
  strsep(input, "="); bcm_nvram_set(name, value);
  ```
- **Keywords:** strsep, bcm_nvram_set
- **Notes:** Check whether the underlying bcm_nvram_set implementation is secure.

---
