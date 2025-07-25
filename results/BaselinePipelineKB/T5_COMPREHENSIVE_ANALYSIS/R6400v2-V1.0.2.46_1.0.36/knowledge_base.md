# R6400v2-V1.0.2.46_1.0.36 (25 alerts)

---

### buffer_overflow-eapd-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/eapd:0x000090e4 fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** At address 0x000090e4, an unsafe strcpy call was detected, copying the contents of the src buffer to the dest buffer without length checking. The dest buffer (r6) has a size of 0x40 bytes (defined at 0x0000909c), while the src buffer content may exceed this size, resulting in a buffer overflow. An attacker could potentially control the src content to overwrite adjacent memory and execute arbitrary code.
- **Code Snippet:**
  ```
  0x000090e0 mov r0, r6 ; char *dest
  0x000090e4 bl sym.imp.strcpy
  ```
- **Keywords:** strcpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, r6, src, eapd
- **Notes:** Further confirmation is required to determine whether the src buffer originates from externally controllable input. If src is sourced from network or user input, the vulnerability can be exploited remotely.

---
### nvram-command_injection-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The `acos_service` binary implements NVRAM functionality, containing multiple critical operation functions such as `acosNvramConfig_get/set/unset/match`, etc. There exists a code path that directly calls `system()` to execute commands, potentially leading to command injection through NVRAM parameter injection. Multiple NVRAM operations lack input validation, such as `acosNvramConfig_set` directly using user-controllable parameters.
- **Keywords:** acosNvramConfig_get, acosNvramConfig_set, acosNvramConfig_unset, acosNvramConfig_match, acosNvramConfig_save, system, _eval, acos_service
- **Notes:** Verify how NVRAM parameters are input externally and the specific purposes of each NVRAM configuration item.

---
### command_injection-rc-nvram_system

- **File/Directory Path:** `N/A`
- **Location:** `sbin/rc:fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** It was discovered that NVRAM data is directly used to construct system commands and executed via system(), posing a command injection risk. In function fcn.REDACTED_PASSWORD_PLACEHOLDER, multiple NVRAM values are directly concatenated into command strings without proper validation or escaping. Attackers could potentially inject malicious commands by modifying NVRAM values.
- **Keywords:** nvram_get, system, sprintf, fcn.REDACTED_PASSWORD_PLACEHOLDER, rc
- **Notes:** It is necessary to verify that all values obtained using nvram_get are properly validated, especially when constructing system commands.

---
### ssrf-genie.cgi-curl

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x000097f8`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In function fcn.REDACTED_PASSWORD_PLACEHOLDER, unvalidated user input was found to be passed to an external URL via curl_easy_setopt, which may lead to Server-Side Request Forgery (SSRF) attacks. Attackers could control the target URL of the request, resulting in internal network probing or data leakage.
- **Code Snippet:**
  ```
  bl sym.imp.curl_easy_setopt
  ```
- **Keywords:** curl_easy_setopt, curl_easy_perform, var_3ch, genie.cgi
- **Notes:** Verify that URL input is strictly filtered

---
### buffer_overflow-utelnetd-ptsname_strcpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/utelnetd:0x95cc fcn.000090a4`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** An unverified strcpy call was found in function fcn.000090a4, used to copy pseudo-terminal device names (return value of ptsname). Since the target buffer size is not checked, this may lead to a buffer overflow vulnerability. Attackers could exploit this vulnerability by controlling the length of the pseudo-terminal device name.
- **Code Snippet:**
  ```
  uVar4 = sym.imp.ptsname(puVar15);
  sym.imp.strcpy(ppuVar3 + 5,uVar4);
  ```
- **Keywords:** sym.imp.strcpy, sym.imp.ptsname, fcn.000090a4, utelnetd
- **Notes:** Further verification is required regarding the target buffer size and the possibility of an attacker controlling the return value of ptsname.

---
### memory_corruption-wol-string_ops

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/wol`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The program uses unsafe string manipulation functions (strcpy/strncpy) to process network and configuration data, presenting typical memory corruption risks. These functions are called in multiple locations without proper boundary checks.
- **Keywords:** strcpy, strncpy, memcpy, main, send_wol, wol
- **Notes:** It is recommended to check the buffer size at all call points

---
### command_injection-rc-nvram_eval

- **File/Directory Path:** `N/A`
- **Location:** `sbin/rc:fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple instances of eval calls using NVRAM data as parameters were found, which may lead to command injection. In function fcn.REDACTED_PASSWORD_PLACEHOLDER, NVRAM values are directly passed to the _eval function, which could potentially execute system commands.
- **Keywords:** _eval, nvram_get, fcn.REDACTED_PASSWORD_PLACEHOLDER, rc
- **Notes:** The specific implementation of the _eval function requires further analysis to confirm its security.

---
### nvram_tampering-remote.sh-url_config

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/remote.sh`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple NVRAM configuration operations were identified in the remote.sh script, including settings for remote service URLs and firewall configurations. These configurations could potentially be exploited by attackers to alter device behavior or redirect traffic. Notably, URL settings such as leafp2p_replication_url and leafp2p_remote_url could be tampered with, causing the device to connect to malicious servers.
- **Keywords:** leafp2p_replication_url, leafp2p_remote_url, leafp2p_firewall, leafp2p_service_0, nvram, remote.sh
- **Notes:** Permission control for NVRAM settings needs to be checked to ensure only authorized users can modify these critical configurations.

---
### unvalidated_input-utelnetd-socket_execv

- **File/Directory Path:** `N/A`
- **Location:** `bin/utelnetd:0x97b4 fcn.000090a4`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Unverified socket input handling detected, where the client connection returned by accept is directly used to create a new session without proper input validation and filtering. Attackers may inject malicious commands through crafted network inputs.
- **Code Snippet:**
  ```
  iVar14 = sym.imp.accept(puVar13,puVar22 + 0xffffffe4);
  ...
  iVar14 = sym.imp.fork();
  ...
  sym.imp.execv((*0x9af4)[2],*0x9af4 + 3);
  ```
- **Keywords:** sym.imp.accept, sym.imp.fork, sym.imp.execv, utelnetd
- **Notes:** Analyze the source and controllability of execv parameters

---
### format_string-genie.cgi-snprintf

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x9564`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** In the `fcn.REDACTED_PASSWORD_PLACEHOLDER` function, URL construction uses `snprintf` with parameters from `param_2` (potentially from user input). Unvalidated input may lead to format string vulnerabilities or URL injection. Trigger condition: Attacker controls HTTP request parameters. Security impact: May result in arbitrary code execution or server-side request forgery (SSRF).
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, snprintf, param_2, curl_easy_setopt, genie.cgi
- **Notes:** Further verification is required to determine whether the source of param_2 comes directly from user input.

---
### memory_management-genie.cgi-malloc

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x000096b8`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Memory management issue: Multiple instances of malloc used to allocate memory without checking the return value, potentially leading to NULL pointer dereference. For example, the malloc call at address 0x000096b8.
- **Code Snippet:**
  ```
  bl sym.imp.malloc
  ```
- **Keywords:** malloc, ptr, var_74h, genie.cgi
- **Notes:** All malloc calls should check the return value

---
### hardcoded_creds-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Hardcoded REDACTED_PASSWORD_PLACEHOLDER paths (such as `REDACTED_PASSWORD_PLACEHOLDER`) and sensitive operations were detected, which could potentially be exploited to access system-sensitive files or perform privileged operations.
- **Keywords:** crypt, fopen, fwrite, REDACTED_PASSWORD_PLACEHOLDER, acos_service
- **Notes:** Verify whether the hard-coded path is writable

---
### buffer_overflow-wol-sscanf

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/wol:0x8be0(main)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the main function, when using sscanf to parse the configuration file, the input string length is not validated, which may lead to buffer overflow. Attackers can exploit this vulnerability by carefully crafting configuration files. Constraint: The input string length must exceed the target buffer size (100 bytes).
- **Keywords:** main, sscanf, fgets, auStack_118, wol
- **Notes:** Verify whether the configuration file can be externally controlled

---
### web_exposure-remote.sh-symlinks

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/remote.sh`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The remote.sh script was found to contain operations creating symbolic links to the web directory, including CGI scripts and HTML files. These files could potentially serve as attack entry points, particularly if vulnerabilities exist in the CGI scripts.
- **Keywords:** RMT_invite.cgi, RemoteShare.htm, func.sh, /tmp/www/cgi-bin, remote.sh
- **Notes:** Further analysis of the content of these CGI scripts is required to check for command injection or other web vulnerabilities.

---
### buffer_overflow-genie.cgi-strncpy

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x9a3c`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The HTTP response handling contains an unvalidated `strncpy` operation that copies data from response headers into a fixed-size buffer (0x800 bytes). Trigger condition: A malicious server returns an excessively long response header. Security impact: May lead to stack buffer overflow and arbitrary code execution.
- **Keywords:** strncpy, 0x800, X-Error-Code, X-Error-Message, genie.cgi
- **Notes:** The buffer size of 0x800 may be insufficient to handle certain malicious responses

---
### privilege_escalation-utelnetd-pty_handling

- **File/Directory Path:** `N/A`
- **Location:** `bin/utelnetd:0x96a0 fcn.000090a4`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** Vulnerabilities related to pseudo-terminal (pty) handling have been identified, including the direct use of pseudo-terminal devices after grantpt/unlockpt operations without sufficient security checks. This may lead to privilege escalation or session hijacking.
- **Code Snippet:**
  ```
  iVar14 = sym.imp.grantpt();
  ...
  iVar14 = sym.imp.unlockpt(puVar15);
  ...
  uVar4 = sym.imp.ptsname(puVar15);
  ```
- **Keywords:** sym.imp.grantpt, sym.imp.unlockpt, sym.imp.ptsname, utelnetd
- **Notes:** Verify the permission settings of the pseudo-terminal device

---
### ioctl_vulnerability-eapd-wl_iovar

- **File/Directory Path:** `N/A`
- **Location:** `bin/eapd:0xREDACTED_PASSWORD_PLACEHOLDER fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** The function handles wl_iovar_get/set calls (0xREDACTED_PASSWORD_PLACEHOLDER, 0x000098f0). These IOCTL interfaces may expose sensitive information or allow privileged operations. If parameters are not properly validated, they could be abused.
- **Keywords:** wl_iovar_get, wl_iovar_set, event_msgs, eapd
- **Notes:** Analysis of the implementation of wl_iovar_get/set is required to confirm the impact of the vulnerability.

---
### string_handling-genie.cgi-strncpy

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x00009ac4`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** Using strncpy for string copying without properly terminating the string may lead to buffer overflow or information leakage. At address 0x00009ac4, no null terminator was added after the copy operation.
- **Code Snippet:**
  ```
  bl sym.imp.strncpy
  ```
- **Keywords:** strncpy, var_3ch, var_58h, genie.cgi
- **Notes:** All strncpy uses should manually append a null terminator

---
### string_handling-eapd-strncpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/eapd:0xREDACTED_PASSWORD_PLACEHOLDER fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The function uses strncpy multiple times without properly handling null terminators (at 0xREDACTED_PASSWORD_PLACEHOLDER, 0x000091fc, and other locations). Although the copy length is limited, subsequent operations may lead to information leaks or memory corruption due to missing null terminators.
- **Keywords:** strncpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, eapd
- **Notes:** These vulnerabilities may need to be chained with other vulnerabilities to form a complete attack path.

---
### symlink_attack-afpd-tmp_directory

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/afpd:10`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The script uses a hardcoded path /tmp/netatalk to create a temporary directory and copies the AppleVolumes.default file. If an attacker gains control over the /tmp directory or its parent directory, it could lead to symlink attacks or file overwriting. Additionally, the script does not verify whether the source file being copied exists or is readable.
- **Code Snippet:**
  ```
  AFP_CONF_DIR=/tmp/netatalk
  mkdir -p $AFP_CONF_DIR
  cp -f REDACTED_PASSWORD_PLACEHOLDER.default $AFP_CONF_DIR
  ```
- **Keywords:** AFP_CONF_DIR, AppleVolumes.default, cp -f, mkdir -p, afpd
- **Notes:** It is necessary to check the permission settings and mount options of the /tmp directory, as well as the permissions of the REDACTED_PASSWORD_PLACEHOLDER.default file.

---
### network_tampering-rc-nvram_config

- **File/Directory Path:** `N/A`
- **Location:** `sbin/rc:fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Unverified NVRAM values were found being used for network interface configuration. In function fcn.REDACTED_PASSWORD_PLACEHOLDER, the MAC address retrieved from NVRAM is directly applied to network interface configuration, which may lead to tampering of network settings.
- **Keywords:** nvram_get, ioctl, ifconfig, ether_atoe, rc
- **Notes:** It is recommended to perform strict validation on the network configuration values in NVRAM.

---
### system_control-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Critical functions such as LED status and network interfaces can be controlled through NVRAM configuration, but the lack of sufficient verification mechanisms may allow malicious tampering with system behavior.
- **Keywords:** acosNvramConfig_set, acosNvramConfig_save, acos_service
- **Notes:** It is recommended to analyze the network interface and configuration management related code in subsequent steps.

---
### script_execution-leafp2p.sh-checkleafnets

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/leafp2p.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the leafp2p.sh script, the checkleafnets.sh script is found to be utilized, which runs in the background and its path is determined by NVRAM configuration. If an attacker can control the leafp2p_sys_prefix variable, arbitrary script execution may be possible.
- **Keywords:** checkleafnets.sh, leafp2p_sys_prefix, nvram, leafp2p.sh
- **Notes:** Verify the source and content of the checkleafnets.sh script to ensure it has not been tampered with.

---
### stack_overflow-eapd-fixed_buffers

- **File/Directory Path:** `N/A`
- **Location:** `bin/eapd:0x0000909c fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The function extensively uses fixed-size stack buffers (such as var_40h, var_4d0h, etc.) without performing adequate input validation, posing potential stack overflow risks.
- **Keywords:** var_40h, var_4d0h, fcn.REDACTED_PASSWORD_PLACEHOLDER, eapd
- **Notes:** Combining the strcpy vulnerability may form a more severe attack path.

---
### auth_bypass-genie.cgi-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x93e4`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The return value of the authentication REDACTED_PASSWORD_PLACEHOLDER processing logic (fcn.000093e4) is directly used in subsequent operations without sufficient validation. Trigger condition: Providing an invalid or maliciously formatted access REDACTED_PASSWORD_PLACEHOLDER. Security impact: May lead to authentication bypass or memory corruption.
- **Keywords:** fcn.000093e4, access REDACTED_PASSWORD_PLACEHOLDER, Wrong access REDACTED_PASSWORD_PLACEHOLDER, genie.cgi
- **Notes:** Analyze the specific implementation of fcn.000093e4 to confirm the vulnerability.

---
