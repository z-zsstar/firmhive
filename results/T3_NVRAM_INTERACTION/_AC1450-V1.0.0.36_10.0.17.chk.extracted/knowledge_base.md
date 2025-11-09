# _AC1450-V1.0.0.36_10.0.17.chk.extracted (19 alerts)

---

### env_get-IPREMOTE-network_config

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `./sbin/acos_service:fcn.REDACTED_PASSWORD_PLACEHOLDER:0x1523c [getenv]`
- **Risk Score:** 8.5
- **Confidence:** 8.75
- **Description:** The remote IP address is used for route configuration. Using it unsanitized directly in the route_add command may lead to arbitrary route injection.
- **Code Snippet:**
  ```
  getenv('IPREMOTE') used in route_add command
  ```
- **Keywords:** IPREMOTE, route_add, acosNvramConfig_set
- **Notes:** Multiple locations found: 0x1523c, 0x155e8, 0x156d4

---
### env_get-IPLOCAL-network_config

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `./sbin/acos_service:fcn.REDACTED_PASSWORD_PLACEHOLDER:0x1523c [getenv]`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The local IP address is used for network configuration. Using it directly in route_add without sanitization may lead to network redirection or man-in-the-middle attacks.
- **Code Snippet:**
  ```
  getenv('IPLOCAL') used in route_add command
  ```
- **Keywords:** IPLOCAL, route_add, strcmp, 10.64.64.64
- **Notes:** Multiple locations found: 0x1523c, 0x15480, 0x15598

---
### nvram_access-telnetenabled-telnetd_enable

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `telnetenabled:0x00008f50 (main)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file '.REDACTED_PASSWORD_PLACEHOLDER' accesses the NVRAM configuration item 'telnetd_enable' through the `acosNvramConfig_match` function. The value of this configuration item is directly used in the `system` function call, posing a command injection risk. If an attacker can modify these NVRAM configuration items, arbitrary commands may be executed. Specifically, the 'telnetd_enable' configuration item controls the enabling of the telnet service. If maliciously modified, it could lead to unauthorized remote access.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.acosNvramConfig_match("telnetd_enable",0xbe50);
  if (iVar1 != 0) {
      sym.imp.system("utelnetd");
  }
  iVar1 = sym.imp.acosNvramConfig_match("parser_enable",0xbe50);
  if (iVar1 != 0) {
      sym.imp.system("parser");
  }
  ```
- **Keywords:** acosNvramConfig_match, telnetd_enable, parser_enable, system, utelnetd, parser
- **Notes:** It is recommended to further analyze the implementation of the `acosNvramConfig_match` function to verify the presence of buffer overflow or other security vulnerabilities. Additionally, the access control mechanisms for NVRAM configuration items should be examined to ensure they are sufficiently secure.

---
### nvram_access-telnetenabled-parser_enable

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `telnetenabled:0x00008f50 (main)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file '.REDACTED_PASSWORD_PLACEHOLDER' accesses the NVRAM configuration item 'parser_enable' through the `acosNvramConfig_match` function. The value of this configuration item is directly used in the `system` function call, posing a command injection risk. If an attacker can modify these NVRAM configuration items, arbitrary commands may be executed.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.acosNvramConfig_match("parser_enable",0xbe50);
  if (iVar1 != 0) {
      sym.imp.system("parser");
  }
  ```
- **Keywords:** acosNvramConfig_match, telnetd_enable, parser_enable, system, utelnetd, parser
- **Notes:** It is recommended to further analyze the implementation of the `acosNvramConfig_match` function to confirm whether buffer overflow or other security vulnerabilities exist. Additionally, the access control mechanisms for NVRAM configuration items should be examined to ensure they are sufficiently secure.

---
### dataflow-env-nvram-network_config

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `HIDDEN: ./sbin/acos_service HIDDEN ./sbin/bd`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The data flow correlation between environment variables (IFNAME/IPREMOTE) and NVRAM configuration (acosNvramConfig_set). Environment variable values may be written to NVRAM through the acosNvramConfig_set function, creating a potential attack vector. Attackers could influence NVRAM configuration by manipulating environment variables, thereby affecting system behavior.
- **Code Snippet:**
  ```
  HIDDEN -> acosNvramConfig_set -> NVRAM -> HIDDEN
  ```
- **Keywords:** IFNAME, IPREMOTE, acosNvramConfig_set, route_add, ifconfig
- **Notes:** Further verification is required to confirm whether the environment variables have indeed been written to NVRAM and the specific path where they are written.

---
### nvram-set-potential

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `./usr/sbin/nvram:fcn.REDACTED_PASSWORD_PLACEHOLDER:0x8904`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** nvram_set

Setting NVRAM variables carries potential security risks and may allow arbitrary variable settings. REDACTED_PASSWORD_PLACEHOLDER-value pairs are parsed via strsep.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** strsep, sym.imp.nvram_set, 0x8904
- **Notes:** Further analysis of the input source and call chain is required to determine whether exploitable paths exist.

---
### nvram-getall-buffer-risk

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `./usr/sbin/nvram:fcn.REDACTED_PASSWORD_PLACEHOLDER:0x899c`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** nvram_getall, with potential buffer overflow risk.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** sym.imp.nvram_getall, 0x899c
- **Notes:** Buffer size check needs to be added.

---
### NVRAM-WPS-security_risk

- **File/Directory Path:** `usr/sbin/wpsd`
- **Location:** `./usr/sbin/wpsd:Various`
- **Risk Score:** 7.8
- **Confidence:** 7.25
- **Description:** The security risks primarily lie in the lack of validation when NVRAM values are used for security operations, as well as critical security behaviors being controlled by NVRAM configurations. There is a potential risk of NVRAM injection attacks.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** wps_addenrollee, wps_method, wps_aplockdown, acosNvramConfig_get
- **Notes:** Potential risk of NVRAM injection attacks exists

---
### NVRAM-WPS-validation_issue

- **File/Directory Path:** `usr/sbin/wpsd`
- **Location:** `./usr/sbin/wpsd:0x8dc4, 0x8a30, 0x8a94`
- **Risk Score:** 7.8
- **Confidence:** 7.25
- **Description:** The NVRAM value lacks sufficient validation before being used in secure operations, particularly in the case of WPS REDACTED_PASSWORD_PLACEHOLDER usage.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** wps_pin, wps_addenrollee
- **Notes:** especially the use of WPS REDACTED_PASSWORD_PLACEHOLDER

---
### env-get-PROXY

- **File/Directory Path:** `bin/wget`
- **Location:** `wget:0x24b64`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** env_get
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** http_proxy, https_proxy, ftp_proxy, sym.getproxy, 0x24b64
- **Notes:** env_get

---
### env_get-EDITOR-busybox-0x2c76c

- **File/Directory Path:** `bin/busybox`
- **Location:** `busybox:0x2c76c (execl)`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** At address 0x2c76c, accessing the 'EDITOR' environment variable with its value passed to the execl function for execution poses a high risk of command injection. Attackers could potentially execute arbitrary commands by controlling this variable.
- **Code Snippet:**
  ```
  Not available in raw data
  ```
- **Keywords:** getenv, EDITOR, execl, command_injection
- **Notes:** The EDITOR variable value is directly passed to execl, which may lead to command injection.

---
### env-get-WGETRC

- **File/Directory Path:** `bin/wget`
- **Location:** `wget:sym.wgetrc_env_file_name`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The 'WGETRC' variable controls configuration file location. Malicious files could lead to arbitrary code execution.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** WGETRC, sym.wgetrc_env_file_name
- **Notes:** env_get

---
### env_get-IFNAME-network_config

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `./sbin/acos_service:fcn.REDACTED_PASSWORD_PLACEHOLDER:0x1523c [getenv]`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The network interface name is used for configuration and file operations. It is not properly sanitized before being used in file paths and system commands. An attacker-controlled IFNAME could lead to arbitrary file access or command execution.
- **Code Snippet:**
  ```
  getenv('IFNAME') used in file operations and command execution
  ```
- **Keywords:** IFNAME, strcat, fopen, ifconfig, acosNvramConfig_set
- **Notes:** Multiple locations found: 0x1523c, 0x152b4, 0x15310, 0x157ac, 0x158d8

---
### nvram-unsafe-strcpy-upnpd

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0xae9c`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** An unsafe operation was identified in function fcn.0000ae38: values retrieved from NVRAM are directly copied to a local buffer without boundary checking. This may lead to buffer overflow vulnerabilities, particularly when the NVRAM values are controlled by an attacker.
- **Code Snippet:**
  ```
  uVar2 = sym.imp.acosNvramConfig_get(*0xb030);
  sym.imp.strcpy(puVar11,uVar2);
  ```
- **Keywords:** fcn.0000ae38, acosNvramConfig_get, strcpy
- **Notes:** It is recommended to replace strcpy with safer functions such as strncpy.

---
### nvram-bd-nvram-access

- **File/Directory Path:** `sbin/bd`
- **Location:** `./sbin/bd (HIDDENstringsHIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Access to the NVRAM system was detected in the file './sbin/bd', utilizing the libnvram.so library and multiple REDACTED_PASSWORD_PLACEHOLDER functions for NVRAM operations. Multiple NVRAM configuration variables were identified, including network and security-related settings (lan_ipaddr, lan_netmask, wla_ssid, wla_passphrase, etc.). Instances of combining NVRAM values with system commands were observed, potentially posing command injection risks. Security risks primarily manifest in: sensitive information (such as passwords) being stored and accessed via NVRAM; the use of dangerous functions like system() to process NVRAM values; and insufficient validation of NVRAM values.
- **Code Snippet:**
  ```
  HIDDEN:
  acosNvramConfig_get
  acosNvramConfig_set
  acosNvramConfig_match
  
  HIDDEN:
  lan_ipaddr, lan_netmask, wla_ssid, wla_passphrase, http_REDACTED_PASSWORD_PLACEHOLDER, http_REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** libnvram.so, acosNvramConfig_get, acosNvramConfig_set, acosNvramConfig_match, lan_ipaddr, lan_netmask, wla_ssid, wla_passphrase, wla_secu_type, http_REDACTED_PASSWORD_PLACEHOLDER, http_REDACTED_PASSWORD_PLACEHOLDER, system, strcpy, sprintf
- **Notes:** It is recommended to further analyze the specific implementation of the REDACTED_PASSWORD_PLACEHOLDER functions, with particular attention to configuration variables used in conjunction with system commands (system). Additionally, it is advised to examine other files to complete a comprehensive global analysis.

---
### nvram-get-network-fcn.000092d0

- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `./sbin/ubdcmd:fcn.000092d0`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In function fcn.000092d0, 'wan_ipaddr' and 'wan_gateway' are accessed, and these values are passed to inet_addr() for IP address conversion, but input validation is lacking.
- **Code Snippet:**
  ```
  Not provided in the input
  ```
- **Keywords:** wan_ipaddr, wan_gateway, inet_addr, acosNvramConfig_get
- **Notes:** If an attacker can tamper with these NVRAM values, it may lead to abnormal network configurations or security bypasses.

---
### NVRAM-WPS-wps_pin_access

- **File/Directory Path:** `usr/sbin/wpsd`
- **Location:** `./usr/sbin/wpsd:0x8dc4, 0x8998, 0x8a30, 0x8a94HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Multiple NVRAM variables were accessed, including the security-sensitive variable 'wps_pin' and several WPS configuration flags. These variables may be used for security-sensitive operations but lack sufficient validation.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** wps_pin, wps_proc_status, wps_config_command, wps_status, acosNvramConfig_get
- **Notes:** A total of 28 distinct NVRAM variables were accessed

---
### nvram-get-parser-fcn00008eb8

- **File/Directory Path:** `sbin/parser`
- **Location:** `./sbin/parser:fcn.00008eb8`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The function fcn.00008eb8 was found to access NVRAM, retrieving the value of parameter param_1 via acosNvramConfig_get. This value is directly copied into buffer puVar9 and processed by sprintf, posing a buffer overflow risk. The trigger condition occurs when param_1 is externally controlled.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** acosNvramConfig_get, param_1, puVar9, sprintf
- **Notes:** Verify whether the source of param_1 can be externally controlled

---
### nvram-get-parser-fcn00009a68

- **File/Directory Path:** `sbin/parser`
- **Location:** `./sbin/parser:fcn.00009a68`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Multiple NVRAM accesses were found in function fcn.00009a68, where the value of pointer *0x9b7c is obtained through acosNvramConfig_get. This value is directly used in printf and sprintf outputs, posing a risk of format string vulnerability. The trigger condition occurs when the value pointed to by *0x9b7c is tainted.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** acosNvramConfig_get, *0x9b7c, printf, sprintf
- **Notes:** Verify the source and write point of *0x9b7c

---
