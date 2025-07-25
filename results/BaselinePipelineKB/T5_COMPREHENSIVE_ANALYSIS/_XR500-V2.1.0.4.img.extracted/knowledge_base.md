# _XR500-V2.1.0.4.img.extracted (23 alerts)

---

### vulnerability-uhttpd-permissions

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/uhttpd.sh`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The CGI script invoked during the uHTTPd startup process has globally writable permissions (rwxrwxrwx), meaning any local user can modify this script, potentially leading to privilege escalation or service disruption.
- **Keywords:** uhttpd.sh permissions, rwxrwxrwx, file_permission
- **Notes:** The file permissions should be immediately changed to 750, and ensure the owner is REDACTED_PASSWORD_PLACEHOLDER.

---
### core-script-impact

- **File/Directory Path:** `N/A`
- **Location:** `lib/functions.sh:1-3`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** system_core
- **Keywords:** OpenWrt.org, functions.sh, busybox, core_script
- **Notes:** system_core

---
### vulnerability-rmt-eval-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The script executes the output of proccgi through eval, which may lead to command injection. Attackers can inject arbitrary commands by carefully crafting CGI parameters. The use of eval is dangerous, especially when the input comes from untrusted sources.
- **Keywords:** eval, proccgi, $*, command_injection
- **Notes:** Analyze the proccgi script to verify input sanitization

---
### attack-chain-web-to-firewall

- **File/Directory Path:** `N/A`
- **Location:** `multiple`
- **Risk Score:** 9.0
- **Confidence:** 6.75
- **Description:** Possibility of discovering a complete attack chain:
1. Gain initial foothold through vulnerabilities in the uHTTPd web interface (e.g., CGI handling)
2. Leverage permissive ICMPv6/IGMP firewall rules for lateral movement
3. Establish persistence by modifying firewall.user to add backdoor rules

Trigger conditions:
- Presence of web application vulnerabilities (CGI/Lua scripts)
- Attacker located on the same IPv6 network segment
- Acquisition of low-privilege accounts (e.g., www-data)
- **Keywords:** option cgi_prefix, lua_handler, Allow-ICMPv6-Forward, firewall.user, attack_chain
- **Notes:** This attack chain requires multiple conditions to be met simultaneously, but once successful, the harm is severe.

---
### vulnerability-proccgi-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x000085d0`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** proccgi uses strcpy for string copying when processing POST data without performing length checks. When handling data specified by CONTENT_LENGTH, if an attacker provides excessively long input, it may lead to a buffer overflow. The trigger condition is sending excessively long data via an HTTP POST request.
- **Keywords:** strcpy, CONTENT_LENGTH, POST, proccgi -- out of memory allocating, buffer_overflow
- **Notes:** Further verification is needed to determine whether this vulnerability can be triggered via the network interface.

---
### vulnerability-uhttpd-configuration

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/uhttpd.sh`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The uHTTPd service configuration presents multiple security issues: 1) Using hardcoded paths /etc/uhttpd.crt and /etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER, where file replacement could lead to MITM attacks; 2) Running with REDACTED_PASSWORD_PLACEHOLDER privileges while listening on all network interfaces (0.0.0.0); 3) Forcibly terminating processes with kill -9 may cause state issues; 4) The script reads content from /module_name as REALM, where file tampering could result in HTTP response header injection.
- **Keywords:** uhttpd.sh, UHTTPD_BIN, PX5G_BIN, /etc/uhttpd.crt, /etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER, 0.0.0.0:80, 0.0.0.0:443, kill -9, /module_name, uhttpd_config
- **Notes:** Recommendations: 1) Use a more secure permission model; 2) Restrict listening interfaces; 3) Implement proper service termination mechanisms; 4) Filter REALM values

---
### vulnerability-nvram-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER fcn.000086d0`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** nvram_set
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER      0d00a0e1       mov r0, sp                  ; char *dest
  0xREDACTED_PASSWORD_PLACEHOLDER      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** sym.imp.strcpy, fcn.000086d0, config_set, argv[2], nvram_set
- **Notes:** nvram_set

---
### vulnerability-rmt-auth-bypass

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:12-45`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Using unvalidated user input (FORM_TXT_remote_login, FORM_TXT_remote_password) directly for NVRAM settings and API calls may lead to authentication bypass or information disclosure. Attackers could inject malicious values to modify system configurations.
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_password, readycloud_control.cgi, nvram, auth_bypass
- **Notes:** Critical authentication parameters must undergo rigorous verification.

---
### vulnerability-firewall-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/config/firewall`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Potential firewall bypass risks identified in configuration:
1. Allowing WAN→LAN communication via DHCP/UDP port 68
2. Overly permissive ICMPv6 rules (covering 9 packet types)
3. Complete allowance of IGMP and multicast UDP traffic
4. Inclusion of user-defined rule path (/etc/firewall.user)

Exploitable vectors:
- DHCP packets could be used for network reconnaissance
- ICMPv6 flood attacks
- Multicast protocol abuse
- Potential tampering with user-defined rules
- **Keywords:** Allow-DHCP-Renew, Allow-ICMPv6-Input, option proto igmp, option dest_ip 224.0.0.0/4, option path /etc/firewall.user, firewall_config
- **Notes:** It is recommended to refine ICMPv6 rules and monitor the integrity of the firewall.user file.

---
### vulnerability-readycloud-nvram-input-validation

- **File/Directory Path:** `N/A`
- **Location:** `bin/readycloud_nvram`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The program processes user input via command-line arguments, but no apparent input validation mechanism is detected. Attackers could potentially exploit buffer overflow vulnerabilities by crafting malicious arguments to execute arbitrary code. Particularly for the `config set name=value` operation, if the value parameter is excessively long and not properly validated, it may lead to stack overflow.
- **Keywords:** config_set, strcpy, sprintf, input_validation
- **Notes:** Dynamic analysis is required to verify the maximum length limit of input parameters and buffer size.

---
### vulnerability-hotplug-device-control

- **File/Directory Path:** `N/A`
- **Location:** `lib/functions.sh:12-14`
- **Risk Score:** 8.0
- **Confidence:** 6.25
- **Description:** The `hotplug_dev()` function directly interfaces with the system's hotplug mechanism using environment variables. If the `INTERFACE` parameter can be controlled by an attacker, it might lead to privilege escalation or unauthorized device access.
- **Keywords:** hotplug_dev, ACTION, INTERFACE, hotplug-call, device_control
- **Notes:** Analyze all functions that call hotplug_dev() and their input sources.

---
### vulnerability-uhttpd-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/config/uhttpd`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The uHTTPd web server configuration presents potential security risks:
1. HTTP/HTTPS ports (80/443) are listening on all interfaces (0.0.0.0)
2. Use of 1024-bit RSA keys (below current security standards)
3. CGI script timeout set to 60 seconds may lead to DoS
4. RFC1918 filtering is enabled but without detailed rule configuration

Attackers could exploit:
- Weak encryption for man-in-the-middle attacks
- Long-running CGI scripts consuming resources
- Insufficient internal network filtering may enable DNS rebinding attacks
- **Keywords:** listen_http, listen_https, option bits 1024, script_timeout, rfc1918_filter, uhttpd_config
- **Notes:** It is recommended to upgrade the REDACTED_PASSWORD_PLACEHOLDER strength to 2048 bits or higher, restrict listening IPs, and reduce script timeout duration.

---
### vulnerability-nvram-auth-bypass

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x000087f8, 0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER, 0x000088ac`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** nvram_set
- **Keywords:** sym.imp.config_commit, sym.imp.config_uncommit, sym.imp.config_backup, sym.imp.config_restore, fcn.000086d0, nvram_operations
- **Notes:** nvram_set

---
### vulnerability-ppp-parameter-injection

- **File/Directory Path:** `N/A`
- **Location:** `lib/network/ppp.sh`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Multiple insufficiently validated external input points were identified in `ppp.sh`, including configuration parameters such as PPTP/L2TP/PPPoE REDACTED_PASSWORD_PLACEHOLDERs, passwords, and MTU values. These parameters are obtained through the `config get` command and directly used for constructing PPP configurations without proper input validation or filtering. Attackers could potentially exploit this vulnerability to perform command injection or configuration tampering by injecting malicious parameters.
- **Keywords:** wan_pptp_REDACTED_PASSWORD_PLACEHOLDER, wan_pptp_password, wan_l2tp_REDACTED_PASSWORD_PLACEHOLDER, wan_REDACTED_PASSWORD_PLACEHOLDER, wan_pppoe_REDACTED_PASSWORD_PLACEHOLDER, wan_pppoe_REDACTED_PASSWORD_PLACEHOLDER, config get, ppp_injection
- **Notes:** It is necessary to check how the upper layer calls set these configuration values and confirm whether there are other filtering mechanisms.

---
### vulnerability-readycloud-nvram-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `bin/readycloud_nvram`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** readycloud_nvram is an NVRAM configuration management tool that provides multiple configuration operation functions. The program uses insecure string manipulation functions (strcpy, sprintf), posing potential buffer overflow risks.
- **Keywords:** config_restore, config_unset, config_getall, config_uncommit, config_backup, config_commit, config_set, config_default, config_get, strcpy, sprintf, buffer_overflow
- **Notes:** nvram_set  

Important: Since the program has been stripped, more detailed function implementation cannot be obtained. It is recommended to perform dynamic analysis to verify potential buffer overflow vulnerabilities.

---
### vulnerability-functions-eval-injection

- **File/Directory Path:** `N/A`
- **Location:** `lib/functions.sh:15-30`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The script contains multiple eval operations (in append() and list_contains() functions) that dynamically evaluate variables. If attacker-controlled input reaches these functions without proper sanitization, it could lead to command injection vulnerabilities. The functions are used for system configuration and network interface management.
- **Keywords:** append, list_contains, eval, hotplug_dev, command_injection
- **Notes:** It is necessary to track the calling locations of these functions and the inputs they receive.

---
### vulnerability-cgi-scripts-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** RMT_invite.cgi and runtests.cgi are shell scripts that need to be checked for command injection vulnerabilities. Specifically, verify whether unvalidated user input is directly used to construct system commands.
- **Keywords:** RMT_invite.cgi, runtests.cgi, command_injection
- **Notes:** Further analysis of the script content is required

---
### vulnerability-rmt-json-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:13-14`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** When processing JSON data via readycloud_control.cgi, the lack of content type validation may lead to HTTP request smuggling or JSON injection. Attackers could craft malicious JSON to manipulate backend processing logic.
- **Keywords:** readycloud_control.cgi, REQUEST_METHOD, PATH_INFO, json_injection
- **Notes:** Verify the Content-Type and JSON structure

---
### vulnerability-nvram-unsafe-string-ops

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER, 0x000087bc, 0x000087d8, 0xREDACTED_PASSWORD_PLACEHOLDER, 0x000088c4, 0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** nvram_set
- **Keywords:** sym.imp.strcpy, sym.imp.strncmp, sym.imp.sprintf, fcn.000086d0, nvram_operations
- **Notes:** nvram_set

---
### vulnerability-proccgi-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x00008b44`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The program directly constructs output strings using user-provided inputs when processing FORM_ parameters, posing a potential injection vulnerability. Attackers may inject special characters or commands through carefully crafted input parameters.
- **Keywords:** FORM_%s=, fprintf, stdout, injection
- **Notes:** The web interface calling this CGI needs to be checked to determine exploitability.

---
### vulnerability-nvram-input-validation

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER fcn.000086d0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The binary lacks proper input validation when processing the '=' character in set operations (0xREDACTED_PASSWORD_PLACEHOLDER). The function uses strchr to locate the '=' character but doesn't verify if the resulting pointer is within bounds of the input buffer. This could lead to memory corruption if the input lacks an '=' character.
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER      d0ffffeb       bl sym.imp.strchr           ; char *strchr(const char *s, int c)
  ```
- **Keywords:** sym.imp.strchr, fcn.000086d0, config_set, argv[2], nvram_set
- **Notes:** nvram_set

---
### vulnerability-rmt-wan-config

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:30-37`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The script lacks permission checks when modifying multiple WAN connection configurations (nvram set REDACTED_PASSWORD_PLACEHOLDER), which could lead to denial of service attacks. Attackers may disable critical network interfaces.
- **Keywords:** wan_pppoe_demand, wan_pptp_demand, wan_mulpppoe_demand, wan_l2tp_demand, FORM_change_wan_pppoe_demand, wan_config
- **Notes:** Network input configuration modifications require administrator privileges.

---
### potential-vulnerability-apply-cgi

- **File/Directory Path:** `N/A`
- **Location:** `www/apply.cgi`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** Initial analysis has identified the content of the www/apply.cgi file, but a more detailed examination is required to determine potential security risks. Recommended follow-up analysis steps: 1) Conduct a thorough review of the file content to identify command execution functions 2) Analyze parameter processing logic 3) Examine input validation mechanisms
- **Keywords:** apply.cgi, www, cgi_handler
- **Notes:** Further analysis of the complete file content is required to confirm whether there are any sensitive function calls that could be externally input.

---
