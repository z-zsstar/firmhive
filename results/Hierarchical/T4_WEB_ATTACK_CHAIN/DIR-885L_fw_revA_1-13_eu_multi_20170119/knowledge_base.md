# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (9 alerts)

---

### command-injection-tsa-fcn.REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `mydlink/tsa`
- **Location:** `mydlink/tsa:fcn.REDACTED_PASSWORD_PLACEHOLDER (case 9HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A command injection vulnerability was discovered in the file 'mydlink/tsa'. Risk path: HTTP request parameter -> strncpy copies to stack variable -> used in sprintf to construct command string. REDACTED_PASSWORD_PLACEHOLDER function: sprintf(iVar9,*0x9dc0,puVar15 + -0xaf). Trigger condition: attacker can control the puVar15 + -0xaf parameter. Security impact: may lead to arbitrary command execution.
- **Code Snippet:**
  ```
  sym.imp.sprintf(iVar9,*0x9dc0,puVar15 + -0xaf);
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, sprintf, puVar15, *0x9dc0, command injection
- **Notes:** It is recommended to prioritize fixing this command injection vulnerability. Further analysis of the HTTP request handling process is required to confirm whether the parameters are fully controllable.

---
### web-wireless_config-http_params

- **File/Directory Path:** `htdocs/mydlink/form_wireless.php`
- **Location:** `htdocs/mydlink/form_wireless.php`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Multiple security risks were identified in the 'htdocs/mydlink/form_wireless.php' file:
1. Critical HTTP POST parameters (f_enable, f_ssid, f_wep, f_REDACTED_PASSWORD_PLACEHOLDER, etc.) are passed directly to the 'set' function without adequate validation, potentially enabling configuration tampering or command injection
2. The validation in the 'check_key_type_and_valid' function is insufficiently strict, with inadequate minimum length requirements for WPA keys (8 characters)
3. The handling of wireless network configuration parameters (including Radius server IP and keys) lacks rigorous security checks

Specific risk vectors:
- Attackers could modify wireless configurations by crafting malicious POST requests
- Weak REDACTED_PASSWORD_PLACEHOLDER validation may result in the use of insecure wireless network keys
- Lack of input sanitization could lead to injection attacks (depending on the specific implementation of the 'set' function)
- **Code Snippet:**
  ```
  set($wifi."/ssid", $ssid);
  set($wifi."/nwkey/psk/REDACTED_PASSWORD_PLACEHOLDER", $REDACTED_PASSWORD_PLACEHOLDER);
  function check_key_type_and_valid($key_type, $REDACTED_PASSWORD_PLACEHOLDER) {...}
  ```
- **Keywords:** set, f_enable, f_ssid, f_wep, f_REDACTED_PASSWORD_PLACEHOLDER, f_radius_ip1, f_REDACTED_PASSWORD_PLACEHOLDER1, check_key_type_and_valid, isxdigit, strlen
- **Notes:** The actual security impact depends on the specific implementation of the 'set' function, and it is recommended to further analyze the definition of this function. Wireless network configuration interfaces typically have high privileges, and such vulnerabilities could potentially lead to complete device compromise.

---
### format-string-tsa-fcn.000135cc

- **File/Directory Path:** `mydlink/tsa`
- **Location:** `mydlink/tsa:0x13ed4 (sprintfHIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A format string vulnerability was discovered in the file 'mydlink/tsa'. Affected interface: POST /goform/form_login. REDACTED_PASSWORD_PLACEHOLDER call: sprintf(0x13ed4). Trigger condition: User-controllable input is directly used as a format string. Security impact: May lead to memory leaks or arbitrary code execution.
- **Code Snippet:**
  ```
  sym.imp.sprintf(0x13ed4);
  ```
- **Keywords:** fcn.000135cc, sprintf, POST /goform/form_login, format string
- **Notes:** Need to confirm whether the parameters of the POST /goform/form_login interface are fully controllable.

---
### web-format-string-fcn.000152b4

- **File/Directory Path:** `mydlink/tsa`
- **Location:** `fcn.000152b4`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A format string vulnerability was discovered in function fcn.000152b4. This function uses vsnprintf to process potentially user-controllable format strings, with output limited to 1024 bytes but without validating the format string content. It is called by multiple higher-level functions, including fcn.REDACTED_PASSWORD_PLACEHOLDER. If the format string parameter originates from HTTP requests, it may lead to information disclosure or memory corruption.
- **Code Snippet:**
  ```
  sym.imp.vsnprintf(iVar9, 1024, param_1, local_20);
  ```
- **Keywords:** fcn.000152b4, vsnprintf, param_1, fcn.REDACTED_PASSWORD_PLACEHOLDER, /goform/form_login, POST /index.php, GET /index.php
- **Notes:** Verify the source of the format string argument for fcn.000152b4, specifically checking whether it originates from HTTP request parameters.

---
### web-command-injection-fcn.000135cc

- **File/Directory Path:** `mydlink/tsa`
- **Location:** `fcn.000135cc`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A command injection vulnerability was identified in function fcn.000135cc. This function executes external commands (mdb_get_admin_REDACTED_PASSWORD_PLACEHOLDER) via popen, with parameters derived from hardcoded strings and stack buffers. If upstream call chains permit user control over these parameters (e.g., through HTTP requests), it may lead to arbitrary command execution.
- **Keywords:** fcn.000135cc, popen, mdb_get_admin_REDACTED_PASSWORD_PLACEHOLDER, 0x19728, 0x13eac, 0x142f4, /goform/form_login
- **Notes:** It is necessary to audit all function paths that call fcn.000135cc to verify whether the source of the 0x19728 value can be controlled by users, especially checking if it originates from HTTP request parameters.

---
### web-sensitive_info_leak-get_Wireless.php

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.php`
- **Location:** `get_Wireless.php`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The file 'get_Wireless.php' contains a sensitive information disclosure vulnerability. This script controls the display of sensitive information through the GET parameter 'REDACTED_PASSWORD_PLACEHOLDER'. When 'REDACTED_PASSWORD_PLACEHOLDER=1', it directly exposes sensitive data such as WEP keys, WPA PSK keys, and RADIUS keys of wireless networks without any authentication or filtering. Attackers can obtain these sensitive credentials through simple GET requests.
- **Code Snippet:**
  ```
  <? 
  $REDACTED_PASSWORD_PLACEHOLDER = $_GET["REDACTED_PASSWORD_PLACEHOLDER"];
  ...
  <f_wep><? if ($REDACTED_PASSWORD_PLACEHOLDER==1){echo $REDACTED_PASSWORD_PLACEHOLDER;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($REDACTED_PASSWORD_PLACEHOLDER==1){echo $pskkey;} ?></f_wps_psk>
  <f_REDACTED_PASSWORD_PLACEHOLDER1><? if ($REDACTED_PASSWORD_PLACEHOLDER==1){echo $eapkey;} ?></f_REDACTED_PASSWORD_PLACEHOLDER1>
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $_GET, <f_wep>, <f_wps_psk>, <f_REDACTED_PASSWORD_PLACEHOLDER1>
- **Notes:** It is recommended to implement strict validation for the REDACTED_PASSWORD_PLACEHOLDER parameter to ensure only authorized users can access such sensitive information. Additionally, consideration should be given to whether this sensitive information should be exposed through this method.

---
### buffer-overflow-tsa-strncpy

- **File/Directory Path:** `mydlink/tsa`
- **Location:** `mydlink/tsa:0x94b4 (strncpyHIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Multiple buffer overflow risks were detected in file 'mydlink/tsa'. Critical call points: strncpy(puVar15 + -0x4d,*0x9cfc,0x11) and strncpy(puVar15 + -0xaf,*0x9d30,0x20). Trigger condition: when HTTP parameter length exceeds target buffer size. Security impact: may lead to stack overflow and arbitrary code execution.
- **Code Snippet:**
  ```
  sym.imp.strncpy(puVar15 + -0x4d,*0x9cfc,0x11);
  ```
- **Keywords:** strncpy, puVar15, *0x9cfc, *0x9d30, buffer overflow
- **Notes:** All strncpy call sites should verify that the buffer size is sufficient.

---
### vulnerability-fileaccess.cgi-fcn.0000ac78

- **File/Directory Path:** `htdocs/fileaccess.cgi`
- **Location:** `fileaccess.cgi:fcn.0000ac78`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Multiple dangerous function calls were identified in the fcn.0000ac78 function of fileaccess.cgi:
1. strcpy call: The parameter source may contain environment variables, but it cannot be confirmed whether it comes directly from HTTP requests. Further analysis of the call chain is required to determine the data flow.
2. sprintf calls: Two potential format string vulnerabilities exist, where parameters may indirectly originate from HTTP request headers (via environment variables obtained through getenv). These calls could allow attackers to perform format string attacks by carefully crafted HTTP headers.
- **Code Snippet:**
  ```
  sym.imp.sprintf(puVar6 + 0 + -0x2aec,0x583c | 0x30000,puVar6 + 0 + -0x1068);
  sym.imp.sprintf(*puVar6,0x5864 | 0x30000,*puVar6,puVar6 + 0 + -0x1068);
  ```
- **Keywords:** fcn.0000ac78, strcpy, sprintf, getenv, puVar6, 0x583c, 0x5864, 0x30000
- **Notes:** Suggested follow-up analysis directions:
1. Analyze the entry0 function and fcn.0000a1f4 function to determine the parameter source of strcpy
2. Verify which HTTP request headers will be set as environment variables
3. Check buffer size limitations
4. Evaluate the practical feasibility of format string attacks

---
### command_injection-libservice-runservice

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `libservice.php:8`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Command injection vulnerability identified in 'libservice.php': 1) The 'runservice' function directly concatenates command strings via 'service '.$cmd.' &'; 2) When called by 'form_wlan_acl', this function uses the '$SRVC_WLAN' variable. Although no direct HTTP parameter transmission path was found, the following risk characteristics exist:
- Dangerous function call: Executes concatenated command strings via 'addevent'
- Potential contamination source: The file processes multiple $_POST parameters (mac_X/enable_X, etc.)
- Incomplete data flow: The source of the '$SRVC_WLAN' variable has not been fully traced

Actual risk depends on whether '$SRVC_WLAN' is ultimately influenced by user input.
- **Code Snippet:**
  ```
  function runservice($cmd){
    addevent("PHPSERVICE","service ".$cmd." &");
    event("PHPSERVICE");
  }
  ```
- **Keywords:** runservice, $cmd, addevent, service, $SRVC_WLAN, form_wlan_acl, $_POST[mac_X], $_POST[enable_X]
- **Notes:** Further verification is required for the following: 1) The exact location where '$SRVC_WLAN' is fully defined; 2) Whether included files (such as config.php) pass HTTP parameters to this variable; 3) Whether MAC address filtering parameters ($_POST[mac_X]) could indirectly affect command execution. No direct evidence has been found within the current directory scope indicating that HTTP parameters can control command injection.

---
