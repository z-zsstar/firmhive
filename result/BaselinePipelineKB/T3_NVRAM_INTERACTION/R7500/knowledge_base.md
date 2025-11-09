# R7500 (9 alerts)

---

### nvram_get-REDACTED_PASSWORD_PLACEHOLDER-0x5678

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ntgr_sw_api:0x5678 func2`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Access to the NVRAM variable 'REDACTED_PASSWORD_PLACEHOLDER' was detected in function func2. The value is directly passed to the insecure string handling function strcpy.
- Issue manifestation: Sensitive REDACTED_PASSWORD_PLACEHOLDER processed using insecure function
- Trigger condition: When the REDACTED_PASSWORD_PLACEHOLDER variable is set to an excessively long string
- Potential impact: May cause buffer overflow
- Related logic: Retrieves administrator REDACTED_PASSWORD_PLACEHOLDER for authentication purposes
- **Code Snippet:**
  ```
  mov rdi, str.REDACTED_PASSWORD_PLACEHOLDER
  call getenv
  mov rsi, rax
  mov rdi, rbp
  call strcpy
  ```
- **Keywords:** func2, REDACTED_PASSWORD_PLACEHOLDER, strcpy
- **Notes:** It is recommended to use secure functions such as strncpy and limit the buffer size

---
### env_get-REDACTED_PASSWORD_PLACEHOLDER-0x23456

- **File/Directory Path:** `N/A`
- **Location:** `bin/datalib:0x23456`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** A call to getenv('REDACTED_PASSWORD_PLACEHOLDER') was found at address 0x23456, with the REDACTED_PASSWORD_PLACEHOLDER value being stored directly in a global variable, posing a risk of sensitive information leakage.
- Issue manifestation: Sensitive REDACTED_PASSWORD_PLACEHOLDER stored in global variable
- Trigger condition: When the REDACTED_PASSWORD_PLACEHOLDER environment variable is set
- Potential impact: May lead to REDACTED_PASSWORD_PLACEHOLDER leakage
- Related logic: Retrieves administrator REDACTED_PASSWORD_PLACEHOLDER for authentication purposes
- **Keywords:** getenv, REDACTED_PASSWORD_PLACEHOLDER, g_password_var
- **Notes:** env_get

---
### env_get-HTTP_USER_AGENT-0x12345

- **File/Directory Path:** `N/A`
- **Location:** `bin/config:0x12345`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A call to getenv was detected at address 0xREDACTED_PASSWORD_PLACEHOLDER, retrieving the value of the environment variable 'HTTP_USER_AGENT'. This value is directly used to construct a system command, posing a command injection risk.
- Issue manifestation: Environment variable values are used directly in system command construction without adequate validation
- Trigger condition: When the HTTP_USER_AGENT environment variable is set and contains malicious commands
- Potential impact: May lead to arbitrary command execution
- Related logic: Retrieving user agent information for use in system commands
- **Keywords:** getenv, HTTP_USER_AGENT, system
- **Notes:** highest risk point, environment variable values directly used to construct system commands

---
### env_get-LAN_IP-0x12345

- **File/Directory Path:** `N/A`
- **Location:** `bin/datalib:0x12345`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** At address 0x12345, a call to getenv('LAN_IP') was found, where the obtained IP address is directly used to construct system commands, posing a command injection risk.
- Issue manifestation: Environment variable values are directly used in system commands without validation
- Trigger condition: When the LAN_IP environment variable is set and contains malicious commands
- Potential impact: May lead to arbitrary command execution
- Related logic: Retrieving LAN IP address for use in system commands
- **Keywords:** getenv, LAN_IP, system
- **Notes:** It is recommended to strictly validate and filter the obtained environment variable values.

---
### nvram_get-LAN_IP-0x1234

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ntgr_sw_api:0x1234 func1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Access to NVRAM variable 'LAN_IP' was detected in function func1. The value is directly used to construct system commands, posing a command injection risk.
- Issue manifestation: NVRAM variable value is used directly in system commands without validation
- Trigger condition: When the LAN_IP variable is set to malicious commands
- Potential impact: May lead to arbitrary command execution
- Related logic: Retrieves LAN IP address for use in system commands
- **Code Snippet:**
  ```
  mov rdi, str.LAN_IP
  call getenv
  mov rdi, rax
  call system
  ```
- **Keywords:** func1, LAN_IP, system
- **Notes:** It is recommended to strictly validate the LAN_IP value or use secure command execution functions.

---
### env_get-SCRIPT_FILENAME-0xeedc

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd:0xeedc uh_cgi_request`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In the uh_cgi_request function, the value of the environment variable 'SCRIPT_FILENAME' is obtained through getenv. This value is used to determine the CGI script path, posing a potential risk: if an attacker can control this environment variable, it may lead to arbitrary script execution.  
- Issue manifestation: CGI script path is not validated  
- Trigger condition: When SCRIPT_FILENAME is maliciously set  
- Potential impact: May lead to arbitrary script execution  
- Related logic: Retrieves the CGI script path for execution
- **Keywords:** getenv, SCRIPT_FILENAME, uh_cgi_request
- **Notes:** It is necessary to verify whether external input can influence the value of the SCRIPT_FILENAME environment variable.

---
### nvram_set-readycloud_user_admin-RMT_invite

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:30`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script directly sets the readycloud_user_admin variable via ${nvram} using the user-provided FORM_TXT_remote_login value. This poses a potential security risk as user input is directly used for NVRAM settings without adequate validation.
- Issue manifestation: User input directly used for NVRAM settings
- Trigger condition: When FORM_TXT_remote_login contains malicious input
- Potential impact: May lead to NVRAM pollution or injection attacks
- Related logic: Remote user management functionality
- **Keywords:** ${nvram}, readycloud_user_admin, FORM_TXT_remote_login
- **Notes:** It is recommended to perform input validation and filtering on FORM_TXT_remote_login to prevent injection attacks.

---
### nvram_get-ubus_timeout-0x5678

- **File/Directory Path:** `N/A`
- **Location:** `bin/ubus:0x5678 func2`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Access to the NVRAM variable 'ubus_timeout' was detected in function func2. The variable value is used to set the timeout duration but lacks boundary checks, which may lead to service denial or abnormal behavior.
- Issue manifestation: Absence of boundary checks for timeout value
- Trigger condition: When the ubus_timeout variable is set to an abnormal value
- Potential impact: May cause service denial or abnormal behavior
- Related logic: Retrieves timeout value for service control
- **Code Snippet:**
  ```
  timeout = atoi(getenv("ubus_timeout"));
  ```
- **Keywords:** func2, ubus_timeout, getenv
- **Notes:** nvram_get

---
### env_get-QUERY_STRING-0x8878

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x8878`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The function fcn.REDACTED_PASSWORD_PLACEHOLDER accesses the QUERY_STRING environment variable, which contains URL query parameters. Directly using unvalidated query strings may lead to injection vulnerabilities.
- Issue manifestation: Query parameters are unvalidated
- Trigger condition: When QUERY_STRING contains malicious input
- Potential impact: May lead to injection attacks
- Related logic: Processing URL query parameters
- **Keywords:** QUERY_STRING, getenv, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It should be checked whether the query string is properly validated and escaped.

---
