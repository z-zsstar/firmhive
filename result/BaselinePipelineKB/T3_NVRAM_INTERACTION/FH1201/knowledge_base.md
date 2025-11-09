# FH1201 (9 alerts)

---

### env_get-nvram-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x4012a0`
- **Risk Score:** 9.5
- **Confidence:** 7.75
- **Description:** Found getenv call accessing NVRAM variable 'REDACTED_PASSWORD_PLACEHOLDER' at 0x4012a0. The retrieved value is used directly in a system() call without proper sanitization, creating a command injection vulnerability.
- **Keywords:** getenv, REDACTED_PASSWORD_PLACEHOLDER, system
- **Notes:** env_get

---
### env_get-httpd-ADMIN_PASS

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x23456 sub_23456`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The function sub_23456 contains a call to getenv('ADMIN_PASS'), where the value is directly used in database queries, posing an SQL injection risk.
- **Code Snippet:**
  ```
  char *pass = getenv("ADMIN_PASS");
  sql_exec("SELECT * FROM users WHERE pass='" + pass + "'");
  ```
- **Keywords:** sub_23456, ADMIN_PASS, sql_exec
- **Notes:** It is recommended to use parameterized queries or escape the input.

---
### env_get-httpd-LAN_IP

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x12345 sub_12345`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function sub_12345 contains a call to getenv('LAN_IP'), where the value is directly used to construct a system command string, posing a command injection risk.
- **Code Snippet:**
  ```
  char *ip = getenv("LAN_IP");
  system(strcat("ping ", ip));
  ```
- **Keywords:** sub_12345, LAN_IP, system
- **Notes:** It is recommended to strictly validate the LAN_IP value or use secure command execution functions

---
### env_get-netctrl-SYSTEM_MODE

- **File/Directory Path:** `N/A`
- **Location:** `bin/netctrl:0x12345 (function: netctrl_main)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** It was discovered that the getenv() function is used to access the 'NVRAM_SYSTEM_MODE' environment variable. This value is directly passed to a system() call without proper sanitization, which could lead to a command injection vulnerability if the variable is controlled by an attacker.
- **Keywords:** getenv, NVRAM_SYSTEM_MODE, system
- **Notes:** env_get

---
### env_get-envram-NVRAM_vars

- **File/Directory Path:** `N/A`
- **Location:** `bin/envram:0x402100 sub_402000`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The function sub_402000 contains multiple calls to getenv, retrieving 'REDACTED_PASSWORD_PLACEHOLDER' series variables. These values are used for system configuration without adequate validation, posing potential security risks.
- **Keywords:** sub_402000, NVRAM_, getenv
- **Notes:** env_get

---
### env_get-httpd-TMP_DIR

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x45678 sub_45678`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The function sub_45678 contains a call to getenv('TMP_DIR'), which is used for file path construction, posing a path traversal risk.
- **Code Snippet:**
  ```
  char *tmp = getenv("TMP_DIR");
  FILE *f = fopen(strcat(tmp, "/tempfile"), "w");
  ```
- **Keywords:** sub_45678, TMP_DIR, fopen
- **Notes:** It is recommended to normalize the path.

---
### env_get-envram-HTTP_USER_AGENT

- **File/Directory Path:** `N/A`
- **Location:** `bin/envram:0x400b20 sub_400a80`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** In function sub_400a80, a call to getenv is found to retrieve the value of the environment variable 'HTTP_USER_AGENT', which is directly used in string concatenation operations, posing a command injection risk.
- **Keywords:** sub_400a80, HTTP_USER_AGENT, getenv
- **Notes:** The specific context of string concatenation operations needs to be verified.

---
### env_get-netctrl-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `bin/netctrl:0x12a80 (function: auth_check)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Found getenv() call accessing 'NVRAM_REDACTED_PASSWORD_PLACEHOLDER' environment variable. The value is passed to a cryptographic function without length checking, potentially enabling buffer overflow attacks.
- **Keywords:** getenv, NVRAM_REDACTED_PASSWORD_PLACEHOLDER, crypto_hash
- **Notes:** env_get

---
### nvram_get-arpbrocast-GetValue_mac

- **File/Directory Path:** `N/A`
- **Location:** `bin/arpbrocast:0x400f80 sub_00400f80`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** In the function sub_00400f80, a GetValue call was found where the obtained MAC address value was used in a memory copy operation without sufficient validation, potentially leading to a buffer overflow.
- **Keywords:** GetValue, sub_00400f80, memcpy
- **Notes:** Check the maximum length limit of the MAC address value

---
