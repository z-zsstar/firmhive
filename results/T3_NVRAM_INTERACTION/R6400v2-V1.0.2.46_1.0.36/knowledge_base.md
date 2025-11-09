# R6400v2-V1.0.2.46_1.0.36 (11 alerts)

---

### command_execution-fcn.0001a084-0x1a210

- **File/Directory Path:** `sbin/rc`
- **Location:** `sbin/rc:0x1a210 (fcn.0001a084)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** In the fcn.0001a084 function, the environment variable value at address 0x1a210 is directly used in the `system()` call, posing a high risk of command injection. The environment variable value is passed to system command execution without adequate validation.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** getenv, *0x1a510, system, fcn.0001a084
- **Notes:** This is the highest-risk finding, where environment variable values are directly passed to the `system()` call, potentially leading to command injection.

---
### env-get-INTERFACE-command-injection

- **File/Directory Path:** `sbin/init`
- **Location:** `sbin/init:0x15330 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The function fcn.REDACTED_PASSWORD_PLACEHOLDER (0x15330) accesses the 'INTERFACE' environment variable, whose value is directly used to construct ifconfig command arguments and eval system call parameters, posing a command injection risk. Strict validation and filtering of the 'INTERFACE' environment variable value are required.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** getenv, INTERFACE, ifconfig, _eval, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to strictly validate and filter the value of the 'INTERFACE' environment variable to prevent command injection.

---
### env-get-TZ-command-injection

- **File/Directory Path:** `sbin/init`
- **Location:** `sbin/init:0x11180 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The function fcn.REDACTED_PASSWORD_PLACEHOLDER (0x11180) accesses the 'TZ' environment variable, and this value is directly used to construct a command and executed via execve, posing a command injection risk. Strict validation and filtering of the 'TZ' environment variable value are required.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** getenv, TZ, snprintf, execve, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to strictly validate and filter the value of the 'TZ' environment variable to prevent command injection.

---
### env-EDITOR-execl

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x2cc08`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The value of the environment variable 'EDITOR' is passed to the 'execl' function for execution, potentially allowing arbitrary command execution. Strict validation of the 'EDITOR' environment variable's value is required to prevent command injection attacks.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** EDITOR, execl, 0x2cc08
- **Notes:** Strict validation of the 'EDITOR' environment variable value is required to prevent command injection attacks.

---
### env_get-X509_verify_cert-getenv

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `libcrypto.so.1.0.0:0xfa388 (X509_verify_cert)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** An `env_get` call was found in the `X509_verify_cert` function, likely used to retrieve the 'OPENSSL_ALLOW_PROXY_CERTS' environment variable. Security risk: This variable may influence certificate verification logic, potentially allowing attackers to bypass certificate validation.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** X509_verify_cert, getenv, OPENSSL_ALLOW_PROXY_CERTS
- **Notes:** Critical configurations that directly affect certificate verification

---
### env_get-X509_get_default_cert_file_env-getenv

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `libcrypto.so.1.0.0:0x100350`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** At address 0x100350, a getenv call was found, retrieving the 'SSL_CERT_FILE' or 'SSL_CERT_DIR' environment variables for certificate loading. Security risk: may lead to loading malicious certificate files, resulting in man-in-the-middle attacks.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** getenv, X509_get_default_cert_file_env, SSL_CERT_FILE, SSL_CERT_DIR
- **Notes:** The critical path for certificate loading requires checking subsequent file operations.

---
### env-get-network-nvram-set

- **File/Directory Path:** `sbin/init`
- **Location:** `sbin/init:0x16e14 (fcn.00016e14)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The function fcn.00016e14 accesses multiple network-related environment variables ('ip', 'subnet', 'router', 'lease'), which are directly used to set NVRAM variables and may affect device network configuration. Strict validation of these network-related environment variable values is required.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** getenv, ip, subnet, router, lease, nvram_set, fcn.00016e14
- **Notes:** It is recommended to strictly validate these network-related environment variable values to prevent unauthorized modifications to network configurations.

---
### env_get-autoconfig_wan_down-getenv_system

- **File/Directory Path:** `sbin/autoconfig_wan_down`
- **Location:** `sbin/autoconfig_wan_down:fcn.0001728c`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the file 'sbin/autoconfig_wan_down', a call to the `getenv` function was found where the environment variable's value is directly used for system command execution (via the `system` function), posing a potential command injection risk. Specifically, the environment variable's value is passed unfiltered to the `system` function, which could lead to arbitrary command execution.
- **Code Snippet:**
  ```
  iVar7 = sym.imp.getenv(*0x15e64);
  iVar12 = *0x15e68;
  if (iVar7 != 0) {
      iVar12 = iVar7;
  }
  sym.imp.ifconfig(iVar12,0x1343,*0x15e6c);
  ```
- **Keywords:** getenv, system, ifconfig, route_add, route_del
- **Notes:** Further verification is needed to determine whether the source of environment variables is controllable and whether there is any unfiltered user input directly passed to the `system` function.

---
### env_get-RAND_file_name-getenv

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `libcrypto.so.1.0.0:0xc1d34,0xc1d80 (RAND_file_name)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Two getenv calls were found in the RAND_file_name function: 1) Retrieving the 'RANDFILE' environment variable to specify the random seed file location; 2) Retrieving the 'HOME' environment variable to construct the default path. Security risk: Attackers could potentially influence random number generation or cause path traversal by controlling these variables.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** RAND_file_name, getenv, RANDFILE, HOME
- **Notes:** env_get

---
### env_get-X509_get_default_cert_dir_env-getenv

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `libcrypto.so.1.0.0:0x100cec`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** At address 0x100cec, a getenv call was found retrieving the 'SSL_CERT_DIR' environment variable. Security risk: May lead to loading certificate files from unintended directories.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** getenv, X509_get_default_cert_dir_env, SSL_CERT_DIR
- **Notes:** Certificate directory configuration requires checking for directory traversal vulnerabilities.

---
### env_get-fcn.0001a084-multi

- **File/Directory Path:** `sbin/rc`
- **Location:** `sbin/rc:0x1a110-0x1a150 (fcn.0001a084)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Multiple `getenv` calls were identified in the fcn.0001a084 function, accessing several environment variables (*0x1a504, *0x1a508, *0x1a50c, *0x1a510, *0x1a514). These environment variable values are used for file operation path construction and system command execution, posing potential path injection risks.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** getenv, *0x1a504, *0x1a508, *0x1a50c, *0x1a510, *0x1a514, fcn.0001a084
- **Notes:** Further analysis is required to determine the specific environment variable names these pointers reference.

---
