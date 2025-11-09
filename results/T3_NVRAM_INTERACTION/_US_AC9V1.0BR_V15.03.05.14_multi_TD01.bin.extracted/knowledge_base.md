# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (13 alerts)

---

### env_get-PATH_LD-path_hijack

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x4cf24`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In bin/busybox, environment variables such as PATH/LD_LIBRARY_PATH are obtained through getenv. High risk, may affect the search paths for executables and libraries.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** getenv, PATH, LD_LIBRARY_PATH, 0x4d1c0
- **Notes:** High-risk points for path hijacking

---
### env_get-LOGIN_PRE_SUID_SCRIPT-command_injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0xf248`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In bin/busybox, the LOGIN_PRE_SUID_SCRIPT environment variable is obtained via getenv, potentially used for command construction and execution logic. High risk, possibly exploitable for command injection.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** LOGIN_PRE_SUID_SCRIPT, getenv, 0xf248, 0x0002ef2c
- **Notes:** Further verification is required for the usage scenarios of this variable.

---
### NVRAM-bcm_nvram_get

- **File/Directory Path:** `lib/libCfm.so`
- **Location:** `lib/libCfm.so`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Directly reads NVRAM data, copies parameters using strcpy without length checks. Risk of buffer overflow exists due to lack of input validation.
- **Code Snippet:**
  ```
  sym.imp.strcpy(*(puVar4 + -0xc),*(puVar4 + -0x78));
  uVar2 = sym.imp.read(*(iVar3 + 0xc1c0 + *0xc2bc),*(puVar4 + -0xc),*(puVar4 + -0x10));
  ```
- **Keywords:** bcm_nvram_get, strcpy
- **Notes:** High-risk operation, requires checking whether the caller has performed appropriate validation on the input parameters

---
### env_get-console_file-file_operation

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x4999c`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** In bin/busybox, the env_get function retrieves the name/console environment variables for file operations (open64/dup2). High risk, potentially exploitable for file operation hijacking.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** getenv, name, console, open64, dup2
- **Notes:** high-risk file operation point

---
### env_get-dynamic_loader-LD_PRELOAD

- **File/Directory Path:** `lib/ld-uClibc.so.0`
- **Location:** `lib/ld-uClibc.so.0:0x2c70 (sym._dl_get_ready_to_run)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'lib/ld-uClibc.so.0' was found to access environment variables, primarily involving the functions '_dl_getenv' and '_dl_get_ready_to_run'. The accessed environment variables include LD_LIBRARY_PATH and LD_PRELOAD, which control the loading behavior of dynamic link libraries. The potential security risk is that attackers could manipulate these environment variables to load malicious shared libraries, leading to arbitrary code execution. In particular, the LD_PRELOAD variable is widely exploited for library injection attacks.
- **Keywords:** _dl_getenv, _dl_get_ready_to_run, LD_LIBRARY_PATH, LD_PRELOAD, sym.imp.getenv
- **Notes:** It is recommended to further examine how these environment variables are used in the program, especially whether they are utilized in privileged programs.

---
### REDACTED_PASSWORD_PLACEHOLDER-weak_password_hash-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' contains user account information with REDACTED_PASSWORD_PLACEHOLDER hashes for multiple users including 'REDACTED_PASSWORD_PLACEHOLDER', 'REDACTED_PASSWORD_PLACEHOLDER', 'support', 'user', and 'nobody'. The 'REDACTED_PASSWORD_PLACEHOLDER' user's REDACTED_PASSWORD_PLACEHOLDER is hashed using MD5 (indicated by '$1$'), which is considered weak. The presence of these hashes in a readable file poses a security risk if the passwords can be cracked, potentially allowing unauthorized access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody, password_hash
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER hashes should be further analyzed with tools like 'john' or 'hashcat' to determine if they are weak or default. The 'REDACTED_PASSWORD_PLACEHOLDER' user's MD5 hash is particularly vulnerable. Immediate action should be taken to secure these accounts, such as changing passwords to stronger ones and ensuring the 'REDACTED_PASSWORD_PLACEHOLDER' file has proper permissions.

---
### env-command-injection-risk

- **File/Directory Path:** `bin/ash`
- **Location:** `0x2ef2c`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** A potential hazardous pattern has been identified where dynamically constructed environment variables (names starting with '$') are retrieved and ultimately used in system calls, which may lead to command injection risks.
- **Keywords:** getenv, system, fcn.0002ece0, command injection
- **Notes:** High-risk finding, requires immediate verification and remediation.

---
### env_get-LOGIN_PRE_SUID_SCRIPT-ifconfig

- **File/Directory Path:** `sbin/ifconfig`
- **Location:** `ifconfig:0xf248`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** A high-risk access to the environment variable 'LOGIN_PRE_SUID_SCRIPT' was detected at address 0xf248. This variable may be used for script execution prior to privilege escalation, and if maliciously controlled, could lead to arbitrary script execution.
- **Keywords:** LOGIN_PRE_SUID_SCRIPT, getenv
- **Notes:** env_get

---
### nvram-vlanports-config

- **File/Directory Path:** `lib/libtpi.so`
- **Location:** `libtpi.so:0xb374 sym.tpi_set_vlanports`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The NVRAM operations on variables from vlan1ports to vlan5ports were identified in libtpi.so, including the use of bcm_nvram_get/set functions and executing nvram set/unset commands via doSystemCmd. These operations are hardcoded for setting/unsetting in the sym.tpi_set_vlanports function, posing a command injection risk.
- **Code Snippet:**
  ```
  0x0000b3b4      033084e0       add r3, r4, r3              ; 0x50068 ; "nvram unset vlan1ports"
  add r3, r4, r3 ; 0x500e8 ; "nvram set vlan1ports=\"0 1 2 3 4 REDACTED_PASSWORD_PLACEHOLDER\""
  ```
- **Keywords:** bcm_nvram_get, bcm_nvram_set, doSystemCmd, nvram set, nvram unset, vlan1ports, vlan5ports, sym.tpi_set_vlanports
- **Notes:** Further auditing is required to determine if the doSystemCmd function implementation contains command injection vulnerabilities.

---
### REDACTED_PASSWORD_PLACEHOLDER-shadow-md5-hash

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the 'etc_ro/shadow' file, encrypted using MD5 ($1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER). MD5 is a relatively weak hashing algorithm that is vulnerable to brute-force attacks or rainbow table attacks. If an attacker gains access to this file, they may attempt to crack the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER, potentially gaining full control of the system.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** shadow, REDACTED_PASSWORD_PLACEHOLDER, $1$, MD5
- **Notes:** It is recommended to check whether the system uses stronger hash algorithms (such as SHA-256 or SHA-512) for REDACTED_PASSWORD_PLACEHOLDER storage and to restrict access permissions to the shadow file.

---
### NVRAM-envram_set_value

- **File/Directory Path:** `lib/libCfm.so`
- **Location:** `lib/libCfm.so`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** nvram_set

Used to set configuration values in NVRAM. May pose a risk of configuration tampering depending on the content of the variables being written.
- **Keywords:** envram_set_value
- **Notes:** Need to check the specific variables being written and the calling context

---
### NVRAM-bcm_nvram_set

- **File/Directory Path:** `lib/libCfm.so`
- **Location:** `lib/libCfm.so`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** nvram_set. Directly sets NVRAM data. Configuration tampering risks may exist, depending on the content of the variables being written.
- **Keywords:** bcm_nvram_set
- **Notes:** Need to check the specific variables being written and the calling context

---
### env_get-dynamic_var-user_input

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x2ef2c`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** env_get in bin/busybox handles environment variable references (pcVar15) in user input. Medium to high risk, involving string processing and regular expression matching.
- **Code Snippet:**
  ```
  Not available
  ```
- **Keywords:** getenv, pcVar15, strchr, regexec
- **Notes:** Further analysis of the user input processing logic is required

---
