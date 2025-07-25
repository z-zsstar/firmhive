# R8500 (5 alerts)

---

### acos_service-getenv-command-injection

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service:0x15f64-0x16cd8`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function fcn.0001777c retrieves environment variables using getenv() and directly incorporates the result into constructing a system() command, posing a command injection risk.
- **Keywords:** getenv, system, fcn.0001777c
- **Notes:** Verify that environment variables are properly filtered

---
### remote_sh-nvram-urls

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:15-79`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** The script retrieves multiple NVRAM variable values, including URL-related configurations, through the `nvram get` command. These values are used to initialize configurations, with default values being set and committed if the variables do not exist. The primary risk lies in the potential tampering of these URLs and configurations, which could lead to remote code execution or information leakage.
- **Keywords:** nvram, leafp2p_sys_prefix, leafp2p_replication_url, leafp2p_replication_hook_url, leafp2p_remote_url, leafp2p_debug, leafp2p_firewall, leafp2p_rescan_devices, leafp2p_services, leafp2p_service_0, leafp2p_run
- **Notes:** Further inspection is required regarding the usage of these NVRAM variables in other components, particularly whether URL-related variables are utilized for insecure functionalities such as command execution.

---
### leafp2p_sh-path-injection

- **File/Directory Path:** `etc/init.d/leafp2p.sh`
- **Location:** `etc/init.d/leafp2p.sh:5`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script retrieves the NVRAM variable `leafp2p_sys_prefix` using the `nvram get` command and assigns its value to the `SYS_PREFIX` variable. This value is subsequently used to construct paths for the `CHECK_LEAFNETS` and `PATH` variables. If an attacker gains control over the `leafp2p_sys_prefix` value in NVRAM, it could lead to path injection or command injection vulnerabilities.
- **Code Snippet:**
  ```
  SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)
  CHECK_LEAFNETS=${SYS_PREFIX}/bin/checkleafnets.sh
  PATH=${SYS_PREFIX}/bin:${SYS_PREFIX}/usr/bin:/sbin:/usr/sbin:/bin:/usr/bin
  ```
- **Keywords:** nvram, leafp2p_sys_prefix, SYS_PREFIX, CHECK_LEAFNETS, PATH
- **Notes:** Further analysis of the `checkleafnets.sh` script is required to verify the safety of `SYS_PREFIX` usage. If this value is directly used for constructing commands or paths without proper validation, potential security risks may exist.

---
### printenv-getenv-usage

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox (printenv_main)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** When called with parameters, printenv searches for specific environment variables. The getenv function directly retrieves variable values without input validation. If the variable values are used for sensitive operations, it may pose injection risks.
- **Code Snippet:**
  ```
  mov rdi, [argv]
  call getenv
  mov rdi, rax
  call puts
  ```
- **Keywords:** printenv_main, getenv
- **Notes:** Check if the script calling printenv passes the return value to an unsafe function.

---
### acos_service-env-file-ops

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service:0x17c60-0x17cdc`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Environment variables are directly used in file operations (fopen/fread) and memory allocation (malloc), posing a potential buffer overflow risk.
- **Keywords:** getenv, fopen, fread, malloc
- **Notes:** potential_buffer_overflow

---
