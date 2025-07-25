# R8000-V1.0.4.4_1.1.42 (5 alerts)

---

### acos_service-NVRAM-command_injection

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service:0x16d44-0x17bb4`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function fcn.000184c makes multiple calls to getenv to retrieve environment variables, which are then used for network configuration and system command execution. Some environment variable values are directly incorporated into system command construction (via system calls), posing a command injection risk. If these environment variables are maliciously controlled, it could lead to arbitrary command execution.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** fcn.0001849c, getenv, system, ifconfig, route_add, route_del
- **Notes:** It is recommended to strictly validate all external inputs.

---
### remote-NVRAM-multi_config

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The remote.sh script contains extensive NVRAM operations, including retrieving and setting multiple leafp2p-related configuration variables. These variables control critical functions such as remote access, debug levels, and firewall settings. The lack of input validation may pose security risks.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** leafp2p_sys_prefix, leafp2p_replication_url, leafp2p_replication_hook_url, leafp2p_remote_url, leafp2p_debug, leafp2p_firewall, leafp2p_rescan_devices, leafp2p_services, leafp2p_service_0, leafp2p_run, nvram get, nvram set, nvram commit
- **Notes:** These NVRAM variables control critical network functions; it is recommended to review all relevant URLs and configuration values.

---
### httpd-command_injection

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:fcn.000384a0`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Direct system command execution (`system` call) detected, where some commands may incorporate data from environment variables. Command injection risk exists, particularly when processing user-controllable inputs.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** system, 0x38e08, 0x38e68, 0x38e70, 0x38e84, 0x38e94
- **Notes:** Need to confirm whether these system calls use unvalidated user input

---
### acos_service-NVRAM-config_access

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service:HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Multiple NVRAM configuration operations (acosNvramConfig_set/get) have been detected for storing and retrieving network configuration parameters. Some parameters are used directly without validation, which may lead to configuration tampering or information leakage.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** acosNvramConfig_set, acosNvramConfig_get, acosNvramConfig_match, acosNvramConfig_read
- **Notes:** NVRAM operations should include permission checks and input validation.

---
### busybox-PATH_injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x51670`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A getenv call was found in function fcn.00050ee0 to retrieve the PATH environment variable. This value is used for command lookup, posing a path injection risk. The PATH environment variable is utilized for command lookup and could be hijacked to execute malicious programs.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** fcn.00050ee0, sym.imp.getenv, PATH
- **Notes:** Validate the PATH value.

---
