# R7000 (3 alerts)

---

### env_get-system-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service (HIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In `sbin/acos_service`, environment variable values are directly used to construct `system()` command arguments, posing a command injection risk. The environment variable values are utilized for sensitive operations, including network configuration and system command execution, without adequate validation.
- **Code Snippet:**
  ```
  iVar4 = sym.imp.getenv(*0x18088);
  iVar9 = *0x18090;
  if (iVar4 != 0) {
      iVar9 = iVar4;
  }
  ```
- **Keywords:** getenv, system, ifconfig, route_add, route_del
- **Notes:** High-risk points:
1. Environment variable values are directly passed to system() calls
2. Network configuration parameters originate from unverified environment variables
3. Presence of hardcoded sensitive configuration paths

---
### env_get-MODALIAS-0x11784

- **File/Directory Path:** `N/A`
- **Location:** `sbin/init:0x11784`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** At address 0x11784, a call to getenv is found with the parameter 'MODALIAS'. The value of this environment variable is subsequently passed to the strcmp function for comparison with the hardcoded string 'platform:coma_dev'. If this value is maliciously controlled, it could potentially lead to bypassing the program's logic.
- **Keywords:** getenv, MODALIAS, strcmp, platform:coma_dev
- **Notes:** The MODALIAS environment variable is typically set by the kernel, but poses a risk if it can be controlled by user space.

---
### env_get-PATH-0x16df0

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x16df0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** At address 0x16df0, a getenv call is found accessing the environment variable 'PATH'. This value is used for command lookup, posing a potential path hijacking risk.
- **Keywords:** getenv, PATH
- **Notes:** This environment variable is used for command lookup and poses a path hijacking risk.

---
