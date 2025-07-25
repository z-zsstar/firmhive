# R6200v2-V1.0.3.12_10.1.11 (5 alerts)

---

### env_get-acos_init-0x13c84

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_init:0x13c84 fcn.000151b4`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** In function fcn.000151b4, the environment variable obtained via getenv is directly used in system command execution, posing a severe command injection risk.
- **Keywords:** getenv, system, 0x13dc4, 0x13dac, 0x13da8
- **Notes:** High-risk vulnerability, immediate remediation required

---
### env_get-acos_service-fcn.000151b4

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:fcn.000151b4`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The function fcn.000151b4 makes multiple calls to getenv() to retrieve environment variables, and uses the results for system command execution (system()) and network configuration (ifconfig). This poses potential command injection risks.
- **Keywords:** system, ifconfig, getenv
- **Notes:** env_get

---
### env_get-acos_init-0x13a5c

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_init:0x13a5c fcn.000151b4`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In function fcn.000151b4, environment variables are retrieved via getenv for network interface configuration. The obtained values are directly used in ifconfig commands, posing a command injection risk.
- **Keywords:** getenv, ifconfig, 0x13d8c, 0x13d90, 0x13d94
- **Notes:** env_get

---
### env_get-acos_init-0x1529c

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_init:0x1529c fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** In function fcn.REDACTED_PASSWORD_PLACEHOLDER, the IP configuration information obtained via getenv is directly used for network interface configuration, posing risks of configuration errors or injection.
- **Keywords:** getenv, ifconfig, 0x14dac, 0x14db4, 0x14dbc
- **Notes:** env_get

---
### env_get-wps_monitor-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `bin/wps_monitor:0x12bcd (function sub_12bcd)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The binary accesses NVRAM variable 'REDACTED_PASSWORD_PLACEHOLDER' through getenv. The value is used in device authentication. Potential security risk if the REDACTED_PASSWORD_PLACEHOLDER is exposed or weakly protected.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, getenv

---
