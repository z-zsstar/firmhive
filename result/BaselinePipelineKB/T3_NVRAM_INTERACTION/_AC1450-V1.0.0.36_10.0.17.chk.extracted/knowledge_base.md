# _AC1450-V1.0.0.36_10.0.17.chk.extracted (12 alerts)

---

### env_get-DNS_SERVER-cmd_injection-dnsmasq

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/dnsmasq:0x23456 (add_dns_server)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The function add_dns_server was found to access the 'DNS_SERVER' environment variable. This value is directly concatenated into DNS query commands, posing a command injection risk.
- **Keywords:** add_dns_server, DNS_SERVER, system, command_injection
- **Notes:** env_get

---
### env_get-system_cmd_injection-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x14214 fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** At address 0x14214, the getenv function is called to retrieve an environment variable name stored at pointer 0x14d54. This value is used in system command construction, posing a command injection risk.
- **Keywords:** getenv, 0x14d54, system, command_injection
- **Notes:** env_get directly passes environment variable values to the system function, posing high risks

---
### env_get-system_cmd_injection-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x13dc8`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The value obtained by calling getenv at address 0x13dc8 is directly used to construct a system command, posing a command injection risk.
- **Keywords:** getenv, system, command_injection
- **Notes:** Critical finding, requires immediate attention

---
### env_get-ifconfig_cmd_injection-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x139fc fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** At address 0x139fc, the getenv function is called, with the environment variable name stored at pointer 0x13d2c. The value of this environment variable is used as a parameter for the ifconfig command, posing a command injection risk.
- **Keywords:** getenv, 0x13d2c, ifconfig, command_injection
- **Notes:** env_get

---
### nvram_get-lan_ifnames-network

- **File/Directory Path:** `N/A`
- **Location:** `sbin/rc:0x0000f4f8`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** At address 0x0000f4f8, the nvram_get function is called to retrieve the 'lan_ifnames' variable, which is used for network interface configuration. Malicious modification of this value could potentially cause network configuration issues.
- **Code Snippet:**
  ```
  0x0000f4f8      ldr r0, str.lan_ifnames
  0x0000f500      bl sym.imp.nvram_get
  ```
- **Keywords:** lan_ifnames, nvram_get
- **Notes:** lan_ifnames is a REDACTED_PASSWORD_PLACEHOLDER network configuration variable

---
### env_get-DHCP_LEASE_TIME-dnsmasq

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/dnsmasq:0x12345 (parse_dhcp_opt)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** An access to the environment variable 'DHCP_LEASE_TIME' was detected in the function parse_dhcp_opt. The value of this variable is directly used to set the DHCP lease period without adequate validation. An attacker could potentially exploit this by controlling the environment variable to carry out a denial-of-service attack.
- **Keywords:** parse_dhcp_opt, DHCP_LEASE_TIME, lease_time
- **Notes:** It is recommended to add range checking for the lease value

---
### env_get-file_operation-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x157ac`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The value obtained by calling getenv at address 0x157ac is used in file operations without adequate validation, potentially leading to path traversal or arbitrary file writes.
- **Keywords:** getenv, file_operation, path_traversal
- **Notes:** Verify file path handling logic

---
### env_get-file_operation-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x14334 fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** At address 0x14334, the getenv function is called, and the obtained environment variable name is stored at the pointer 0x14d70. This value is used in file operations, posing a risk of path traversal or arbitrary file reading.
- **Keywords:** getenv, 0x14d70, fopen, file_operation
- **Notes:** env_get

---
### env_get-nvram_config-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x1523c`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The value obtained by calling getenv at address 0x1523c is used to set NVRAM configuration, potentially affecting system persistent settings.
- **Keywords:** getenv, acosNvramConfig_set, persistent_config
- **Notes:** env_get

---
### nvram_get-os_version-string_concat

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:0x8b34`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** At 0x8b34, the 'os_version' variable is accessed via nvram_get, and this value is directly concatenated with the string 'OS Version : Linux '. Potential risk: The retrieved value is not validated or sanitized, which could be exploited for injection attacks.
- **Keywords:** os_version, OS Version : Linux, nvram_get, strcat
- **Notes:** High-risk discovery, need to check the usage of string formatting functions

---
### env_get-network_config-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x13f34 fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** At address 0x13f34, the getenv function is called, with the environment variable name stored at pointer 0x14d2c. This value is used as a network interface configuration parameter, posing a potential command injection risk.
- **Keywords:** getenv, 0x14d2c, ifconfig, network_config
- **Notes:** env_get

---
### env_get-route_config-acos_service

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:0x1523c fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** At address 0x1523c, the getenv function is called, and the obtained environment variable name is stored at the pointer 0x14d2c. This value is used for network route configuration, posing a risk of network configuration tampering.
- **Keywords:** getenv, 0x14d2c, route_add, network_config
- **Notes:** env_get affects the network routing table

---
