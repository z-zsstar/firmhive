# FH1201 (4 alerts)

---

### nvram-wan_primary

- **File/Directory Path:** `bin/igd`
- **Location:** `bin/igd:0x40192c (nvram_get)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The nvram_get function is used to access the 'wan%d_primary' variable, which controls the primary settings of the WAN interface. High-risk operation, may affect network connectivity.
- **Code Snippet:**
  ```
  0x0040192c: lw t9, -sym.imp.nvram_get(gp); move s4, t9
  ```
- **Keywords:** nvram_get, wan%d_primary
- **Notes:** nvram_get

---
### nvram-pppoe_ifname

- **File/Directory Path:** `bin/igd`
- **Location:** `bin/igd:0x401ac0 (nvram_get)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The text "nvram_get" is used to access the 'pppoe_ifname' variable, which controls the PPPoE interface name. High-risk operation, potentially used for network redirection.
- **Code Snippet:**
  ```
  0x00401ac0: lw t9, -sym.imp.nvram_get(gp); addiu v1, v1, 0x58c8; "pppoe_ifname"
  ```
- **Keywords:** nvram_get, pppoe_ifname
- **Notes:** nvram_get

---
### nvram-wps_monitor-nvram_access

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `Various functions throughout wps_monitor binary`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Extensive access to NVRAM was identified in the file 'bin/wps_monitor', primarily implemented through the nvram_get, nvram_set, and nvram_commit functions. These accesses are distributed across multiple critical functionalities, including WPS configuration, LED control, button handling, and security settings. While no direct security vulnerabilities (such as command injection or environment variable misuse) were discovered, the extensive NVRAM usage may pose potential risks, particularly when variables are not properly sanitized or access controls are insufficient.
- **Keywords:** nvram_get, nvram_set, nvram_commit, wps_osl_set_conf, wps_REDACTED_SECRET_KEY_PLACEHOLDER, wps_REDACTED_SECRET_KEY_PLACEHOLDER, wps_setPinFailInfo, wps_setStaDevName, wps_gpio_led_multi_color_init, wps_gpio_led_init, wps_gpio_btn_init, wps_hal_led_init, wps_REDACTED_SECRET_KEY_PLACEHOLDER, print_conf, wps_osl_build_conf, wps_set_wsec, wpsenr_osl_restore_wsec
- **Notes:** It is recommended to further investigate specific NVRAM variable names and their usage contexts to identify potential security issues.

---
### nvram_access-nvram_get-puts_output

- **File/Directory Path:** `bin/nvram`
- **Location:** `HIDDEN: nvram_get -> puts`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The binary file reveals that the `nvram_get` function is called, and its return value is directly passed to the `puts` function for output without any validation or filtering. This may pose a security risk of leaking sensitive NVRAM contents. Although the specific NVRAM variable names could not be identified, this operational pattern presents a clear security vulnerability.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** nvram_get, puts, arg_18h
- **Notes:** Recommended mitigation measures:
1. Implement proper access control for NVRAM
2. Filter or desensitize the output NVRAM values
3. Restrict execution permissions for this binary file

---
