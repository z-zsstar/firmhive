# R6200v2-V1.0.3.12_10.1.11 (2 alerts)

---

### rc-nvram-access

- **File/Directory Path:** `N/A`
- **Location:** `sbin/rc`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** A large number of NVRAM operations were found in the /sbin/rc system initialization script, including direct calls to functions such as nvram_get and nvram_set, as well as access to multiple NVRAM configuration variables. These operations are primarily used for system initialization and network configuration.
- **Code Snippet:**
  ```
  HIDDENNVRAMHIDDEN:
  wl0_ssid
  wl1_ssid
  lan_ifnames
  wan_ifnames
  os_version
  wl_version
  ```
- **Keywords:** nvram_get, nvram_set, nvram_unset, nvram_commit, nvram_getall, wl0_ssid, wl1_ssid, lan_ifnames, wan_ifnames
- **Notes:** nvram_get/nvram_set

---
### nvram-binary-interface

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The core function calls for NVRAM operations were found in the /usr/sbin/nvram binary, including nvram_get, nvram_set, nvram_unset, nvram_commit, etc. These functions provide comprehensive NVRAM configuration management capabilities.
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER    1     12 sym.imp.nvram_set
  0xREDACTED_PASSWORD_PLACEHOLDER    1     12 sym.imp.nvram_get
  0xREDACTED_PASSWORD_PLACEHOLDER    1     12 sym.imp.nvram_unset
  0xREDACTED_PASSWORD_PLACEHOLDER    1     12 sym.imp.nvram_commit
  ```
- **Keywords:** nvram_get, nvram_set, nvram_unset, nvram_commit, nvram_getall, nvram_loaddefault
- **Notes:** nvram_get/nvram_set

These functions may be called by other programs to access NVRAM configurations, requiring further tracing of call relationships.

---
