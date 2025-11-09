# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (1 alerts)

---

### nvram-interface

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:0x000085d4 (sym.imp.nvram_get), 0x000085b0 (sym.imp.nvram_set), 0x000085e0 (sym.imp.nvram_unset), 0x000085ec (sym.imp.nvram_commit)`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** The /usr/sbin/nvram binary contains a complete set of NVRAM operation interfaces, including get, set, unset, commit, show, and dump functions. These functions interact directly with the device's NVRAM storage and may be called by other programs.
- **Code Snippet:**
  ```
  0x000085b0    1     12 sym.imp.nvram_set
  0x000085d4    1     12 sym.imp.nvram_get
  0x000085e0    1     12 sym.imp.nvram_unset
  0x000085ec    1     12 sym.imp.nvram_commit
  ```
- **Keywords:** nvram_get, nvram_set, nvram_unset, nvram_commit, nvram_getall
- **Notes:** nvram_get/nvram_set

---
