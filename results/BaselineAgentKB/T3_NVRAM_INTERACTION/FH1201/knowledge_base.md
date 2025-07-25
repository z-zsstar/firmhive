# FH1201 (1 alerts)

---

### NVRAM-access-iptv-config

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x45c824 (sym.formSetIptv)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** Multiple NVRAM variable setting operations were identified in the HTTPD's IPTV configuration functionality, including IPTV activation status, STB configuration, and VLAN settings. These configurations may impact network isolation and traffic control security.
- **Code Snippet:**
  ```
  //str.iptv_enabled
  iVar1 = (**(iStack_160 + -0x78cc))(*&uStackX_0,*(iStack_160 + -0x7fd8) + -0x2890,*(iStack_160 + -0x7fd8) + -0x2918);
  //str.iptv_stb_enabled
  uVar2 = (**(iStack_160 + -0x78cc))(*&uStackX_0,*(iStack_160 + -0x7fd8) + -0x2880,*(iStack_160 + -0x7fd8) + -0x2918);
  ```
- **Keywords:** iptv_enabled, iptv_stb_enabled, stballvlans, stbpvid, iptv.enable, iptv.stb.enable
- **Notes:** These NVRAM variables control IPTV functionality, and improper configuration may lead to network isolation failure or traffic control issues.

---
