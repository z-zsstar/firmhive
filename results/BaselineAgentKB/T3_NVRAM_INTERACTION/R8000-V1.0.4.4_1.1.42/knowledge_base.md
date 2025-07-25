# R8000-V1.0.4.4_1.1.42 (1 alerts)

---

### NVRAM-access-eapd-0xca1c

- **File/Directory Path:** `N/A`
- **Location:** `bin/eapd:0xca1c (fcn.0000c9f8)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A call to nvram_get was found at address 0xca1c in the eapd binary. The retrieved NVRAM value is used in snprintf formatted output, posing a potential command injection risk.
- **Code Snippet:**
  ```
  pcVar1 = sym.imp.nvram_get(param_3);
  ...
  sym.imp.snprintf(param_1,param_2,*0xca90);
  ```
- **Keywords:** nvram_get, snprintf
- **Notes:** Further clarification is needed regarding the specific NVRAM variable name and calling context.

---
