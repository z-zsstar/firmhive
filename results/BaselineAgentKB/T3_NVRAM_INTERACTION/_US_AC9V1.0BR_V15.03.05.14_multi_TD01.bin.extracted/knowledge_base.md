# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (1 alerts)

---

### nvram-check-button-access

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x00069eac (fcn.00069e7c)`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The HTTP server accesses the 'check_button_result' variable via bcm_nvram_get and copies it to the destination buffer using the insecure strcpy function. The lack of boundary checking may lead to a buffer overflow vulnerability.
- **Code Snippet:**
  ```
  0x00069eac      7094feeb       bl sym.imp.bcm_nvram_get
  0x00069ebc      7996feeb       bl sym.imp.strcpy
  ```
- **Keywords:** bcm_nvram_get, check_button_result, strcpy
- **Notes:** Using the insecure strcpy function to copy NVRAM variable values may be exploited for buffer overflow attacks.

---
