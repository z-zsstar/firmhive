# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (4 alerts)

---

### httpd-strcpy-vulnerability-1

- **File/Directory Path:** `N/A`
- **Location:** `sbin/httpd:0x13628 (fcn.0001331c)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** An unverified strcpy() call was identified in the fcn.0001331c function, which may lead to buffer overflow. The source data originates from external input, while the destination buffer has a fixed size without length validation. Attackers could potentially overwrite adjacent memory through carefully crafted input.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar7 + iVar6 + -0x67c,*(puVar7 + -0x30));
  ```
- **Keywords:** strcpy, fcn.0001331c, acStack_680, puVar7, iVar6
- **Notes:** Further verification is required to determine whether the input source is fully controllable.

---
### httpd-strcpy-vulnerability-2

- **File/Directory Path:** `N/A`
- **Location:** `sbin/httpd:0x13720 (fcn.0001331c)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** In the function fcn.0001331c, a second unverified strcpy() call was identified, which also poses a buffer overflow risk. The source data originates from external input, while the destination buffer has a fixed size.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar7 + iVar6 + -0x67c,*(puVar7 + -0x30));
  ```
- **Keywords:** strcpy, fcn.0001331c, acStack_680, puVar7, iVar6
- **Notes:** Similar to the first strcpy vulnerability, it is necessary to validate the input path.

---
### httpd-strcpy-vulnerability-4

- **File/Directory Path:** `N/A`
- **Location:** `sbin/httpd:0x16b54,0x16b8c (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Two unverified strcpy() calls (0x16b54 and 0x16b8c) were identified in the fcn.REDACTED_PASSWORD_PLACEHOLDER function, potentially leading to buffer overflow. The source data originates from path information, while the destination buffer has a fixed size without length validation. An attacker could potentially trigger overflow by crafting malicious path inputs.
- **Code Snippet:**
  ```
  sym.imp.strcpy(dest, src); // HIDDEN
  ```
- **Keywords:** strcpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, path_info, buffer_overflow, network_input
- **Notes:** Need to verify whether the path information is entirely controlled by external input

---
### httpd-strcpy-vulnerability-3

- **File/Directory Path:** `N/A`
- **Location:** `sbin/httpd:0x14ee8 (fcn.00014a30)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In the fcn.00014a30 function, an unchecked strcpy() call was identified, which may lead to a buffer overflow. The source data originates from the device name in network configuration, while the destination buffer has a fixed size (0x20 bytes) without length validation. An attacker could potentially trigger an overflow by configuring a malicious device name.
- **Code Snippet:**
  ```
  sym.imp.strcpy(dest, src); // HIDDEN
  ```
- **Keywords:** strcpy, fcn.00014a30, stream, device_name, network_config
- **Notes:** Verify whether the device name is entirely controlled by external configuration

---
