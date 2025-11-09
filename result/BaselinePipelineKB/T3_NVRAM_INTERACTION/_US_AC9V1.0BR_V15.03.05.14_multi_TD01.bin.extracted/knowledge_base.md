# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (4 alerts)

---

### getenv-HTTP_COOKIE-bin_httpd-0x0804d470

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x0804d470 fcn.0804d430`
- **Risk Score:** 8.5
- **Confidence:** 8.75
- **Description:** env_get
- **Keywords:** HTTP_COOKIE, fcn.0804d430, sqlite3_exec
- **Notes:** env_get

---
### nvram_getall-bin_nvram-0x8b38

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x8b38 fcn.000087b8`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In bin/nvram, a call to bcm_nvram_getall was found, which is used to retrieve all NVRAM variables. This operation is located at address 0x8b38 within function fcn.000087b8. All obtained configuration information is directly output by the puts function, posing a severe information leakage risk.
- **Keywords:** bcm_nvram_getall, puts, fcn.000087b8
- **Notes:** nvram_get

---
### nvram_set-bin_nvram-0x89e4

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x89e4 fcn.000087b8`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** In bin/nvram, a call to bcm_nvram_set was found for setting NVRAM variable values. This operation is located at address 0x89e4 within function fcn.000087b8. The strncpy function is used to copy user input with a buffer size of 0x10000 bytes, posing a buffer overflow risk.
- **Keywords:** bcm_nvram_set, strncpy, fcn.000087b8
- **Notes:** Using strncpy to copy user input to NVRAM poses a buffer overflow risk.

---
### getenv-atoi-bin_busybox-0xd0f0

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0xd0f0 fcn.0000d0d8`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A call to getenv was found at address 0xd0f0, where the environment variable value is directly passed to atoi() without input validation. This may lead to integer overflow or undefined behavior.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.getenv(param_3);
  param_1 = sym.imp.atoi();
  ```
- **Keywords:** getenv, atoi
- **Notes:** Further verification of the environment variable name and calling context is required. It is recommended to check the input validation at all atoi call points.

---
