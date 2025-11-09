# R8000-V1.0.4.4_1.1.42 (6 alerts)

---

### libnvram-direct_io_access

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Direct access to the /dev/nvram device was found in multiple functions, utilizing low-level I/O operations without necessary security controls.
- **Keywords:** /dev/nvram, read, write, open
- **Notes:** It is recommended to add access control and input validation.

---
### binary-strcat-buffer_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:multiple offsets in fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** nvram_get
- **Keywords:** strcat, nvram_get, memcpy
- **Notes:** nvram_get

---
### libnvram-strcpy_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:0x00005cf8`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The sym.nvram_get function was found to directly use strcpy for copying NVRAM variable values, which may lead to a buffer overflow vulnerability. After reading data from the /dev/nvram device, this function copies the data directly to the target buffer without performing length checks.
- **Code Snippet:**
  ```
  0x00005cf0      0810a0e1       mov r1, r8
  0x00005cf4      0500a0e1       mov r0, r5
  0x00005cf8      0bffffeb       bl loc.imp.strcpy
  ```
- **Keywords:** nvram_get, strcpy, /dev/nvram
- **Notes:** Attackers may trigger a buffer overflow by setting excessively long NVRAM variable values.

---
### nvram_script-leafp2p_path_injection

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/leafp2p.sh:5`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script retrieves the NVRAM variable value of 'leafp2p_sys_prefix' using the `/usr/sbin/nvram get` command and assigns it to the SYS_PREFIX variable. This value is subsequently used to construct the paths for the CHECK_LEAFNETS and PATH variables. If an attacker can control this value in NVRAM, it may lead to path injection or command injection vulnerabilities.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)
  CHECK_LEAFNETS=${SYS_PREFIX}/bin/checkleafnets.sh
  ```
- **Keywords:** nvram, leafp2p_sys_prefix, SYS_PREFIX, CHECK_LEAFNETS, PATH
- **Notes:** It is recommended to verify the source and restrictions of NVRAM values to ensure they cannot be modified by unauthorized users. Additionally, path normalization should be considered.

---
### libnvram-nvram_set_validation

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Direct writing to NVRAM variables was found in the sym.nvram_set function without adequate validation of the input values.
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER      dafcffeb       bl rsym.nvram_set
  0xREDACTED_PASSWORD_PLACEHOLDER      003050e2       subs r3, r0, 0
  ```
- **Keywords:** nvram_set, nvram_commit
- **Notes:** May result in malicious values being written to NVRAM, affecting system stability

---
### binary-nvram_set-buffer_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:unlabeled offset in fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Found NVRAM variable setting through nvram_set() with a strncpy of 0x10000 bytes, which could lead to buffer overflow if not properly bounded. The values are taken from command line arguments and processed through strsep() before being committed to NVRAM.
- **Keywords:** nvram_set, strncpy, strsep
- **Notes:** nvram_set

---
