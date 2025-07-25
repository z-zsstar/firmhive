# _AC1450-V1.0.0.36_10.0.17.chk.extracted (5 alerts)

---

### dlnad-command-injection

- **File/Directory Path:** `usr/sbin/dlnad`
- **Location:** `usr/sbin/dlnad:0x88e8`
- **Risk Score:** 9.0
- **Confidence:** 7.0
- **Description:** command_injection
- **Code Snippet:**
  ```
  sprintf(command, "minidlna.exe -f %s", acosNvramConfig_get("dlna_config"));
  ```
- **Keywords:** sprintf, minidlna.exe, dlna_enable, acosNvramConfig_match
- **Notes:** Verify if all parameters for minidlna.exe are fully controlled. Implement strict input validation and avoid constructing commands with user-controlled input.

---
### httpd-strcpy-gui_region

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x15724`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** buffer_overflow
- **Code Snippet:**
  ```
  memset(sp, 0, 0x100);
  strcpy(sp, acosNvramConfig_get("gui_region"));
  ```
- **Keywords:** strcpy, acosNvramConfig_get, gui_region, memset
- **Notes:** The `acosNvramConfig_get` function's return value length should be validated. Consider replacing `strcpy` with `strncpy`.

---
### dlnad-strcpy-nvram

- **File/Directory Path:** `usr/sbin/dlnad`
- **Location:** `usr/sbin/dlnad:0x87f0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In usr/sbin/dlnad at address 0x87f0, a `strcpy` function is used to copy data from NVRAM configuration to a stack buffer without length validation. This could lead to a buffer overflow if an attacker controls the NVRAM configuration. A similar issue exists at address 0x88d0, where another `strcpy` call copies NVRAM data without checks.
- **Code Snippet:**
  ```
  strcpy(puVar5, acosNvramConfig_get("config_param"));
  ```
- **Keywords:** strcpy, acosNvramConfig_get, sscanf, puVar5
- **Notes:** buffer_overflow

---
### upnpd-recv-buffer-overflow

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `usr/sbin/upnpd:0x13d6c fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** In usr/sbin/upnpd at address 0x13d6c, the `recv` function is called to receive up to 0x203e bytes of data, but the buffer size is not clearly limited. Subsequent checks only verify if the data exceeds 0x1ffd bytes, leaving potential for buffer overflow. This is particularly dangerous as it handles HTTP headers like 'Content-length:' and 'SetFirmware'.
- **Code Snippet:**
  ```
  recv(socket, buffer, 0x203e, 0);
  if (data_length > 0x1ffd) {...}
  ```
- **Keywords:** recv, Content-length:, SetFirmware, strstr, stristr
- **Notes:** buffer_overflow

---
### httpd-agApi-clear-nat

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x1568c`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** configuration_manipulation
- **Code Snippet:**
  ```
  if (acosNvramConfig_match("restart_all_processes")) {
    agApi_clear_nat_for_httpd();
  }
  ```
- **Keywords:** agApi_clear_nat_for_httpd, restart_all_processes, acosNvramConfig_match
- **Notes:** configuration_manipulation

---
