# _DWR-118_V1.01b01.bin.extracted (7 alerts)

---

### httpd-buffer-overflow

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The HTTP daemon (`httpd`) contains multiple unsafe `strcpy` calls in configuration processing functions (e.g., `Apply_ezConfig`, `SaveWISPConfig_to_CSID`). These functions may process user input from the web interface without proper length checks, leading to buffer overflow vulnerabilities. Attackers could craft malicious HTTP requests to exploit these vulnerabilities and execute arbitrary code.
- **Code Snippet:**
  ```
  N/A (multiple locations)
  ```
- **Keywords:** strcpy, Apply_ezConfig, SaveWISPConfig_to_CSID, REDACTED_SECRET_KEY_PLACEHOLDER_to_CSID
- **Notes:** buffer_overflow

---
### rdcsman-buffer-overflow

- **File/Directory Path:** `usr/bin/csmankits`
- **Location:** `usr/bin/csmankits:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The `rdcsman` binary contains multiple vulnerabilities, including an unsafe `strcpy` usage in the `conv_param` function, which could lead to buffer overflow. Attackers could craft special characters in the input to trigger this vulnerability and overwrite critical memory regions.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** conv_param, strcpy, strtoul
- **Notes:** buffer_overflow

---
### busybox-command-execution

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0xREDACTED_PASSWORD_PLACEHOLDER (sym.execve), 0xREDACTED_PASSWORD_PLACEHOLDER (sym.system)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** BusyBox contains multiple command execution vulnerabilities, including unsafe use of `execve()` and `system()` functions without proper input sanitization. These vulnerabilities can be exploited through various command-line interfaces in BusyBox applets, potentially allowing remote code execution if the applets are exposed to untrusted input.
- **Code Snippet:**
  ```
  N/A (multiple locations)
  ```
- **Keywords:** sym.execve, sym.spawn, sym.run_applet_by_name, sym.system, sym.bb_do_delay, sym.run_shell
- **Notes:** command_execution

---
### ated-buffer-overflow

- **File/Directory Path:** `usr/bin/ated`
- **Location:** `usr/bin/ated:0x00400ef0-0x00400f10 in main`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The `ated` binary contains an unprotected `strcpy` operation in its main function that copies a command-line argument to a buffer without length checking. This could lead to a stack-based buffer overflow if the argument is longer than the destination buffer. The vulnerable code path is triggered when the program is executed with the '-i' flag followed by an interface name.
- **Code Snippet:**
  ```
  0x00400ef0      0000438c       lw v1, (v0)
  0x00400ef4      4100023c       lui v0, 0x41
  0x00400ef8      REDACTED_PASSWORD_PLACEHOLDER       addiu a0, v0, 0x3150
  0x00400efc      REDACTED_PASSWORD_PLACEHOLDER       move a1, v1
  0x00400f00      ac80998f       lw t9, -sym.imp.strcpy(gp)
  0x00400f04      REDACTED_PASSWORD_PLACEHOLDER       nop
  0x00400f08      09f82003       jalr t9
  0x00400f0c      REDACTED_PASSWORD_PLACEHOLDER       nop
  ```
- **Keywords:** strcpy, main, 0x00400ef0, 0x00400f10, -i
- **Notes:** The buffer size at 0x413150 is unknown. Further analysis would require determining the size of this buffer to assess the full impact. The program appears to handle network interfaces, suggesting this could potentially be exploited remotely if the program is exposed to untrusted input.

---
### dev-core-symlink

- **File/Directory Path:** `dev/core`
- **Location:** `dev/core`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The `dev/core` symbolic link points to `/proc/kcore`, which is a memory image of the Linux kernel. This link allows any user to read kernel memory, potentially exposing sensitive information such as passwords and cryptographic keys. The link has global read-write permissions (`drwxrwxrwx`), significantly increasing the risk.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** dev/core, /proc/kcore
- **Notes:** information_disclosure

---
### l2tp-script-command-injection

- **File/Directory Path:** `etc/init.d/l2tp.sh`
- **Location:** `etc/init.d/l2tp.sh`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The `l2tp.sh` script in `etc/init.d` does not validate the L2TP server address obtained from the `rdcsman` command before using it to start a session. This lack of validation could allow an attacker to inject malicious commands by controlling the output of `rdcsman`.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** L2TP_LNSSERVER, rdcsman, l2tp-control, l2tp-result
- **Notes:** command_injection

---
### libssl-buffer-overflow

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `lib/libssl.so.1.0.0:0x32cbc`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The `SSL_get_shared_ciphers` function in `libssl.so.1.0.0` uses `strcpy` to copy cipher strings without proper bounds checking. This could lead to a buffer overflow if an attacker can control the cipher list and the destination buffer is not sufficiently large. The function takes a buffer and its size as arguments but doesn't properly validate that the copied data fits within the buffer before using `strcpy`.
- **Code Snippet:**
  ```
  0x00032cbc      1c84998f       lw t9, -sym.imp.strcpy(gp)
  0x00032cc0      REDACTED_PASSWORD_PLACEHOLDER       beqz v0, 0x32d1c
  0x00032cc4      REDACTED_PASSWORD_PLACEHOLDER       move a0, s3
  0x00032cc8      09f82003       jalr t9
  ```
- **Keywords:** SSL_get_shared_ciphers, strcpy, buffer overflow, libssl.so.1.0.0
- **Notes:** buffer_overflow

---
