# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (2 alerts)

---

### usr-bin-spawn-fcgi-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/spawn-fcgi:sym.fcgi_spawn_connection`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In spawn-fcgi (usr/bin), the fcgi_spawn_connection function uses execv/execl to execute potentially user-controlled parameter commands. If an attacker can influence these parameters (via command-line arguments or environment variables), it may lead to command injection. Since these functions directly execute system commands, the risk level is considered high.
- **Code Snippet:**
  ```
  Not provided in findings but involves execv/execl calls with external parameters
  ```
- **Keywords:** execv, execl, fcgi_spawn_connection, spawn-fcgi
- **Notes:** Further investigation is required to determine whether network input can reach these parameters. It is recommended to implement input validation and use execve with full pathnames.

---
### usr-lib-libnetconf-iptc_commit-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnetconf.so:0xREDACTED_PASSWORD_PLACEHOLDER iptc_commit`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** In libnetconf.so (usr/lib), the iptc_commit function contains multiple unsafe strcpy operations (0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER, 0x000063e0). The most critical is at 0xREDACTED_PASSWORD_PLACEHOLDER where external input (arg1+0x28) is copied to a buffer (fp) without length checks, creating a potential buffer overflow vulnerability. This could allow attackers to overwrite adjacent memory if they control the input.
- **Code Snippet:**
  ```
  0x0000606c      0b00a0e1       mov r0, fp
  0xREDACTED_PASSWORD_PLACEHOLDER      24109de5       ldr r1, [var_24h]
  0xREDACTED_PASSWORD_PLACEHOLDER      ccebffeb       bl loc.imp.strcpy
  ```
- **Keywords:** iptc_commit, strcpy, libnetconf.so, fp, arg1
- **Notes:** vulnerability

---
