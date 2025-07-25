# _DWR-118_V1.01b01.bin.extracted (8 alerts)

---

### stack_overflow-EzSetup-Apply_ezConfig

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x41d7b0 (sym.Apply_ezConfig)`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** High-Risk Stack Buffer Overflow Vulnerability (EzSetup Configuration Handling):
- Trigger Condition: Attacker sends an HTTP request with message ID 0x1000f (path associated with /cgi-bin/ezsetup), submitting malicious parameters exceeding 6 bytes in length
- Vulnerability Mechanism: Apply_ezConfig function performs 12 iterations of copying user data into a 6-byte stack buffer (auStack_28)
- Boundary Check: No length validation, relying solely on assumed fixed length of source data
- Security Impact: Overwrites return address to achieve arbitrary code execution (RCE) with high success probability
- Complete Exploit Chain: HTTP Request → ws_select_service → ws_parse_form → Apply_ezConfig
- **Keywords:** Apply_ezConfig, ws_select_service, 0x1000f, auStack_28, puStack_600, EzSetup
- **Notes:** Dynamic verification required: 1) Construction method of 0x1000f message 2) Actual call path of ws_parse_form

---
### command_execution-telnetd-BIND_PORT_injection

- **File/Directory Path:** `usr/bin/telnetd-action`
- **Location:** `bin/telnetd-action:24`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** A high-risk command injection vulnerability was identified in the telnetd-action startup script: the $BIND_PORT variable (sourced from rdcsman) is directly concatenated into the telnetd startup command without sanitization. Trigger condition: An attacker must manipulate the rdcsman data source (e.g., via NVRAM/web interface) and trigger a service restart. Successful injection could lead to arbitrary command execution with REDACTED_PASSWORD_PLACEHOLDER privileges. REDACTED_PASSWORD_PLACEHOLDER constraints: 1) The rdcsman data source must be externally controllable; 2) Service management privileges are required to trigger a restart. Actual security impact: If a pollution path exists, it could form a complete RCE attack chain.
- **Code Snippet:**
  ```
  telnetd $LANIP $BIND_PORT
  ```
- **Keywords:** BIND_PORT, rdcsman, telnetd, 0xREDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Immediate verification required: 1) Implementation location and data source of rdcsman 2) Access control mechanism for NVRAM configuration items

---
### command_execution-telnetd-action-root_privilege

- **File/Directory Path:** `usr/bin/telnetd-action`
- **Location:** `bin/telnetd-action`
- **Risk Score:** 8.5
- **Confidence:** 8.75
- **Description:** The telnetd-action script runs the telnetd service with REDACTED_PASSWORD_PLACEHOLDER privileges. Verification basis: 1) File permissions are set to 777. 2) PID file is written to the /var/run directory. 3) No privilege downgrade operation is performed. Trigger condition: System startup or service management process invokes the script. Security impact: Vulnerabilities in telnetd will directly lead to REDACTED_PASSWORD_PLACEHOLDER privilege compromise.
- **Keywords:** telnetd-action, start(), PIDFILE, /var/run

---
### hardware_input-usblist-command_injection

- **File/Directory Path:** `sbin/usblist`
- **Location:** `sbin/usblist:sym.load_driver@0x00407a38`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A high-risk command injection vulnerability was discovered in the `sym.load_driver` function. The program parses Vendor/Product IDs (iStack_20/iStack_1c parameters) of USB devices from `REDACTED_PASSWORD_PLACEHOLDER` and directly concatenates them into the `modprobe usbserial vendor=0x%x product=0x%x` command (executed via system) without validation. Attackers can execute arbitrary commands by forging malicious USB devices with injected special characters (e.g., `; rm -rf /`). Trigger conditions: 1) Physically connecting a malicious USB device; 2) The device providing ID values containing special characters. Successful exploitation could lead to complete device compromise.
- **Code Snippet:**
  ```
  (**(iVar4 + -0x7e60))(*(iVar4 + -0x7fd8) + 0x72dc,iStack_20,iStack_1c);
  (**(iVar4 + -0x7e88))(command_string);
  ```
- **Keywords:** iStack_20, iStack_1c, modprobe usbserial vendor=0x%x product=0x%x, REDACTED_PASSWORD_PLACEHOLDER, system, sscanf
- **Notes:** Requires physical access to the device. Related vulnerability: Buffer overflow risk exists in the main function of the same file (sharing /proc input source).

---
### file_read-usblist-buffer_overflow

- **File/Directory Path:** `sbin/usblist`
- **Location:** `usblist:main@0x00400fe2`
- **Risk Score:** 8.0
- **Confidence:** 5.75
- **Description:** Parsing REDACTED_PASSWORD_PLACEHOLDER poses a buffer overflow risk. After reading file contents via fgets, unvalidated data (such as vendor names) is copied into the fixed-size stack buffer auStack_130 (only 12 bytes) using sscanf. Attackers manipulating /proc files to inject oversized data could overwrite return addresses. Trigger conditions: 1) Attacker requires write permissions to /proc filesystem 2) Injection of spoofed device data containing oversized fields. Successful exploitation could lead to arbitrary code execution.
- **Code Snippet:**
  ```
  iVar2 = (**(iStack_270 + -0x7e7c))(auStack_230,0x100,uVar1);
  (**(iStack_270 + -0x7ed4))(auStack_230,*(iStack_270 + -0x7f7c) + -0x6afc,auStack_130,...);
  ```
- **Keywords:** sscanf, auStack_130, REDACTED_PASSWORD_PLACEHOLDER, fgets, system
- **Notes:** Verify the actual attack surface of /proc write permissions. Related vulnerability: the same data flow triggers command injection (shared system call).

---
### url_decode-httpd-0x40a268

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x40a268`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Double Vulnerabilities in URL Decoding Function:
- Out-of-Bounds Read: Reads illegal memory when fewer than two characters follow % (e.g., %x) → Information Leak/DoS
- Uninitialized Data Pollution: Non-hexadecimal characters after % (e.g., %zz) cause auStack_10 to use uninitialized values → Configuration Pollution
- Trigger Condition: HTTP parameters contain malformed % sequences
- Boundary Checks: No validation for character existence after %, no hexadecimal validity check
- Related Function: fcn.0040a268 ← ws_parse_form
- **Keywords:** fcn.0040a268, pcStack_18, auStack_10, %, ws_parse_form

---
### env_set-tainted_paths

- **File/Directory Path:** `usr/etc/profile`
- **Location:** `usr/etc/profile:3-4`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** The PATH environment variable contains a non-standard directory '/mydlink', and LD_LIBRARY_PATH includes '/ram/lib' and '/mydlink'. If an attacker can plant malicious binary/library files in these directories, they could achieve hijacking when privileged processes execute. Trigger condition: When any process (especially privileged ones) utilizing these environment variables executes commands or loads dynamic libraries. Constraint: The attacker must have write permissions to the target directories. Security impact: May lead to arbitrary code execution or privilege escalation.
- **Code Snippet:**
  ```
  export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/bin/scripts:/mydlink
  export LD_LIBRARY_PATH=/ram/lib:/lib:/lib/iptables:/mydlink
  ```
- **Keywords:** PATH, LD_LIBRARY_PATH, /mydlink, /ram/lib
- **Notes:** Verify the permissions of the /mydlink and /ram/lib directories. If the directories are globally writable (e.g., with 777 permissions), the risk level will significantly increase.

---
### buffer_overflow-httpd-httpd_get_config

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x408a4c`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** sprintf Buffer Overflow Risk:
- Trigger Condition: When ioctl returns an excessively long string
- Vulnerability Mechanism: The combined length of the format string "%s:%u" in httpd_get_config may exceed the 128-byte target buffer
- Boundary Check: No output length restriction
- Potential Impact: Global data structure corruption leading to service crash or logical vulnerabilities
- **Keywords:** httpd_get_config, acStack_58, uStack_14, 0x408a4c

---
