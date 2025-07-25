# _DWR-118_V1.01b01.bin.extracted - Verification Report (2 alerts)

---

## command_execution-telnetd-action-root_privilege

### Original Information
- **File/Directory Path:** `usr/bin/telnetd-action`
- **Location:** `bin/telnetd-action`
- **Description:** The telnetd-action script runs the telnetd service with REDACTED_PASSWORD_PLACEHOLDER privileges. Verification basis: 1) File permissions are set to 777. 2) PID file is written to the /var/run directory. 3) No privilege downgrade operation is performed. Trigger condition: System startup or service management process calls the script. Security impact: Vulnerabilities in telnetd will directly lead to REDACTED_PASSWORD_PLACEHOLDER privilege compromise.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Evidence fully validates the findings described: 1) File permissions 777 confirmed 2) PID file written to /var/run confirmed 3) No privilege downgrade operation confirmed. The script executes the telnetd startup command with REDACTED_PASSWORD_PLACEHOLDER privileges and lacks any access control or privilege restriction mechanisms. When the system boots or when the service management process invokes this script, the telnet service is directly exposed with REDACTED_PASSWORD_PLACEHOLDER privileges. Attackers exploiting telnetd vulnerabilities can immediately obtain REDACTED_PASSWORD_PLACEHOLDER access, forming a complete and directly triggerable attack chain.

### Verification Metrics
- **Verification Duration:** 164.29 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 39173

---

## url_decode-httpd-0x40a268

### Original Information
- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x40a268`
- **Description:** URL Decode Function Double Vulnerability:
- Out-of-Bounds Read: Reads illegal memory when fewer than two characters follow % (e.g., %x) → Information Leak/DoS
- Uninitialized Data Pollution: Non-hexadecimal characters after % (e.g., %zz) cause auStack_10 to use uninitialized values → Configuration Item Pollution
- Trigger Condition: HTTP parameters contain malformed % sequences
- Boundary Check: No validation for existence of characters after %, no hexadecimal validity check
- Associated Function: fcn.0040a268 ← ws_parse_form

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The disassembly evidence is conclusive: 1) An out-of-bounds read vulnerability exists at 0x40a368-0x40a384 (%x triggers sscanf to read illegal memory) 2) Uninitialized stack variable auStack_10 is used at 0x40a394 (%zz causes contamination) 3) No boundary check (0x40a388 directly performs pcStack_18+=3) 4) ws_parse_form directly passes user-supplied HTTP parameters. The vulnerability can be triggered by a single malformed HTTP request, forming a complete attack chain.

### Verification Metrics
- **Verification Duration:** 803.96 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 264760

---

