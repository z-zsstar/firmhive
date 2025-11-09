# R8500 (1 alerts)

---

### web-cgi-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0xac68 (fcn.0000ac68)`
- **Risk Score:** 9.5
- **Confidence:** 9.25
- **Description:** The genie.cgi program contains a command injection vulnerability, allowing attackers to inject arbitrary commands through the QUERY_STRING parameter. The program directly executes insufficiently validated user input via popen, leading to remote code execution risks.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.popen(piVar4[-0x102],0xb6e0);
  *piVar4 = iVar1;
  if (*piVar4 != 0) {
      *piVar4[-0x104] = 0;
      *piVar4[-0x103] = 0;
  ```
- **Keywords:** QUERY_STRING, popen, genie.cgi, fcn.0000ac68, fcn.000093e4
- **Notes:** An attacker can inject commands through the query string of an HTTP request, such as `?t=$(malicious_command)`.

---
