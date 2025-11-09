# FH1201 (1 alerts)

---

### httpd-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x46f0d0 (formexeCommand)`
- **Risk Score:** 9.5
- **Confidence:** 9.25
- **Description:** The formexeCommand function executes user-provided commands (via the cmdinput parameter) through doSystemCmd without any filtering or validation, resulting in a command injection vulnerability. Attackers can inject arbitrary commands by crafting specially designed HTTP requests.
- **Code Snippet:**
  ```
  0x0046f0c4      f487858f       lw a1, -obj.path_buf(gp)
  0x0046f0c8      a087998f       lw t9, -sym.imp.doSystemCmd(gp)
  0x0046f0cc      REDACTED_PASSWORD_PLACEHOLDER       nop
  0x0046f0d0      09f82003       jalr t9
  ```
- **Keywords:** formexeCommand, doSystemCmd, cmdinput
- **Notes:** Further verification is required regarding the specific implementation of doSystemCmd, but current evidence already indicates the presence of high-risk command injection vulnerabilities.

---
