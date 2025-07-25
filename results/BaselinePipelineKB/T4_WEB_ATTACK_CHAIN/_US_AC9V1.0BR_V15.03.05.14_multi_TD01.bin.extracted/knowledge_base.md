# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (4 alerts)

---

### telnetd-cmd-injection-TendaTelnet

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x4f99c (sym.TendaTelnet)`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Found command injection vulnerability in the TendaTelnet function of the HTTPD web server. The function executes system commands using user-controlled input without proper sanitization. Specifically: 1) Directly calls 'killall -9 telnetd' via system(), and 2) Constructs a 'telnetd -b [user_input] &' command using doSystemCmd where user_input is obtained from GetValue without validation. An attacker could inject malicious commands through the telnetd binding address parameter.
- **Code Snippet:**
  ```
  mov r0, r3                  ; const char *string
  bl sym.imp.system           ; int system(const char *string)
  ...
  mov r0, r2                  ; 0xdf774 ; "telnetd -b %s &"
  mov r1, r3
  bl sym.imp.doSystemCmd
  ```
- **Keywords:** TendaTelnet, system, doSystemCmd, telnetd, GetValue, httpd, web_server
- **Notes:** command_execution

---
### command-injection-TendaTelnet-4f99c

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x4f99c`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function sym.TendaTelnet contains a call to system() with a command constructed from GetValue() input (puVar4 + iVar1 + -300). This represents a command injection vulnerability if the input is not properly sanitized before being passed to doSystemCmd(). The function also makes a direct system() call with a hardcoded command. This appears to be related to telnet functionality. An attacker could potentially inject commands through unvalidated input.
- **Keywords:** sym.TendaTelnet, system, doSystemCmd, GetValue, telnet
- **Notes:** command_execution

---
### cmd-injection-TendaTelnet-4f99c

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x4f99c`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** command_execution
- **Keywords:** sym.TendaTelnet, system, GetValue, doSystemCmd, telnet
- **Notes:** command_execution

---
### potential-cmd-injection-a60c0

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xa60c0`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** command_execution
- **Keywords:** 0xa60c0, system, sprintf, sym.fill_REDACTED_PASSWORD_PLACEHOLDER_input_file
- **Notes:** command_execution

---
