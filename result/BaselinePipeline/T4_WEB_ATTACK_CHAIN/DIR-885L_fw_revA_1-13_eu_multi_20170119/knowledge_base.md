# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (5 alerts)

---

### command-injection-fileaccess.cgi

- **File/Directory Path:** `htdocs/fileaccess.cgi`
- **Location:** `htdocs/fileaccess.cgi:0xd874`
- **Risk Score:** 9.5
- **Confidence:** 8.25
- **Description:** A high-risk command injection vulnerability was discovered in fileaccess.cgi. Attackers can craft malicious commands by manipulating input parameters, which are then formatted using sprintf and directly passed to the system function for execution. The vulnerability resides in function fcn.0000d634, where command strings are constructed using the format specifiers 'upnpc -z ssl -c %s -m %s' and 'upnpc -z wfa -c %s -m %s'.
- **Code Snippet:**
  ```
  sym.imp.sprintf(piVar4 + 0 + -0x638,0x5b80 | 0x30000,piVar4[-0x1a4] + 4,piVar4 + 0 + -0x684);
  sym.imp.system(piVar4 + 0 + -0x638);
  ```
- **Keywords:** fcn.0000d634, sym.imp.system, sym.imp.sprintf, upnpc -z ssl -c %s -m %s, upnpc -z wfa -c %s -m %s
- **Notes:** Further analysis is required to determine how HTTP request parameters map to the parameters of these format strings in order to identify specific attack vectors. It is recommended to patch this vulnerability immediately.

---
### multiple-system-calls-cgibin

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `htdocs/cgibin:fcn.0000e244`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple instances of directly invoking the system function to execute shell commands were identified in the cgibin binary. Specifically, within the function fcn.0000e244, several system call points (0xe968, 0xe974, 0xe980) were found, utilizing hardcoded paths to execute scripts (e.g., 'REDACTED_PASSWORD_PLACEHOLDER_config.sh'). These calls lack sufficient input validation, posing a command injection risk.
- **Keywords:** system, fcn.0000e244, decrypt_config.sh, cgibin
- **Notes:** Further verification is needed to determine whether these system calls can be triggered via HTTP request parameters. It is recommended to inspect all contexts where these functions are invoked.

---
### dangerous-shell-scripts-web

- **File/Directory Path:** `htdocs/web`
- **Location:** `htdocs/web`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Multiple shell script execution paths have been identified, including '/etc/events/checkfw.sh', '/var/run/wand_activate_%d.sh', etc. These script paths may be exploited through crafted HTTP requests, particularly when the paths contain user-controllable parameters. A potential command injection risk exists.
- **Keywords:** checkfw.sh, wand_activate, shell_actionsh, system
- **Notes:** It is necessary to verify whether these script paths can be controlled through web interface parameters. It is recommended to restrict script execution paths.

---
### multiple-system-calls-cgibin-2

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `['htdocs/cgibin:0xf81c (fcn.0000ec7c)', 'htdocs/cgibin:0xf828 (fcn.0000ec7c)', 'htdocs/cgibin:0xf834 (fcn.0000ec7c)']`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Multiple dangerous system calls were found at addresses 0xf81c-0xf834 in the cgibin binary, performing file deletion (rm -rf) and script execution (dlsyslog_hlper.sh) operations. Although no direct user input injection was identified, command concatenation risks exist.
- **Keywords:** sym.imp.system, fcn.0000ec7c, rm -rf, dlsyslog_hlper.sh
- **Notes:** Dynamic analysis is required to confirm whether these commands could be influenced by user input. It is recommended to examine all functions calling fcn.0000ec7c to verify the source of parameters.

---
### unsafe-string-functions-cgibin

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `htdocs/cgibin`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The use of unsafe string functions such as strcpy was identified in the cgibin binary, potentially leading to buffer overflow vulnerabilities. If the length of HTTP request parameters is not properly validated when processed by these functions, they could be exploited.
- **Keywords:** strcpy, strcat, sprintf, cgibin
- **Notes:** buffer_overflow

It is necessary to analyze whether these functions handle user-controllable input. It is recommended to replace them with secure string handling functions.

---
