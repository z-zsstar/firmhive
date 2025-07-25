# _DCS-935L_A1_FW_1.10.01_REDACTED_PASSWORD_PLACEHOLDER_r4156.bin.extracted (7 alerts)

---

### command-injection-param.cgi-system

- **File/Directory Path:** `web/cgi-bin/cgi/param.cgi`
- **Location:** `web/cgi-bin/cgi/param.cgi (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** Multiple instances of direct calls to the system() function were found in param.cgi, where command strings are partially constructed from HTTP parameters. Attackers can inject arbitrary commands by crafting malicious parameters, particularly when handling configuration items such as System.Info, Network, and SMTP, which directly execute commands like service restarts.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** system, /usr/sbin/msger, /etc/init.d/, System.Info, Network, SMTP
- **Notes:** Special attention must be paid to the risk of command injection when handling parameters such as System.Info and Network.

---
### buffer-overflow-httpd-strcpy

- **File/Directory Path:** `web/httpd`
- **Location:** `web/httpd:0x403fc4`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A buffer overflow vulnerability was identified in the web/httpd component due to the use of the unsafe strcpy function when processing parameters in HTTP requests. At address 0x00403fc4, strcpy is used to copy the peer address into a buffer without verifying the size of the destination buffer.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** strcpy, skGetPeer6, var_28h
- **Notes:** An attacker may trigger a buffer overflow by crafting a specially designed HTTP request

---
### command-injection-hnap_service-system

- **File/Directory Path:** `web/cgi-bin/hnap/hnap_service`
- **Location:** `web/cgi-bin/hnap/hnap_service:main`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The main function was found to directly use system calls to execute commands, including actions such as resetting WiFi and restarting the HTTPS service. These commands are triggered via HTTP requests, posing a risk of command injection.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** system, /usr/sbin/msger, /etc/init.d/https-0 restart, /usr/sbin/set_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Verify whether all system calls have properly filtered user input

---
### command-injection-dcp_class3_handler-sprintf

- **File/Directory Path:** `mydlink/dcp`
- **Location:** `mydlink/dcp:0xREDACTED_PASSWORD_PLACEHOLDER sym.dcp_class3_handler`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Command injection vulnerability was identified in the dcp_class3_handler function where unvalidated external input is used to construct system command strings. Attackers could inject malicious commands through specially crafted HTTP requests. The function employs sprintf to build command strings, creating potential command injection risks.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7d34))(iVar12,0x1000,"3;M=%s;D=%s;R=%d;0=%c;1=%s;2=%s;3=%s;4=%s;5=%s;6=%c;7=%s;8=%s;9=%c;10=%c;11=%s;14=%c;15=%c;18=%s;23=%s;24=%s;25=%s;26=%s;27=%s;50=%s;51=%s",param_2 + 200,param_2 + 0x84,1,uStack_74,puStack_6c,puStack_68,puStack_64,puStack_60,puStack_70,iStack_48,puStack_7c,puStack_8c,iStack_3c,iStack_40,puStack_80,iStack_44,iStack_38,puStack_90,puStack_50,puStack_4c,puStack_5c,puStack_58,puStack_54,auStack_1ad0,auStack_1ac8);
  ```
- **Keywords:** dcp_class3_handler, sprintf, system_shell_cmd
- **Notes:** Ensure all input parameters are properly validated and escaped

---
### buffer-overflow-dcp_class7_handler-strcpy

- **File/Directory Path:** `mydlink/dcp`
- **Location:** `mydlink/dcp:0x0040829c sym.dcp_class7_handler`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The dcp_class7_handler function contains a REDACTED_PASSWORD_PLACEHOLDER reset feature that uses strcpy and strncpy to process user input, which may lead to buffer overflow. Attackers could craft specific requests to overwrite adjacent memory.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7e7c))(auStack_12c8,iVar6,0x9c);
  (**(loc._gp + -0x7d64))(auStack_12c8);
  ```
- **Keywords:** dcp_class7_handler, strcpy, strncpy
- **Notes:** buffer_overflow

---
### buffer-overflow-param.cgi-strncpy

- **File/Directory Path:** `web/cgi-bin/cgi/param.cgi`
- **Location:** `web/cgi-bin/cgi/param.cgi (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The program uses unsafe functions like strncpy to handle user input, posing a risk of buffer overflow. Particularly when processing long fields such as OverlayText and FriendlyName, it may lead to memory corruption.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** strncpy, OverlayText, FriendlyName, ServerName, ESSID
- **Notes:** Check the boundary conditions for all string handling functions

---
### ssrf-dcp_class8_handler-dns_query

- **File/Directory Path:** `mydlink/dcp`
- **Location:** `mydlink/dcp:0x00407e2c sym.dcp_class8_handler`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The dcp_class8_handler function contains DNS query functionality, which could be exploited for SSRF attacks. Attackers can control the target hostname being queried.
- **Code Snippet:**
  ```
  iVar1 = (**(loc._gp + -0x7ec4))(pcVar5,uVar2);
  ```
- **Keywords:** dcp_class8_handler, DNS_query, SSRF
- **Notes:** Implement whitelist restrictions for allowed hostname queries.

---
