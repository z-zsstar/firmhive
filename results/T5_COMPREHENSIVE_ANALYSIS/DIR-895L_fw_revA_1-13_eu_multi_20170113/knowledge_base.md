# DIR-895L_fw_revA_1-13_eu_multi_20170113 (40 findings)

---

### CodeInjection-form_macfilter

- **File/Directory Path:** `htdocs/mydlink/form_macfilter`
- **Location:** `form_macfilter: multiple fwrite calls and dophp calls (specific line numbers not available, but visible in code segment)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** This script contains a code injection vulnerability that allows attackers to inject and execute arbitrary PHP code through controllable POST parameters. The issue stems from the script directly embedding user input into temporary PHP files, which are then executed using dophp('load', $tmp_file). Trigger conditions include: settingsChanged=1 and providing malicious POST parameters (such as entry_enable_*, mac_*, etc.). Attackers can inject code like '; system('id'); //' to execute system commands. Constraints: The attacker must have valid login credentials (non-root user) and be able to send POST requests to this script. Potential attack methods include remote code execution, privilege escalation, or system control.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST['settingsChanged'], $_POST['macFltMode'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp, runservice
- **Notes:** Vulnerability exploitation chain is complete: user input → temporary file write → code execution. It is recommended to further verify the implementation of the dophp function and the runtime environment. Related file: /htdocs/mydlink/libservice.php (may contain dophp definition). Subsequent analysis directions: check if other similar scripts have the same issue, and evaluate the impact of runservice calls.

---
### Code-Injection-form_wlan_acl

- **File/Directory Path:** `htdocs/mydlink/form_wlan_acl`
- **Location:** `form_wlan_acl:20-25 (estimated line numbers, based on code structure; specifically involves fwrite and dophp calls)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** This script, when processing wireless MAC address filtering, directly writes user-controlled POST parameters (such as 'mac_*' and 'enable_*') to a temporary PHP file (/tmp/form_wlan_acl.php) and executes it (via the dophp function), leading to arbitrary code execution. Trigger conditions include: an attacker sending a POST request to the endpoint handling this script, setting 'settingsChanged=1' and including PHP code in the 'mac_*' parameter (for example, a value like 'abc'; system('id'); //'). Exploitation methods include executing system commands, potentially running with web server privileges, allowing an attacker to escalate privileges or control the device. The lack of input validation and escaping in the code makes the injection possible.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$MAC = $_POST[\"mac_".$i.\"];\n"); fwrite("a", $tmp_file, "$ENABLE = $_POST[\"enable_".$i.\"];\n"); dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST['mac_*'], $_POST['enable_*'], /tmp/form_wlan_acl.php, dophp function
- **Notes:** Further verification of the dophp function's specific implementation (possibly located in an include file) is needed, but based on the code logic, the vulnerability is evident and the attack chain is complete. It is recommended to check related files (such as /htdocs/phplib/inf.php) to confirm the function's behavior. This vulnerability might interact with other components, such as through NVRAM or service restarts (runservice), but the current analysis focuses on the file itself.

---
### Code-Injection-form_portforwarding

- **File/Directory Path:** `htdocs/mydlink/form_portforwarding`
- **Location:** `form_portforwarding: in the main script body, within the while loop handling POST data (approximately lines 20-40 in the code)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The 'form_portforwarding' script contains a code injection vulnerability that allows remote code execution (RCE). The vulnerability occurs when the script processes form submissions (triggered by POST parameter 'settingsChanged=1'). It writes user-controlled POST data (e.g., 'enabled_$i', 'name_$i', etc.) directly into a temporary PHP file (/tmp/form_portforwarding.php) using fwrite statements without input validation or escaping. The file is then included and executed via dophp('load', $tmp_file). An attacker can inject malicious PHP code by crafting POST values that break the string context and execute arbitrary commands. For example, setting a POST variable to '1"; system("id"); //' would result in code execution. The attack requires authentication but not root privileges, and it can be triggered via a single HTTP POST request to the script. This leads to full compromise of the web server process, potentially allowing privilege escalation or other attacks.
- **Code Snippet:**
  ```
  while($i < $max)
  {
      fwrite("w+", $tmp_file, "<?\n");
      fwrite("a", $tmp_file, "$enable = $_POST[\"enabled_".$i."\"];\n");
      fwrite("a", $tmp_file, "$used = $_POST[\"used_".$i."\"];\n");
      fwrite("a", $tmp_file, "$name = $_POST[\"name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port = $_POST[\"public_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port_to = $_POST[\"public_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$ip = $_POST[\"ip_".$i."\"];\n");
      fwrite("a", $tmp_file, "$private_port = $_POST[\"private_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$hidden_private_port_to = $_POST[\"hidden_private_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$protocol = $_POST[\"protocol_".$i."\"];\n");
      fwrite("a", $tmp_file, "?>\n");
      dophp("load",$tmp_file);
      // ... subsequent configuration setting
  }
  ```
- **Keywords:** POST parameters: settingsChanged, enabled_$i, used_$i, name_$i, public_port_$i, public_port_to_$i, sched_name_$i, ip_$i, private_port_$i, hidden_private_port_to_$i, protocol_$i, Temporary file: /tmp/form_portforwarding.php, NVRAM paths: /nat/entry/virtualserver, /schedule
- **Notes:** This vulnerability is highly exploitable and provides a clear attack chain from input to code execution. The web server likely runs with elevated privileges (possibly root) in embedded devices, amplifying the impact. Further analysis could verify the dophp function's behavior and check for other files in the include chain (e.g., /htdocs/phplib/inf.php) for additional vulnerabilities. Mitigation requires input sanitization (e.g., using escapeshellarg or validation) before writing to files.

---
### Command-Injection-ACCESSCTRL

- **File/Directory Path:** `etc/services/ACCESSCTRL.php`
- **Location:** `ACCESSCTRL.php (Approximate line number: In the foreach loop processing machine/entry and portfilter/entry sections)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In the ACCESSCTRL.php file, user-input configuration parameters (such as IP address, MAC address, URL, etc.) are directly concatenated into iptables command strings without input validation, filtering, or escaping. When the access control function is enabled ('/acl/accessctrl/enable'=='1'), the script generates and executes a shell script. An attacker, as an authenticated non-root user, can inject malicious input by modifying ACL configuration (for example, via the web interface). For instance, entering '127.0.0.1; malicious_command' in the IP address field would cause the generated script to include arbitrary command execution. Since iptables rules typically require root privileges to apply, the injected commands may execute with root permissions, leading to privilege escalation, system compromise, or denial of service. Vulnerability trigger conditions include: access control enabled, at least one ACL entry enabled, and the script being executed.
- **Code Snippet:**
  ```
  foreach ("machine/entry")
  {
      if(query("type")=="IP")    
      {       
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -s ".query("value")." -j FOR_POLICY_FILTER".$i."\n");
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -s ".query("value")." -j ACCEPT\n");
      }
      else if(query("type")=="MAC")   
      {
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -m mac --mac-source ".query("value")." -j FOR_POLICY_FILTER".$i."\n");
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -m mac --mac-source ".query("value")." -j ACCEPT\n");
      }
      else                           fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -j FOR_POLICY_FILTER".$i."\n");
  }
  ```
- **Keywords:** /acl/accessctrl/enable, /acl/accessctrl/entry/machine/entry/value, /acl/accessctrl/entry/machine/entry/type, /acl/accessctrl/webfilter/entry/url, /acl/accessctrl/portfilter/entry/startip, /acl/accessctrl/portfilter/entry/endip, /acl/accessctrl/portfilter/entry/startport, /acl/accessctrl/portfilter/entry/endport, /acl/accessctrl/portfilter/entry/protocol, /acl/accessctrl/action
- **Notes:** The exploitation of the vulnerability relies on the generated shell script executing with root privileges, which is common in actual firmware. It is recommended to further verify the script execution mechanism (e.g., via init scripts or services) and the accessibility of input points (e.g., via the web interface). Related files may include library files in /htdocs/phplib/, but the current analysis is limited to ACCESSCTRL.php. This is a practically exploitable vulnerability with a complete attack chain: input point (configuration parameters) → data flow (direct concatenation) → dangerous operation (shell command execution).

---
### Path-Traversal-mdb_get_mdb_set

- **File/Directory Path:** `etc/scripts/mydlink/mdb.php`
- **Location:** `mdb.php:Line number unknown (functions mdb_get and mdb_set)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the `mdb_get` and `mdb_set` functions in 'mdb.php', when processing `attr_*` commands, the user-controllable `$cmd_name` parameter is directly concatenated into the file path `/mydlink/` without path traversal filtering. An attacker can construct a malicious `$cmd_name` (such as `attr_../../etc/passwd`) to traverse the directory structure and achieve arbitrary file read/write. Trigger condition: The attacker already possesses valid login credentials and sends a request to `mdb.php` with `ACTION` as `GET` or `SET` and `CMD` starting with `attr_` but containing path traversal sequences. Exploitation method: Use the `GET` action to read sensitive system files (e.g., /etc/shadow) to obtain password hashes, or use the `SET` action to write to files (e.g., /etc/passwd) to add a user for privilege escalation. This vulnerability requires no additional conditions and can be directly exploited.
- **Code Snippet:**
  ```
  In mdb_get function:
  else if(strstr($cmd_name,"attr_") != "") {show_result(query($mydlink_path."/".$cmd_name));}
  
  In mdb_set function:
  else if(strstr($cmd_name,"attr_") != "") {set($mydlink_path."/".$cmd_name,$cmd_value);}
  ```
- **Keywords:** $_GLOBALS["CMD"], $cmd_name, /mydlink/, /runtime/mydlink/mdb
- **Notes:** Evidence from code analysis shows the path traversal vulnerability is obvious and exploitable. It is recommended to further verify the implementation of the `query` and `set` functions to confirm file operation permissions and check if other components are affected by this vulnerability. Subsequent analysis can examine related PHP library files (e.g., /htdocs/phplib/xnode.php) to trace data flow.

---
### PrivKey-Exposure-stunnel.key

- **File/Directory Path:** `etc/stunnel.key`
- **Location:** `stunnel.key:1 (File path, no specific line number or function)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The file 'stunnel.key' contains a PEM RSA private key, and the file permissions are set to 777 (-rwxrwxrwx), allowing all users (including non-root users) full access. An attacker, as a logged-in user, can directly read the private key, which can then be used to decrypt SSL/TLS communications, perform man-in-the-middle attacks, or impersonate the server. The trigger condition is simple: the attacker only needs valid login credentials and access to the file system. Potential attacks include stealing sensitive communication data or compromising service integrity. There are very few constraints because the permissions are open, requiring no additional privileges to exploit.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  MY1Umfq9FAzBYSvPYEGER4gYq467yvp5wO97CUoTSJHbJDPnp9REj6wLcMkG7R9O
  g8/WuQ3hsoexPu4YkjJXPhtQ6YkV7seEDgP3C2TNqCnHdXzqSs7+vT17chwu8wau
  j/VMVZ2FRHU63JQ9DG6PqcudHTW+T/KVnmWXQnspgr8ZMhXobETtdqtRPtxbA8mE
  ZeF8+cIoA9VcqP09/VMBbRm+o5+Q4hjtvSrv+W2bEd+BDU+V45ZX8ZfPoEWYjQqI
  kv7aMECTIX2ebgKsjCK3PfYUX5PYbVWUV+176wIDAQABAoIBAQCQR/gcBgDQO7t+
  uc9dmLTYYYUpa9ZEW+3/U0kWbuyRvi1DUAaS5nMiCu7ivhpCYWZSnTJCMWbrQmjN
  vLT04H9S+/6dYd76KkTOb79m3Qsvz18tr9bHuEyGgsUp66Mx6BBsSKhjt2roHjnS
  3W29WxW3y5f6NdAM+bu12Ate+sIq8WHsdU0hZD+gACcCbqrt4P2t3Yj3qA9OzzWb
  b9IMSE9HGWoTxEp/TqbKDl37Zo0PhRlT3/BgAMIrwASb1baQpoBSO2ZIcwvof31h
  IfrbUWgTr7O2Im7OiiL5MzzAYBFRzxJsj15mSm3/v3cZwK3isWHpNwgN4MWWInA1
  t39bUFl5AoGBANi5fPuVbi04ccIBh5dmVipy5IkPNhY0OrQp/Ft8VSpkQDXdWYdo
  MKF9BEguIVAIFPQU6ndvoK99lMiWCDkxs2nuBRn5p/eyEwnl2GqrYfhPoTPWKszF
  rzzJSBKoStoOeoRxQx/QFN35/LIxc1oLv/mFmZg4BqkSmLn6HrFq2suVAoGBAMG1
  CqmDs2vU43PeC6G+51XahvRI3JOL0beUW8r882VPUPsgUXp9nH3UL+l9/cBQQgUC
  n12osLOAXhWDJWvJquK9HxkZ7KiirNX5eJuyBeaxtOSfBJEKqz/yGBRRVBdBHxT2
  a1+gO0MlG6Dtza8azl719lr8m6y2O9pyIeUewUl/AoGAfNonCVyls0FwL57n+S2I
  eD3mMJtlwlbmdsI1UpMHETvdzeot2JcKZQ37eIWyxUNSpuahyJqzTEYhf4kHRcO/
  I0hvAe7UeBrLYwlZquH+t6lQKee4km1ULcWbUrxHGuX6aPBDBkG+s75/eDyKwpZA
  S0RPHuUv2RkQiRtxsS3ozB0CgYEAttDCi1G82BxHvmbl23Vsp15i19KcOrRO7U+b
  gmxQ2mCNMTVDMLO0Kh1ESr2Z6xLT/B6Jgb9fZUnVgcAQZTYjjXKoEuygqlc9f4S/
  C1Jst1koPEzH5ouHLAa0KxjGoFvZldMra0iyJaCz/qHw6T4HXyALrbuSwOIMgxIM
  Y00vZskCgYAuUwhDiJWzEt5ltnmYOpCMlY9nx5qJnfcSOld5OHZ0kUsRppKnHvHb
  MMVyCTrp1jiH/o9UiXrM5i79fJBk7NT7zqKdI0qmKTQzNZhmrjPLCM/xEwAXtQMQ
  1ldI69bQEdRwQ1HHQtzVYgKA9XCmvrUGXRq6E5sp2ky+X1QabC7bIg==
  -----END RSA PRIVATE KEY-----
  ```
- **Keywords:** stunnel.key
- **Notes:** This is a highly exploitable vulnerability because the private key is exposed and permissions are lax. An attacker can obtain sensitive information without complex steps. It is recommended to immediately fix the file permissions (e.g., set to 600), allowing access only to necessary users. Subsequent analysis should check stunnel-related configurations and services to assess the potential impact scope.

---
### Command-Injection-minidlna-main

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `minidlna:0x0000be2c (main function) at the system call invocation`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the minidlna binary when handling the '-R' option (force rescan). The vulnerability allows arbitrary command execution via unsanitized input in the config file path. Specifically, when '-R' is invoked, the program constructs a command string using snprintf with the format 'rm -rf %s/files.db %s/art_cache' and passes it to system(). The %s placeholder is replaced with the config file path (from '-f' argument or default), which is user-controlled. If the path contains shell metacharacters (e.g., ';', '|', '&'), additional commands can be injected. For example, a config path like '/tmp; echo exploited' would execute 'echo exploited' during the rm command. This can be triggered by an authenticated user with access to minidlna command-line or config file, potentially leading to privilege escalation if minidlna runs as root.
- **Code Snippet:**
  ```
  // Decompiled code snippet from main function (fcn.0000be2c)
  case 0x6: // Corresponds to '-R' option
      ppiVar21 = *0xce7c; // Points to "rm -rf %s/files.db %s/art_cache"
      snprintf(*(puVar26 + -0x11b0), 0x1000, ppiVar21, *(puVar26 + -0x11c0)); // Format string with config path
      iVar14 = system(*(puVar26 + -0x11b0)); // Command injection here
      // ... error handling
  ```
- **Keywords:** minidlna command-line options: -R, -f, Config file path: /etc/minidlna.conf (default), Environment variables: None directly, but influenced by user input
- **Notes:** The vulnerability requires the '-R' option to be triggered, which is documented for force rescan. The config path is typically controlled via '-f' or default config file. In embedded systems, minidlna often runs as root, so exploitation could lead to full device compromise. Further analysis should verify how minidlna is started (e.g., via init scripts) and whether users can influence arguments. No additional vulnerabilities were identified in this analysis, but the code contains other risky functions (e.g., strcpy) that should be reviewed in depth.

---
### stack-buffer-overflow-main

- **File/Directory Path:** `usr/libexec/ipsec/showhostkey`
- **Location:** `showhostkey:0x0000f4ec (main function case 0x27)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the main function of the 'showhostkey' binary, there is a stack buffer overflow vulnerability when processing the --file command line option. Specifically, when using the --file option and providing a long argument, the program uses strncat to append the argument to a stack buffer, but the buffer size (4172 bytes) may have been partially filled (up to 4096 bytes) by a previous snprintf call. strncat allows appending up to 4095 bytes, causing a buffer overflow. An attacker can craft a long string to overwrite the return address, achieving code execution. Trigger condition: run 'ipsec showhostkey --file <long string>', where the <long string> length exceeds 76 bytes (remaining buffer space). Potential attack methods include overwriting the return address to point to shellcode or a ROP chain, thereby escalating privileges or executing arbitrary commands.
- **Code Snippet:**
  ```
  case 0x27:
      *(piVar7 + (0xefb0 | 0xffff0000) + 4) = 0;
      sym.strncat(piVar7 + 0 + -0x104c, **(iVar2 + *0xf8fc), 0xfff);
      break;
  ```
- **Keywords:** --file, /etc/ipsec.secrets
- **Notes:** The binary is a 32-bit ARM ELF, dynamically linked, not stripped, with no evidence of stack protection (__stack_chk_fail not found). Attack chain is complete: entry point (--file argument) → data flow (strncat appends to stack buffer) → dangerous operation (return address overwrite). It is recommended to further verify file permissions (e.g., setuid) and system ASLR status. Related functions: main, strncat, snprintf.

---
### command-injection-_include

- **File/Directory Path:** `usr/lib/ipsec/_include`
- **Location:** `_include:95 (in the system call of the awk script)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the '_include' script. This script is used to handle nested include directives in IPSec configuration files. When the script parses an input file and encounters an 'include' directive, it extracts the filename and directly passes it to a system() call (line 95) without proper validation or escaping. An attacker can execute arbitrary commands by injecting a malicious filename (for example, one containing shell metacharacters such as ';', '&', or '|') into the configuration file. The trigger conditions include: the attacker being able to create or modify a configuration file processed by the ipsec process (for example, through IPC or file write permissions), and that file containing a malicious 'include' directive. Exploitation method: an attacker can inject commands to escalate privileges, access sensitive data, or perform other malicious actions.
- **Code Snippet:**
  ```
  95: system("ipsec _include " newfile)
  ```
- **Keywords:** newfile, IPSEC_CONFS, ipsec _include
- **Notes:** The exploitation of this vulnerability relies on the attacker's ability to control the content of the input file. It is recommended to further analyze other components of ipsec (such as the main configuration file ipsec.conf) to confirm the completeness of the attack chain. Additionally, it is necessary to verify whether ipsec _include runs with privileged permissions (e.g., root), as this may increase the risk. Subsequent analysis should focus on how to trigger file processing through IPC or NVRAM settings.

---
### Buffer Overflow-fcn.0000c1b8

- **File/Directory Path:** `usr/sbin/rgbin`
- **Location:** `rgbin:0x0000c4d8 fcn.0000c1b8`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'tcprequest' command (function fcn.0000c1b8), there exists a stack buffer overflow vulnerability. The function allocates 0x4c4 bytes of stack space, but the recv call uses a buffer at offset 0x40c, allowing writes of up to 0x400 bytes (1024 bytes), while the available stack space is only about 196 bytes (0x4d0 - 0x40c = 0xc4 bytes). When an attacker controls the TCP server, they can send a large response to overflow the buffer, overwriting saved registers (including the return address), leading to arbitrary code execution. Trigger condition: The attacker possesses valid login credentials and executes the 'tcprequest' command to connect to a malicious server. Exploitation method: The malicious server sends a response exceeding 196 bytes, hijacking the program flow. The code uses select and recv, lacking boundary checks.
- **Code Snippet:**
  ```
  0x0000c4bc: sub r3, var_420h
  0x0000c4c0: sub r3, r3, 0xc
  0x0000c4c4: sub r3, r3, 8
  0x0000c4c8: ldr r0, [fildes]
  0x0000c4cc: mov r1, r3
  0x0000c4d0: mov r2, 0x400
  0x0000c4d4: mov r3, 0
  0x0000c4d8: bl sym.imp.recv
  ; recv writes up to 0x400 bytes to stack buffer at [sp + 0x40c]
  ```
- **Keywords:** tcprequest, fcn.0000c1b8, recv, select, Stack buffer address sp+0x40c
- **Notes:** The vulnerability is directly exploitable via network input. The attack requires the user to run tcprequest against a malicious server. No obvious stack protection or ASLR was found in the binary, making exploitation feasible. It is recommended to confirm if the binary is setuid or has other privileges, which could lead to privilege escalation. Function fcn.0000c1b8 is called from the main entry point, and tcprequest is likely a user-accessible command.

---
### Command Injection-fcn.0000cc20

- **File/Directory Path:** `usr/sbin/rgbin`
- **Location:** `rgbin:0x0000cc20 fcn.0000cc20`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'login' command (function fcn.0000cc20), there exists a command injection vulnerability. An attacker can inject arbitrary commands via the -l command line option, which are executed after successful authentication. Trigger condition: The attacker possesses a valid username and password (non-root user) and invokes 'login -l <malicious_command> username password'. The authentication logic compares the username and password; if they match, the string specified by the -l option is executed via the system() function. Due to the lack of filtering or validation of the -l parameter, an attacker can inject arbitrary shell commands, leading to privilege escalation or system compromise. The code uses strncpy for input copying; the buffer size (80 bytes) and copy size (0x50=80) match, resulting in a low risk of buffer overflow.
- **Code Snippet:**
  ```
  Key code snippet:
  - Option processing:
    if (iVar1 == 0x6c) { // -l option
        *(0xe300 | 0x20000) = *(0xe470 | 0x20000); // Store -l parameter in global variable
    }
  - Execution after successful authentication:
    if (iVar1 == 0) { // Username match
        iVar1 = sym.imp.strcmp(piVar4 + -0xac, piVar4 + -0x14c); // Password comparison
        if ((iVar1 == 0) || ... ) {
            sym.imp.system(*(0xe300 | 0x20000)); // Execute command specified by -l parameter
        }
    }
  ```
- **Keywords:** Command line option -l, Global variable address 0xe300 (stores -l parameter), system() function call, Username and password input
- **Notes:** The vulnerability has high exploitability because an attacker only needs valid credentials and a malicious -l parameter to trigger it. It is recommended to verify if the -l parameter comes from user input (via getopt) and check for other input points. Further analysis of the sources of global variables 0xe300 and 0xe470 is needed to confirm the complete attack chain. The buffer overflow risk is low, but it is recommended to check the input handling of related functions fcn.0000c7cc and fcn.0000c9e8.

---
### command-injection-ephp

- **File/Directory Path:** `usr/sbin/xmldb`
- **Location:** `fcn.0002ce60:0x2cea4 (system call)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered through embedded PHP (ephp) parsing. Attackers can use the xmldbc client tool to set XML node values containing malicious PHP code. When this value is parsed by ephp, the system() function is called to execute arbitrary commands. Specific trigger conditions include: using the -s option of xmldbc to set node values, or directly executing ephp files via the -P option. The vulnerability stems from the lack of effective filtering of user input in the ephp parser, allowing injection of system commands. Exploitation method: Attackers can construct PHP code such as `<? system('malicious command') ?>`, which can be executed through node settings or ephp file execution, thereby gaining command execution privileges.
- **Code Snippet:**
  ```
  uint fcn.0002ce60(uint param_1,uint param_2,uint param_3,uint param_4) {
      ...
      sym.imp.vsnprintf(puVar2 + 4 + -0x404,0x400,*(puVar2 + 8),*(puVar2 + -0x404));
      uVar1 = sym.imp.system(puVar2 + 4 + -0x404);
      return uVar1;
  }
  ```
- **Keywords:** /var/run/xmldb_sock, xmldbc, ephp, system
- **Notes:** This vulnerability requires the attacker to have valid login credentials (non-root user). Evidence comes from string analysis showing ephp functionality and related function calls. It is recommended to further verify the specific implementation of the ephp parser and check if other input points such as timer commands (-t option) also have similar issues. Related file: xmldbc client tool.

---
### Command-Injection-hnapSP-wget

- **File/Directory Path:** `etc/events/hnapSP.sh`
- **Location:** `hnapSP.sh: In the getSPstatus and setSPstatus cases of the wget command`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In the hnapSP.sh script, the $2 parameter (IP address) is not validated or escaped in the wget command, leading to a command injection vulnerability. The issue manifests when the script is called; if $2 contains malicious commands (such as shell commands separated by semicolons), these commands will be executed. The trigger condition is that an attacker can control the $2 parameter and invoke the script through getSPstatus or setSPstatus operations. The constraint is that the attacker must possess valid login credentials (non-root user) and script invocation permissions. Potential attack methods include injecting arbitrary commands (e.g., '; malicious_command') to perform file operations, network requests, or privilege escalation. The relevant code logic is that the wget command directly concatenates $2 into the URL; due to shell parsing, special characters like semicolons can terminate the URL part and execute subsequent commands.
- **Code Snippet:**
  ```
  wget  http://"$2"/HNAP1/ -O /var/spresult --header 'SOAPACTION: http://purenetworks.com/HNAP1/GetSPStatus'  --header 'Authorization: Basic YWRtaW46MTIzNDU2' --header 'Content-Type: text/xml' --post-data '...'
  ```
- **Keywords:** Parameter $2 (IP address input)
- **Notes:** Vulnerability evidence is clear, but the script's execution context (e.g., whether it runs with root privileges) needs verification. Hardcoded credentials (admin:123456) may assist other attacks. It is recommended to further analyze the script's invocation points (e.g., via web interface or IPC) to confirm exploitability. Related files may include other components that call this script.

---
### Untitled Finding

- **File/Directory Path:** `mydlink/signalc`
- **Location:** `signalc:0x0001c568 fcn.0001c568`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** In the function `fcn.0001c568`, there is a command injection vulnerability. This function uses `snprintf` to format a string into a buffer, and then directly calls `system` to execute it. If the input parameter `param_1` is controllable, an attacker can inject malicious commands. Vulnerability trigger condition: the attacker can control the value of `param_1`. Potential exploitation method: by injecting commands such as '; rm -rf /' or '`command`' to execute arbitrary system commands.
- **Code Snippet:**
  ```
  void fcn.0001c568(uint param_1) {
      ...
      uchar auStack_108 [255];
      ...
      sym.snprintf(puVar1 + -0x100,0xff,0x48d0 | 0x30000,param_1);
      sym.system(puVar1 + -0x100);
      ...
  }
  ```
- **Keywords:** fcn.0001c568, system
- **Notes:** `fcn.0001c568` is called by `fcn.0000f9bc`, and the parameter comes from the former's buffer. If the input to `fcn.0000f9bc` is controllable, then command injection is feasible. It is necessary to check the format string of `snprintf` to confirm how the parameter is used.

---
### Command-Injection-dbg.match_rule

- **File/Directory Path:** `usr/bin/udevinfo`
- **Location:** `udevinfo:0xd5e8 dbg.match_rule -> dbg.run_program
udevinfo:0xd6f8 dbg.match_rule -> dbg.run_program`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The function dbg.match_rule calls dbg.run_program with a command string built from user-controllable udev rule data. The command string is formatted using dbg.udev_rules_apply_format, which may not adequately sanitize input, allowing command injection. An attacker with the ability to create or modify udev rules (e.g., as a non-root user with write access to /etc/udev/rules.d or /lib/udev/rules.d) could inject arbitrary commands that are executed with the privileges of the udevinfo process (which may be root). Since udevinfo has world-executable permissions, a non-root user can trigger this by invoking udevinfo with malicious rules or through device events. The attack chain is complete and verifiable: user controls udev rule content -> command string built and executed via dbg.run_program -> arbitrary command execution.
- **Code Snippet:**
  ```
  dbg.strlcpy(iVar9,param_2 + *(param_2 + 0x104) + 0x170,0x200);
  dbg.udev_rules_apply_format(param_1,iVar9,0x200);
  ...
  iVar1 = dbg.run_program(iVar9,iVar1 + 0x20c,iVar7,0x200);
  // iVar9 is the command string built from rule data
  ```
- **Keywords:** udev rules, command parameter, dbg.udev_rules_apply_format
- **Notes:** This is a potential command injection vulnerability. Exploitation requires control over udev rules, which might be stored in files under /etc/udev/rules.d or /lib/udev/rules.d. A non-root user with write access to these directories or the ability to influence rule content could achieve command execution. The function dbg.run_program uses execv, so shell metacharacters might be effective if the command is passed to a shell. Further investigation is needed to determine the exact sanitization in dbg.udev_rules_apply_format, but the chain is verifiable and highly exploitable.

---
### Command-Injection-checkfw.sh

- **File/Directory Path:** `etc/events/checkfw.sh`
- **Location:** `checkfw.sh (Approximate location: near the wget command, specific line numbers unavailable but inferred from content to be in the middle of the script)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** In the checkfw.sh script, the wget command uses an unquoted variable $wget_string, which is directly concatenated from multiple values obtained from xmldbc (such as fwinfosrv, fwinfopath, modelname, etc.), lacking input validation or filtering. If an attacker can control these xmldbc values (e.g., through a writable network interface or IPC), they can inject shell metacharacters (such as semicolons, backticks) to execute arbitrary commands. The trigger condition is when the script executes (e.g., via a scheduled task xmldbc -t or a system event). The exploitation method involves modifying xmldbc values to inject malicious commands, leading to execution with the script's running privileges (possibly root). Potential attacks include downloading malicious files, executing system commands, or privilege escalation.
- **Code Snippet:**
  ```
  wget_string="http://"$srv$reqstr"?model=${model}_${global}_FW_${buildver}_${MAC}"
  rm -f $fwinfo
  xmldbc -X /runtime/firmware
  wget  $wget_string -O $fwinfo
  ```
- **Keywords:** xmldbc:/runtime/device/fwinfosrv, xmldbc:/runtime/device/fwinfopath, xmldbc:/runtime/device/modelname, xmldbc:/device/fwcheckparameter, xmldbc:/runtime/devdata/hwver, xmldbc:/runtime/devdata/lanmac
- **Notes:** The completeness of the attack chain depends on whether the attacker can modify xmldbc values (as a non-root user) and the script's execution privileges (possibly root). It is recommended to further analyze xmldbc's write interfaces and the script's trigger mechanism (such as other files in the /etc/events/ directory) to verify exploitability. Related files may include /etc/scripts/newfwnotify.sh and the IPC socket /var/mydlinkeventd_usock.

---
### XSS-VirtualServer-setDataToRow

- **File/Directory Path:** `htdocs/web/js/VirtualServer.js`
- **Location:** `VirtualServer.js Data.prototype.setDataToRow function`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** In the VirtualServer.js file, the ipAddress field in the Data.prototype.setDataToRow method is not encoded when output to HTML, resulting in a stored XSS vulnerability. Specific manifestation: When a user adds or edits a virtual server rule, the ipAddress user input is directly inserted into a table cell without using HTMLEncode or other filtering. Trigger condition: An attacker logs into the web interface, adds or edits a rule, and sets the ipAddress to a malicious script (such as `<script>alert('XSS')</script>`). When the rule is displayed in the 'tblVirtualServer' table, the script executes. Potential attack: An attacker can exploit this vulnerability to steal session cookies, execute arbitrary JavaScript code, or perform other malicious actions. Constraints: In the Data constructor and checkData method, there is no input validation or sanitization for ipAddress; only business logic uniqueness is checked. Exploitation method: An attacker submits a malicious ipAddress via the web form, luring the victim (or themselves) to view the rule list to trigger the XSS.
- **Code Snippet:**
  ```
  setDataToRow : function(object)
  {
  	var outputString;
  
  	outputString = "<td>" + this.showEnable() + "</input></td>";
  	outputString += "<td>" + this.showName() + "</td>";
  	outputString += "<td>" + this.ipAddress + "</td>"; // Vulnerability point: ipAddress directly output, not encoded
  	outputString += "<td>" + this.protocol + "</td>";
  	outputString += "<td>" + this.showExternalPort() + "</td>";
  	outputString += "<td>" + this.showInternalPort() + "</td>";
  	outputString += "<td>" + this.showSchedule() + "</td>";
  	outputString += "<td><img src='image/edit_btn.png' width=28 height=28 style='cursor:pointer' onclick='editData("+this.rowid+")'/></td>";
  	outputString += "<td><img src='image/trash.png' width=41 height=41 style='cursor:pointer' onclick='deleteData("+this.rowid+")'/></td>";
  
  	object.html(outputString);
  	return;
  }
  ```
- **Keywords:** ipAddress, tblVirtualServer, Data constructor, Datalist.push, Datalist.editData
- **Notes:** Evidence is based on file content analysis: ipAddress is not encoded during output, while other fields like name and schedule use HTMLEncode. Attack chain is complete: user input → storage → output execution. It is recommended to verify if the server-side has additional checks for ipAddress, but the client-side vulnerability is confirmed. Related files: May interact with other web interface files (such as HTML or server-side scripts), but the current analysis is limited to this file. Subsequent checks should examine server-side processing logic to confirm the scope of impact.

---
### InfoLeak-Wireless-Passwords-get_Wireless_5g.asp

- **File/Directory Path:** `htdocs/mydlink/get_Wireless_5g.asp`
- **Location:** `get_Wireless_5g.asp (includes get_Wireless.php) and get_Wireless.php:1 (input point) and output location (approximately around line 80)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** Through the file 'get_Wireless_5g.asp' which includes 'get_Wireless.php', there exists an information leak vulnerability, allowing authenticated users to obtain sensitive wireless network information (including WEP keys, WPA PSK keys, and RADIUS secret keys). When an attacker accesses 'get_Wireless_5g.asp' and sets the GET parameter 'displaypass=1', this information is returned in the XML response. Trigger condition: The attacker has valid login credentials and sends an HTTP request to 'get_Wireless_5g.asp' including 'displaypass=1'. Constraint: The attacker must be authenticated; there is no other input validation or filtering. Potential attack: The leaked passwords can be used to connect to the wireless network, perform man-in-the-middle attacks, or further network penetration. The code logic directly uses $_GET["displaypass"] without validation and conditionally outputs sensitive data.
- **Code Snippet:**
  ```
  Code snippet extracted from get_Wireless.php:
  Input point: $displaypass = $_GET["displaypass"];
  Output example: <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  Similar output for <f_wps_psk> and <f_radius_secret1>
  ```
- **Keywords:** GET parameter 'displaypass', XML output field 'f_wep', XML output field 'f_wps_psk', XML output field 'f_radius_secret1'
- **Notes:** The attack chain is complete and verifiable: Authenticated user → Accesses get_Wireless_5g.asp?displaypass=1 → Obtains sensitive information → Uses passwords to access the network. Analysis of other included files: header.php has no vulnerability, xnode.php does not exist, config.php not analyzed (task mismatch). It is recommended to verify the source of the $WLAN2 variable to assess potential risks, but currently no evidence supports other vulnerabilities. This vulnerability shares the same 'displaypass' GET parameter mechanism as the information leak vulnerability in 'get_Email.asp', indicating a possible cross-script generic pattern.

---
### DoS-ufsd_proc_dev_log_write

- **File/Directory Path:** `lib/modules/ufsd.ko`
- **Location:** `ufsd.ko:0x080116a0 sym.ufsd_proc_dev_log_write`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A critical vulnerability was discovered in the sym.ufsd_proc_dev_log_write function, which handles write operations to /proc/ufsd/dev_log. The vulnerability stems from a hardcoded invalid address (0xb0) used in strcmp and memcpy operations. When a user writes data to this proc entry, the function first uses __copy_from_user to copy user data to a stack buffer (size limited to 127 bytes), then calls strcmp to compare the buffer content with the address 0xb0. Since 0xb0 is an invalid memory address, strcmp attempts to read unmapped or kernel memory, causing a page fault and kernel crash. If strcmp returns non-zero (due to the invalid read), the function proceeds to call memcpy, writing user data to the same invalid address 0xb0, further exacerbating the crash. An attacker only needs write access to /proc/ufsd/dev_log (e.g., as a non-root user) to trigger this vulnerability by writing arbitrary data, resulting in a reliable denial of service. The trigger condition is simple, requires no special privileges, and has a high probability of exploitation.
- **Code Snippet:**
  ```
  Key code snippet:
  0x080116ec      ldr r0, [0x080117b8]        ; Load hardcoded address 0xb0 into r0
  0x080116f0      add r3, r2, r4
  0x080116f4      mov r2, 0
  0x080116f8      mov r1, sp                   ; r1 points to the stack buffer
  0x080116fc      strb r2, [r3, -0x80]
  0x08011700      bl strcmp                    ; Call strcmp, compare user data with invalid address 0xb0
  ...
  0x0801179c      mov r1, sp                   ; r1 points to the stack buffer
  0x080117a0      add r2, r4, 1               ; r2 is the copy length
  0x080117a4      ldr r0, [0x080117b8]        ; Load hardcoded address 0xb0 into r0 again
  0x080117a8      bl memcpy                    ; Call memcpy, attempt to write to invalid address 0xb0
  ```
- **Keywords:** /proc/ufsd/dev_log, ufsd_proc_dev_log_write
- **Notes:** This vulnerability is practically exploitable; an attacker can easily trigger it via the proc filesystem interface. The hardcoded address 0xb0 is invalid in the memory map (sections start at 0x08000000), causing a deterministic kernel crash. While code execution is not achievable, system stability is compromised. It is recommended to check the permission settings for /proc/ufsd/dev_log; if writable by non-root users, immediate remediation is required. Further analysis should verify if other proc write functions have similar issues and review the initialization code of ufsd.ko to determine the origin of the hardcoded address.

---
### XSS-show_media_list

- **File/Directory Path:** `htdocs/web/webaccess/movie.php`
- **Location:** `movie.php: In the `show_media_list` function (the exact line number cannot be precisely obtained from the content, but it is located in the part that constructs the HTML string)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A Cross-Site Scripting (XSS) vulnerability exists in the video list display function. Specific issue: When constructing the HTML string, `obj.name` (the file name) is directly inserted into the `title` attribute of the `<a>` tag without HTML escaping. An attacker can upload a file with a malicious file name (for example, containing `" onmouseover="alert(1)`), which triggers script execution when a user hovers their mouse over the video link. Trigger condition: The user visits the 'movie.php' page and views the video list; the attacker must be able to upload a file or control the file name returned by the backend. Potential exploitation methods: Stealing session cookies, executing arbitrary JavaScript code, escalating privileges, or attacking other users. Constraints: The attacker must be a logged-in user, and the backend must allow uploading file names containing special characters.
- **Code Snippet:**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
   + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
   + "<img src=\"webfile_images/icon_movies.png\" width=\"36\" height=\"36\" border=\"0\">"
   + "</td>"
   + "<td width=\"868\" class=\"text_2\">"
   + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
   + "<div>"                             
   + file_name + "<br>" + get_file_size(obj.size) + ", " + obj.mtime
   + "</div>"
   + "</a>"                             
   + "</td></tr>";
  ```
- **Keywords:** obj.name, /dws/api/ListCategory, storage_user
- **Notes:** The vulnerability has high exploitability because an attacker, as a logged-in user, likely has permission to upload files. Further verification is needed to check if the backend API (such as `/dws/api/ListCategory`) filters file names; it is recommended to inspect the file upload functionality and related backend code. Associated files: May involve upload handling scripts or backend CGI. Subsequent analysis direction: Trace the data source of `obj.name` and check the backend file list generation logic.

---
### XSS-PortForwarding

- **File/Directory Path:** `htdocs/web/js/PortForwarding.js`
- **Location:** `PortForwarding.js: Data.prototype.setDataToRow function`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Stored Cross-Site Scripting (XSS) vulnerability in the IP address field of port forwarding rules. The vulnerability occurs because user-provided IP address data is directly concatenated into HTML output without encoding, allowing JavaScript execution. Trigger condition: when a logged-in user adds or edits a port forwarding rule with a malicious IP address containing script payloads, and any user views the port forwarding page where the rule is displayed. The code lacks input validation and output encoding for the IP address field, enabling attackers to inject and persist malicious scripts. Potential exploitation includes session hijacking, CSRF attacks, or privilege escalation if the XSS is used to perform actions on behalf of the user.
- **Code Snippet:**
  ```
  outputString += "<td>" + this.ipAddress + "</td>"; // Direct insertion without encoding
  ```
- **Keywords:** ipAddress parameter in Data constructor, Data.prototype.setDataToRow method, HTML rendering in port forwarding table
- **Notes:** This vulnerability is exploitable by any authenticated non-root user. The attack chain is verifiable from input to execution. Further analysis should verify server-side handling of IP address data and whether additional input validation exists elsewhere. Consider checking related files for data persistence mechanisms and server-side rendering.

---
### IPsec-Command-Injection-doipsecrule

- **File/Directory Path:** `usr/lib/ipsec/_updown`
- **Location:** `_updown.mast: doipsecrule function (specific line number not provided, but can be located in the code snippet)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A command injection vulnerability exists in the `doipsecrule` function of the '_updown.mast' file. This function uses `eval` to execute constructed iptables command strings, which contain unvalidated input from environment variables (such as PLUTO_MY_CLIENT_NET, PLUTO_PEER_CLIENT_NET). If an attacker can control these environment variables (for example, by configuring the leftsubnet/rightsubnet parameters of an IPsec connection), they can inject shell metacharacters (such as semicolons, backticks) to execute arbitrary commands. Trigger conditions include: when the Pluto daemon calls the script during IPsec connection establishment or teardown, and when PLUTO_VERB is 'spdadd-host', etc. Exploitation method: a non-root user configures malicious IPsec connection parameters via the web interface or API, causing commands to be executed with root privileges, achieving privilege escalation.
- **Code Snippet:**
  ```
  rulespec="--src $srcnet --dst $dstnet -m mark --mark 0/0x80000000 -j MARK --set-mark $nf_saref"
  if $use_comment ; then
      rulespec="$rulespec -m comment --comment '$PLUTO_CONNECTION'"
  fi
  case $1 in
      add)
          it="iptables -t mangle -I NEW_IPSEC_CONN 1 $rulespec"
          ;;
      delete)
          it="iptables -t mangle -D NEW_IPSEC_CONN $rulespec"
          ;;
  esac
  oops="\`set +x; eval $it 2>&1\`"
  ```
- **Keywords:** PLUTO_MY_CLIENT_NET, PLUTO_MY_CLIENT_MASK, PLUTO_PEER_CLIENT_NET, PLUTO_PEER_CLIENT_MASK, PLUTO_CONNECTION, PLUTO_VERB
- **Notes:** The vulnerability relies on non-root users being able to influence IPsec configuration (e.g., via an administrative interface); actual system permissions need to be verified. It is recommended to check the access controls of the IPsec configuration interface. Related file: '_updown' (which calls '_updown.mast'). Subsequent analysis could focus on other environment variable usage points or input validation in the Pluto daemon.

---
### Untitled Finding

- **File/Directory Path:** `mydlink/signalc`
- **Location:** `signalc:0x0000f9bc fcn.0000f9bc`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the function `fcn.0000f9bc` (possibly corresponding to 'Util_Shell_Command'), there is a buffer overflow vulnerability. This function uses `strcat` to concatenate multiple parameters (`param_1`, `param_2`, `param_3`) into a fixed-size stack buffer (256 bytes) without performing bounds checking. An attacker can overflow the buffer by controlling these parameters, potentially overwriting the return address or executing arbitrary code. Additionally, this function calls `fcn.0001c568`, which uses `system` to execute commands; if the parameters are controllable, this could lead to command injection. Vulnerability trigger condition: The attacker can control the parameters passed to `fcn.0000f9bc`, and the total length of the parameters exceeds 256 bytes. Potential exploitation methods: Controlling program flow through buffer overflow, or executing arbitrary system commands through command injection.
- **Code Snippet:**
  ```
  int32_t fcn.0000f9bc(int32_t param_1,int32_t param_2,int32_t param_3,uint param_4) {
      ...
      uchar auStack_118 [256];
      ...
      if (param_1 != 0) {
          sym.strcat(iVar2,param_1);
          ...
      }
      ...
      if (param_2 != 0) {
          sym.strcat(iVar1,param_2);
          ...
      }
      ...
      if (param_3 != 0) {
          sym.strcat(iVar1,param_3);
          ...
      }
      ...
      if (iVar3 == 0) {
          fcn.0001c568(iVar1);  // Calls system
      }
      ...
  }
  ```
- **Keywords:** Util_Shell_Command, fcn.0000f9bc, fcn.0001c568, system
- **Notes:** Further verification of the callers of `fcn.0000f9bc` is needed to confirm the input source. From string analysis, this function may be related to 'Util_Shell_Command', indicating it is used to execute shell commands. An attacker might pass controllable parameters through network callbacks (such as ExecuteTaskAPP_RecvCB) or environment variables. It is recommended to follow up with analysis of network processing functions and data flow.

---
### stack-buffer-overflow-receive_ping

- **File/Directory Path:** `usr/libexec/ipsec/ikeping`
- **Location:** `ikeping:0xd368 receive_ping`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the 'ikeping' receive_ping function, a stack buffer overflow vulnerability was discovered. Specific trigger condition: when the program processes ping replies, it uses recvfrom to receive network data into the stack buffer acStack_160 (size 256 bytes), but the write starting offset for recvfrom is at the 0x14 byte of the buffer, and it attempts to write up to 0x100 (256) bytes. This results in an actual writable space of only 236 bytes, exceeding by 20 bytes, overwriting adjacent variables on the stack (such as the return address). An attacker, as an authenticated user (non-root), can trigger the overflow by sending a malicious ping reply packet (larger than 236 bytes), potentially achieving arbitrary code execution. Exploiting the vulnerability requires constructing a precise payload to bypass possible mitigation measures (such as ASLR), but in embedded environments, mitigation measures may be weaker.
- **Code Snippet:**
  ```
  uVar3 = sym.__GI_recvfrom(*(puVar6 + -0x1ac), puVar6 + iVar2 + -0x15c, 0x100, 0);
  *(puVar6 + -0x14) = uVar3;
  sym.memcpy(puVar6 + iVar2 + -0x5c, puVar6 + iVar2 + -0x15c, 0x1c);
  ```
- **Keywords:** recvfrom, memcpy, acStack_160
- **Notes:** The vulnerability has been verified through code analysis, but the exploit chain needs to be tested in a real environment. It is recommended to further analyze the reply_packet function and network interaction to refine the attack payload. The file is for ARM architecture and may be subject to platform-specific limitations.

---
### heap-buffer-overflow-handle_service

- **File/Directory Path:** `usr/sbin/servd`
- **Location:** `servd:0x0000d9e0 fcn.0000d9e0 (handle_service)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A heap buffer overflow vulnerability was identified in the handle_service function (fcn.0000d9e0) of servd. This occurs when processing 'service alias' commands, where user-provided service names and aliases are copied using strcpy without bounds checking into fixed-size heap-allocated buffers. An attacker with valid login credentials (non-root user) can exploit this by sending a malicious command through the Unix socket /var/run/servd_ctrl_usock with overly long arguments, leading to heap corruption. This could potentially allow arbitrary code execution or privilege escalation if servd runs with elevated privileges. The vulnerability is triggered by commands like 'service <service_name> alias <alias_name>', where either argument exceeds the buffer size. The attack chain is complete: input from the socket flows directly to the vulnerable strcpy operations without validation.
- **Code Snippet:**
  ```
  0x0000e1d0      mov r0, r3                  ; char *dest (buffer at offset 0x52c)
  0x0000e1d4      mov r1, r2                  ; const char *src (user input from command)
  0x0000e1d8      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  0x0000e1f4      mov r0, r3                  ; char *dest (buffer at offset 0x55e)
  0x0000e1f8      mov r1, r2                  ; const char *src (user input from command)
  0x0000e1fc      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** /var/run/servd_ctrl_usock, service_command:service, alias_command:alias
- **Notes:** The vulnerability was confirmed through decompilation analysis. Servd may run with root privileges, increasing the impact. Further testing is recommended to determine exact buffer sizes and exploitability. No other exploitable chains were found in command-line parsing or socket handling functions.

---
### CommandInjection-_realsetup-perform

- **File/Directory Path:** `usr/lib/ipsec/_realsetup`
- **Location:** `File: _realsetup Function: perform (around lines 106-116) and startup section (around lines 200-210)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A command injection vulnerability via the 'IPSECinterfaces' environment variable was discovered in the '_realsetup' script. The issue originates from the 'perform' function using 'eval' to execute command strings, and the '$IPSECinterfaces' variable is not quoted during concatenation. When the script is run with 'start' or '_autostart' arguments, if 'IPSECinterfaces' contains shell metacharacters (such as ';', '&'), malicious commands will be executed. An attacker, as a non-root user, can exploit this by setting the environment variable and waiting for the script to run with root privileges (e.g., via a system service), achieving command execution and privilege escalation. Triggering the vulnerability requires script execution and controllable environment variables; the exploit chain is complete but relies on external conditions.
- **Code Snippet:**
  ```
  perform() {
      if $display
      then
          echo "    " "$*"
      fi
  
      if $execute
      then
          eval "$*"   # Dangerous: directly eval arguments
      fi
  }
  
  # Used in the startup section, $IPSECinterfaces is unquoted:
  perform ipsec _startklips \
          --info $info \
          --debug "\"$IPSECklipsdebug\"" \
          --omtu "\"$IPSECoverridemtu\"" \
          --fragicmp "\"$IPSECfragicmp\"" \
          --hidetos "\"$IPSEChidetos\"" \
          --log "\"$IPSECsyslog\"" \
          $IPSECinterfaces "||" \
      "{" rm -f $lock ";" exit 1 ";" "}"
  ```
- **Keywords:** IPSECinterfaces, IPSEC_setupflags, perform function
- **Notes:** The exploit chain is complete but relies on external conditions: the script must run with root privileges, and the attacker must be able to set environment variables (e.g., via login shell, service configuration, or file injection). It is recommended to further analyze how the script is invoked (e.g., via init script or service) and the source of environment variables (e.g., /etc/default/ipsec). Other variables like 'IPSEC_setupflags' may also affect behavior but do not directly cause command injection.

---
### InfoLeak-Wireless-Passwords-get_Wireless.asp

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.asp`
- **Location:** `get_Wireless.asp:5 (include statement), get_Wireless.php:1 (input handling), get_Wireless.php:approximately lines 70-72 (output handling)`
- **Risk Score:** 7.0
- **Confidence:** 9.0
- **Description:** The 'get_Wireless.asp' file, by including 'get_Wireless.php', allows authenticated non-root users to disclose sensitive wireless passwords (e.g., WEP key, WPA PSK, RADIUS secret) without proper validation or access control. The vulnerability is triggered when an attacker sends a GET request with the 'displaypass' parameter set to 1, causing the script to output passwords in the XML response. This lack of input validation and authorization checks enables information disclosure, potentially leading to unauthorized network access or further attacks. The attack chain is straightforward: authenticated user → malicious GET request → password disclosure.
- **Code Snippet:**
  ```
  From get_Wireless.asp: \`include "/htdocs/mydlink/get_Wireless.php";\`
  From get_Wireless.php:
  - Input: \`$displaypass = $_GET["displaypass"];\`
  - Output snippets:
    - \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
    - \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\`
    - \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **Keywords:** $_GET['displaypass'], <f_wep>, <f_wps_psk>, <f_radius_secret1>
- **Notes:** This finding is based on direct code evidence from accessible files. The attack chain is verified as complete and exploitable by authenticated non-root users. However, further analysis of web server access controls (e.g., whether 'get_Wireless.asp' is restricted to admin users) could affect the risk level. Other included files like 'xnode.php' and 'config.php' were not analyzable due to directory restrictions. No additional exploitable issues were found in 'header.php'.

---
### Untitled Finding

- **File/Directory Path:** `usr/lib/ipsec/_plutorun`
- **Location:** `_plutorun: near the eval statement (end part of the script)`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the '_plutorun' script via the `--opts` parameter. An attacker (non-root user) can pass a malicious string to the `--opts` parameter, which is directly executed in an `eval` statement, leading to arbitrary command injection. Trigger condition: A non-root user directly executes the script and controls the `--opts` parameter (e.g., `./_plutorun --opts "; malicious_command"`). Exploitation method: The injected command is executed with the current user's privileges, potentially used to perform arbitrary operations, bypass restrictions, or as part of a more complex attack chain. The script lacks validation or filtering of the `--opts` parameter, making the injection feasible.
- **Code Snippet:**
  ```
  #!/bin/ash
  # ... script header ...
  # Parameter parsing section:
  --opts)                 popts="$2" ; shift ;;
  # ... other code ...
  # eval statement:
  eval $execdir/pluto --nofork --secretsfile "$IPSEC_SECRETS" $ipsecdiropt $popts
  ```
- **Keywords:** --opts parameter, popts variable, eval statement
- **Notes:** The vulnerability is practically exploitable, but the command executes with non-root user privileges, potentially preventing direct privilege escalation. It is necessary to verify if the script is called in a privileged context (e.g., by the root user), but based on file permissions, non-root users can directly exploit it. It is recommended to check the calling context and restrict parameter input. Other parameters (such as --pre and --post) might be similar, but --opts is the most direct injection point.

---
### command-injection-auto

- **File/Directory Path:** `usr/libexec/ipsec/auto`
- **Location:** `auto: In multiple command constructions within the 'case "$op" in' section (e.g., --up, --down, --add, etc.), specific line numbers are unavailable, but the code snippet is as follows`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'auto' script. The user-supplied 'names' parameter is directly used in multiple commands without escaping or validation. When the script executes, if 'names' contains shell metacharacters (such as semicolons, backticks), an attacker can inject and execute arbitrary commands. Trigger condition: An attacker executes the 'ipsec auto' command and provides a malicious 'names' parameter. Potential attack methods include executing system commands, accessing or modifying files, or further privilege escalation. The vulnerability originates from the script using unquoted variables in command strings, which are passed to 'ash' for execution via the 'runit' function.
- **Code Snippet:**
  ```
  For example, in the --up operation:
  --up)  echo "ipsec whack $async --name $names --initiate"    | runit ; exit ;;
  Similarly, in other operations:
  --down)        echo "ipsec whack --name $names --terminate"          | runit ; exit ;;
  --delete)         echo "ipsec whack --name $names --delete"  | runit ; exit ;; 
  ...
  
  runit() {
  	if test "$showonly"
  	then
  		cat
  	else
  		(
  		    echo '(''
  		    echo 'exec <&3'     # regain stdin
  		    cat
  		    echo ');'
  		) | ash $shopts |
  			awk "/^= / { exit \$2 } $logfilter { print }"
  	fi
  }
  ```
- **Keywords:** names (command line argument), ipsec whack (command), ash (shell execution), /var/run/pluto/ipsec.info (environment file)
- **Notes:** The vulnerability is practically exploitable, but the script runs with the current user's permissions (no setuid), so an attacker may not directly obtain root privileges. It is recommended to further analyze the 'ipsec whack' command or other components to look for privilege escalation opportunities. It is necessary to verify whether the 'names' parameter is subject to other constraints in the actual environment. Associated file: May involve /var/run/pluto/ipsec.info; if this file is maliciously controlled, it could introduce other risks.

---
### InfoDisclosure-get_Wireless

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.php`
- **Location:** `get_Wireless.php:1 ($_GET["displaypass"] assignment) and get_Wireless.php:~70-80 (output section)`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** The script uses an unvalidated `displaypass` GET parameter to control the display of sensitive information, potentially causing authenticated users to leak wireless network passwords (WEP key, WPA PSK) and RADIUS keys. An attacker only needs to send a GET request to 'get_Wireless.php' and set `displaypass=1` to trigger it. Trigger conditions include: the attacker possesses valid login credentials (non-root user) and can access this script; the constraint is that the script relies on an authentication mechanism, but the parameter itself is unvalidated. The potential attack is information disclosure, where the attacker can use the obtained sensitive data to further attack the wireless network. In the code logic, `$displaypass` comes directly from `$_GET["displaypass"]`, and its value is checked in the output condition to be 1 to decide whether to output the keys.
- **Code Snippet:**
  ```
  Relevant code snippet:
  - Input: \`$displaypass = $_GET["displaypass"];\`
  - Output condition: \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **Keywords:** displaypass GET parameter, $path_wlan_wifi."/nwkey/psk/key", $path_wlan_wifi."/nwkey/wep/key:".$id, $path_wlan_wifi."/nwkey/eap/secret"
- **Notes:** This vulnerability requires the attacker to already have login credentials, so the risk is medium. It is recommended to further validate the web server's access control mechanism and authentication process to ensure only authorized users can access this script. Also, check the implementation of the `XNODE_getpathbytarget`, `query`, `get` functions to confirm if they introduce other vulnerabilities (such as injection). Associated files may include PHP files that define these functions.

---
### Path Traversal-fcn.0000bb1c

- **File/Directory Path:** `usr/sbin/rgbin`
- **Location:** `rgbin:0x0000bb1c fcn.0000bb1c`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** In the 'pfile' command (function fcn.0000bb1c), the file path is obtained via the command line option -f and passed directly to fopen, lacking path validation and sanitization. An attacker can construct a malicious path (such as '../../etc/passwd') to read sensitive system files, leading to information disclosure. Trigger condition: The attacker possesses valid login credentials (non-root user) and executes the 'pfile -f <malicious_path>' command. Exploitation method: Read arbitrary file contents via path traversal and output to the terminal. In the code logic, the file is opened in read-only mode, with no directory access restrictions, but there is no code execution risk. The vulnerability has been verified to exist, but is limited to information disclosure.
- **Code Snippet:**
  ```
  // Option processing section (decompiled code)
  case 3:
      if (*(0xe940 | 0x20000) != 0) {
          sym.imp.free(*(0xe940 | 0x20000));
      }
      uVar1 = sym.imp.strdup(*(0xe470 | 0x20000)); // User-controlled path copy
      *(0xe940 | 0x20000) = uVar1;
      break;
  // File opening section
  if (*(0xe940 | 0x20000) != 0) {
      uVar1 = sym.imp.fopen(*(0xe940 | 0x20000), 0x24f8 | 0x20000); // Directly uses path, mode "r"
      *(puVar2 + -8) = uVar1;
  }
  ```
- **Keywords:** Command line argument -f, File path string, fopen file operation, Global variable address 0xe940
- **Notes:** The path traversal vulnerability has been verified to exist, but is limited to information disclosure, with no code execution. Further verification is needed to confirm that the fopen mode string (0x24f8 | 0x20000) is indeed "r", and to verify the attacker's permissions to read sensitive files in the actual environment. It is recommended to check if other components call the 'pfile' command and handle its output.

---
### XSS-show_media_list

- **File/Directory Path:** `htdocs/web/webaccess/doc.php`
- **Location:** `doc.php: JavaScript function show_media_list (approximately lines 50-70, based on code structure)`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** A stored cross-site scripting (XSS) vulnerability exists in the file list display function. When a user visits the doc.php page, the filename (obj.name) retrieved from the server is directly inserted into the HTML without escaping, leading to the execution of malicious scripts. Trigger condition: An attacker, as a logged-in user, uploads a file with a filename that is a malicious script (e.g., `<script>alert('XSS')</script>` or `<img src=x onerror=alert(1)>`), and then accesses the doc.php page to view the file list. Potential attacks include stealing user sessions and performing arbitrary actions (such as modifying settings or launching further attacks), because the XSS runs in the context of an authenticated user. The vulnerability originates from the failure to encode or escape the filename when constructing the HTML string within the show_media_list function.
- **Code Snippet:**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_files.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name+ "<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"                                 
       + "</td></tr>";
  ```
- **Keywords:** obj.name, storage_user, /dws/api/GetFile, ListCategory
- **Notes:** The vulnerability has high exploitability because an attacker, as a logged-in user, can control the filename (via the file upload function). It is necessary to verify whether the file upload function allows arbitrary filename settings. It is recommended to check the server-side file upload processing and other related files (such as upload handling scripts) to confirm the complete attack chain. Subsequent analysis should focus on the file upload component and server-side validation.

---
### InfoLeak-SMTP-Password-get_Email.asp

- **File/Directory Path:** `htdocs/mydlink/get_Email.asp`
- **Location:** `get_Email.asp (approx. line 18-19 in output)`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** An information disclosure vulnerability exists in the 'get_Email.asp' file, allowing authenticated users to leak the SMTP password via the 'displaypass' GET parameter. Specific behavior: when the parameter is set to 1, the script outputs the SMTP password in the XML response. The trigger condition is an authenticated user accessing a URL like 'get_Email.asp?displaypass=1'. Constraint: relies only on the basic authentication check in 'header.php' (`$AUTHORIZED_GROUP>=0`), lacking additional permission verification for password access. Potential attack: after obtaining the SMTP password, an attacker could use it to send malicious emails or conduct further network attacks. The code logic directly uses the GET parameter to control output, without filtering or boundary checks.
- **Code Snippet:**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **Keywords:** HTTP GET parameter: displaypass, NVRAM path: /device/log/email/smtp/password, NVRAM path: /device/log/email/smtp/user, ENV variable: AUTHORIZED_GROUP
- **Notes:** The authentication mechanism relies on the $AUTHORIZED_GROUP variable, whose setting location is unknown (possibly in other include files). It is recommended to further analyze '/htdocs/webinc/config.php' or similar files to verify authentication details. This vulnerability only affects authenticated users but could be misused for lateral movement attacks. Related files: header.php (authentication check), xnode.php (query function).

---
### Buffer-Overflow-dbg.create_path

- **File/Directory Path:** `usr/bin/udevinfo`
- **Location:** `udevinfo:0xf7cc dbg.create_path`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The function dbg.create_path uses strcpy to copy a user-provided path string into a fixed-size stack buffer of 512 bytes (acStack_270). If the path parameter exceeds 512 bytes, it will cause a stack-based buffer overflow. This function is called during device node creation operations and could be triggered by malicious udev rules or direct invocation. An attacker with control over the path input (e.g., as a non-root user with write access to udev rules directories) could overwrite return addresses or other stack data to execute arbitrary code. The function is recursive, which might complicate exploitation but does not prevent it. The attack chain is verifiable: user controls path input -> strcpy copies without bounds check -> buffer overflow -> potential code execution.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar5 + -0x268,param_1);
  // puVar5 + -0x268 points to acStack_270[512]
  // param_1 is the input path
  ```
- **Keywords:** path parameter, udev rules, device node paths
- **Notes:** Exploitation requires the attacker to control the path input, which might be achievable through crafted udev rules or by invoking udevinfo with a long path. Stack protections like ASLR and stack canaries might mitigate this, but the binary is not stripped and has debug info, which could aid exploitation. Further analysis is needed to confirm the exact attack vector, but the chain is complete for non-root users with appropriate access.

---
### Buffer-Overflow-dbg.delete_path

- **File/Directory Path:** `usr/bin/udevinfo`
- **Location:** `udevinfo:0xf870 dbg.delete_path`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The function dbg.delete_path uses strcpy to copy a user-provided path string into a fixed-size stack buffer of 512 bytes, similar to dbg.create_path. A path longer than 512 bytes will overflow the buffer, potentially allowing code execution. This function is called during device node removal operations. An attacker could exploit this by supplying a malicious path, possibly through udev rules or direct command-line arguments. The attack chain is verifiable: user controls path input -> strcpy copies without bounds check -> buffer overflow -> potential code execution. As a non-root user, exploitation is feasible if they can influence udev rules or invoke the binary.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar5 + -0x268,param_1);
  // puVar5 + -0x268 points to a 512-byte stack buffer
  // param_1 is the input path
  ```
- **Keywords:** path parameter, udev rules, device node paths
- **Notes:** Similar to dbg.create_path, exploitation depends on controlling the path input. The function might be called in response to device events, so crafting malicious udev rules could trigger it. The risk is comparable to dbg.create_path, and the chain is complete for non-root users with access to modify rules or invoke commands.

---
### Open-Redirect-OnClickLogin

- **File/Directory Path:** `htdocs/web/info/Login.html`
- **Location:** `Login.html: JavaScript section, within the success callback of the OnClickLogin function`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** An open redirect vulnerability was discovered in the post-login redirection logic of 'Login.html'. The issue stems from insufficient validation of the 'RedirectUrl' value in sessionStorage: if 'RedirectUrl' contains the substring 'html' but does not contain 'Login.html', the user will be redirected to that URL after logging in. An attacker can control 'RedirectUrl' (for example, via XSS or by setting sessionStorage from another page) to trick a user into visiting a malicious website after login, which can be used for phishing attacks. Trigger condition: The user successfully logs in and the 'RedirectUrl' in sessionStorage is set to an external URL containing 'html'. Exploitation method: The attacker sets 'RedirectUrl' to 'http://evil.com/phishing.html', and the user is automatically redirected after login. The code logic is in the success callback of the OnClickLogin function, using indexOf for a lenient check.
- **Code Snippet:**
  ```
  .done(function(){
      var redirect_url = sessionStorage.getItem("RedirectUrl");
      if((redirect_url == null) || (redirect_url.indexOf("Login.html") > 0) || (redirect_url.indexOf("html") < 0))
      {
          window.location.href = "/IndexHome.php";
      }
      else                                
      {   
          window.location.href = redirect_url;        
      }
  })
  ```
- **Keywords:** sessionStorage:RedirectUrl, window.location.href
- **Notes:** Full exploitation of this vulnerability requires the attacker to be able to control the 'RedirectUrl' in sessionStorage, which might be achieved through other pages or XSS vulnerabilities. It is recommended to further analyze related JavaScript files (such as /js/Login.js or /js/SOAP/SOAPLogin.js) to understand the mechanism for setting 'RedirectUrl'. Open redirects are commonly used in phishing attacks, posing a medium risk, but the harm may increase when combined with other vulnerabilities.

---
### command-injection-adapter_cmd

- **File/Directory Path:** `etc/scripts/adapter_cmd.php`
- **Location:** `adapter_cmd.php:7-18`
- **Risk Score:** 6.0
- **Confidence:** 5.0
- **Description:** In 'adapter_cmd.php', the 'devname' and 'cmdport' parameters are directly used to construct the 'chat' command without input validation or escaping, creating a command injection vulnerability. Trigger condition: If an attacker can control the values of these parameters (for example, by modifying NVRAM or environment variables), they can inject malicious commands. Potential attack method: By setting 'devname' or 'cmdport' to a value like '; malicious_command #', arbitrary commands can be executed in the generated shell script. The code logic shows that these values come from the 'query' function and are directly concatenated into strings, lacking boundary checks.
- **Code Snippet:**
  ```
  $vid		=query("/runtime/tty/entry:1/vid");
  $pid		=query("/runtime/tty/entry:1/pid");
  $devname	=query("/runtime/tty/entry:1/devname");
  $cmdport	=query("/runtime/tty/entry:1/cmdport/devname");
  if($vid ==1e0e && $pid ==deff)
  {
  	echo "chat -D ".$devname." OK-ATE1-OK\n";
  }
  else
  {
  	if($cmdport != "")
  	{
  		echo "chat -D ".$cmdport." OK-AT-OK\n";
  		echo "chat -e -v -c -D ".$cmdport." OK-AT+CIMI-OK\n";
  	}
  	else
  	{
  		echo "chat -D ".$devname." OK-AT-OK\n";
  		echo "chat -e -v -c -D ".$devname." OK-AT+CIMI-OK\n";
  	}
  }
  ```
- **Keywords:** /runtime/tty/entry:1/devname, /runtime/tty/entry:1/cmdport, /runtime/tty/entry:1/vid, /runtime/tty/entry:1/pid
- **Notes:** The input source '/runtime/tty/entry:1/' might be set via NVRAM or environment variables, but there is a lack of evidence proving how an attacker can modify these values. It is recommended to further analyze the web interface or other components (such as CGI scripts) to verify the data flow and controllability. If the attack chain is complete (for example, triggering script execution via a web request and controlling the input), the risk could be higher.

---
### info-leak-wan_stats.xml

- **File/Directory Path:** `htdocs/widget/wan_stats.xml`
- **Location:** `wan_stats.xml (Estimated line number: In the PPPoE, PPTP, L2TP session output section, specifically near the echo statements outputting the <username> and <password> tags)`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** When generating XML output, the script directly includes sensitive information such as PPPoE, PPTP, and L2TP connection usernames and passwords in the response. When an attacker, as an authenticated user (non-root), accesses this file, they can obtain these credentials, which could potentially be used for unauthorized access to related network services (such as PPP connections). Trigger condition: The attacker accesses 'wan_stats.xml' via the web interface or by making a direct request. The vulnerability stems from the script's lack of filtering or encryption for output data and its reliance on the integrity of the system configuration.
- **Code Snippet:**
  ```
  // PPPoE section
  echo "<username>".$ppp_username."</username>";
  echo "<password>".$ppp_password."</password>";
  // PPTP section
  echo "<username>".$pptp_username."</username>";
  echo "<password>".$pptp_password."</password>";
  // L2TP section
  echo "<username>".$l2tp_username."</username>";
  echo "<password>".$l2tp_password."</password>";
  ```
- **Keywords:** $ppp_username, $ppp_password, $pptp_username, $pptp_password, $l2tp_username, $l2tp_password, /htdocs/phplib/xnode.php, /htdocs/webinc/config.php
- **Notes:** This vulnerability requires the attacker to have already obtained login credentials, so the risk is medium. It is recommended to check the web server's access control mechanisms to ensure sensitive statistical information is only accessible to necessary users, or to desensitize the output data. Additionally, relevant include files (such as xnode.php and config.php) should be verified for any other security vulnerabilities.

---
### Command-Injection-newhostkey

- **File/Directory Path:** `usr/libexec/ipsec/newhostkey`
- **Location:** `newhostkey:50 Script Body`
- **Risk Score:** 5.0
- **Confidence:** 7.0
- **Description:** A command injection vulnerability was discovered in the 'newhostkey' script. The script uses unquoted variables (such as $verbose, $random, $configdir, $password, $host, $bits) when calling the `ipsec rsasigkey` command (line 50). Attackers can inject malicious commands by controlling command-line arguments (such as --hostname or --password). Full attack chain: entry point (command-line arguments) → data flow (arguments directly concatenated into the command) → dangerous operation (command execution). Trigger condition: the attacker is a non-root user but possesses login credentials and can execute the script and control the arguments. Exploitation method: for example, setting the --hostname value to 'foo; cat /etc/passwd' can leak sensitive information. Constraints: the injected command executes with non-root user privileges, which may not directly allow privilege escalation, but malicious actions within the user's permissions can be performed (such as file leakage, script execution).
- **Code Snippet:**
  ```
  ipsec rsasigkey $verbose $random $configdir $password $host $bits
  ```
- **Keywords:** --hostname (argument), --password (argument)
- **Notes:** The command injection vulnerability exists and is exploitable, but as a non-root user, exploitation may be limited to the user's permission scope. It is recommended to verify the behavior of the `ipsec` command and the permissions of output files to assess potential escalation risks. Subsequent analysis should check if the script is invoked by a privileged user or interacts with other components.

---
### XML-Injection-UPnP-PortMapping

- **File/Directory Path:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.GetGenericPortMappingEntry.php`
- **Location:** `ACTION.GetGenericPortMappingEntry.php (Output section, specific line number unknown)`
- **Risk Score:** 5.0
- **Confidence:** 6.0
- **Description:** In ACTION.GetGenericPortMappingEntry.php, port mapping data (such as description, remote host, port, etc.) is retrieved from query functions and directly output to the XML response, lacking proper escaping or validation. Attackers can control these fields (e.g., NewPortMappingDescription) via ACTION.DO.AddPortMapping.php to inject malicious XML content (such as closing tags or entities). When retrieving port mapping entries, the malicious content is injected into the XML response, potentially breaking the XML structure or leading to XML injection attacks (like XXE, if entities are processed). Trigger condition: The attacker possesses valid login credentials, calls AddPortMapping to add a port mapping with a malicious description, then calls GetGenericPortMappingEntry to retrieve that entry. Potential exploitation: Depending on client-side XML response parsing, it may lead to denial of service, data leakage, or limited data manipulation, but there is no direct evidence of code execution.
- **Code Snippet:**
  ```
  <NewPortMappingDescription><? echo query("description"); ?></NewPortMappingDescription>
  ```
- **Keywords:** NewPortMappingDescription, /runtime/upnpigd/portmapping/entry, ACTION.DO.AddPortMapping.php, ACTION.GetGenericPortMappingEntry.php, query
- **Notes:** Lack of evidence on how the client parses the XML response, so exploitability is uncertain; it is recommended to further validate the XML processing logic of the UPnP client or related components; associated file ACTION.DO.AddPortMapping.php shows input may be controlled but lacks escaping.

---
