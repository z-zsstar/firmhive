# _DIR890LA1_FW111b02_REDACTED_PASSWORD_PLACEHOLDER_beta01.bin.extracted (29 alerts)

---

### systemic_command_injection-GLOBALS_vars

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `multiple files`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** Systemic command injection risk patterns identified in multiple PHP scripts:
1. Parameters obtained through $_GLOBALS variables (INF, PHYINF, DEVNAM, etc.)
2. Directly passed to command execution functions (cmd/system)
3. If these global variables originate from HTTP requests, it will lead to severe command injection vulnerabilities

Affected files:
IP-WAIT.php, dhcp6s_helper.php, stopchild.php, etc.
- **Keywords:** $_GLOBALS, cmd, system, INF, PHYINF, DEVNAM, DNS, ME, DST, GATEWAY, CHILDUID
- **Notes:** Systemic risk requires prioritizing the investigation of the source of the $_GLOBALS variable and creating a complete variable contamination path map.

---
### systemic-command_injection-GLOBALS_vars

- **File/Directory Path:** `etc/scripts/IP-WAIT.php`
- **Location:** `multiple files`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Systemic command injection risk patterns were identified in multiple PHP scripts. Several scripts (IP-WAIT.php, dhcp6s_helper.php, stopchild.php) retrieve parameters through the $_GLOBALS superglobal variable and directly pass them to command execution functions (such as cmd() or system()). These global variables include: INF, PHYINF, DEVNAM, DNS, ME, DST, GATEWAY, CHILDUID, etc. If these global variables originate from unvalidated HTTP input, they will lead to severe command injection vulnerabilities. Recommendations: 1) Conduct comprehensive audits of all scripts using $_GLOBALS variables; 2) Verify whether the sources of these variables are controllable; 3) Implement strict input validation and command parameter escaping.
- **Code Snippet:**
  ```
  Multiple instances found:
  1. IP-WAIT.php: main_entry($_GLOBALS["INF"], $_GLOBALS["PHYINF"], $_GLOBALS["DEVNAM"], $_GLOBALS["DNS"], $_GLOBALS["ME"]);
  2. dhcp6s_helper.php: cmd("ip -6 route add ".$_GLOBALS["DST"]." via ".$_GLOBALS["GATEWAY"]." dev ".$_GLOBALS["DEVNAM"]." table DHCP\n");
  3. stopchild.php: cmd("service INET.".$_GLOBALS["CHILDUID"]." stop");
  ```
- **Keywords:** $_GLOBALS, cmd, system, INF, PHYINF, DEVNAM, DNS, ME, DST, GATEWAY, CHILDUID
- **Notes:** This is a systemic risk pattern involving multiple scripts and global variables. Priority should be given to investigating the source of the $_GLOBALS variable, particularly confirming whether it originates from HTTP request parameters. It is recommended to create a complete variable contamination path diagram.

---
### command_injection-cgibin-fcn.000175f4

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `htdocs/cgibin:fcn.000175f4:0x17a50`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A high-risk command injection vulnerability was discovered in cgibin:
1. Function fcn.000175f4 constructs a command string via sprintf and executes it using system
2. The command parameters originate from environment variables *(puVar6 + -0x1c) in HTTP requests
3. No input validation is performed, allowing attackers to inject arbitrary commands

Vulnerability path:
HTTP request -> environment variable -> sprintf -> system
- **Code Snippet:**
  ```
  sym.imp.sprintf(0x7544 | 0x30000,0xbf50 | 0x20000,0xbf1c | 0x20000,*(puVar6 + -0x1c));
  sym.imp.system(0x7544 | 0x30000);
  ```
- **Keywords:** fcn.000175f4, system, sprintf, getenv, *(puVar6 + -0x1c)
- **Notes:** Recommendations: 1) Identify the HTTP interface calling this function 2) Verify the source of environment variables 3) Implement strict input validation and command escaping

---
### command_injection-usbmount_helper-1

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `usbmount_helper.php:7-9`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** A high-risk command injection vulnerability was discovered in the 'REDACTED_PASSWORD_PLACEHOLDER_helper.php' file. Unvalidated external input variables $prefix and $pid are directly used to construct system commands (such as 'smartctl -H /dev/$dev' and 'sh REDACTED_PASSWORD_PLACEHOLDER_fsid.sh $prefix$pid'). Attackers can execute arbitrary commands by controlling these parameters. Further verification is required to determine whether these variables originate from HTTP requests.
- **Code Snippet:**
  ```
  $UID = toupper($prefix.$pid);
  if ($pid=="0") $dev = $prefix;
  else $dev = $prefix.$pid;
  setattr($base."/id", "get", "sh REDACTED_PASSWORD_PLACEHOLDER_fsid.sh ".$prefix.$pid);
  ```
- **Keywords:** $prefix, $pid, $dev, setattr, smartctl, usbmount_fsid.sh, toupper($prefix.$pid), XNODE_getpathbytarget
- **Notes:** Recommendations: 1) Validate all web interfaces calling this script 2) Check the sources of $prefix and $pid 3) Implement input validation and command escaping. Need to confirm whether these variables originate from HTTP requests to meet core user requirements.

---
### web-vulnerability-delpathbytarget-arbitrary-file-deletion

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `delpathbytarget.php:3-7`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** A high-risk security vulnerability has been discovered in the 'delpathbytarget.php' file:
1. Unvalidated HTTP parameters ($BASE/$NODE/$TARGET/$VALUE/$POSTFIX) are directly passed to file operation functions
2. These parameters are used to construct file paths and execute deletion operations (del function)
3. Attackers may achieve arbitrary file deletion by crafting malicious parameters

REDACTED_PASSWORD_PLACEHOLDER evidence:
- Vulnerability location: delpathbytarget.php:3-7
- Dangerous parameter transmission path: HTTP parameters → XNODE_getpathbytarget() → del()
- **Code Snippet:**
  ```
  $stsp = XNODE_getpathbytarget($BASE, $NODE, $TARGET, $VALUE, 0);
    del($stsp.'/'.$POSTFIX);
  ```
- **Keywords:** $BASE, $NODE, $TARGET, $VALUE, $POSTFIX, XNODE_getpathbytarget, del
- **Notes:** Limiting factors:
1. Unable to obtain 'phplib/xnode.php' to verify the complete attack chain
2. Need to confirm the specific implementation of the del() function

Recommendations:
1. Implement strict validation for all HTTP parameters
2. Implement path normalization checks
3. Restrict the directory scope for delete operations

---
### web-vulnerability-delpathbytarget-arbitrary-file-deletion

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `delpathbytarget.php:3-7`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** A high-risk arbitrary file deletion vulnerability has been discovered in the file 'REDACTED_PASSWORD_PLACEHOLDER.php'. Unauthenticated HTTP parameters ($BASE, $NODE, $TARGET, $VALUE, $POSTFIX) are directly passed to the 'del' function after being processed by the 'XNODE_getpathbytarget' function. Attackers can manipulate the final file deletion path by crafting malicious HTTP parameters, resulting in arbitrary file deletion.
- **Code Snippet:**
  ```
  $stsp = XNODE_getpathbytarget($BASE, $NODE, $TARGET, $VALUE, 0);
    del($stsp.'/'.$POSTFIX);
  ```
- **Keywords:** del, XNODE_getpathbytarget, $BASE, $NODE, $TARGET, $VALUE, $POSTFIX
- **Notes:** The following fixes are recommended: 1) Implement strict validation for all HTTP parameters 2) Add path normalization checks 3) Restrict the directory scope for deletion operations. Further analysis of the 'phplib/xnode.php' file is required to confirm the specific implementations of the 'XNODE_getpathbytarget' and 'del' functions.

---
### command_injection-wfa_igd_handle-SEND_IGD

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** A command injection vulnerability was discovered in wfa_igd_handle.php. In 'SEND_IGD' mode, the unvalidated $DS_PORT parameter is directly concatenated into iptables commands and executed via 'exe_ouside_cmd'. Attackers can inject arbitrary commands by controlling HTTP parameters, potentially leading to complete system compromise. REDACTED_PASSWORD_PLACEHOLDER triggering conditions:
1. DS_PORT parameter passed through web interface
2. Parameter lacks proper validation
3. Direct concatenation into system command execution
- **Code Snippet:**
  ```
  $igd_cmd="upnpc -m ".$wan_ip." -r ";
  $port=$DS_PORT;
  $igd_cmd=$igd_cmd.$port." tcp &";
  exe_ouside_cmd($igd_cmd);
  ```
- **Keywords:** exe_ouside_cmd, SEND_IGD, DS_PORT, wan_ip, upnpc
- **Notes:** It is recommended to further verify the source and validation mechanism of the DS_PORT parameter. Check if there are other similar patterns of dangerous function calls.

---
### web-file_delete-delpathbytarget

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `delpathbytarget.php:3-7`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A high-risk arbitrary file deletion vulnerability was discovered in the 'delpathbytarget.php' file. The HTTP parameters `$BASE`, `$NODE`, `$TARGET`, `$VALUE`, and `$POSTFIX` are used to construct file paths and passed to the `del` function without sufficient validation. Attackers could potentially delete arbitrary files by crafting malicious parameters. Specific manifestations include: 1. Parameters are directly used to construct file paths; 2. Lack of effective validation of parameters; 3. Direct invocation of the `del` function to perform deletion operations.
- **Code Snippet:**
  ```
  $stsp = XNODE_getpathbytarget($BASE, $NODE, $TARGET, $VALUE, 0);
    del($stsp.'/'.$POSTFIX);
  ```
- **Keywords:** del, XNODE_getpathbytarget, $BASE, $NODE, $TARGET, $VALUE, $POSTFIX
- **Notes:** Due to security restrictions, the content of the 'xnode.php' file cannot be retrieved. It is recommended to further analyze this file to confirm the specific implementation and security measures of the `XNODE_getpathbytarget` and `del` functions.

---
### command-injection-wfa_igd_handle-igd_prepare

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php (HIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was identified in the `igd_prepare` function. This function takes the `$wan_ip` parameter and directly concatenates it into an `iptables` command executed via `exe_ouside_cmd`. The `$wan_ip` originates from network interface configurations or runtime storage, potentially allowing attackers to inject arbitrary commands by modifying these configurations. The critical code locations are within the `igd_prepare` function definition and its invocation points in `wfa_igd_handle.php`.
- **Code Snippet:**
  ```
  function exe_ouside_cmd($cmd)
  {
      $ext_node="REDACTED_PASSWORD_PLACEHOLDER_node";
      setattr($ext_node, "get", $cmd);
      get("x", $ext_node);
      del($ext_node);
  }
  ```
- **Keywords:** exe_ouside_cmd, igd_prepare, $wan_ip, $igd_cmd, iptables, query, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further analysis is required to determine the specific source path of `$wan_ip` and verify whether it originates directly from HTTP request parameters.

---
### command-injection-wfa_igd_handle-SEND_IGD

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php:187-202`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was identified in the `SEND_IGD` mode. `$wan_ip` is obtained via `query("REDACTED_PASSWORD_PLACEHOLDER")`, and `$DS_PORT` may originate from user input. These variables are concatenated into the `upnpc` command and executed through `exe_ouside_cmd`. The critical code location is at `wfa_igd_handle.php:187-202`.
- **Code Snippet:**
  ```
  function exe_ouside_cmd($cmd)
  {
      $ext_node="REDACTED_PASSWORD_PLACEHOLDER_node";
      setattr($ext_node, "get", $cmd);
      get("x", $ext_node);
      del($ext_node);
  }
  ```
- **Keywords:** exe_ouside_cmd, SEND_IGD, $wan_ip, $DS_PORT, upnpc, query, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER_default_port
- **Notes:** Further analysis is required to determine the specific source of `$DS_PORT` to confirm whether it originates directly from HTTP request parameters. It is recommended to review all code paths that invoke `exe_ouside_cmd`.

---
### web-cgi-dangerous_functions-fcn.0000eab0

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `htdocs/cgibin`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple security vulnerabilities were discovered in the 'htdocs/cgibin' file:
1. The function 'fcn.0000eab0' contains multiple 'system()' calls. Although hardcoded strings are used, potential command injection risks still require vigilance.
2. More severe security issues exist in other CGI processing functions, including:
   - Multiple 'system()' calls using parameters potentially controllable by attackers
   - Insecure 'sprintf()' calls that may lead to buffer overflows
   - Environment variables obtained via 'getenv()' that could be controlled by attackers
3. The HTTP request parameter processing logic contains potential risks of user input contamination.
- **Keywords:** fcn.0000eab0, system, sprintf, getenv, strcasecmp, atoi, fopen, fgets, fclose, dlapn.cgi, dldongle.cgi, dlcfg.cgi, seama.cgi, fwup.cgi
- **Notes:** It is recommended to further verify the specific content of hardcoded strings and examine the security issues of other CGI processing functions. Special attention should be paid to how user input is obtained and passed to these dangerous functions.

---
### web-cgi-command-injection

- **File/Directory Path:** `htdocs/fileaccess.cgi`
- **Location:** `fileaccess.cgi:fcn.0000d624, fileaccess.cgi:fcn.0000bc34, fileaccess.cgi:HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple security vulnerabilities were identified in the file 'htdocs/fileaccess.cgi': 1) The function fcn.0000d624 constructs a command string using sprintf and directly passes it to the system function, with parameters sourced from the param_1 structure that may contain user-controllable input, posing a command injection risk; 2) The function fcn.0000bc34 directly invokes the system function to execute hardcoded commands; 3) Multiple instances of strcpy usage for string copying may lead to buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  HIDDEN，HIDDENsprintf+systemHIDDENstrcpyHIDDEN
  ```
- **Keywords:** fcn.0000d624, system, sprintf, param_1, fcn.0000bc34, strcpy
- **Notes:** Further analysis of the source of param_1 is required to confirm the degree of user control over the input and to verify the specific trigger conditions for these vulnerabilities.

---
### command-injection-fcn.000175f4

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `fcn.000175f4:0x17a50`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A remote command injection vulnerability was discovered in function fcn.000175f4 (address 0x17a50). An attacker can inject malicious commands by controlling the environment variable *(puVar6 + -0x1c) in HTTP requests. The vulnerability constructs command strings using sprintf and executes them via system without proper input validation.
- **Code Snippet:**
  ```
  sym.imp.sprintf(0x7544 | 0x30000,0xbf50 | 0x20000,0xbf1c | 0x20000,*(puVar6 + -0x1c));
  sym.imp.system(0x7544 | 0x30000);
  ```
- **Keywords:** fcn.000175f4, system, sprintf, getenv, *(puVar6 + -0x1c)
- **Notes:** It is recommended to identify the HTTP interface calling this function and verify the source of the environment variables.

---
### command_injection-dhcp6s_helper-ip_route

- **File/Directory Path:** `etc/scripts/dhcp6s_helper.php`
- **Location:** `dhcp6s_helper.php: add_route(), remove_route()`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'dhcp6s_helper.php' file. The `add_route()` and `remove_route()` functions directly pass `$_GLOBALS["DST"]`, `$_GLOBALS["GATEWAY"]`, and `$_GLOBALS["DEVNAM"]` to the `cmd()` function to execute the `ip -6 route` command. If these global variables originate from unvalidated HTTP request parameters, attackers could potentially inject arbitrary commands by crafting malicious parameters.
- **Code Snippet:**
  ```
  cmd("ip -6 route add ".$_GLOBALS["DST"]." via ".$_GLOBALS["GATEWAY"]." dev ".$_GLOBALS["DEVNAM"]." table DHCP\n");
  cmd("ip -6 route del ".$_GLOBALS["DST"]." table DHCP\n");
  ```
- **Keywords:** cmd, msg, $_GLOBALS, DST, GATEWAY, DEVNAM, ip -6 route
- **Notes:** Further verification is needed to determine whether the `$_GLOBALS` variables originate directly from HTTP request parameters. If these variables are not properly validated or escaped, they may lead to command injection attacks. It is recommended to examine the web interface that calls this script and the method of parameter transmission.

---
### command-execution-wfa_igd_handle-exe_ouside_cmd

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple functions in the file 'wfa_igd_handle.php' pass external input to the `exe_ouside_cmd` function, which executes external commands via `setattr` and `get`. Specific risk points include:
1. The `exe_ouside_cmd` function directly executes the input command string, potentially leading to command injection.
2. The `get_public_ip` function retrieves an external IP address via `urlget` and writes the result to a temporary file, posing potential path traversal or file operation risks.
3. The `igd_prepare` and `SEND_IGD` functions construct `iptables` commands and execute them directly, which could be exploited by malicious input.
4. The `DS_IPT` function constructs and executes `iptables` commands, potentially allowing injection of malicious parameters.

This finding is directly related to the web service component and involves the transmission path from external input to command execution.
- **Code Snippet:**
  ```
  function exe_ouside_cmd($cmd)
  {
      $ext_node="REDACTED_PASSWORD_PLACEHOLDER_node";
      setattr($ext_node, "get", $cmd);
  	get("x", $ext_node);
  	del($ext_node);
  }
  ```
- **Keywords:** exe_ouside_cmd, cmd, urlget, iptables, setattr, get, MODE, ST, EXT_IP, EXT_PORT, INT_PORT, DS_PORT, C_IP, E_PORT, SSL, webaccess, runtime
- **Notes:** Further analysis of the `setattr` and `get` function implementations is required to confirm the presence of command injection vulnerabilities. It is recommended to inspect all invocations of `exe_ouside_cmd` to ensure input parameters undergo rigorous filtering. This finding is directly related to the web service component and may involve the HTTP request processing flow.

---
### command_injection-dhcp6s_helper-cmd

- **File/Directory Path:** `etc/scripts/dhcp6s_helper.php`
- **Location:** `dhcp6s_helper.php`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'dhcp6s_helper.php' contains command injection vulnerabilities in the add_route and remove_route functions. These functions use the cmd() function to execute system commands with untrusted $_GLOBALS parameters (DST, GATEWAY, DEVNAM) directly concatenated into the command string without sanitization. An attacker could manipulate these parameters to execute arbitrary commands.
- **Code Snippet:**
  ```
  cmd("ip -6 route add ".$_GLOBALS["DST"]." via ".$_GLOBALS["GATEWAY"]." dev ".$_GLOBALS["DEVNAM"]." table DHCP\n");
  ```
- **Keywords:** cmd, add_route, remove_route, $_GLOBALS, DST, GATEWAY, DEVNAM
- **Notes:** These parameters should be properly validated and sanitized before being used in system commands. The cmd() function should implement correct escaping or use parameterized commands. Note: This finding is not directly related to HTTP request processing and is documented only for completeness.

---
### command_injection-dhcp6s_helper-cmd_execution

- **File/Directory Path:** `etc/scripts/dhcp6s_helper.php`
- **Location:** `dhcp6s_helper.php`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Command injection vulnerabilities were found in the dhcp6s_helper.php file:  
1. The `cmd()` function directly concatenates external inputs (such as `$_GLOBALS["DST"]`, `$_GLOBALS["GATEWAY"]`, `$_GLOBALS["DEVNAM"]`) and executes system commands (e.g., `ip -6 route add`), posing a command injection risk.  
2. The `add_route()` and `remove_route()` functions execute `ip -6 route` commands via `cmd()`, incorporating unvalidated external inputs.  
3. The `main_entry()` function calls different functions based on the value of `$_GLOBALS["ACTION"]` without strict input validation.  

Potential impact: Attackers can inject malicious commands by manipulating these global variables, potentially leading to arbitrary command execution.
- **Code Snippet:**
  ```
  cmd("ip -6 route add ".$_GLOBALS["DST"]." via ".$_GLOBALS["GATEWAY"]." dev ".$_GLOBALS["DEVNAM"]." table DHCP\n");
  ```
- **Keywords:** cmd, msg, $_GLOBALS, DST, GATEWAY, DEVNAM, ACTION, add_route, remove_route, main_entry
- **Notes:** It is recommended to implement strict validation and filtering of inputs from `$_GLOBALS` to avoid direct command concatenation. Functions such as `escapeshellarg()` or similar should be used to escape inputs. Although this file is not a direct CGI script, it processes potentially web-interface-originated inputs and executes system commands, necessitating further tracing of input sources.

---
### command_injection-stopchild.php-uid

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `stopchild.php`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The script 'REDACTED_PASSWORD_PLACEHOLDER.php' contains a potential command injection vulnerability. The variable $uid is retrieved from $_GLOBALS["CHILDUID"] and directly used in the system command 'service INET.$uid stop' without proper validation. If $_GLOBALS["CHILDUID"] originates from user-controllable input (e.g., GET/POST parameters), this would allow an attacker to inject arbitrary commands.
- **Code Snippet:**
  ```
  $uid = $_GLOBALS["CHILDUID"];
  $ret = main_entry($uid);
  cmd("service INET.".$uid." stop");
  ```
- **Keywords:** main_entry, $uid, $_GLOBALS, CHILDUID, cmd, service INET.$uid stop
- **Notes:** Further verification is required to determine whether $_GLOBALS["CHILDUID"] originates from user-controllable input (such as GET/POST parameters). If confirmed, a severe command injection vulnerability exists.

---
### command_injection-wfa_igd_handle-DS_IPT

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** A command injection vulnerability was discovered in wfa_igd_handle.php. In 'DS_IPT' mode, multiple parameters ($C_IP, $E_PORT, $SSL) are used to construct iptables commands. These parameters originate from HTTP requests without adequate validation, potentially leading to command injection. REDACTED_PASSWORD_PLACEHOLDER risk points:
1. Multiple HTTP parameters are directly used in command construction
2. Lack of input validation and escaping
3. Constructed commands are executed via 'exe_ouside_cmd'
- **Keywords:** exe_ouside_cmd, DS_IPT, C_IP, E_PORT, SSL, iptables
- **Notes:** It is necessary to confirm whether these parameters all originate from HTTP requests and check if there are other similar parameter processing patterns.

---
### buffer_overflow-fileaccess.cgi-0x0000a40c

- **File/Directory Path:** `htdocs/fileaccess.cgi`
- **Location:** `fileaccess.cgi:0x0000a40c`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** A buffer overflow risk was identified in function fcn.0000a40c:
1. The strncpy function is used to copy HTTP request parameters into a fixed-size buffer (0x40 bytes). Although there is a length check (piVar4[-2] < 0x40), the source data originates from unvalidated HTTP request parameters (*piVar4).
2. Before the function returns, strcpy is used to copy the processed data to the target buffer (piVar4[-0x50]) without any length check.

Trigger conditions:
- An attacker can control HTTP request parameters (via query strings or HTTP headers)
- The parameter length exceeds the size of the target buffer

Security impact:
- May lead to buffer overflow, potentially enabling remote code execution or service crash
- **Code Snippet:**
  ```
  strncpy(piVar4[-0x130], *piVar4, 0x40);
  strcpy(piVar4[-0x50], piVar4[-0x130]);
  ```
- **Keywords:** fcn.0000a40c, strncpy, strcpy, piVar4[-0x130], piVar4[-0x50], 0x52a8, 0x3f, HTTPHIDDEN
- **Notes:** Further verification is required for the actual size of the target buffer and the calling context.

---
### command_injection-wfa_igd_handle-get_public_ip

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** A command injection vulnerability was discovered in wfa_igd_handle.php. The get_public_ip() function directly executes URL commands obtained from external sources, which may lead to remote code execution. REDACTED_PASSWORD_PLACEHOLDER risks:
1. External URL content is directly executed as commands
2. Lack of validation for URL content
3. Execution of potentially malicious commands through system calls
- **Keywords:** get_public_ip, urlget, external_command
- **Notes:** Analyze the call path of the get_public_ip() function to confirm whether there are other similar patterns of remote command acquisition and execution.

---
### buffer_overflow-fileaccess.cgi-1

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `htdocs/fileaccess.cgi:0x0000a40c`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** A high-risk buffer overflow vulnerability was discovered in fileaccess.cgi:
1. HTTP request parameters are directly passed to the strncpy function and copied into a fixed-size buffer (0x40 bytes)
2. The processed data is then copied via the strcpy function to the target buffer (piVar4[-0x50]) without length verification
3. Attackers can trigger buffer overflow by manipulating HTTP request parameters

Vulnerability path:
HTTP request parameters -> strncpy -> intermediate buffer -> strcpy -> target buffer
- **Code Snippet:**
  ```
  strncpy(piVar4[-0x130], *piVar4, 0x40);
  strcpy(piVar4[-0x50], piVar4[-0x130]);
  ```
- **Keywords:** fcn.0000a40c, strncpy, strcpy, piVar4[-0x130], piVar4[-0x50], HTTPHIDDEN
- **Notes:** Recommendations: 1) Verify all web interfaces calling this CGI 2) Implement strict input validation and length checks 3) Replace with secure string functions

---
### command_injection-IP-WAIT.php-GLOBALS_vars

- **File/Directory Path:** `etc/scripts/IP-WAIT.php`
- **Location:** `IP-WAIT.php: multiple locations`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The file 'IP-WAIT.php' contains a command injection vulnerability. The script executes command strings passed through the `cmd` function, with command parameters sourced from `$_GLOBALS` global variables (including `INF`, `PHYINF`, `DEVNAM`, `DNS`, and `ME`). If these global variable values originate from unvalidated HTTP inputs (such as GET/POST parameters), attackers could potentially inject arbitrary commands by crafting malicious parameters. Further analysis of the web interface calling this script is required to verify whether the `$_GLOBALS` variables originate from HTTP inputs.
- **Code Snippet:**
  ```
  function cmd($cmd) {echo $cmd."\n";}
  main_entry(
  	$_GLOBALS["INF"],
  	$_GLOBALS["PHYINF"],
  	$_GLOBALS["DEVNAM"],
  	$_GLOBALS["DNS"],
  	$_GLOBALS["ME"]
  	);
  ```
- **Keywords:** cmd, main_entry, $_GLOBALS, INF, PHYINF, DEVNAM, DNS, ME
- **Notes:** Further analysis is required on the web interface that calls this script to confirm whether the source of the `$_GLOBALS` variable originates from HTTP input. If confirmed to come from HTTP input, a severe command injection vulnerability exists.

---
### format_string-fileaccess.cgi-0x0000ac44

- **File/Directory Path:** `htdocs/fileaccess.cgi`
- **Location:** `fileaccess.cgi:0x0000ac44`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A formatting string vulnerability has been identified in function fcn.0000ac44:
1. The function uses sprintf to process data from HTTP environment variables (getenv) or request handling results
2. Format string addresses are 0x5488 | 0x30000 and 0x54b0 | 0x30000, but specific contents are unknown

Trigger conditions:
- Attacker can control HTTP request parameters
- Format string contains user-controllable portions

Security impact:
- May lead to format string vulnerability, potentially enabling memory read or write operations
- **Code Snippet:**
  ```
  sprintf(puVar6, 0x5488 | 0x30000, ...);
  sprintf(puVar6, 0x54b0 | 0x30000, ...);
  ```
- **Keywords:** fcn.0000ac44, sprintf, getenv, puVar6, 0x5488, 0x54b0, fcn.0000a40c
- **Notes:** Further parsing is required for the specific content of the formatted string.

---
### web-command_injection-usbmount_helper

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Multiple potential security issues were identified in the 'REDACTED_PASSWORD_PLACEHOLDER_helper.php' file:
1. The `setattr` function executes shell commands containing user-controllable variables `$prefix` and `$pid` (via the `$dev` variable), which may lead to command injection vulnerabilities.
2. In the `detach` operation, shell commands are directly constructed using `$dev` and `$mntp` variables, potentially enabling command injection
3. The `fread` function reads file contents without sufficient validation of file paths

These issues can be triggered by passing maliciously crafted parameters (such as `$prefix`, `$pid`, `$dev`, `$mntp`) through HTTP requests, which are directly used to construct shell commands or file operations.
- **Code Snippet:**
  ```
  setattr("/runtime/SMART/".$prefix."/status", "get", "smartctl -H /dev/".$dev." | grep \"SMART Health Status\" | cut -d: -f2 | sed -e 's/ //g'");
  echo "umount \`mount | grep ".$dev." | cut -d' ' -f3\` 2> /dev/null\n";
  echo "rm -rf ".$mntp."\n";
  ```
- **Keywords:** setattr, fread, $prefix, $pid, $dev, $mntp, $action
- **Notes:** Further validation is required for the sources of variables such as `$prefix`, `$pid`, and `$mntp` to confirm whether these variables can be directly controlled via HTTP requests. It is recommended to inspect the web interface that invokes this script to identify potential attack surfaces.

---
### command_injection-usbmount_helper-setattr

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `usbmount_helper.php`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A command injection vulnerability was discovered in the 'usbmount_helper.php' file. The `setattr` function executes the `smartctl` command, where `/dev/`.$dev may contain user-controlled input. An attacker could potentially execute arbitrary commands by manipulating the input parameters.
- **Code Snippet:**
  ```
  setattr("/runtime/SMART/".$prefix."/status", "get", "smartctl -H /dev/".$dev." | grep \"SMART Health Status\" | cut -d: -f2 | sed -e 's/ //g'");
  ```
- **Keywords:** setattr, smartctl, dev, prefix, pid, mntp, usbmount_fsid.sh
- **Notes:** Further verification is needed regarding the source of the $dev variable to confirm whether it can be controlled by users. It is recommended to inspect the web interface that calls this script and verify the validation of input parameters.

---
### command_injection-usbmount_helper-setattr_script

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `usbmount_helper.php`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A command injection vulnerability was discovered in the 'usbmount_helper.php' file. The `setattr` function executes the `REDACTED_PASSWORD_PLACEHOLDER_fsid.sh` script, where `$prefix.$pid` may contain user-controlled input. Attackers could potentially execute arbitrary commands by manipulating the input parameters.
- **Code Snippet:**
  ```
  setattr($base."/id", "get", "sh REDACTED_PASSWORD_PLACEHOLDER_fsid.sh ".$prefix.$pid);
  ```
- **Keywords:** setattr, usbmount_fsid.sh, prefix, pid, dev, mntp
- **Notes:** Further verification is required regarding the sources of the $prefix and $pid variables to confirm whether they can be controlled by users. It is recommended to inspect the web interface that calls this script to verify the validation of input parameters.

---
### command_injection-usbmount_helper-echo

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_helper.php`
- **Location:** `usbmount_helper.php`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A command injection vulnerability was discovered in the 'usbmount_helper.php' file. When the `echo` command executes shell commands, `$prefix.$pid` and `$mntp` may contain user-controlled input. Attackers could potentially execute arbitrary commands by manipulating the input parameters.
- **Code Snippet:**
  ```
  echo "sh mkdir -p /tmp/disk \n";
  echo "sh echo 0 > /tmp/disk/".$prefix.$pid."\n";
  ```
- **Keywords:** echo, prefix, pid, mntp, dev, usbmount_fsid.sh
- **Notes:** Further verification is required regarding the sources of the $prefix, $pid, and $mntp variables to confirm whether they can be controlled by users. It is recommended to inspect the web interface that calls this script to verify the validation of input parameters.

---
### potential-command-injection-vpnroute

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `vpnroute.php`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The 'vpnroute.php' script constructs shell commands using variables (`$DOMAINIP`, `$SERVER`, `$INF`, `$PATH`, `$IP`, `$MASK`, `$DEV`, `$GW`) that are embedded into shell commands via `echo`. While these variables could lead to command injection if not properly sanitized, the script does not directly process HTTP inputs (`$_GET` or `$_POST`). The source of these variables is unclear from this file alone, requiring further analysis of included files (e.g., '/htdocs/phplib/inet.php') or the calling context to determine if they can be attacker-controlled.
- **Code Snippet:**
  ```
  echo "sed -i \"s/".$DOMAINIP."/".$SERVER."/g\" /etc/ppp/options.".$INF."\n";
  echo "xmldbc -s ".$PATH." ".$SERVER."\n";
  if (INET_validv4network($IP, $SERVER, $MASK) == 1)
  {
  	echo "ip route add ".$SERVER." dev ".$DEV."\n";
  }
  else
  {
  	echo "ip route add ".$SERVER." via ".$GW." dev ".$DEV."\n";
  }
  ```
- **Keywords:** $DOMAINIP, $SERVER, $INF, $PATH, $IP, $MASK, $DEV, $GW, INET_validv4network
- **Notes:** command_execution

---
