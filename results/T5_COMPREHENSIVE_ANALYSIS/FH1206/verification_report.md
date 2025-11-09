# FH1206 - Verification Report (10 findings)

---

## Original Information

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd: sym.formexeCommand (0x0046eefc)`
- **Description:** A command injection vulnerability exists in the 'formexeCommand' function, which handles HTTP form submissions. The function retrieves user input from the 'cmdinput' parameter using 'websGetVar' and directly incorporates it into system commands executed via 'doSystemCmd' without any input validation or sanitization. This allows an attacker to inject arbitrary commands by crafting malicious input in the 'cmdinput' parameter. The vulnerability is triggered when a POST request is sent to the associated form handler, and the injected commands are executed with the privileges of the HTTP server process (likely root in embedded systems). Attackers can achieve remote code execution, leading to full compromise of the device.
- **Code Snippet:**
  ```
  // Vulnerable code in formexeCommand
  // Retrieving user input from 'cmdinput' parameter
  uVar1 = (**(iVar4 + -0x78cc))(*&uStackX_0,*(iVar4 + -0x7fd8) + -0x3bc,*(iVar4 + -0x7fd8) + -0x3b0);
  (**(iVar4 + -0x71b0))(auStack_2308,uVar1);
  // ...
  // Constructing command with user input without sanitization
  (**(iVar4 + -0x7860))(*(iVar4 + -0x7fd8) + -0x388,auStack_2308);
  // Executing command via doSystemCmd
  (**(iVar4 + -0x7508))(auStack_2308);
  ```
- **Notes:** The function 'formexeCommand' is registered in 'formDefineTendDa' during HTTP server initialization, making it accessible via HTTP requests. No explicit authentication checks are visible in the function, but it may rely on web application-level authentication. Given that the attacker has valid login credentials, this vulnerability is directly exploitable. Further analysis should verify the execution context (e.g., if httpd runs as root) and check for other similar vulnerabilities in form handlers.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. In the formexeCommand function, user input is retrieved from the 'cmdinput' parameter via websGetVar and directly used to construct system commands (such as using the format string '%s > /tmp/cmdTmp.txt'), which are executed via doSystemCmd without any input validation or sanitization. The attacker model assumes an authenticated remote user (with web application access), as the function may rely on upper-layer authentication. The vulnerability is exploitable because an attacker can control the 'cmdinput' parameter, inject malicious commands (such as semicolons or pipe symbols), and execute them in the context of the HTTP server process (which typically runs with root privileges in embedded systems), leading to complete compromise of the device. PoC example: Send a POST request to the HTTP endpoint corresponding to formexeCommand, setting the 'cmdinput' parameter to 'ls; whoami', which would execute 'ls; whoami > /tmp/cmdTmp.txt', and the injected 'whoami' command would be executed.

## Verification Metrics

- **Verification Duration:** 97.36 s
- **Token Usage:** 122210

---

## Original Information

- **File/Directory Path:** `bin/iprule.sh`
- **Location:** `iprule.sh:15 (estimated line number, based on code structure)`
- **Description:** The script uses an unquoted variable $FILE when reading the input file, allowing command injection. Specific manifestation: When the script is executed, if the FILE parameter contains shell metacharacters (such as ;, |, &), the `cat $FILE` command will be interpreted by the shell and execute arbitrary commands. Trigger condition: An attacker directly executes the script and passes a malicious FILE parameter (e.g., './iprule.sh add ";malicious_command" table prio'). Constraint: The script only checks that the number of parameters is 4, but does not validate the parameter content; the file existence check has a syntax error (`[ -z -rts ]`) and may not take effect. Potential attack: An attacker can inject commands to perform arbitrary operations. If the script runs with root privileges, it may lead to privilege escalation. The exploitation method is simple and direct, requiring no complex steps.
- **Code Snippet:**
  ```
  rts=\`cat $FILE\`
  ```
- **Notes:** Evidence for the vulnerability's existence is sufficient, but exploitability depends on the script's execution privileges. It is recommended to further analyze the script's invocation context (e.g., whether it is called by a root process) to confirm the possibility of privilege escalation. Additionally, check if other parameters (such as TABLE and PRIO) in the ip rule command also pose injection risks, but the current focus is on the FILE parameter.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes the vulnerability. At line 15 of bin/iprule.sh, the unquoted $FILE variable in 'rts=`cat $FILE`' allows command injection. Attacker model: A local user or remote attacker (via a web interface, etc.) can execute the script and control the FILE parameter. The script has execute permissions (-rwxrwxrwx), and the parameter check only verifies the count is 4, with no filtering of the content. The file existence check 'if [ -z -rts ]' has a syntax error and is invalid. Complete attack chain: The attacker provides a malicious FILE parameter (e.g., shell metacharacters), and the script executes the injected command. PoC: Execute './iprule.sh add "; malicious_command" table prio', where 'malicious_command' can be any command such as 'id > /tmp/exploit'. If the script runs with root privileges, the injected command executes as root, leading to privilege escalation. The vulnerability has high exploitability, and the risk is High.

## Verification Metrics

- **Verification Duration:** 118.42 s
- **Token Usage:** 134812

---

## Original Information

- **File/Directory Path:** `var/etc/passwd_private`
- **Location:** `passwd_private:1 (File path, no specific line number)`
- **Description:** The file 'passwd_private' contains the root user's MD5 password hash and has its permissions set to globally readable, writable, and executable (permissions 777). This allows any non-root user (with valid login credentials) to directly read the file. An attacker can obtain the hash value and use offline cracking tools (such as John the Ripper or hashcat) to perform brute-force or dictionary attacks. If the password strength is weak, the attacker may successfully crack the hash, thereby obtaining root privileges and achieving privilege escalation. The trigger condition is simple: the attacker only needs to execute a read command (such as 'cat passwd_private'). Boundary check is missing: the file lacks proper access control, allowing low-privilege users to access highly sensitive data. Potential attack methods include directly reading the hash and cracking it; the exploit chain is complete and feasible.
- **Code Snippet:**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **Notes:** This finding is based on direct evidence: the file content contains the root hash, and the permission settings are improper. The attack chain is complete, but successful exploitation depends on password strength and the efficiency of cracking tools. It is recommended to further verify the hash's susceptibility to cracking (for example, by testing with common password dictionaries). Associated files may include other system password files, but this analysis focuses solely on 'passwd_private'. Subsequent analysis directions: check the permissions of other sensitive files in the system, or evaluate whether the password policy enforces the use of strong passwords.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is completely accurate: the file 'var/etc/passwd_private' exists, its permissions are set to 777 (globally readable, writable, and executable), and its content contains the root user's MD5 password hash ('$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1'). The attacker model is an authenticated local user (with valid login credentials) who can easily read the file (for example, using 'cat /var/etc/passwd_private'). Complete attack chain: after reading the hash, the attacker can use offline cracking tools (such as John the Ripper or hashcat) to perform brute-force or dictionary attacks. If the password strength is weak (for example, a common password), the attacker may successfully crack the hash, obtain root privileges, and achieve privilege escalation. The vulnerability is practically exploitable because the input is controllable (the file is readable), the path is reachable (permissions allow any user access), and the actual impact is severe (loss of root privileges). Reproducible PoC steps: 1. The attacker logs into the system as a non-root user; 2. Executes the command 'cat /var/etc/passwd_private' to obtain the root password hash; 3. Uses a cracking tool (such as running 'john passwd_private' or 'hashcat -m 500 passwd_private wordlist.txt') to attempt cracking; 4. If cracking is successful, uses the obtained password to escalate privileges (for example, via 'su root'). The evidence supports all claims, no further analysis is needed.

## Verification Metrics

- **Verification Duration:** 121.58 s
- **Token Usage:** 140121

---

## Original Information

- **File/Directory Path:** `var/etc/shadow`
- **Location:** `shadow:1`
- **Description:** A critical permission configuration error was found in the 'shadow' file. The file permissions are -rwxrwxrwx, allowing all users (including non-root users) to read, write, and execute. This leads to two practically exploitable attack chains: 1) Non-root users can directly modify the file content, for example, modifying the root password hash or adding new user accounts, thereby obtaining root privileges (via su or login); 2) Non-root users can read the password hashes (using MD5 algorithm, $1$ prefix) and perform offline cracking (if the password is weak). The trigger condition is simple: an attacker only needs to have valid login credentials (non-root user) and access to the file. Boundary check is missing: the file has no permission restrictions, allowing arbitrary modifications. Exploitation methods include using a text editor or commands to directly edit the file, or using tools like john the ripper to crack the hashes.
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Notes:** This finding is based on direct evidence: file permissions and content. It is recommended to immediately fix the file permissions (for example, set to 640, only root can write). Subsequent analysis should verify whether the system relies on this file for authentication and check the permissions of other sensitive files.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert is accurate based on evidence: the file permissions are -rwxrwxrwx, allowing all users to read, write, and execute; the file content contains the root user's MD5 password hash ($1$ prefix). The attacker model is an authenticated non-root user (with valid login credentials). The vulnerability is practically exploitable: attackers can read the hash for offline cracking (if the password is weak), or directly modify the file to change the root password or add users, thereby obtaining root privileges. Complete attack chain: 1) Attacker logs into the system as a non-root user; 2) Reads the file: uses commands like 'cat /var/etc/shadow' to obtain the hash; 3) Modifies the file: uses a text editor (like vi) or commands (like 'echo "root::0:0:root:/root:/bin/bash" >> /var/etc/shadow' to set an empty password); 4) Uses the modified file to execute 'su root' or log in to gain root privileges. Evidence supports all claims, no additional analysis needed.

## Verification Metrics

- **Verification Duration:** 137.24 s
- **Token Usage:** 145257

---

## Original Information

- **File/Directory Path:** `webroot/js/privatejs/wireless_extra.js`
- **Location:** `wireless_extra.js: wirelessScan function and fillAcc function (specific line numbers unavailable, but the code is located in the part that handles scan result display)`
- **Description:** A stored XSS vulnerability was discovered in the wireless scanning functionality of the 'wireless_extra.js' file. An attacker can inject JavaScript code by setting the SSID field of a malicious AP. When a logged-in user performs a wireless scan (via the '/goform/ApclientScan' interface) and views the results, the malicious SSID is inserted into the page via innerHTML, causing script execution. Trigger condition: the user accesses the wireless settings page and clicks the scan button; the attacker needs to be able to control the AP's SSID (e.g., via physical proximity or network infiltration). Potential exploitation methods: stealing user session cookies, tampering with wireless settings, redirecting users to malicious pages. The vulnerability lies in the client-side display logic, lacking HTML escaping for SSID content.
- **Code Snippet:**
  ```
  // In the wirelessScan function:
  nc.innerHTML = str[0]; // SSID directly inserted into HTML
  nc.innerHTML = str[1]; // MAC address
  // In the fillAcc function:
  nc.innerHTML = str[0]; // SSID used for table display
  nc.title = decodeSSID(str[0]); // Possibly not escaped
  ```
- **Notes:** Exploiting this vulnerability requires the attacker to control the wireless environment (e.g., by setting up a malicious AP). The decodeSSID function is not defined in the file; it is assumed it may not adequately escape HTML. It is recommended to subsequently analyze how the backend '/goform/ApclientScan' interface handles SSID input. This vulnerability could be used for privilege escalation or persistent attacks but is limited by the network environment.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** In the 'wireless_extra.js' file, the wirelessScan function and fillAcc function indeed contain a stored XSS vulnerability. Evidence is as follows:
- In the wirelessScan function, the SSID (str[0]) is directly inserted into a table cell via innerHTML (e.g., nc.innerHTML = str[0];) without HTML escaping.
- In the fillAcc function, the SSID is similarly inserted via innerHTML (nc.innerHTML = str[0];), and the title attribute uses decodeSSID(str[0]), but the decodeSSID function is not defined in the file and may not adequately escape.
- Input is controllable: An attacker can control the input by setting the SSID field of a malicious AP (e.g., the SSID contains malicious JavaScript code).
- Path is reachable: When a logged-in user accesses the wireless settings page and clicks the scan button, the '/goform/ApclientScan' interface call is triggered, and the scan results are displayed on the page, making the vulnerability path reachable.
- Actual impact: Execution of malicious scripts can lead to security damages such as session cookie theft, settings tampering, and redirection to malicious pages.
Attacker model: An unauthenticated remote attacker who sets up a malicious AP via physical proximity or network infiltration.
PoC steps:
1. The attacker sets up a malicious AP with an SSID like `<script>alert('XSS')</script>` or a more complex payload like `<img src=x onerror=alert(document.cookie)>`.
2. The user logs into the router management interface, goes to the wireless settings page, and clicks the scan button.
3. The scan results include the malicious SSID, which is inserted into the page via innerHTML, and the script executes.
The risk level is Medium because the vulnerability requires user interaction (clicking scan) and the attacker to control the wireless environment, but if exploited, it could cause significant harm.

## Verification Metrics

- **Verification Duration:** 146.50 s
- **Token Usage:** 176353

---

## Original Information

- **File/Directory Path:** `var/etc/stupid-ftpd/stupid-ftpd.conf`
- **Location:** `stupid-ftpd.conf:~line 75 (user definition line)`
- **Description:** The configuration file defines an anonymous user (anonymous) with full permissions (A), allowing unauthenticated users to perform arbitrary file operations (download, upload, overwrite, delete, create directories, etc.). Attackers can connect to the FTP service (port 2121) and use anonymous login (no password required) to exploit these permissions. If the server is not running with root privileges (as mentioned in the configuration file comments), changeroottype=real may fail, resulting in no effective file system isolation, allowing attackers to access system files outside the serverroot (/usr/home/cinek/tmp3/aaa), provided the server process has the corresponding permissions. This constitutes a complete attack chain: entry point (FTP network interface) → data flow (FTP command processing) → dangerous operation (arbitrary file access and modification).
- **Code Snippet:**
  ```
  user=anonymous	*	 /	  5   A
  ```
- **Notes:** Based on analysis of the configuration file content, the attack chain is complete and practically exploitable. However, further verification of the server binary code is needed to confirm changeroottype behavior and the server's actual running privileges (e.g., whether it runs as root). It is recommended to analyze the stupid-ftpd binary file to verify data flow and permission checks. Related files may include the server executable file and relevant logs.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is accurate based on configuration file evidence. Line 75 of the configuration file 'var/etc/stupid-ftpd/stupid-ftpd.conf' clearly defines an anonymous user (user=anonymous) with full permissions (A), allowing arbitrary file operations such as download, upload, overwrite, delete, create directories, etc. The server listens on port 2121, and anonymous login requires no password (password is *). The attacker model is an unauthenticated remote attacker who can connect to the FTP service over the network. Complete attack chain verification: entry point (FTP network interface port 2121) → data flow (anonymous login and processing FTP commands) → dangerous operation (arbitrary file access and modification). Actual impacts include data leakage, tampering, or service disruption. Proof of Concept (PoC) steps: 1. Use an FTP client (such as command-line ftp or a graphical tool) to connect to the target IP address port 2121; 2. Enter username 'anonymous', password any (e.g., empty or any string); 3. After login, arbitrary FTP commands can be executed, for example: - List files (ls), download files (get), upload files (put), delete files (delete), create directories (mkdir), etc. This vulnerability can be exploited without additional conditions, but if the server is not running with root privileges (as mentioned in the configuration file comments), changeroottype=real may fail, further expanding the attack surface to system files outside the serverroot (/usr/home/cinek/tmp3/aaa).

## Verification Metrics

- **Verification Duration:** 150.52 s
- **Token Usage:** 183291

---

## Original Information

- **File/Directory Path:** `var/etc/shadow_private`
- **Location:** `etc/shadow_private`
- **Description:** The file 'shadow_private' has its permissions set to 777 (readable, writable, and executable by all users), resulting in the exposure of the root user's password hash. An attacker, as a non-root user but possessing login credentials, can directly read the file's content and obtain the root's MD5 password hash ($1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1). The attack chain includes: 1) The attacker logs into the system; 2) Reads the '/etc/shadow_private' file; 3) Uses cracking tools (such as John the Ripper) to perform offline hash cracking; 4) If the cracking is successful, obtains the root password and escalates privileges. The MD5 hash algorithm is weak, making the probability of successful cracking high, especially if the password is simple. The trigger condition is simply the attacker having file read permissions, and the reproduction steps are straightforward (execute 'cat /etc/shadow_private').
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Notes:** This file might be a custom shadow file; it is necessary to verify whether it is used by the system for authentication. It is recommended to further analyze the system's authentication mechanism and related components (such as PAM configuration) to confirm the file's purpose and scope of impact. Additionally, check if other files have similar permission issues.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes the vulnerability. Evidence shows that the file 'var/etc/shadow_private' has permissions set to 777, making it readable by all users, and its content includes the root user's MD5 password hash '$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1'. Based on the attacker model (an authenticated local non-root user), the attack chain is complete: 1) The attacker logs into the system; 2) Executes 'cat /var/etc/shadow_private' to read the file; 3) Extracts the hash; 4) Uses cracking tools (such as John the Ripper) to perform offline cracking of the MD5 hash; 5) If the cracking is successful, obtains the root password and escalates privileges. The MD5 algorithm is weak, resulting in a high probability of successful cracking, especially when the password is simple. Reproduction PoC: As a non-root user, execute 'cat /var/etc/shadow_private' to obtain the hash, then use 'john --format=md5crypt hash.txt' to crack it. This vulnerability leads to the exposure of root credentials, posing a high risk.

## Verification Metrics

- **Verification Duration:** 156.15 s
- **Token Usage:** 188895

---

## Original Information

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.so:0x00006a38 sym.soap_control`
- **Description:** This vulnerability allows an attacker to achieve arbitrary code execution through SOAP requests. Specifically, in sym.soap_process, user-input SOAP request data is passed to the sym.soap_control function. At address 0x00006a38, a function pointer is loaded from offset 0x14 of a user-controlled parameter (param_3) and called via the `jalr t9` instruction. Due to a lack of input validation, an attacker can manipulate the input string in the SOAP request to make the function pointer point to a malicious address, thereby executing arbitrary code. The trigger condition is sending a specially crafted SOAP request (for example, via the HTTP interface), and the attacker must possess valid login credentials and network access. Potential attacks include complete remote system compromise. Constraints include the attacker needing to be able to send SOAP requests to the UPnP service, and the function pointer call lacks boundary checks.
- **Code Snippet:**
  ```
  iVar1 = (**(param_3 + 0x14))(param_1,param_2,*(param_1 + 0x38d0),*(param_1 + 0x38d8)); // param_3 is user-controlled, leading to arbitrary function call
  ```
- **Notes:** This vulnerability is common in UPnP libraries and may affect multiple devices. It is recommended to further verify exploitability in the actual environment and check other SOAP-related functions (such as action_process) to confirm there are no other attack vectors. Associated files may include network service components, but the current analysis is limited to libupnp.so.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert accurately describes the vulnerability. Analysis of libupnp.so confirms that in sym.soap_control at 0x00006a38, a function pointer is loaded from param_3 + 0x14 (user-controlled via SOAP requests) and called via jalr t9 without validation. The attack model assumes an authenticated remote attacker with valid credentials and network access to the UPnP SOAP interface. The path is reachable as sym.soap_control is called from sym.action_process during SOAP request handling. The impact is arbitrary code execution, as controlling the function pointer allows jumping to any address. For exploitation, an attacker can craft a SOAP request with a manipulated action structure where the field at offset 0x14 contains a malicious address (e.g., pointing to shellcode). PoC steps: 1) Send a POST request to the UPnP SOAP endpoint (e.g., /soap.cgi) with authentication; 2) Include a crafted XML SOAP body that sets the function pointer field to the target address; 3) Upon processing, the jalr t9 instruction executes code at that address, leading to full system compromise.

## Verification Metrics

- **Verification Duration:** 229.88 s
- **Token Usage:** 230893

---

## Original Information

- **File/Directory Path:** `usr/sbin/igd`
- **Location:** `igd:0x00402084 sym.igd_osl_nat_config`
- **Description:** A command injection vulnerability exists in the UPnP IGD service's port mapping functionality. The vulnerability allows an attacker to execute arbitrary commands with the privileges of the 'igd' process (typically root) by crafting a malicious UPnP AddPortMapping request. Specifically, the `NewInternalClient` parameter is user-controlled and is embedded into a command string using `sprintf` without sanitization. The constructed command is then executed via `_eval`, which interprets shell metacharacters. Trigger conditions include sending a UPnP request with `NewInternalClient` containing commands (e.g., '192.168.1.1; id'). The attack requires the attacker to be on the local network with access to the UPnP service, which is often enabled by default. Potential exploits include full system compromise, data theft, or device takeover.
- **Code Snippet:**
  ```
  // From igd_osl_nat_config decompilation
  // Command string construction using sprintf
  (**(iVar13 + -0x7f78))(pcVar6, *(iVar13 + -0x7fe0) + 0x591c, param_1, *(param_2 + 0x10), *(param_2 + 0x1a), *(param_2 + 0x2c));
  // Later, strcpy is used to append user-controlled data
  (*pcVar12)(pcVar6, param_2); // param_2 contains NewInternalClient
  // Command execution via _eval
  (**(iVar13 + -0x7f20))(apcStack_19c, *(iVar13 + -0x7fe0) + 0x5968, 0, 0); // _eval call
  ```
- **Notes:** The vulnerability is highly exploitable due to the lack of input sanitization and the use of `_eval` for command execution. The attack chain involves UPnP request processing, making it accessible to authenticated network users. Further verification could involve dynamic testing to confirm command execution. Additional vulnerabilities such as buffer overflows may exist but require more analysis.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is accurate. Based on decompiled code analysis, in the function 'sym.igd_osl_nat_config', the user-controlled 'NewInternalClient' parameter (accessed via 'param_2 + 0x1c') is directly embedded into the command string 'igdnat -i %s -eport %d -iport %d -en %d' without input sanitization. The constructed command is then executed via the '_eval' function, allowing shell injection. The attacker model is an unauthenticated remote attacker on the local network, as the UPnP service is typically enabled by default and accessible. Vulnerability exploitability verification: input is controllable (attacker can forge UPnP AddPortMapping requests), path is reachable (UPnP request processing calls this function), actual impact (executes arbitrary commands with root privileges, leading to system compromise). PoC steps: send a UPnP AddPortMapping request where the 'NewInternalClient' parameter contains malicious commands, such as '192.168.1.1; id', which will execute the 'id' command and return the result.

## Verification Metrics

- **Verification Duration:** 281.77 s
- **Token Usage:** 250601

---

## Original Information

- **File/Directory Path:** `webroot/js/privatejs/nat_virtualser.js`
- **Location:** `nat_virtualser.js: rule_entry function (specific line number unknown, but located in the part of the function that constructs HTML)`
- **Description:** A stored cross-site scripting (XSS) vulnerability exists in the rendering process of the internal IP address field on the NAT virtual server configuration page. An attacker can submit a malicious rule where the internal IP address contains an XSS payload (e.g., ' onmouseover='alert(1)'). When the page loads, the malicious script is executed because the input value is not properly escaped. Trigger condition: After an attacker submits a malicious rule, any user (including administrators) viewing the NAT configuration page. Exploitation method: The attacker can steal session cookies, execute arbitrary JavaScript code, or perform privilege escalation. The vulnerability originates from the `rule_entry` function directly concatenating user input into HTML attributes without escaping.
- **Code Snippet:**
  ```
  text += '<input type="text" class="input-medium" id="pip' + idx + '" name="pip' + idx + '" size="15" maxlength="15" value=' + row[3] + ' validchars="0123456789." onkeypress="return allowChars(this, event)"/>';
  ```
- **Notes:** The vulnerability relies on the backend storing and returning unescaped data, but the frontend rendering code clearly shows it is unescaped. It is recommended to check the backend processing to ensure input validation and output encoding. Related functions: `showlist` and `preSubmit`. Further verification is needed to check if the backend sanitizes the stored data.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Frontend code confirmed: In the rule_entry function in nat_virtualser.js, row[3] (internal IP address) is directly concatenated into the HTML value attribute, unescaped and not enclosed in quotes, which allows injection of malicious attributes (like onmouseover). However, the alert describes it as a stored XSS, which relies on the backend storing and returning unescaped data, but the current evidence does not verify the backend processing (such as input validation or output encoding). The attacker model requires an authenticated user to submit a malicious rule (e.g., the internal IP field contains ' onmouseover=alert(1)'), then any user viewing the page might trigger the XSS. But the full attack chain is incomplete: if the backend escapes the stored data, the vulnerability is not exploitable. Therefore, the vulnerability is not confirmed as real, and the risk level is low. PoC steps (assuming the backend does not escape): 1. Attacker submits a NAT rule with authentication, setting the internal IP to ' onmouseover=alert(1)'; 2. Administrator or other user views the NAT configuration page; 3. If the backend returns unescaped data, hovering the mouse triggers alert(1). But this external condition was not verified.

## Verification Metrics

- **Verification Duration:** 413.92 s
- **Token Usage:** 258600

---

