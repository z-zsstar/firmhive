# FH1206 (10 findings)

---

### Vulnerability-soap_control

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.so:0x00006a38 sym.soap_control`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** This vulnerability allows an attacker to achieve arbitrary code execution through SOAP requests. Specifically, in sym.soap_process, user-input SOAP request data is passed to the sym.soap_control function. At address 0x00006a38, a function pointer is loaded from offset 0x14 of a user-controlled parameter (param_3) and called via the `jalr t9` instruction. Due to a lack of input validation, an attacker can manipulate the input string in the SOAP request to make the function pointer point to a malicious address, thereby executing arbitrary code. The trigger condition is sending a specially crafted SOAP request (for example, via the HTTP interface); the attacker must possess valid login credentials and network access. Potential attacks include complete remote system compromise. Constraints include the attacker needing to be able to send SOAP requests to the UPnP service, and the function pointer call lacks bounds checking.
- **Code Snippet:**
  ```
  iVar1 = (**(param_3 + 0x14))(param_1,param_2,*(param_1 + 0x38d0),*(param_1 + 0x38d8)); // param_3 is user-controlled, leading to arbitrary function call
  ```
- **Keywords:** SOAPACTION HTTP header, urn:schemas-upnp-org:control-1-0#QueryStateVariable, sym.soap_process, sym.soap_control
- **Notes:** This vulnerability is common in UPnP libraries and may affect multiple devices. It is recommended to further validate exploitability in real-world environments and check other SOAP-related functions (such as action_process) to confirm there are no other attack vectors. Related files may include network service components, but the current analysis is limited to libupnp.so.

---
### PermissionMisconfig-ShadowFile

- **File/Directory Path:** `var/etc/shadow`
- **Location:** `shadow:1`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** A critical permission misconfiguration was found in the 'shadow' file, with file permissions set to -rwxrwxrwx, allowing all users (including non-root users) to read, write, and execute. This leads to two practically exploitable attack chains: 1) Non-root users can directly modify the file content, such as changing the root password hash or adding new user accounts, thereby gaining root privileges (via su or login); 2) Non-root users can read password hashes (using MD5 algorithm, $1$ prefix) and perform offline cracking (if the password is weak). The trigger condition is simple: an attacker only needs valid login credentials (non-root user) and access to the file. Boundary check is missing: the file has no permission restrictions, allowing arbitrary modifications. Exploitation methods include using a text editor or commands to directly edit the file, or using tools like john the ripper to crack the hashes.
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Keywords:** shadow
- **Notes:** This finding is based on direct evidence: file permissions and content. It is recommended to immediately fix the file permissions (for example, set to 640, only root can write). Subsequent analysis should verify whether the system relies on this file for authentication and check the permissions of other sensitive files.

---
### command-injection-formexeCommand

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd: sym.formexeCommand (0x0046eefc)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
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
- **Keywords:** cmdinput (HTTP parameter), formexeCommand (function symbol), websGetVar (function call), doSystemCmd (function call)
- **Notes:** The function 'formexeCommand' is registered in 'formDefineTendDa' during HTTP server initialization, making it accessible via HTTP requests. No explicit authentication checks are visible in the function, but it may rely on web application-level authentication. Given that the attacker has valid login credentials, this vulnerability is directly exploitable. Further analysis should verify the execution context (e.g., if httpd runs as root) and check for other similar vulnerabilities in form handlers.

---
### Command-Injection-igd_osl_nat_config

- **File/Directory Path:** `usr/sbin/igd`
- **Location:** `igd:0x00402084 sym.igd_osl_nat_config`
- **Risk Score:** 9.0
- **Confidence:** 8.5
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
- **Keywords:** NewInternalClient (UPnP parameter), igd_osl_nat_config function, _eval function
- **Notes:** The vulnerability is highly exploitable due to the lack of input sanitization and the use of `_eval` for command execution. The attack chain involves UPnP request processing, making it accessible to authenticated network users. Further verification could involve dynamic testing to confirm command execution. Additional vulnerabilities such as buffer overflows may exist but require more analysis.

---
### PrivEsc-File-passwd_private

- **File/Directory Path:** `var/etc/passwd_private`
- **Location:** `passwd_private:1 (File path, no specific line number)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The file 'passwd_private' contains the root user's MD5 password hash and has its permissions set to globally readable, writable, and executable (permissions 777). This allows any non-root user (with valid login credentials) to directly read the file. An attacker can obtain the hash value and use offline cracking tools (such as John the Ripper or hashcat) to perform brute-force or dictionary attacks. If the password strength is weak, the attacker may successfully crack the hash, thereby obtaining root privileges and achieving privilege escalation. The trigger condition is simple: the attacker only needs to execute a read command (such as 'cat passwd_private'). Boundary check is missing: the file lacks proper access control, allowing low-privilege users to access highly sensitive data. Potential attack methods include directly reading the hash and cracking it; the exploit chain is complete and feasible.
- **Code Snippet:**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **Keywords:** passwd_private
- **Notes:** This finding is based on direct evidence: the file content contains the root hash, and the permission settings are improper. The attack chain is complete, but successful exploitation depends on password strength and the efficiency of cracking tools. It is recommended to further verify the hash's susceptibility to cracking (for example, by testing with common password dictionaries). Related files may include other system password files, but this analysis focuses solely on 'passwd_private'. Subsequent analysis directions: check the permissions of other sensitive files in the system, or evaluate whether the password policy enforces the use of strong passwords.

---
### Config-AnonymousFTP

- **File/Directory Path:** `var/etc/stupid-ftpd/stupid-ftpd.conf`
- **Location:** `stupid-ftpd.conf:~line 75 (user definition line)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The configuration file defines an anonymous user (anonymous) with full permissions (A), allowing unauthenticated users to perform arbitrary file operations (download, upload, overwrite, delete, create directories, etc.). Attackers can connect to the FTP service (port 2121) and use anonymous login (no password required) to exploit these permissions. If the server is not running with root privileges (as mentioned in the configuration file comments), changeroottype=real may fail, resulting in no effective filesystem isolation, allowing attackers to access system files outside the serverroot (/usr/home/cinek/tmp3/aaa), provided the server process has the corresponding permissions. This constitutes a complete attack chain: entry point (FTP network interface) → data flow (FTP command processing) → dangerous operation (arbitrary file access and modification).
- **Code Snippet:**
  ```
  user=anonymous	*	 /	  5   A
  ```
- **Keywords:** stupid-ftpd.conf, FTP port 2121, serverroot=/usr/home/cinek/tmp3/aaa, user=anonymous
- **Notes:** Based on analysis of the configuration file content, the attack chain is complete and practically exploitable. However, further verification of the server binary code is needed to confirm changeroottype behavior and the server's actual running privileges (e.g., whether it runs as root). It is recommended to analyze the stupid-ftpd binary file to verify data flow and permission checks. Associated files may include the server executable and related logs.

---
### Untitled Finding

- **File/Directory Path:** `var/etc/shadow_private`
- **Location:** `etc/shadow_private`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The file 'shadow_private' has its permissions set to 777 (readable, writable, and executable by all users), resulting in the exposure of the root user's password hash. An attacker, as a non-root user but possessing login credentials, can directly read the file's contents and obtain the root user's MD5 password hash ($1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1). The attack chain includes: 1) The attacker logs into the system; 2) Reads the '/etc/shadow_private' file; 3) Uses a cracking tool (such as John the Ripper) to crack the hash offline; 4) If successful, obtains the root password and escalates privileges. The MD5 hash algorithm is weak, making the probability of cracking high, especially if the password is simple. The trigger condition is simply the attacker having file read permissions, and the reproduction steps are straightforward (execute 'cat /etc/shadow_private').
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Keywords:** etc/shadow_private
- **Notes:** This file might be a custom shadow file; it is necessary to verify whether it is used by the system for authentication. It is recommended to further analyze the system's authentication mechanism and related components (such as PAM configuration) to confirm the purpose and impact scope of this file. Simultaneously, check if other files have similar permission issues.

---
### XSS-nat_virtualser_rule_entry

- **File/Directory Path:** `webroot/js/privatejs/nat_virtualser.js`
- **Location:** `nat_virtualser.js:rule_entry function (specific line number unknown, but located in the part of the function that constructs HTML)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A stored cross-site scripting (XSS) vulnerability exists in the rendering process of the internal IP address field on the NAT virtual server configuration page. An attacker can submit a malicious rule where the internal IP address contains an XSS payload (for example: ' onmouseover='alert(1)). When the page loads, the malicious script is executed due to the input value not being properly escaped. Trigger condition: After an attacker submits a malicious rule, any user (including administrators) viewing the NAT configuration page. Exploitation method: An attacker can steal session cookies, execute arbitrary JavaScript code, or perform privilege escalation. The vulnerability originates from the `rule_entry` function directly concatenating user input into HTML attributes without escaping.
- **Code Snippet:**
  ```
  text += '<input type="text" class="input-medium" id="pip' + idx + '" name="pip' + idx + '" size="15" maxlength="15" value=' + row[3] + ' validchars="0123456789." onkeypress="return allowChars(this, event)"/>';
  ```
- **Keywords:** reqStr, pipX (Internal IP Address Field), document.frmSetup
- **Notes:** The vulnerability relies on the backend storing and returning unescaped data, but the frontend rendering code clearly shows it is unescaped. It is recommended to check the backend processing to ensure input validation and output encoding. Related functions: `showlist` and `preSubmit`. Further verification is needed to check if the backend sanitizes the stored data.

---
### Command Injection-iprule.sh

- **File/Directory Path:** `bin/iprule.sh`
- **Location:** `iprule.sh:15 (estimated line number, based on code structure)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The script uses the unquoted variable $FILE when reading the input file, allowing command injection. Specific manifestation: When the script is executed, if the FILE parameter contains shell metacharacters (such as ;, |, &), the `cat $FILE` will be interpreted by the shell and execute arbitrary commands. Trigger condition: An attacker directly executes the script and passes a malicious FILE parameter (e.g., './iprule.sh add ";malicious_command" table prio'). Constraints: The script only checks that the number of parameters is 4, but does not validate the parameter content; the file existence check has a syntax error (`[ -z -rts ]`), which may not take effect. Potential attack: An attacker can inject commands to perform arbitrary operations. If the script runs with root privileges, it may lead to privilege escalation. The exploitation method is simple and direct, requiring no complex steps.
- **Code Snippet:**
  ```
  rts=\`cat $FILE\`
  ```
- **Keywords:** FILE parameter
- **Notes:** Evidence for the existence of the vulnerability is sufficient, but exploitability depends on the script's execution privileges. It is recommended to further analyze the script's invocation context (e.g., whether it is called by a root process) to confirm the possibility of privilege escalation. Additionally, check if other parameters (such as TABLE and PRIO) in the ip rule command also pose injection risks, but the current focus is on the FILE parameter.

---
### XSS-wirelessScan

- **File/Directory Path:** `webroot/js/privatejs/wireless_extra.js`
- **Location:** `wireless_extra.js: wirelessScan function and fillAcc function (specific line numbers unavailable, but the code is located in the part handling scan result display)`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** A stored XSS vulnerability was discovered in the wireless scanning function of the 'wireless_extra.js' file. An attacker can inject JavaScript code by setting the SSID field of a malicious AP. When a logged-in user performs a wireless scan (via the '/goform/ApclientScan' interface) and views the results, the malicious SSID is inserted into the page via innerHTML, leading to script execution. Trigger conditions: the user visits the wireless settings page and clicks the scan button; the attacker needs to be able to control the AP's SSID (e.g., via physical proximity or network infiltration). Potential exploitation methods: stealing user session cookies, tampering with wireless settings, redirecting users to malicious pages. The vulnerability lies in the client-side display logic, lacking HTML escaping for SSID content.
- **Code Snippet:**
  ```
  // In the wirelessScan function:
  nc.innerHTML = str[0]; // SSID directly inserted into HTML
  nc.innerHTML = str[1]; // MAC address
  // In the fillAcc function:
  nc.innerHTML = str[0]; // SSID used for table display
  nc.title = decodeSSID(str[0]); // Possibly not escaped
  ```
- **Keywords:** /goform/ApclientScan, remoteSsid, wlScanTab
- **Notes:** Exploiting this vulnerability requires the attacker to control the wireless environment (e.g., by setting up a malicious AP). The decodeSSID function is not defined in the file; it is assumed it might not adequately escape HTML. It is recommended to subsequently analyze how the backend '/goform/ApclientScan' interface handles SSID input. This vulnerability could be used for privilege escalation or persistent attacks, but is limited by the network environment.

---
