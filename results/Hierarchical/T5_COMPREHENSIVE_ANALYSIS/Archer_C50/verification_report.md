# Archer_C50 - Verification Report (6 alerts)

---

## network_input-libjs_dom_xss-187

### Original Information
- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js:187,203`
- **Description:** High-risk DOM-based XSS vulnerability: The html() function directly sets elem.innerHTML (line 187), and the dhtml() function dynamically executes scripts (line 203). Trigger conditions: Attacker controls the value parameter (html function) or str parameter (dhtml function). Exploitation method: Inject malicious HTML/JS code. Constraint: The dhtml function only executes scripts when the input contains <script> tags. Security impact: Full control over page DOM, enabling cookie theft (including Authorization) or malicious request initiation.
- **Code Snippet:**
  ```
  elem.innerHTML = value;
  $.each(scripts, function() {$.script(this.text || this.textContent || this.innerHTML || '')});
  ```
- **Notes:** Combining with the document.cookie operation (line 331) allows stealing authentication tokens. It is necessary to trace the source of the value/str parameters. Related knowledge base: 'Combined with XSS vulnerabilities, it can form a complete attack chain: XSS execution → cookie theft → obtaining administrator privileges.'

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code existence verification successful: Confirmed that the html() function directly sets innerHTML (line 187), the dhtml() function executes <script> tags (line 203), and document.cookie operations exist (line 331).  
2) Critical evidence missing: Through 6 tool invocations and knowledge base queries, unable to verify the source of value/str parameters:  
   - No function call points found within lib.js (grep returned empty)  
   - No call chain records in the knowledge base  
3) Vulnerability assessment: Unable to prove parameters can be externally controlled (e.g., via network input), failing to meet basic CVE vulnerability criteria  
4) Trigger possibility: Even if the vulnerability exists, it requires unverified preconditions (parameter contamination) and cannot be directly triggered

### Verification Metrics
- **Verification Duration:** 624.38 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 520965

---

## config-dir_permission-rcS

### Original Information
- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `rcS:18,24`
- **Description:** The script creates globally writable directories (0777), including /var/samba/private (line 24) and /var/tmp/dropbear (line 18). Trigger condition: Automatically executed during system startup. Security impact: Attackers can tamper with dropbear keys or samba configuration files (e.g., injecting malicious smb.conf), achieving privilege escalation or information theft when related services start. Exploitation chain: Control directory → inject malicious configuration/keys → service loading → system compromise.
- **Notes:** Verify whether dropbear/samba uses these directories

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification confirmed: 1) Lines 18/24 of rcS indeed create a globally writable directory (0777); 2) The dropbearmulti binary contains the path string '/var/tmp/dropbear', proving the directory is used by the service and can be tampered with by attackers; 3) No configuration file evidence was found for the samba portion, making it impossible to verify the usage of /var/samba/private. Therefore, the findings are generally accurate except for the unconfirmed samba portion, and the vulnerability as a whole is valid and directly triggered (executed automatically during startup).

### Verification Metrics
- **Verification Duration:** 1647.32 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 899387

---

## network_input-libjs_dom_xss

### Original Information
- **File/Directory Path:** `web/mainFrame.htm`
- **Location:** `js/lib.js: loadMainHIDDEN`
- **Description:** High-risk DOM-based XSS vulnerability: When an attacker controls the `path` parameter of `$.loadMain` with an HTML string (e.g., `'<script>alert(1)</script>'`), arbitrary scripts can be executed through direct DOM insertion via `innerHTML`. Trigger conditions: 1) Injecting a malicious `path` value through prototype pollution or error handling; 2) Triggering the `$.err`/`$.errBack` call chain (e.g., inducing HTTP errors or CGI failures). Actual impact: Combined with the authentication REDACTED_PASSWORD_PLACEHOLDER vulnerability in `login.htm`, it can steal administrator credentials to achieve full device control.
- **Code Snippet:**
  ```
  if (!path) path = $.curPage;
  var bFile = (path.indexOf("<") < 0);
  ...
  $.loadPage("main", path, function(){...})
  ```
- **Notes:** It is necessary to verify how external input reaches the path parameter in conjunction with the backend error generation mechanism. Associated vulnerability chain: can trigger authentication REDACTED_PASSWORD_PLACEHOLDER theft in login.htm.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Dangerous operation (unfiltered innerHTML insertion) exists, but the trigger path is unverified: 1) All `$.loadMain` call points have `path` parameters that are either hardcoded or internal states (e.g., `$.curPage`), with no evidence of external input contaminating the path; 2) The `$.err`/`$.errBack` mechanism only passes numeric error codes, making HTML injection impossible; 3) The associated vulnerability chain (login.htm authentication REDACTED_PASSWORD_PLACEHOLDER theft) lacks code evidence to support it. Practical exploitation would require simultaneously satisfying: a) Prototype pollution modifying `$.mainParam` (no evidence) b) Inducing specific HTTP errors (uncontrollable) c) Bypassing numeric error code restrictions (unfeasible).

### Verification Metrics
- **Verification Duration:** 1942.50 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 968020

---

## attack_chain-file_pollution_to_rce

### Original Information
- **File/Directory Path:** `usr/bin/cos`
- **Location:** `usr/bin/cos:0x409bfc [strcpy]`
- **Description:** High-Risk Attack Chain: File Contamination Leading to Command Injection and Buffer Overflow. Specific Manifestations: 1) Globally writable file '/var/tmp/umount_failed_list' content is contaminated; 2) fcn.REDACTED_PASSWORD_PLACEHOLDER fails to validate file content during reading; 3) Contaminated data triggers stack overflow via strcpy (0x409bfc); 4) Same data executes arbitrary shell commands in rm -rf at fcn.004099f4. Trigger Condition: Attacker writes ≥320 bytes of malicious content to target file. Security Impact: Full device control (Risk Level 9.5).
- **Code Snippet:**
  ```
  // HIDDEN
  0x00409bfc  jalr t9 ; sym.imp.strcpy  // HIDDEN
  (**(gp-0x7f58))(buf,"rm -rf %s%s","/var/usbdisk/",param) // HIDDEN
  ```
- **Notes:** Exploit Constraints: 1) Bypass ASLR to achieve overflow exploitation 2) Command injection must avoid path truncation. Recommended follow-up actions: dynamically verify overflow feasibility and inspect HTTP file upload interfaces

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Command injection established: Contaminated file content is directly concatenated into system() execution (evidence: 0x00409a68 instruction)  
2) File reference exists: '/var/tmp/umount_failed_list' string present in binary  
3) Description discrepancies:  
   a) No strcpy call (0x409bfc is jalr instruction)  
   b) No buffer overflow component  
   c) Trigger requires only command separator, not 320 bytes  
Revised analysis still confirms directly triggerable RCE vulnerability (exploitation trivial: write ;malicious_command to file)

### Verification Metrics
- **Verification Duration:** 5822.94 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2241094

---

## file-write-var-perm

### Original Information
- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `rcS:8-16,20-22`
- **Description:** High-risk directory permission settings: Globally writable directories such as /var/tmp and /var/usbdisk are created via '/bin/mkdir -m 0777'. Attackers gaining low-privilege access (e.g., through a telnetd vulnerability) can plant malicious scripts or tamper with data in these directories to achieve privilege escalation or persistent control. Trigger condition: Attackers obtain arbitrary command execution privileges. Constraint: Directories are created at startup with persistent permissions. Potential impact: Privilege escalation, data tampering, or denial of service.
- **Code Snippet:**
  ```
  /bin/mkdir -m 0777 -p /var/tmp
  /bin/mkdir -m 0777 -p /var/usbdisk
  ```
- **Notes:** Check if directories under /var are being used by critical services

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code Verification: Confirm the presence of globally writable directory creation commands at the specified location in rcS, with permissions set to 0777 allowing any user to read, write, and execute;  
2) Logic Verification: The command is unconditionally executed during system startup and the permissions remain persistently effective, with the telnetd service providing a potential attack vector;  
3) Impact Verification: Low-privileged attackers can plant malicious files (e.g., via telnet vulnerabilities) in these directories to achieve persistent control or privilege escalation. However, the vulnerability requires prior execution access to exploit, making it non-directly triggerable.

### Verification Metrics
- **Verification Duration:** 113.64 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 58676

---

## command_execution-iptables_path_pollution

### Original Information
- **File/Directory Path:** `etc/iptables-stop`
- **Location:** `etc/iptables-stop:4`
- **Description:** The script uses relative paths to invoke the iptables command (e.g., 'iptables -F'), without specifying an absolute path or resetting the PATH environment variable. When the PATH is compromised (e.g., containing writable directories like /tmp), an attacker can place a malicious iptables program to achieve command injection. Trigger conditions: 1) The attacker controls the PATH variable, 2) A malicious program is placed in a PATH directory, 3) The script is executed. Impact: Gains REDACTED_PASSWORD_PLACEHOLDER privileges (since iptables typically requires REDACTED_PASSWORD_PLACEHOLDER permissions to execute).
- **Code Snippet:**
  ```
  iptables -t filter -F
  ```
- **Notes:** It is necessary to analyze whether the parent process (such as init scripts) calling this script has securely configured the PATH. Scenarios in firmware where service restarts are triggered through web interfaces may be exploited.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification confirmed: 1) The script indeed uses relative paths to invoke iptables without resetting PATH (technical prerequisite established) 2) However, no evidence of parent processes or triggering mechanisms calling this script could be found 3) Knowledge base queries confirmed no web interface call records. Vulnerability formation requires proof that attackers can control the PATH environment variable - current lack of execution context evidence prevents confirmation of trigger condition fulfillment.

### Verification Metrics
- **Verification Duration:** 702.26 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 558930

---

