# TD-W8980_V1_150514 - Verification Report (13 alerts)

---

## configuration_load-user-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

### Original Information
- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:0`
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user is configured as a REDACTED_PASSWORD_PLACEHOLDER-privilege account with UID=0/GID=0, using an MD5 REDACTED_PASSWORD_PLACEHOLDER hash starting with $1$$. Attackers can brute-force this weak hash through network interfaces (e.g., SSH/Telnet) to gain full control of the device. The home directory is set to '/' and the shell to '/bin/sh' with no permission restrictions. Trigger conditions: 1) REDACTED_PASSWORD_PLACEHOLDER login service is enabled 2) Insufficient REDACTED_PASSWORD_PLACEHOLDER strength. Actual impact: After obtaining REDACTED_PASSWORD_PLACEHOLDER privileges, attackers can directly perform dangerous operations (e.g., modifying system files).
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Notes:** Verify the actual REDACTED_PASSWORD_PLACEHOLDER policy in REDACTED_PASSWORD_PLACEHOLDER; it is recommended to check the login entry for the REDACTED_PASSWORD_PLACEHOLDER account in the network service configuration.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code analysis verification confirms:  
1) The REDACTED_PASSWORD_PLACEHOLDER account in etc/REDACTED_PASSWORD_PLACEHOLDER.bak is confirmed as a REDACTED_PASSWORD_PLACEHOLDER-privileged account with UID=0/GID=0, using a weak MD5 hash starting with $1$$.  
2) etc/init.d/rcS:77 launches an unauthenticated Telnet service.  
3) rcS:17 copies REDACTED_PASSWORD_PLACEHOLDER.bak as the login REDACTED_PASSWORD_PLACEHOLDER file /var/REDACTED_PASSWORD_PLACEHOLDER.  
4) The telnetd startup command lacks additional authentication parameters. Attackers can directly brute-force the weak hash via the network to gain REDACTED_PASSWORD_PLACEHOLDER access without prerequisites, constituting an immediately exploitable real vulnerability.

### Verification Metrics
- **Verification Duration:** 570.44 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 793415

---

## network_input-parentCtrl-formInputs

### Original Information
- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `parentCtrl.htm: <input>HIDDEN`
- **Description:** Discovered 7 form input points (mac1-4/parentMac, etc.) submitted via HTTP POST to the /cgi/lanMac endpoint. This forms a complete attack chain with prior findings (network_input-parentCtrl-doSave): frontend input (maxlength=17 with no content filtering) → AJAX submission → backend NVRAM variable processing. Attackers could craft malicious MAC addresses/URL parameters to trigger parameter injection or buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  <input name='mac1' maxlength='17' onkeyup='checkMac(this)'>
  ```
- **Notes:** Correlate existing findings: network_input-parentCtrl-doSave (File path: web/main/parentCtrl.htm)

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Inaccurate description of input points (actual 5 vs reported 7), but maxlength=17 exists with no content filtering; 2) Full attack chain confirmed: frontend input → AJAX submission → /cgi/lanMac endpoint → direct NVRAM operation ('mac=' + user input); 3) Vulnerability exploitability verified: a) Parameter injection risk (user input directly concatenated into parameters) b) Potential buffer overflow (maxlength can be bypassed) c) No effective filtering (only format validation); 4) Can be directly triggered via HTTP request without prerequisites

### Verification Metrics
- **Verification Duration:** 692.29 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 996151

---

## mount-option-tmp-ramfs

### Original Information
- **File/Directory Path:** `etc/fstab`
- **Location:** `fstab:4`
- **Description:** The /tmp directory is mounted as a globally writable path without noexec/nosuid restrictions. Configured with rw permissions and execution allowed, attackers can upload malicious binaries via methods such as web uploads and execute them directly. Typical exploitation chain: file upload via network interface → write to /tmp → execute to obtain a shell. Constraint: relies on other components to achieve file writing.
- **Notes:** mount

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Verify in line 4 of etc/fstab that /tmp is mounted as ramfs with the 'defaults' option, which typically includes rw, exec, and suid permissions, consistent with the description;  
2) Constitutes a real vulnerability, as the execution of files in /tmp is a critical component of the complete attack chain;  
3) Not directly triggered, as vulnerability exploitation relies on other components (such as web file upload functionality) to write malicious files to /tmp. Static analysis cannot verify:  
a) Whether this configuration is applied during system startup  
b) Whether other security mechanisms exist to restrict execution permissions in /tmp.

### Verification Metrics
- **Verification Duration:** 135.19 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 222759

---

## file_write-rcS-mkdir-5

### Original Information
- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:5-18`
- **Description:** The command `mkdir -m 0777` creates 13 globally writable directories (including sensitive paths such as `/var/log` and `/var/run`). After gaining telnet access, attackers can arbitrarily write files in these directories (e.g., replacing dynamic link libraries or implanting malicious scripts). Combining this with cron or startup scripts enables persistent attacks. The trigger condition is the attacker first obtaining telnet access.
- **Code Snippet:**
  ```
  /bin/mkdir -m 0777 -p /var/log
  /bin/mkdir -m 0777 -p /var/run
  ...
  ```
- **Notes:** Analyze whether other services are using these directories; it is recommended to check the ownership configuration of files under /var; this vulnerability relies on the initial access provided by the unauthenticated telnet service (see rcS:77 for discovery).

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Core findings are accurate but contain minor inaccuracies: 1) Correct aspects - Globally writable sensitive directories (e.g., /var/log, /var/run) were indeed created without protection logic; 2) Inaccurate detail - Actually created 11 directories (not 13); 3) Vulnerability confirmed - Combined with telnetd service (launched from same file) to form attack chain, allowing attackers with telnet access to arbitrarily write to sensitive directories; 4) Not directly triggered - Requires obtaining telnet access as prerequisite condition.

### Verification Metrics
- **Verification Duration:** 146.85 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 182925

---

## xss-usb-dom-01

### Original Information
- **File/Directory Path:** `web/main/usbManage.htm`
- **Location:** `usbManage.htm:180,182,184,144`
- **Description:** High-risk DOM-based XSS exploitation chain: Attackers manipulate USB device metadata (e.g., maliciously crafted volume labels) or hijack backend responses to contaminate properties like volumeList[i].name/fileSystem. When administrators access the USB management page, the contaminated data is directly inserted into innerHTML (lines 180/182/184) without filtration, triggering malicious script execution. Trigger conditions: 1) Attacker must control USB device metadata or perform MITM response hijacking 2) Administrator accesses /web/main/usbManage.htm. Successful exploitation grants complete control over administrator sessions.
- **Code Snippet:**
  ```
  cell.innerHTML = volumeList[i].name;  // HIDDEN
  ```
- **Notes:** Verify whether the backend component (e.g., cgibin) that generates volumeList sanitizes external inputs. Related file: USB data processing functions in /lib/libshared.so.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Front-end vulnerability pattern confirmed: Three instances of unfiltered innerHTML assignments were identified in usbManage.htm (line 180: volumeList[i].name, line 182: volumeList[i].fileSystem, line 184: volumeList[i].capacity). However, back-end validation is missing: 1) Associated file /lib/libshared.so not found 2) No back-end component handling USB data was detected 3) Unable to confirm whether volumeList data undergoes sanitization. Vulnerability establishment requires unverified back-end sanitization conditions. Trigger path is non-direct: Requires attacker to control USB metadata or hijack responses, along with administrator access to specific pages.

### Verification Metrics
- **Verification Duration:** 383.72 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 496167

---

## network_input-parentCtrl-doSave

### Original Information
- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `parentCtrl.htm: doSave()HIDDEN`
- **Description:** Multiple unvalidated user input points (MAC address, URL, time parameters) were identified, which are directly submitted to the /cgi/lanMac backend endpoint through event handler functions such as doSave(). Trigger condition: when a user submits the parental control configuration form. The input values are directly bound to NVRAM variables (e.g., parentMac/urlAddr), with no frontend implementation of MAC format validation, URL whitelist checks, or time range verification, potentially allowing malicious data injection into NVRAM.
- **Code Snippet:**
  ```
  HIDDEN：$('#parentMac').val() HIDDEN → $.act('/cgi/lanMac', {...})
  ```
- **Notes:** The associated keywords 'ACT_CGI'/'doSave' already exist in the knowledge base; verification is required for the backend /cgi/lanMac's handling logic of NVRAM parameters.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Evidence indicates: 1) The MAC verification has a logic inversion flaw, rendering it effectively equivalent to no verification; 2) URL only validates format without content review, matching the description of "no whitelist check implemented"; 3) Time parameters lack any validation; 4) NVRAM binding path is confirmed to exist. The core vulnerability (insufficient validation of user input leading to NVRAM injection) stands, allowing attackers to directly trigger it by submitting malicious forms. Two corrections are required: the actual submission endpoint is $.act(ACT_SET) rather than /cgi/lanMac; MAC/URL have basic validation functions but provide no effective protection.

### Verification Metrics
- **Verification Duration:** 1651.40 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2298217

---

## network_input-telnetd_env_injection-00438cc0

### Original Information
- **File/Directory Path:** `bin/busybox`
- **Location:** `busybox:0x00438cc0-0x00438d10`
- **Description:** The telnetd component has an environment variable injection vulnerability (CVE-2011-2716 pattern). Attackers can send malicious REDACTED_PASSWORD_PLACEHOLDERs (e.g., 'REDACTED_PASSWORD_PLACEHOLDER\nLD_PRELOAD=/tmp/evil.so') via Telnet connections. The function fcn.00438bc0 directly splits this input into multiple lines and sets environment variables such as REDACTED_PASSWORD_PLACEHOLDER without performing any special character filtering or boundary checks. When the login program is subsequently called, injected variables like LD_PRELOAD can lead to dynamic library hijacking, enabling remote code execution. Trigger conditions: 1) telnetd service is enabled (confirmed to start without authentication at /etc/init.d/rcS:77); 2) attackers can establish Telnet connections; 3) the /tmp directory is writable. Actual impact: unauthenticated remote code execution (CVSS 9.8).
- **Code Snippet:**
  ```
  0x00438cc0: lw a1, (s1)
  0x00438cc8: jal fcn.0043ae0c
  0x00438ccc: addiu a0, a0, 0x1860  # "USER"
  ```
- **Notes:** Forms a complete attack chain with the knowledge base record 'command_execution-rcS-telnetd-77'. Verification required: 1) Whether the /tmp mount configuration in the firmware allows arbitrary writes 2) Whether login calls LD_PRELOAD

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code analysis confirms: 1) At address 0x00438cc0, the instruction "lw a1, (s1)" directly loads unfiltered Telnet input 2) Consecutive setenv calls for environment variables (USER/LOGNAME/HOME) fail to handle newline characters 3) Complete attack chain (telnetd started without authentication → input injection → login loading dynamic library). The dynamic linking mechanism (ELF interpreter) ensures LD_PRELOAD takes effect. CVSS 9.8 rating is justified as attackers only need a single Telnet connection with malicious REDACTED_PASSWORD_PLACEHOLDER to trigger remote code execution.

### Verification Metrics
- **Verification Duration:** 3694.46 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3072521

---

## network_input-fwRulesEdit-ruleName_xss_vector

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm:2 (doSave) 0x[HIDDEN]`
- **Description:** Network Input Handling Flaw: The front-end page collects firewall rule parameters such as ruleName (maxlength=15) and directly submits them to the back-end RULE operation endpoint via the doSave() function. Trigger Condition: An attacker submits malicious rule configurations (e.g., injecting special characters) through HTTP requests. Security Impact: The ruleName parameter lacks content filtering, potentially enabling stored XSS or serving as an injection point to compromise back-end services.
- **Code Snippet:**
  ```
  function doSave(){
    fwAttrs.ruleName = $.id("ruleName").value;
    $.act(ACT_ADD, RULE, null, null, fwAttrs);
  }
  ```
- **Notes:** Verify whether the backend processing files for RULE operations (such as CGI programs) filter the ruleName; related knowledge base ACT_GL operations (network_input-manageCtrl-apiEndpoints).

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1. Frontend validation ($.isname) only blocks specific special characters and trailing spaces, but allows HTML/JS construction symbols necessary for XSS payloads such as `<`, `>`, and `'`.  
2. The rule name (ruleName) is directly submitted to the backend via $.act(ACT_ADD, RULE), with no observed encoding/filtering in the code.  
3. The maxlength=15 restriction can limit but not prevent XSS attacks (e.g., `'<script>/*` still meets the length requirement).  
4. Due to a lack of evidence for backend validation (static analysis cannot verify), this input field remains a potential XSS attack vector.  
5. The likelihood of triggering remains high (8.5 points) because malicious rule names can be submitted directly via HTTP requests.

### Verification Metrics
- **Verification Duration:** 239.29 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 196437

---

## network_input-usb-xss_volume_name

### Original Information
- **File/Directory Path:** `web/main/usbManage.htm`
- **Location:** `www/usbManage.htm:109-110,180-184 (render_volume_list)`
- **Description:** Attack Chain 1: Physical Injection XSS. Trigger Condition: Attacker physically connects a USB device containing a malicious volume name (e.g., `<script>payload</script>`) → Administrator accesses the usbManage.htm page → ACT_GL retrieves the LOGICAL_VOLUME list → volumeList[i].name is directly inserted into the DOM via innerHTML without filtering → Triggers XSS. Constraint: Requires bypassing device metadata generation filters (e.g., udev rules). Security Impact: Session hijacking/full device control.
- **Code Snippet:**
  ```
  volumeList = $.act(ACT_GL, LOGICAL_VOLUME, null, null);
  cell.innerHTML = volumeList[i].name;
  ```
- **Notes:** Verification required: 1) /bin/usb volume name filtering mechanism 2) ACT_GL backend authorization 3) Related knowledge base HTTPS configuration (unique value in notes field)

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Frontend vulnerability exists (unfiltered innerHTML insertion), but critical backend evidence is missing: 1) No handler for /bin/usb or equivalent volume name processing found 2) ACT_GL backend implementation location unknown 3) udev rules directory does not exist. The described complete attack chain (physical injection of malicious volume names) cannot be confirmed due to lack of evidence for volume name REDACTED_PASSWORD_PLACEHOLDER mechanisms. Triggering requires simultaneous fulfillment of: a) No backend filtering b) Bypassing metadata generation constraints, making actual exploitability questionable.

### Verification Metrics
- **Verification Duration:** 592.90 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 857706

---

## XSS-Chain-libjs-url_control

### Original Information
- **File/Directory Path:** `web/js/lib.js`
- **Location:** `Multiple functions`
- **Description:** URL-controllable DOM operation chain: 1) $.refresh() directly uses location.href 2) $.deleteCookie() manipulates document.cookie 3) location.hash is unfiltered. Combined with innerHTML, it can form an XSS attack chain. Trigger condition: User controls URL parameters. Impact: Complete XSS exploitation chain.
- **Code Snippet:**
  ```
  $.refresh = function(domain, port, frame, page) {
    location.href = ret[1] + '://' + (domain ? domain : ret[2]) + ... + (page ? '#__' + page.match(/\w+\.htm$/) : '');
  }
  ```
- **Notes:** The associated knowledge base already contains the keyword '#__\w+\.htm$', and it is necessary to verify whether the page parameter originates from the URL.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification Conclusion: 1) Accuracy Assessment (partially): a) The filtering flaw in the $.refresh function's page parameter is confirmed (unanchored regex allows injecting alert.htm) ✓ b) Correct construction of location.hash ✓ c) However, $.deleteCookie is irrelevant to the XSS chain ✗ 2) Vulnerability Authenticity (true): Although the attack chain is incomplete, the fundamental vulnerability of XSS vector persistence via location.hash exists. 3) Direct Trigger (false): Two external conditions are required: a) Passing unsanitized URL parameters when calling $.refresh b) Existence of an HTML page that parses location.hash (e.g., *.htm). Current evidence only proves a local vulnerability in lib.js, with full exploitation dependent on external factors.

### Verification Metrics
- **Verification Duration:** 420.94 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 744695

---

## network_input-manageCtrl-hostValidation

### Original Information
- **File/Directory Path:** `web/main/manageCtrl.htm`
- **Location:** `manageCtrl.htm:79-85 (doSave function)`
- **Description:** The network input validation has a logical flaw, triggered when non-IP and non-MAC values are entered in the l_host/r_host fields. Specific manifestations: 1) Validation requires simultaneous satisfaction of both IP and MAC format conditions (impossible requirement) 2) Non-IP inputs incorrectly invoke the $.num2ip($.ip2num()) conversion 3) MAC addresses are forcibly converted to uppercase without format validation. Potential impact: Attackers could inject special characters (such as command injection symbols) causing backend parsing exceptions, potentially leading to memory corruption or configuration injection.
- **Code Snippet:**
  ```
  arg = $.id("l_host").value;
  if (arg !== "" && $.ifip(arg, true) && $.mac(arg, true))
    return $.alert(ERR_APP_LOCAL_HOST);
  if (!$.ifip(arg, true)) appCfg.localHost = $.num2ip($.ip2num(arg));
  else appCfg.localHost = arg.toUpperCase();
  ```
- **Notes:** It is necessary to combine the backend verification injection feasibility of /cgi/auth

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on code analysis: 1) The validation condition requires simultaneous satisfaction of IP and MAC formats (lines 81-82), which is an impossible event, leading to bypass of validation logic; 2) When non-IP input is received, it directly executes the $.num2ip($.ip2num(arg)) conversion (line 83). If the input contains special characters (e.g., ';'), the conversion function may produce undefined behavior; 3) MAC addresses are forced to uppercase but lack format validation (line 84), allowing attackers to inject unconventional characters. These combined flaws enable attackers to inject malicious content through the l_host/r_host fields, and the vulnerability can be directly triggered through frontend input. Although the backend processing details of /cgi/auth cannot be verified, the frontend validation flaws already constitute an exploitable starting point in the vulnerability chain.

### Verification Metrics
- **Verification Duration:** 278.20 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 447515

---

## attack_chain-manageCtrl-remoteExploit

### Original Information
- **File/Directory Path:** `web/main/manageCtrl.htm`
- **Location:** `HIDDEN（HIDDENmanageCtrl.htmHIDDEN/cgi/authHIDDEN）`
- **Description:** Most feasible attack chain: The attacker intercepts REDACTED_PASSWORD_PLACEHOLDER requests via the remote management interface (r_http_en) → accesses /cgi/auth after obtaining credentials → exploits ACL_CFG configuration flaw to set 0.0.0.0 bypassing ACL → triggers backend vulnerability by injecting special characters in the host field. Trigger probability assessment: Medium-high (requires r_http_en to be enabled and HTTPS disabled)
- **Notes:** Prerequisite conditions: 1) Remote management enabled 2) HTTPS not enforced 3) Backend lacks secondary validation for host input

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Front-end risks (remote management interface and host field input vulnerabilities) have been confirmed, but the attack chain is broken: 1) The critical file 'cgi/auth' does not exist (repeated verification failed to locate it) 2) Unable to verify the backend vulnerability triggering mechanism 3) Insufficient evidence of ACL configuration flaws (only affecting Ping service). The attack chain cannot form a complete vulnerability due to missing core components.

### Verification Metrics
- **Verification Duration:** 1225.81 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1783471

---

## mount-option-var-ramfs

### Original Information
- **File/Directory Path:** `etc/fstab`
- **Location:** `fstab:2`
- **Description:** The /var directory is mounted using ramfs without the noexec/nosuid options. The default configuration permits exec and suid permissions. If an attacker gains write access to the /var directory (e.g., through a log injection vulnerability), they could deploy malicious executable files or suid privilege escalation programs. Trigger condition: Existence of a file write vulnerability + the attacker can trigger execution. Boundary check: No permission restrictions—any process capable of writing to /var can exploit this.
- **Notes:** Mount  

Additional vulnerabilities are required to complete file writing. It is recommended to subsequently check the log processing component.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** REDACTED_PASSWORD_PLACEHOLDER evidence supporting: 1) Line 2 in etc/fstab confirms ramfs is mounted at /var with 'defaults' option (including exec/suid) 2) etc/init.d script verifies configuration is loaded via mount -a 3) /var permissions are set to 0777. Risk validation basis: After an attacker gains write access (e.g., through log vulnerabilities), they can deploy malicious programs in /var and execute them by leveraging default exec permissions. Non-direct trigger reason: No system code was found directly executing files in the /var directory; execution depends on external vulnerability triggers (e.g., log component injection), which aligns with the described trigger conditions in the discovery.

### Verification Metrics
- **Verification Duration:** 2184.96 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2308612

---

