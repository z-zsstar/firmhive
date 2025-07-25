# Archer_C2_V1_170228 - Verification Report (22 alerts)

---

## ipc-diagnostic-diagCommand

### Original Information
- **File/Directory Path:** `web/main/diagnostic.htm`
- **Location:** `diagnostic.htm:264-600`
- **Description:** The diagCommand variable is passed through the DIAG_TOOL object in ACT_SET/ACT_GET operations, directly serving as the carrier for diagnostic commands. All 12 call instances lack input validation (`$.act(ACT_SET, DIAG_TOOL, null, null, diagCommand)`). An attacker could manipulate diagCommand to inject malicious commands, triggering backend execution after writing via ACT_SET. Trigger condition: Requires tampering with diagCommand value and activating diagnostic procedures. Constraints: Must account for backend command execution validation mechanisms. REDACTED_PASSWORD_PLACEHOLDER risk: Critical command injection vulnerability exploitation chain entry point.
- **Code Snippet:**
  ```
  264: $.act(ACT_SET, DIAG_TOOL, null, null, diagCommand)
  278: var diagCommand = $.act(ACT_GET, DIAG_TOOL, null, null)
  ```
- **Notes:** Immediate tracking of the backend DIAG_TOOL processing module (such as CGI programs) is required to verify command execution security.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Frontend verification: Confirmed 12 instances of `$.act(ACT_SET, DIAG_TOOL)` calls in diagnostic.htm. The diagCommand object properties (e.g., REDACTED_PASSWORD_PLACEHOLDER) originate from frontend variables without filtering or validation, consistent with the description. Backend verification: Multiple attempts to locate the DIAG_TOOL processing module failed. No CGI or binary files containing this keyword were found, making it impossible to verify potential command injection risks on the backend. Insufficient evidence to classify as a genuine vulnerability—actual device debugging or additional firmware context is required for confirmation.

### Verification Metrics
- **Verification Duration:** 433.00 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 560379

---

## heap_overflow-sym.reply_trans-memcpy_length

### Original Information
- **File/Directory Path:** `usr/bin/smbd`
- **Location:** `smbd:0x42555c (sym.reply_trans)`
- **Description:** heap overflow vulnerability: An attacker controls the param_2+0x37 field value (uVar18) through SMB TRANS requests to manipulate the memcpy length parameter. Trigger conditions: 1) Send a crafted SMB packet to set the param_2+0x37 value 2) Make uVar18 exceed the allocated buffer size uVar17 3) Exploit the boundary check bypass at 0x42555c. Security impact: Controllable heap corruption may lead to remote code execution.
- **Notes:** Full attack chain: Network interface → SMB protocol parsing → smbd_process() → sym.reply_trans(). Need to verify ASLR/NX protection status in the firmware environment.

### Verification Conclusion
- **Description Accuracy:** `unknown`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Unable to obtain code evidence for address 0x42555c, resulting in complete failure of all critical verification points: 1) Boundary check bypass mechanism unconfirmed 2) Data source of param_2+0x37 untraceable 3) Control chain of memcpy length parameter unverified. Lack of code evidence makes it impossible to prove the existence of the vulnerability or assess triggering probability. Recommend checking binary file integrity or providing more precise address information.

### Verification Metrics
- **Verification Duration:** 838.43 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 978847

---

## configuration_load-radvd-rdnss_stack_overflow

### Original Information
- **File/Directory Path:** `usr/sbin/radvd`
- **Location:** `radvd:0x00404f18 [fcn.00404e40]`
- **Description:** RDNSS Configuration Processing Stack Buffer Overflow Vulnerability: When the configuration file contains more than 73 RDNSS addresses (REDACTED_PASSWORD_PLACEHOLDER=4088>4096-8), the fcn.00404e40 function overflows the 4096-byte stack buffer (auStack_ff0) while constructing RA packet options in a loop. An attacker can exploit this vulnerability by tampering with the configuration file: 1) Modify /etc/radvd.conf to inject malicious RDNSS configurations 2) Restart the radvd service 3) Trigger the send_ra_forall function call chain 4) Precisely control overflow data to overwrite the return address and achieve code execution.
- **Code Snippet:**
  ```
  do {
    *puStack_10a0 = 0x19; // RDNSSHIDDEN
    puStack_10a0[1] = (iVar4 >> 3) + 1; // HIDDEN
    memcpy(puStack_10a0 + 2, &DAT_0041a8a0, 4); // HIDDEN
    memcpy(puStack_10a0 + 6, *piVar16, 0x10); // RDNSSHIDDEN
    iVar4 = iVar4 + 0x38; // HIDDEN56HIDDEN
  } while (piVar16 != NULL);
  ```
- **Notes:** Exploitation requires control over configuration file writing (needs to be combined with other vulnerabilities); it is recommended to inspect the configuration file modification mechanism in the firmware (e.g., web interface).

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code evidence fully matches: 4096-byte stack space, unrestricted loop, configuration file data source, and send_ra_forall call chain are all confirmed;  
2) Mathematical calculation proves 73 iterations (16 + 73 × 56 = 4104) will inevitably overflow by 8 bytes;  
3) The vulnerability genuinely exists but requires two preconditions (configuration file tampering + service restart) for triggering rather than direct activation, consistent with the discovery note stating "requires combination with other vulnerabilities."

### Verification Metrics
- **Verification Duration:** 1172.39 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1303205

---

## FormatString-http_rpm_auth_main

### Original Information
- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `httpd:http_rpm_auth_main`
- **Description:** High-risk format string vulnerability: In the http_rpm_auth_main authentication process, the externally controllable name/pwd parameters are concatenated into a 3978-byte stack buffer (auStack_fbc) using sprintf. Trigger conditions: 1) Send an authentication request 2) Combined name+pwd length exceeds 3978 bytes 3) *(param_1+0x34)==1. Lack of length validation leads to stack overflow.
- **Notes:** Attack Path: Authentication Interface → Environment Variable Retrieval → Format String Construction

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Buffer size description discrepancy (actual 4028 bytes vs reported 3978) results in accuracy being 'partially'; 2) Vulnerability confirmed: externally controllable parameter passed via environment variable to sprintf without length validation, triggering stack overflow directly when *(param_1+0x34)==1; 3) Complete attack path: authentication request → environment variable injection → format string concatenation → stack overflow, no additional prerequisites required. REDACTED_PASSWORD_PLACEHOLDER evidence: a) sprintf call with external parameter at 0x00409bdc b) Conditional check at 0x00409bb4 c) Stack space allocation instruction addiu sp, sp, -0x1818

### Verification Metrics
- **Verification Duration:** 340.85 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 451903

---

## buffer_overflow-hotplug_3g-0x402a98

### Original Information
- **File/Directory Path:** `sbin/hotplug`
- **Location:** `unknown:0 [REDACTED_SECRET_KEY_PLACEHOLDER] 0x402a98`
- **Description:** The attacker injects forged content into REDACTED_PASSWORD_PLACEHOLDER via a malicious USB device to control device descriptor information. When a non-standard 3G device is inserted, hotplug_3g invokes the REDACTED_SECRET_KEY_PLACEHOLDER function to parse this file. During the loop processing of device entries (with index iStack_4c0 capped at 12), string operations of unspecified length are performed on the acStack_4b8[64] buffer. Since a single device entry spans 100 bytes (far exceeding the buffer size), forging two or more device entries or an excessively long device type string can trigger a stack overflow. Successful exploitation may lead to arbitrary code execution with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  char acStack_4b8 [64];
  for (; (acStack_4b8[iStack_4c0 * 100] != '\0' && (iStack_4c0 < 0xc)); iStack_4c0++)
  ```
- **Notes:** Full attack chain: Physical access to insert malicious USB device → Kernel generates tainted data → Overflow during hotplug parsing. Verification required: 1) Actual USB descriptor control granularity 2) Existence of stack protection mechanisms. Follow-up analysis recommendation: Reverse engineer handle_card to validate secondary attack surface.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Critical evidence indicates: 1) The actual buffer size is 1200 bytes (0x4b0 instruction), not the described 64 bytes 2) Loop boundary calculations are precise (12×100=1200), making mathematical overflow impossible 3) Although external input paths exist (/proc file controllable) and stack protection is absent, overflow conditions are eliminated by code design. The original discovery was based on incorrect decompilation results (buffer size misjudgment), with the actual code featuring robust boundary controls.

### Verification Metrics
- **Verification Duration:** 2219.00 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3088164

---

## heap_overflow-upnpd-0x409aa4

### Original Information
- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:0x409aa4(sym.pmlist_NewNode)`
- **Description:** heap_overflow  

pmlist_NewNode heap overflow vulnerability: Triggered when the NewExternalPort parameter is a 5-byte pure numeric string due to a boundary check flaw. The target buffer is only 4 bytes (puStack_10+0x1e), causing a 1-byte overflow during strcpy that corrupts the heap structure. Exploitation steps: Send a malicious UPnP request → fcn.REDACTED_PASSWORD_PLACEHOLDER parameter parsing → pmlist_NewNode heap operation. Success probability is medium-high (depends on heap layout manipulation), potentially leading to RCE.
- **Code Snippet:**
  ```
  uVar1 = (**(loc._gp + -0x7f1c))(param_5);
  if (5 < uVar1) {...} else {
      (**(loc._gp + -0x7dcc))(puStack_10 + 0x1e,param_5);
  ```
- **Notes:** heap_overflow

Special constraint: Parameters must be pure numbers and length=5. Combinable with 0x406440 IP verification bypass

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** The vulnerability accurately describes a boundary check flaw (the "uVar1>5" condition allows strcpy execution when length ≤5), with the target buffer having only 4 bytes of space. The strcpy operation copies 5 bytes of digits plus a null terminator, resulting in a 2-byte overflow. The parameter is externally controllable (originating from the NewExternalPort request field), but triggering relies on bypassing an IP verification vulnerability (0x406440) to form a complete attack chain, rather than direct exploitation. The risk rating of 9.0 is justified, as it can lead to heap corruption and RCE. Corrections needed: 1) Overflow amount should be 2 bytes 2) Trigger condition is length ≤5 3) The actual calling function is fcn.REDACTED_PASSWORD_PLACEHOLDER.

### Verification Metrics
- **Verification Duration:** 2966.12 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3927647

---

## ipc-radvd-privilege_separation_failure

### Original Information
- **File/Directory Path:** `usr/sbin/radvd`
- **Location:** `radvd:0xREDACTED_PASSWORD_PLACEHOLDER [privsep_init]`
- **Description:** Privilege separation mechanism failure: The fcn.REDACTED_PASSWORD_PLACEHOLDER function called by privsep_init did not perform privilege-dropping operations such as setuid/setgid, causing the child process to continue running with REDACTED_PASSWORD_PLACEHOLDER privileges. If the RDNSS vulnerability is exploited, attackers can directly obtain REDACTED_PASSWORD_PLACEHOLDER access.
- **Notes:** This vulnerability can be combined with the RDNSS stack overflow to form a complete privilege escalation chain.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code evidence shows that the child process created by privsep_init indeed calls fcn.REDACTED_PASSWORD_PLACEHOLDER (0x0040878c);  
2) Disassembly confirms that fcn.REDACTED_PASSWORD_PLACEHOLDER contains no privilege-dropping instructions such as setuid/setgid, only data read/write and network configuration operations;  
3) The child process branch lacks privilege control throughout, allowing business logic to execute with REDACTED_PASSWORD_PLACEHOLDER permissions. Although this vulnerability requires the RDNSS vulnerability as a trigger medium (not directly triggered), their combination can form a reliable privilege escalation chain, meeting the characteristics of a high-risk vulnerability.

### Verification Metrics
- **Verification Duration:** 384.26 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 618604

---

## integer_overflow-sym.reply_nttrans-memcpy_length

### Original Information
- **File/Directory Path:** `usr/bin/smbd`
- **Location:** `smbd:0x437d18 (sym.reply_nttrans)`
- **Description:** Integer overflow vulnerability: The memcpy length parameter uVar32 is calculated from the network field param_2+0x48 (uVar31)*2. Trigger condition: Setting uVar31≥0xREDACTED_PASSWORD_PLACEHOLDER causes multiplication overflow (e.g., REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER). Security impact: Bypasses allocation checks to achieve heap out-of-bounds write.
- **Notes:** integer_overflow

Associated with CVE-2023-39615 pattern, attackers need to construct NT TRANS requests to trigger

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Boundary check logic is effective: In the instruction sequence at 0x437cec-0x437cf4, when uVar31 ≥ 0xREDACTED_PASSWORD_PLACEHOLDER causes uVar32 to overflow, uVar26 = 0x49 < 0x4B will inevitably trigger the bnez jump to error handling (0x439754), skipping memcpy; 2) Heap out-of-bounds write path is blocked: The error handler prevents memory operations from executing, rendering the previously discovered 'bypassing allocation check to achieve heap out-of-bounds write' invalid; 3) Risk is overestimated: Boundary checks cover all integer overflow scenarios, with an actual risk of 0.

### Verification Metrics
- **Verification Duration:** 1415.42 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2277715

---

## network_input-login-85-base64-cookie

### Original Information
- **File/Directory Path:** `web/frame/login.htm`
- **Location:** `login.htm:85-91`
- **Description:** Authentication credentials are stored in plain Base64 within cookies. Trigger condition: JavaScript performs Base64 encoding upon submitting the login form. Constraint check: No encryption or HTTPOnly flag is applied. Potential impact: Man-in-the-middle attacks can steal credentials; XSS vulnerabilities can read cookies. Exploitation method: Network sniffing or cross-site scripting attacks to obtain the Authorization cookie value.
- **Code Snippet:**
  ```
  auth = "Basic "+Base64Encoding(REDACTED_PASSWORD_PLACEHOLDER+":"+REDACTED_PASSWORD_PLACEHOLDER);
  document.cookie = "Authorization=" + auth;
  ```
- **Notes:** Verify the server-side handling logic for the Authorization cookie

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification Evidence: 1) Confirmed exact matching code snippet at web/frame/login.htm lines 175-176, where REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER are Base64 encoded and stored in Cookies; 2) Cookie setting statements lack HTTPOnly/Secure attributes, allowing JS read access; 3) The code is directly triggered by the login button's onclick event, forming a complete attack chain (user input → encoding → storage); 4) The Base64Encoding function performs plaintext encoding (lines 92-130) without encryption. In conclusion, this vulnerability can be directly exploited via MITM/XSS attacks, making the risk rating justified.

### Verification Metrics
- **Verification Duration:** 292.04 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 534415

---

## format_string-pppd-option_error

### Original Information
- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:main→parse_args→option_error`
- **Description:** High-risk format string vulnerability: Attackers trigger option_error via malicious command-line arguments, leading to memory leaks/tampering through an unfiltered vslprintf+fprintf chain when obj.phase=1. Trigger condition: Network service invokes pppd with arguments containing format specifiers. Boundary check: Complete lack of input filtering. Security impact: Remote code execution (refer to CVE-2020-15779), high success probability (requires validation with firmware boot parameters).
- **Notes:** Verify the global_stream output target (network/log) in the firmware.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The disassembly evidence fully supports the findings described: 1) An unfiltered format string chain exists (vslprintf→fprintf) 2) The trigger condition (obj.phase=1) is unconditionally set by the main function 3) Input originates from command-line arguments with no bounds checking 4) global_stream constitutes a remote attack surface when running as a network service. The vulnerability can be triggered simply with malicious command-line arguments, consistent with the CVE-2020-15779 mechanism, meeting direct trigger conditions.

### Verification Metrics
- **Verification Duration:** 2816.83 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 4239171

---

## attack_chain-update_bypass_to_config_restore

### Original Information
- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `HIDDEN：usr/bin/httpd → REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Description:** Full privilege bypass → configuration tampering attack chain: 1) Exploit stack overflow vulnerability in /rpm_update endpoint (sym.http_rpm_update) to overwrite g_http_alias_conf_admin permission flag 2) Bypass privilege check for /cgi/confup (originally requiring REDACTED_PASSWORD_PLACEHOLDER rights) 3) Upload malicious configuration file to trigger /cgi/bnr system recovery execution 4) bnr clears authentication credentials ($.deleteCookie) and forces device refresh ($.refresh), resulting in complete device compromise. REDACTED_PASSWORD_PLACEHOLDER evidence: confup operation directly controlled by g_http_alias_conf_admin (discovery 3), bnr recovery logic lacks content verification (known attack chain). Trigger probability assessment: overflow exploitation (8.5/10) × privilege tampering (7.0/10)=6.0, but post-success hazard level 10.0.
- **Code Snippet:**
  ```
  HIDDEN：
  1. send_overflow_request('/rpm_update', filename=REDACTED_PASSWORD_PLACEHOLDER'A' + struct.pack('<I', 0x1))  # HIDDEN
  2. post_malicious_config('/cgi/confup', filename='evil.bin')
  3. trigger_system_recovery('/cgi/bnr')
  ```
- **Notes:** Combine the findings from 1/3 with the existing confup attack chain, requiring physical verification of: 1) Memory offset of g_http_alias_conf_admin 2) Path resolution for the bnr recovery script

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** REDACTED_PASSWORD_PLACEHOLDER links in the attack chain disproven by code evidence:  
1) Stack overflow vulnerability (0x40444c) resides in a local buffer, which is memory-segment isolated from global variable g_http_alias_conf_admin (0x4376d0), making overwrite impossible (evidence: stack frame allocation -0x58 vs. data segment address);  
2) g_http_alias_conf_admin is only used for error response output (0x407ef8) and plays no role in privilege control;  
3) The request handler (/cgi/confup, http_rpm_restore) lacks privilege-checking logic (0x408178 processes requests directly). The attack chain's assumed "privilege flag overwrite" and "privilege bypass" mechanisms do not exist.

### Verification Metrics
- **Verification Duration:** 4190.63 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 5865976

---

## network_input-configure_ia-stack_overflow

### Original Information
- **File/Directory Path:** `usr/sbin/dhcp6c`
- **Location:** `usr/sbin/dhcp6c:0x40e400 configure_ia`
- **Description:** High-risk stack overflow vulnerability: The configure_ia function performs unbounded copy operations on interface names within the 0x1f option when processing IA-PD type (0). Attackers can inject excessively long interface names (≥18 bytes) through DHCPv6 REPLY/ADVERTISE packets to overwrite stack frames and achieve arbitrary code execution. Trigger conditions: 1) Device has DHCPv6 client enabled 2) Attacker impersonates server on the same link 3) Crafted packet contains malicious 0x1f option. Actual impact: Full device control (CVSS 9.8).
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7c04))(auStack_58, puVar4[2]); // HIDDENstrcpyHIDDEN
  ```
- **Notes:** Full attack chain: recvmsg() → client6_recv() → dhcp6_get_options() → cf_post_config() → configure_ia(). Suggested verifications: 1) Firmware ASLR/NX protection status 2) Actual offset calculation

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification conclusion: 1) Core vulnerability confirmed: An unchecked strcpy operation exists at 0x40e400, with source data (puVar4[2]) indeed originating from DHCPv6 packet parsing, consistent with the description. 2) Trigger condition corrected: Actual overflow requires ≥48 bytes to overwrite critical registers (not the described 18 bytes), and ≥84 bytes to control the return address. 3) Attack chain complete: The data flow client6_recv→dhcp6_get_options→configure_ia is valid, and forged DHCPv6 REPLY packets can directly reach the vulnerability point. 4) Impact verified: Absence of NX/ASLR makes arbitrary code execution feasible, justifying the CVSS 9.8 score. In summary, the described core vulnerability exists and can be directly triggered, though the triggering condition parameters are inaccurate.

### Verification Metrics
- **Verification Duration:** 2484.04 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3140121

---

## heap_overflow-upnpd-0x408118

### Original Information
- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:0x408118(fcn.00407e80)`
- **Description:** CVE-2023-27910 Heap Overflow Vulnerability: Incorrect length validation in fcn.00407e80's strcpy (using vsyslog pointer instead of strlen), allowing SOAP parameters exceeding 520 bytes (e.g., NewExternalPort) to overflow heap buffer (puVar2). Trigger sequence: Malicious HTTP request → REDACTED_SECRET_KEY_PLACEHOLDER parsing → fcn.REDACTED_PASSWORD_PLACEHOLDER processing → strcpy heap corruption. High success probability leading directly to RCE.
- **Notes:** heap_overflow

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code verification shows that the actual length check uses sym.imp.strlen(v0) (instruction 0x4080d0), not pointer comparison;  
2) The buffer allocation is 520 bytes (puVar2), with a calculated maximum data requirement of 516 bytes (puVar2+260+256), leaving no overflow space;  
3) The strcpy operation targets ServiceID (param_2), not NewExternalPort;  
4) Call chain analysis confirms that overflow conditions are not met, making RCE unachievable. All core claims have been disproven, and the vulnerability does not exist.

### Verification Metrics
- **Verification Duration:** 2153.72 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2634812

---

## RCE-pppd-chap_auth_peer-peer_name_overflow

### Original Information
- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x0041a5c8`
- **Description:** High-risk Remote Code Execution (RCE) vulnerability: In the chap_auth_peer function, the externally controllable peer_name parameter is copied to the global buffer at 0x465cbc via memcpy without boundary checks.
- **Trigger REDACTED_PASSWORD_PLACEHOLDER: Attacker provides an overlong REDACTED_PASSWORD_PLACEHOLDER (> target buffer capacity) when establishing a PPPoE connection
- **Boundary REDACTED_PASSWORD_PLACEHOLDER: Only uses strlen to obtain length, with no maximum length restriction
- **Security REDACTED_PASSWORD_PLACEHOLDER: Global data area overflow may overwrite adjacent function pointers or critical state variables, enabling stable RCE when combined with carefully crafted overflow data. High exploitation probability (requires network access permissions)
- **Code Snippet:**
  ```
  iVar5 = strlen(uVar8);
  (**(loc._gp + -0x773c))(0x465cbc + uVar1 + 1, uVar8, iVar5);
  ```
- **Notes:** Associated with CVE-2020-15705 attack pattern. Mitigation recommendations: 1) Add peer_name length validation 2) Isolate global authentication buffer

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The verification conclusion is based on the following evidence:  
1. **Existence of Vulnerability REDACTED_PASSWORD_PLACEHOLDER: The code snippet (0x0041a5d0) shows that the length of peer_name is obtained via strlen and directly copied to a fixed address 0x465cbc using memcpy, with no boundary check instructions, and peer_name originates from an external PPPoE connection.  
2. **Inaccuracy in RCE REDACTED_PASSWORD_PLACEHOLDER: The memory layout reveals that the region from 0x465cbc to 0x465d3c is entirely zeroed, with the adjacent address 0x465ca8 also holding a value of 0, and no control-flow structures such as function pointers are present, thus failing to support the conclusion of a reliable RCE.  
3. **Revised Actual REDACTED_PASSWORD_PLACEHOLDER: The vulnerability can lead to data segment overflow (trigger likelihood 8.0), but the maximum impact is limited to denial of service or data corruption (severity 7.0), not the originally described RCE.  
4. **Direct Trigger REDACTED_PASSWORD_PLACEHOLDER: The vulnerability can be triggered simply by network access and sending an excessively long REDACTED_PASSWORD_PLACEHOLDER, with no prerequisite conditions required.

### Verification Metrics
- **Verification Duration:** 8346.84 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 6986488

---

## configuration_load-http_alias-priv_esc

### Original Information
- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x00406bc8`
- **Description:** The global routing permission control variable is at risk of tampering. The permission flag g_http_alias_conf_admin is written into the routing table (ppcVar3[6]) via http_alias_addEntryByArg, affecting access control for subsequent requests. If an attacker modifies this variable through a memory corruption vulnerability (such as the buffer overflow mentioned above), they could bypass permission checks for sensitive interfaces (e.g., /cgi/confup). Trigger conditions: 1) A writable memory vulnerability exists; 2) Tampering occurs after routing initialization. Actual exploitation would require combining with other vulnerabilities.
- **Code Snippet:**
  ```
  ppcVar3[6] = param_5; // HIDDEN
  ```
- **Notes:** Verification required: 1) Whether variables are affected by NVRAM/env 2) Specific permission checking mechanism

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification confirmed: 1) At address 0x00406bc4, there exists a permission flag assignment of ppcVar3[6]=param_5 (disassembly instruction sw s3,0x18(v0)). 2) param_5 originates from a writable .bss segment global variable (0x42ff24e4) with memory permissions rw- and no sanitization logic. 3) This pointer is used for permission check registration in interfaces such as /cgi/confup. Core vulnerability mechanism established: tampering with this variable can bypass permission checks. However, direct triggering is not possible; the following conditions must be met: a) Existence of an independent memory write vulnerability, b) Precise tampering of address 0x42ff24e4, c) Triggering after route initialization. Although the variable name g_http_alias_conf_admin does not appear in the symbol table, disassembly confirms the existence of the permission control mechanism.

### Verification Metrics
- **Verification Duration:** 1935.75 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2405714

---

## network_input-restore-multistage_chain

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `backNRestore.htm:unknown`
- **Description:** The recovery function involves a multi-stage operation chain: user uploads configuration file → submits to /cgi/confup → calls /cgi/bnr interface → actively deletes Authorization cookie. This process contains two risk points: 1) The file upload phase lacks extension/content verification logic (relying on undefined validation details in the doSubmit function) 2) Forced deletion of authentication cookies may lead to session fixation attacks. Attackers could craft malicious configuration files to trigger unintended operations, combining cookie deletion to achieve privilege bypass.
- **Notes:** Follow-up verification required: 1) File processing logic of /cgi/confup 2) Whether cookie deletion requires prerequisites; related to existing Authorization risk items in knowledge base

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code evidence confirms: 1) The doSubmit function only checks for non-empty filenames (without content validation), allowing malicious file uploads. 2) $.deleteCookie('Authorization') executes unconditionally, leading to session termination. 3) The complete operation chain (form submission → CGI invocation → cookie deletion) forms a directly triggerable attack path. Attackers can upload crafted configuration files to trigger unintended operations and clear authentication credentials, creating a privilege bypass vulnerability (CVSS:7.1).

### Verification Metrics
- **Verification Duration:** 313.95 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 283708

---

## network_input-diagnostic-diagType

### Original Information
- **File/Directory Path:** `web/main/diagnostic.htm`
- **Location:** `diagnostic.htm:130,894,911`
- **Description:** The diagType parameter serves as the sole user input point on the page, controlling the selection of diagnostic types (Internet/WAN). It directly governs subsequent processes (such as doDiag() calls) through JavaScript without implementing allowlist validation. Attackers can modify the diagType value in POST requests to forcibly execute unintended diagnostic procedures. Constraints: Requires bypassing front-end disable logic (line 894) or directly constructing HTTP requests. Potential impact: Combined with backend vulnerabilities, it may trigger unauthorized diagnostic operations.
- **Code Snippet:**
  ```
  130: if ("Internet" == $.id("diagType").value)
  894: $.id("diagType").disabled = true
  911: <select id="diagType" name="diagType">
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code Verification: Line 130 confirms the diagType value directly controls the flow branch without whitelist validation; Line 894 shows the disable logic is only frontend-controlled and can be bypassed.  
2) Logic Verification: doDiag() calls loadTest() to select the test suite based on diagType, allowing attackers to force unintended flows by crafting POST requests.  
3) Impact Assessment: Constitutes a real vulnerability but requires chaining with backend vulnerabilities (e.g., command injection) for full exploitation, thus not a direct-trigger flaw. Risk score 7.0 is justified, aligning with the "frontend bypass + no server-side validation" characteristics.

### Verification Metrics
- **Verification Duration:** 319.47 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 288281

---

## command_execution-wireless_attack_chain

### Original Information
- **File/Directory Path:** `web/main/status.htm`
- **Location:** `HIDDEN`
- **Description:** Complete Wireless Attack Chain: Manipulating the sysMode parameter via XSS to trigger the saveSettings() function, injecting malicious set_wireless parameters into apply.cgi, ultimately leading to backend buffer overflow or RCE. This path demonstrates the full exploitation process from interface manipulation to system-layer vulnerabilities.
- **Notes:** Attack steps: 1) XSS manipulation of sysMode parameter → 2) Call to saveSettings() → 3) Injection into apply.cgi → 4) Trigger RCE. Exploit probability 0.65; Related discovery: network_input-status_page-saveSettings

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The core evidence indicates that: 1) The saveSettings() function does not exist in status.htm; 2) The sysMode parameter retrieves the system mode value through an internal ACT_GET operation ($.act(ACT_GET)), serving as a read-only state variable rather than user input; 3) No code path submitting data to apply.cgi was found in the code. The XSS attack chain described—which involves manipulating sysMode and triggering saveSettings()—lacks any supporting code in the target files, rendering the entire vulnerability chain invalid.

### Verification Metrics
- **Verification Duration:** 422.66 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 524762

---

## xss-top-banner-56-57

### Original Information
- **File/Directory Path:** `web/frame/top.htm`
- **Location:** `top.htm:56-57`
- **Description:** Setting innerHTML with dynamic data from the parent window (lines 56-57). Specific behavior: The content of 'nameModel' and 'numModel' elements directly originates from the window.parent object properties. Trigger condition: Attackers need to contaminate the $.desc/m_str.bannermodel/$.model properties of the parent window (e.g., via URL parameter injection). Security impact: Successful triggering can execute arbitrary JS code, leading to session hijacking or phishing attacks. Boundary check: Complete lack of input validation.
- **Code Snippet:**
  ```
  document.getElementById('nameModel').innerHTML = window.parent.$.desc;
  document.getElementById('numModel').innerHTML = window.parent.m_str.bannermodel + window.parent.$.model;
  ```
- **Notes:** It is necessary to analyze the parent window frame page to verify the data source. It is recommended to check ../frame/main.htm. Related findings: If properties such as $.desc are contaminated through the $.dhtml function in js/lib.js (see xss-$.dhtml-js-lib), it may form a combined vulnerability chain.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Code existence verification successful: Lines 56-57 of top.htm indeed use window.parent dynamic data to set innerHTML;  
2) Contamination path unconfirmed: Although the discovery describes contamination requiring URL parameter injection, analysis found no evidence that $.desc/$.model/m_str.bannermodel properties are assigned by external input (implementation of $.act function not exposed, m_str.bannermodel undefined);  
3) Attack chain incomplete: Lack of evidence proving parent window properties can be directly contaminated, and the $.dhtml contamination path mentioned in the discovery was not verified;  
4) Critical evidence missing: The main.htm file does not exist, making it impossible to verify the framework page logic.

### Verification Metrics
- **Verification Duration:** 544.53 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 813322

---

## oid-backend-cgi-tentative

### Original Information
- **File/Directory Path:** `web/MenuRpm.htm`
- **Location:** `cgi-bin:? (?) ?`
- **Description:** Identified 36 sensitive OID identifiers (e.g., DIAG_TOOL, USER_CFG, etc.) corresponding to high-risk operations such as diagnostic command execution and system configuration modifications. These OIDs may be directly processed by backend CGI programs, forming critical attack surfaces. Trigger condition: Attackers pass malicious OIDs and parameters through HTTP requests (e.g., API endpoints). Actual impact: If OID handlers lack permission checks or input validation, it may lead to device configuration tampering, command injection, and other vulnerabilities.
- **Notes:** LOCATION_PENDING: Requires subsequent positioning of specific handler; associated with JS injection discovery ($.dhtml); notes_OID_REF: If CGI-bin handler verification exists, confidence needs to be elevated to 9.5

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification results: 1) Confirmed the presence of high-risk operation identifiers (e.g., ACT_OP_REBOOT) and transmission mechanisms ($.exe() sending /cgi requests) in the lib.js associated with web/MenuRpm.htm; 2) The client completely lacks permission verification, consistent with the discovery description; 3) However, the full list of 36 OIDs could not be verified (definition file not found) nor the critical backend processing logic (cgi-bin directory does not exist). Therefore, the existence of the vulnerability cannot be confirmed: without backend verification evidence, it cannot be concluded that OID requests would be executed without protection.

### Verification Metrics
- **Verification Duration:** 1982.28 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2866215

---

## wan-pollution-attack-chain

### Original Information
- **File/Directory Path:** `web/main/diagnostic.htm`
- **Location:** `diagnostic.htm:240-306`
- **Description:** Discovered a complete theoretical attack chain for WAN configuration pollution: 1) Attacker modifies WAN configuration (e.g., interface name/gateway IP) via NVRAM/network interface 2) When user triggers diagnostic operation, frontend JavaScript passes polluted data (wanList[].name/gwIp) as diagCommand.currHost parameter 3) Data gets transmitted to backend via $.act(ACT_SET, DIAG_TOOL) call 4) If backend directly concatenates commands for execution (without validation), command injection can be achieved. Trigger conditions: a) Existence of WAN configuration write vulnerability b) User/attacker can trigger diagnostic test c) Backend fails to filter special characters. Boundary check: Frontend completely lacks input validation, backend implementation status unknown.
- **Code Snippet:**
  ```
  diagCommand.currHost = wanList[wanIndex].name;
  $.act(ACT_SET, DIAG_TOOL, null, null, diagCommand);
  ```
- **Notes:** Critical Gap: DIAG_TOOL backend not located. Next steps required: 1) Search for DIAG_TOOL handler in /bin, /sbin 2) Analyze safety of currHost parameter usage 3) Validate WAN configuration write points (e.g., nvram_set). Knowledge base correlation reveals 'oid-backend-cgi-tentative': DIAG_TOOL is a sensitive OID, potentially processed by cgi-bin.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification conclusion: 1) Frontend validation confirmed: wanList[].name/gwIp is unfiltered and directly used in diagCommand.currHost (code evidence). 2) The $.act(ACT_SET, DIAG_TOOL) transmission mechanism exists (knowledge base evidence). 3) However, the critical vulnerability point remains unverified: Unable to locate the DIAG_TOOL backend handler (search in /www/cgi-bin and /usr/sbin failed), thus unable to confirm whether currHost leads to command injection. For a true vulnerability to exist, both conditions must be met: a) WAN configuration must be tamperable (unverified) b) Backend must unsafely use currHost (unverified). Current evidence only supports a theoretical attack chain, insufficient to prove an exploitable real-world vulnerability.

### Verification Metrics
- **Verification Duration:** 980.32 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1414385

---

## attack_chain-config_restore-bnr_fullchain

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `backNRestore.htm:0 (HIDDEN)`
- **Description:** Complete Configuration Recovery Attack Chain: 1) Attacker submits malicious configuration file through the file upload interface (name='filename') in backNRestore.htm 2) Frontend only verifies non-empty status before submitting to /cgi/confup 3) Operation automatically triggers /cgi/bnr to execute system recovery upon completion 4) After successful bnr execution, authentication cookies are cleared ($.deleteCookie) and system is forcibly refreshed ($.refresh). REDACTED_PASSWORD_PLACEHOLDER risks: confup lacks filename path normalization (potential path traversal), bnr doesn't validate file contents (potential malicious configuration injection), and device control loss risk during system refresh (explicit 'unmanaged' warning).
- **Code Snippet:**
  ```
  formObj.action = "/cgi/confup";
  $.cgi("/cgi/bnr", null, function(ret){
    $.deleteCookie("Authorization");
    window.parent.$.refresh();
  });
  ```
- **Notes:** Correlation analysis required: 1) Known keyword 'filename' involves /cgi/usb3gup file upload (knowledge base record) 2) Keyword '$.cgi' correlates with multiple CGI endpoints 3) Critical evidence gaps: confup path handling logic (located at /sbin/confup) bnr permission verification (located at /usr/sbin/bnr)

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The verification conclusion is based on the following evidence:
1. Frontend logic (backNRestore.htm) fully matches the description: submission to /cgi/confup with upload field name='filename', automatically triggering bnr and refreshing the system (partial accuracy established)
2. confup component: Knowledge base indicates historical vulnerability (CVE-2016-2147), but no actual code was obtained to verify path traversal risk (evidence gap)
3. bnr core component: Unable to locate /usr/sbin/bnr binary file, resulting in the following critical risks remaining unverified:
   - Lack of configuration file content validation mechanism
   - Code implementation for deviceHIDDEN ('unmanaged' state)
   - High-privilege execution risk
4. Complete attack chain requires coordinated frontend-backend vulnerabilities, but REDACTED_PASSWORD_PLACEHOLDER backend components lack evidentiary support, thus not constituting a verifiable real vulnerability
5. Unable to confirm direct triggerability, as the attack chain relies on unverified backend execution components

### Verification Metrics
- **Verification Duration:** 556.86 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 880419

---

