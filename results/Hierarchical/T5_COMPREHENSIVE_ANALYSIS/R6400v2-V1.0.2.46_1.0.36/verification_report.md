# R6400v2-V1.0.2.46_1.0.36 - Verification Report (10 alerts)

---

## network_input-pppd_PAP_auth-stack_overflow

### Original Information
- **File/Directory Path:** `sbin/pppd`
- **Location:** `sbin/pppd: sym.upap_authwithpeer (HIDDEN)`
- **Description:** PAP Authentication Stack Buffer Overflow Vulnerability (CVE pending): Triggered when an attacker sends an excessively long PAP REDACTED_PASSWORD_PLACEHOLDER via PPP connection. The vulnerability resides in the sym.upap_authwithpeer function: 1) REDACTED_PASSWORD_PLACEHOLDER length (param_3) is not validated 2) Copied via memcpy to a fixed 24-byte stack buffer 3) Return address overwritten when combined REDACTED_PASSWORD_PLACEHOLDER exceeds 15 bytes. Since pppd runs with REDACTED_PASSWORD_PLACEHOLDER privileges, successful exploitation could lead to complete device compromise.
- **Code Snippet:**
  ```
  memcpy(puVar9 + iVar3 + 1, puVar5[3], puVar5[4]); // puVar5[3]=HIDDEN, puVar5[4]=HIDDEN
  ```
- **Notes:** To be verified subsequently: 1) Exact overflow offset 2) Feasibility of ASLR/PIE bypass 3) Input filtering mechanism of the associated configuration file REDACTED_PASSWORD_PLACEHOLDER

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification revealed the following REDACTED_PASSWORD_PLACEHOLDER points:
1. **Vulnerability REDACTED_PASSWORD_PLACEHOLDER: The memcpy operation indeed uses unvalidated external input length (param_3), lacking boundary checks (evidence: ldr r2, [r4, 0x10] directly loads the length parameter).
2. **Inaccuracies in REDACTED_PASSWORD_PLACEHOLDER:
   - The target buffer is the global variable outpacket_buf (address 0x4c36c, size 1504 bytes) rather than a 24-byte stack buffer.
   - The trigger condition should be when the combined REDACTED_PASSWORD_PLACEHOLDER + REDACTED_PASSWORD_PLACEHOLDER + separator length exceeds 1495 bytes (1504 - 9 offset) rather than 15 bytes.
   - The overflow affects adjacent global variables rather than the return address (the function has no stack buffer).
3. **Exploitability REDACTED_PASSWORD_PLACEHOLDER:
   - Risk remains: pppd runs as REDACTED_PASSWORD_PLACEHOLDER, and the overflow could corrupt critical data structures (such as adjacent variables like childwait_done).
   - Direct trigger: Network input can control the REDACTED_PASSWORD_PLACEHOLDER length parameter to directly trigger the overflow.
4. **Revised REDACTED_PASSWORD_PLACEHOLDER: The risk level of the global buffer overflow is downgraded to 7.0 (originally 9.5) due to requiring larger input and not involving control flow hijacking.

### Verification Metrics
- **Verification Duration:** 1040.02 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2145990

---

## command_injection-rc-0x0000efd0

### Original Information
- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000efd0`
- **Description:** Critical Command Injection Vulnerability: The function fcn.0000ed80 (0x0000efd0) in rc executes commands pointed to by global pointers *0xfd88/*0xfd8c via system(). Trigger Condition: When nvram_get(*0xfd80) returns empty or strcmp(*0xfd84) mismatches. REDACTED_PASSWORD_PLACEHOLDER Flaw: The command string is entirely controlled by NVRAM values without validation, allowing attackers to poison inputs via HTTP interface/NVRAM settings to achieve arbitrary command execution.
- **Code Snippet:**
  ```
  if ((iVar2 == 0) || (iVar2 = sym.imp.strcmp(iVar2,*0xfd84), iVar2 != 0)) {
      sym.imp.system(*0xfd88);
      sym.imp.system(*0xfd8c);
  }
  ```
- **Notes:** Full attack path: HTTP parameter → NVRAM setting interface → triggered during rc startup

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The evidence shows: 1) *0xfd88/*0xfd8c point to hardcoded strings 'gpio 10 0'/'gpio 19 1' (.rodata section), which are fixed during compilation and cannot be modified; 2) The actual NVRAM check targets are 'emf_enable' etc., not the *0xfd80 mentioned in the description; 3) No described code was found at address 0xefd0, with the nearest system call executing hardcoded commands. At most, attackers can trigger predefined GPIO operations but cannot control command content, requiring NVRAM write permissions and depending on specific service triggers. This does not constitute an arbitrary command execution vulnerability.

### Verification Metrics
- **Verification Duration:** 2029.94 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 5474770

---

## nvram_pollution-rc-0x0000ed80

### Original Information
- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000ed80`
- **Description:** NVRAM pollution propagation path: fcn.0000ed80 contains 21 nvram_get calls (e.g., *0xfd54, *0xfd80, etc.), with direct impacts on: 1) branch condition evaluation (strcmp), 2) file write content (*0xff08), and 3) command execution parameters (*0xfd88). Critical constraint missing: all NVRAM value usage points lack length checks or content filtering, creating a system-level pollution entry point.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Accuracy: 39 instances of nvram_get calls were actually detected (21 reported), but the three types of pollution propagation (branch/file/command) were correctly verified;  
2) Vulnerability Authenticity: A complete pollution chain exists (e.g., nvram_get → system), with 18 command execution points lacking filtration;  
3) Direct Trigger: The path is uninterrupted (e.g., address 0x0000f0b0 directly executes the system command), allowing attackers to trigger it by polluting NVRAM. The actual risk exceeds the report (including buffer overflow).

### Verification Metrics
- **Verification Duration:** 485.08 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 910270

---

## network_input-ubdcmd-recvmsg

### Original Information
- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `HIDDEN: 0x8e10,0x8ebc,0x8f40,0x9168,0x9a60`
- **Description:** recvmsg Buffer Vulnerability: The length is hardcoded to 0x420 when receiving network data without verifying the actual length. Trigger Condition: Sending a specially crafted UDP packet with a length ≠1056 bytes. Specific Manifestations: 1) Five call sites fix param_2=0x420. 2) The actual received length is not validated → short packets can manipulate memory at *0x8e70+0x26, etc. 3) Long packets trigger a stack overflow in fcn.00008f04. Security Impact: Memory corruption leading to RCE (can form a complete chain when combined with auto commands). Boundary Check: Only fcn.00008b98 includes a check for param_2≤0x420, but fails to validate the actual return value of recvmsg.
- **Code Snippet:**
  ```
  mov r2, #0x420  ; HIDDEN
  bl recvmsg
  ldr r3, [sp, #0x400] ; HIDDEN
  ```
- **Notes:** Verify the exposure status of UDP ports; correlate with fcn.00008b98 (manualset integer overflow).

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on binary analysis evidence: 1) All 5 call sites (0x8e10, etc.) contain hardcoded 'mov r2,0x420' and lack length validation after recvmsg 2) Presence of unvalidated offset memory access (e.g., [sp+0x400]) 3) fcn.00008f04 stack buffer (0x400) smaller than copy length (0x420) causing overflow 4) fcn.00008b98 has incomplete bounds checking. Vulnerability can be triggered simply by sending a crafted UDP packet without prerequisites, forming a directly exploitable RCE chain.

### Verification Metrics
- **Verification Duration:** 2649.92 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 6259246

---

## attack_chain-http_to_command

### Original Information
- **File/Directory Path:** `sbin/acos_service`
- **Location:** `unknown`
- **Description:** Attack chain feasibility verification: Confirm the complete path from the HTTP interface to command injection: 1) Attacker sets tainted NVRAM (lan_ipaddr) 2) acos_service starts and reads the tainted value 3) Value is directly concatenated into a system() command 4) Injected command executes as REDACTED_PASSWORD_PLACEHOLDER. The critical trigger point is located in the network initialization segment of main(), with a high success rate of exploitation.
- **Notes:** Form a complete exploitation chain with Discovery 1. It is recommended to analyze the web components under /cgi-bin/ in subsequent steps to validate the NVRAM write interface.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Accuracy Assessment: The reference to lan_ipaddr was found non-existent (Radare2 shows 0 cross-references), but an equally dangerous pppoe/pptp_gateway injection point exists (evidence: sprintf+system call chain); 2) Vulnerability Authenticity: Unfiltered NVRAM values are directly concatenated into system() commands, and /etc/init.d/S80acos confirms execution as REDACTED_PASSWORD_PLACEHOLDER; 3) Indirect Trigger: Requires polluting specific NVRAM variables (not lan_ipaddr) via the web interface, consistent with attack chain characteristics. Actual risk 8.5 (requires specific pollution points), recommending revision of vulnerability description.

### Verification Metrics
- **Verification Duration:** 2999.35 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 6498825

---

## cmd_injection-env_nvram_system-fcn1728c

### Original Information
- **File/Directory Path:** `sbin/system`
- **Location:** `fcn.0001728c (0x16024, 0x15d5c)`
- **Description:** Critical Command Injection Chain: Attackers can trigger NVRAM pollution (fcn.0001728c+0x16024) by contaminating environment variables (e.g., HTTP_USER_AGENT). The contaminated NVRAM values are directly concatenated into sprintf format strings without filtering at fcn.0001728c+0x15d5c, ultimately executed via system. Trigger conditions: 1) During network configuration operations 2) Contaminated data contains command separators. Boundary check: No input filtering mechanism, only simple whitespace trimming. Exploitability: High (arbitrary command injection possible).
- **Code Snippet:**
  ```
  iVar7 = sym.imp.getenv(*0x16e84);
  sym.imp.acosNvramConfig_set(*0x16f00,iVar7);
  uVar13 = sym.imp.acosNvramConfig_get(...);
  sym.imp.sprintf(iVar18,*0x15e9c,pcVar10,uVar13);
  sym.imp.system(iVar18);
  ```
- **Notes:** Complete attack path: Environment variable pollution → NVRAM storage → Command concatenation → System command execution. It is recommended to verify environment variable setting points in web interfaces.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification confirms the existence of a core vulnerability: the pppoe_localgateway value is concatenated into a system command without filtering at address 0x15d5c (evidence: disassembly shows sprintf+system calls). However, the original description contains three inaccuracies: 1) The actual source of contamination is the subnet environment variable (getenv at 0x1606c) rather than HTTP_USER_AGENT; 2) The offset address 0x16024 corresponds to a fixed command (killall zeroconf) rather than the contamination point; 3) The contamination REDACTED_PASSWORD_PLACEHOLDER (wan_netmask) and injection REDACTED_PASSWORD_PLACEHOLDER (pppoe_localgateway) have no data flow correlation in sbin/system. The vulnerability requires: a) control over the pppoe_localgateway value (source unverified) b) triggering network configuration operations. Therefore, it constitutes a genuine vulnerability but not a direct trigger chain.

### Verification Metrics
- **Verification Duration:** 4092.47 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 7051893

---

## network_input-remote-web_exposure

### Original Information
- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:12-19`
- **Description:** The script creates symbolic links to expose files under `REDACTED_PASSWORD_PLACEHOLDER` as web endpoints (e.g., `/tmp/www/cgi-bin/RMT_invite.cgi`). Trigger condition: Automatically enabled when the web server configuration includes the `/tmp/www` path. External HTTP requests can directly access these endpoints, and no input filtering mechanism was found, potentially forming a complete attack chain from network input to CGI execution.
- **Code Snippet:**
  ```
  ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.cgi /tmp/www/cgi-bin/RMT_invite.cgi
  ln -s REDACTED_PASSWORD_PLACEHOLDER.sh /tmp/www/cgi-bin/func.sh
  ```
- **Notes:** The actual risk depends on: 1) whether the web server loads /tmp/www, and 2) whether vulnerabilities exist in RMT_invite.cgi/func.sh.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Accuracy Assessment: The symbolic link creation command does exist (partially accurate description), but the source file `REDACTED_PASSWORD_PLACEHOLDER_invite.cgi` is missing in the firmware (critical inaccuracy).
2) Vulnerability Judgment: Does not constitute an actual vulnerability because:
   - The exposed CGI file does not exist at all and cannot be accessed.
   - No evidence was found that the web server uses `/tmp/www` as the REDACTED_PASSWORD_PLACEHOLDER directory.
   - Even if the file existed, its vulnerability has not been verified.
3) Trigger Mechanism: Not directly triggerable; requires simultaneous fulfillment of:
   a) The missing CGI file exists during runtime (no evidence).
   b) Web server configuration loads `/tmp/www` (no evidence).
   c) The CGI file contains an exploitable vulnerability (unverified).

### Verification Metrics
- **Verification Duration:** 780.83 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2831687

---

## configuration_load-readydropd-external_usb_admin_chain

### Original Information
- **File/Directory Path:** `www/cgi-bin/readydropd.conf`
- **Location:** `www/cgi-bin/readydropd.conf`
- **Description:** configuration_load specifies an external USB mount path as the home_dir (/tmp/mnt/usb0/part1). When a malicious USB device is connected, attackers can influence service behavior through file implantation or path traversal. Combined with the high privileges of httpd_user=REDACTED_PASSWORD_PLACEHOLDER, this may form an attack chain of 'external media input → path traversal → privilege escalation'. Trigger condition: inserting a malicious USB device and inducing the service to access a specific path.
- **Code Snippet:**
  ```
  home_dir = /tmp/mnt/usb0/part1
  httpd_user = REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Notes:** Verify the handling logic of the home_dir by the readydropd main program (recommended to analyze the www/cgi-bin/readydropd binary file).

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification Confirmation: 1) Configuration risk exists - The high-risk path (home_REDACTED_PASSWORD_PLACEHOLDER) and high-privilege user (httpd_user=REDACTED_PASSWORD_PLACEHOLDER) are indeed set in www/cgi-bin/readydropd.conf; 2) Vulnerability cannot be verified - The readydropd main program handling this configuration was not found (the binary does not exist in the www/cgi-bin directory), and the adjacent file genie.cgi does not reference this configuration; 3) Attack chain broken - Lack of evidence showing the program loads the configuration and uses the path, making it impossible to verify whether path traversal and privilege escalation actually occur; 4) Complex trigger conditions - Requires physical access to a malicious USB device and depends on unverified service behavior.

### Verification Metrics
- **Verification Duration:** 1893.53 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 5189459

---

## configuration_load-readydropd-httpd_admin_privilege

### Original Information
- **File/Directory Path:** `www/cgi-bin/readydropd.conf`
- **Location:** `www/cgi-bin/readydropd.conf`
- **Description:** The httpd_user is configured as the REDACTED_PASSWORD_PLACEHOLDER high-privilege account without defined permission boundaries. If the service has vulnerabilities (such as buffer overflow), attackers may directly obtain REDACTED_PASSWORD_PLACEHOLDER privileges. Trigger condition: Sending malicious data through network interfaces or IPC to exploit the vulnerability.
- **Code Snippet:**
  ```
  httpd_user = REDACTED_PASSWORD_PLACEHOLDER
  httpd_group = REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Notes:** It is recommended to verify the actual permissions of the process (validate through system startup scripts)

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Configuration items exist but are not actually used: 1) The httpd binary does not reference the readydropd.conf or httpd_user strings; 2) No permission-setting functions (setuid/getpwnam) were detected; 3) Missing startup scripts prevent runtime permission verification. Attackers cannot directly obtain REDACTED_PASSWORD_PLACEHOLDER privileges through this configuration, with the risk remaining at the static configuration level.

### Verification Metrics
- **Verification Duration:** 2093.62 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 5642047

---

## nvram_get-ubdcmd-wan_config

### Original Information
- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `ubdcmd:0x91b4`
- **Description:** NVRAM Variable Handling Vulnerability: Variables (wan_proto/wan_mtu) obtained via acosNvramConfig_get are used directly without validation. Trigger Condition: Executing network configuration-related functions after contaminating NVRAM variables. Specific Manifestations: 1) Direct atoi conversion of strings → Logical errors caused by non-numeric input 2) Converted integers used in calculations → Integer overflow triggered by excessively large values. Security Impact: Configuration tampering/service crash. Constraint Check: No input filtering or boundary validation.
- **Code Snippet:**
  ```
  bl acosNvramConfig_get(wan_mtu)
  bl atoi  ; HIDDEN
  sub r0, r0, #10 ; HIDDEN
  ```
- **Notes:** Track NVRAM pollution vectors globally; associate atoi (shared conversion function across multiple chains)

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification confirmed: 1) Code pattern exists: Offset 0x91b8 retrieves wan_mtu → 0x91c0 performs unchecked atoi → 0x9200 directly computes (sub r3, r4, 0x268); 2) Input source externally controllable: wan_mtu can be set via NVRAM pollution; 3) Vulnerability triggerable: Executing 'ubdcmd set' introduces polluted values into the processing flow; 4) Actual impact: Non-numeric input causes negative value logic errors (e.g., atoi('abc')=0→0-616=-616), while oversized values trigger conditional branches but result in service anomalies. Although conditional branches prevent crashes, configuration tampering and service anomalies still constitute an exploitable vulnerability (CWE-190).

### Verification Metrics
- **Verification Duration:** 2427.96 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1842477

---

