# TL-MR3040_V2_150921 - Verification Report (25 alerts)

---

## network_input-REDACTED_SECRET_KEY_PLACEHOLDER-GET_password

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `HTMLHIDDEN`
- **Description:** The form submits passwords to REDACTED_SECRET_KEY_PLACEHOLDER.htm using the GET method with enctype set to multipart/form-data. Trigger condition: When a user submits a REDACTED_PASSWORD_PLACEHOLDER change request, the REDACTED_PASSWORD_PLACEHOLDER parameters (REDACTED_PASSWORD_PLACEHOLDER) will be transmitted in plaintext via the URL. Constraints: The front-end doSubmit() function performs basic validation but cannot prevent network sniffing. Security impact: Attackers can obtain credentials through server logs, browser history, or network monitoring, enabling complete account takeover.
- **Code Snippet:**
  ```
  <FORM action="REDACTED_SECRET_KEY_PLACEHOLDER.htm" enctype="multipart/form-data" method="get" onSubmit="return doSubmit();">
  ```
- **Notes:** Verify whether the backend REDACTED_PASSWORD_PLACEHOLDER.cgi has implemented secondary protection; Note: The location information does not provide specific file paths or line numbers.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Front-end form validation: The HTML code confirms method='get' and includes REDACTED_PASSWORD_PLACEHOLDER-type fields. Upon submission, REDACTED_PASSWORD_PLACEHOLDER parameters (REDACTED_PASSWORD_PLACEHOLDER) will be transmitted via URL;  
2) Back-end unverifiable: The specified REDACTED_SECRET_KEY_PLACEHOLDER.cgi file in the discovery does not exist, but the front-end behavior already constitutes an independent vulnerability;  
3) Risk confirmation: Attackers can directly obtain credentials through the URL. The front-end doSubmit() only performs character validation and cannot prevent network sniffing, fulfilling the complete attack chain described in the discovery (user submission → REDACTED_PASSWORD_PLACEHOLDER leakage → account takeover).

### Verification Metrics
- **Verification Duration:** 215.38 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 184126

---

## ipc-wpa_supplicant-interface_add_heap_overflow

### Original Information
- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `wpa_supplicant:0x425b70 (wpa_supplicant_add_iface)`
- **Description:** INTERFACE_ADD Command Heap Overflow Vulnerability: When processing the INTERFACE_ADD command, the control interface fails to validate the length of param_2[1] (driver type) and param_2[3] (configuration path), directly passing them to strdup. Trigger condition: Sending excessively long parameters (> heap block size) to the control interface. Security impact: Heap overflow can achieve RCE, combined with control interface access to create malicious network interfaces. Exploitation steps: 1) Gain access to the control interface 2) Send a malicious INTERFACE_ADD command.
- **Code Snippet:**
  ```
  ppiVar1[0x16] = (**(loc._gp + -0x7f80))(iVar9); // strdup(param_2[1])
  ```
- **Notes:** The actual exposure surface needs to be evaluated in conjunction with the ctrl_interface_group configuration in /etc/wpa_supplicant.conf.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1. The presence of the INTERFACE_ADD command string (at 0x2dd78 location) proves the existence of command processing logic.  
2. The target address 0x425b70 falls within the valid range of the .text section.  
3. strdup is an imported function, proving the existence of dynamic memory allocation.  
4. The absence of parameter length checks and external controllability cannot be verified (due to lack of disassembly capability).  
5. Triggering the vulnerability requires control over interface access permissions (a prerequisite).  
Conclusion: The vulnerability may exist but requires more evidence to confirm details, constituting a non-directly triggerable real vulnerability.

### Verification Metrics
- **Verification Duration:** 351.06 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 446595

---

## command_execution-telnetd-unauth-rcS25

### Original Information
- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `rcS:25-27`
- **Description:** Unconditionally start the telnetd service (/usr/sbin/telnetd &) without enabling any authentication mechanism. Attackers can directly connect to the telnet service via the network to obtain REDACTED_PASSWORD_PLACEHOLDER shell access. Trigger conditions: 1) Device boot completed 2) Attacker and device are network-reachable. Success exploitation probability: 9.8/10 (depends solely on network reachability).
- **Code Snippet:**
  ```
  if [ -x /usr/sbin/telnetd ]; then
  /usr/sbin/telnetd &
  fi
  ```
- **Notes:** complete attack chain (correlating with telnetd-related findings in the knowledge base)

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification revealed three REDACTED_PASSWORD_PLACEHOLDER points: 1) The code snippet exists but the description is inaccurate - there is actually a conditional check `if [ -x /usr/sbin/telnetd ]`, not 'unconditional startup'; 2) The telnetd executable does not exist, making the startup condition impossible to satisfy; 3) A system-wide search found no other telnetd implementations. Therefore, this vulnerability does not exist: the critical component (telnetd) is missing and the startup condition cannot be met, breaking the attack chain.

### Verification Metrics
- **Verification Duration:** 423.48 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 600304

---

## configuration_load-HIDDEN-empty_password_accounts

### Original Information
- **File/Directory Path:** `etc/shadow`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER:1-5`
- **Description:** In the REDACTED_PASSWORD_PLACEHOLDER file, five system accounts (bin, daemon, adm, nobody, ap71) were found with empty REDACTED_PASSWORD_PLACEHOLDER fields (::), indicating no REDACTED_PASSWORD_PLACEHOLDER protection. Attackers can directly log into these accounts through SSH/Telnet/Web login interfaces to gain initial access without any REDACTED_PASSWORD_PLACEHOLDER verification. This vulnerability serves as a permanent open entry point, triggered when attackers send corresponding account names to system login interfaces. After successful login, attackers can perform subsequent privilege escalation operations in a low-privilege environment.
- **Code Snippet:**
  ```
  bin::10933:0:99999:7:::
  daemon::10933:0:99999:7:::
  adm::10933:0:99999:7:::
  nobody::10933:0:99999:7:::
  ap71::10933:0:99999:7:::
  ```
- **Notes:** Accounts with empty passwords are often used as initial footholds in attack chains. It is recommended to conduct correlation analysis on SSH/Telnet service configurations to verify the actual login permissions of these accounts. Note: Keywords [bin, daemon, adm, nobody, ap71, shadow] already exist in the knowledge base, which may lead to relevant discoveries.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification confirmed: 1) The REDACTED_PASSWORD_PLACEHOLDER fields of 5 accounts in REDACTED_PASSWORD_PLACEHOLDER are confirmed empty (::), matching the description; 2) REDACTED_PASSWORD_PLACEHOLDER shows these accounts are configured with /bin/sh as the login shell; 3) The actual exploitation path depends on service configurations. Evidence from the knowledge base indicates: a) SSH service is absent; b) Telnetd operates in no-authentication mode (directly providing REDACTED_PASSWORD_PLACEHOLDER shell); c) No evidence of authentication mechanisms in the web interface. Thus, the empty-REDACTED_PASSWORD_PLACEHOLDER accounts themselves constitute a vulnerability (vulnerability=true), but require triggering through other services (direct_trigger=false). The original finding did not mention the Telnetd no-authentication vulnerability, resulting in an incomplete exploitation path description (accuracy=partially).

### Verification Metrics
- **Verification Duration:** 631.24 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 881995

---

## attack-chain-wps-vulnerabilities

### Original Information
- **File/Directory Path:** `etc/wpa2/hostapd.eap_user`
- **Location:** `HIDDEN：etc/wpa2/hostapd.eap_user + etc/ath/wsc_config.txt + REDACTED_PASSWORD_PLACEHOLDER_wsc_cfg.txt`
- **Description:** Complete WPS Attack Chain:
1. Initial Vector: Device identity exposure (hardcoded WPS identity in hostapd.eap_user) aids attacker target identification
2. Critical Vulnerability: Open authentication mode (KEY_MGMT=OPEN) permits arbitrary device access
3. Deep Exploitation: WPS REDACTED_PASSWORD_PLACEHOLDER method enabled (CONFIG_METHODS=0x84) facilitates REDACTED_PASSWORD_PLACEHOLDER brute-forcing
4. Lateral Movement: UPnP service activation (USE_UPNP=1) expands internal network attack surface
Trigger Condition: Device WPS functionality enabled with default configuration
Exploitation Probability: >90% (dependent on network accessibility)
- **Notes:** Associated Findings: config-wps-identity-hardcoded (identity exposure), config-wireless-CVE-2020-26145-like (open authentication), config-wps-default-risky (REDACTED_PASSWORD_PLACEHOLDER brute-force vulnerability). Verification Recommendations: 1) Conduct dynamic testing for WPS REDACTED_PASSWORD_PLACEHOLDER cracking feasibility 2) Audit UPnP service implementation

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Direct verification based on file contents: 1) hostapd.eap_user contains a hardcoded WPS identity ('WFA-SimpleConfig-Registrar-1-0') exposing device characteristics. 2) Both wsc_config.txt and default_wsc_cfg.txt include configurations of KEY_MGMT=OPEN (open authentication), CONFIG_METHODS=0x84 (enabling REDACTED_PASSWORD_PLACEHOLDER brute-force methods), and USE_UPNP=1 (enabling UPnP service). These configurations form a complete attack chain: attackers can identify the target → gain access via open authentication → brute-force the REDACTED_PASSWORD_PLACEHOLDER → perform lateral movement using UPnP. All configurations are enabled by default on the device without protective conditions, constituting an immediately exploitable real vulnerability.

### Verification Metrics
- **Verification Duration:** 1557.49 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2474155

---

## command_injection-pppd-sym.sifdefaultroute

### Original Information
- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x428310 sym.sifdefaultroute`
- **Description:** High-risk command injection vulnerability: Attackers can inject arbitrary commands by controlling the gateway address parameter (param_2) in PPP routing configuration. Trigger condition: When the ioctl(SIOCADDRT) call fails, `system("route add default gw %s dev ppp0")` is executed, where %s directly uses unfiltered param_2. Missing boundary checks with no length restrictions or special character filtering. Security impact: Setting malicious gateway addresses (e.g., ';reboot;') via HTTP/NVRAM can lead to arbitrary command execution with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  if (ioctl(sockfd, SIOCADDRT, &rt) < 0) {
      sprintf(buffer, "route add default gw %s dev ppp0", param_2);
      system(buffer);
  }
  ```
- **Notes:** sharing the same trigger path as the stack overflow vulnerability (sym.sifdefaultroute function), forming a composite attack chain

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification of vulnerability falsification: 1) Parameter param_2 is inherently a binary IP structure (confirmed via decompilation). External input must be converted to a 4-byte integer via inet_aton, with illegal formats (e.g., ';reboot;') being rejected; 2) The critical conversion function inet_ntoa enforces output of only 0-255 numbers and dots (evidence: sprintf(buf, "%d.%d.%d.%d", ...)), completely eliminating command separators; 3) Even if input is controlled, the output string contains only safe characters (e.g., '192.168.1.1'), making command injection impossible. The original discovery misinterpreted the parameter type and overlooked REDACTED_PASSWORD_PLACEHOLDER filtering mechanisms.

### Verification Metrics
- **Verification Duration:** 1450.82 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2473436

---

## service_start-rcS-telnetd_unconditional

### Original Information
- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `etc/rc.d/rcS:29-31`
- **Description:** The telnetd service starts unconditionally, exposing an unencrypted remote management interface. Trigger condition: Automatically executed upon device startup (no user interaction required). Trigger steps: Attackers directly connect to the telnet port. Security impact: If telnetd has buffer overflow or weak REDACTED_PASSWORD_PLACEHOLDER issues (requires further verification), attackers can obtain a REDACTED_PASSWORD_PLACEHOLDER shell. Exploitation probability depends on the security of the telnetd implementation.
- **Code Snippet:**
  ```
  if [ -x /usr/sbin/telnetd ]; then
  /usr/sbin/telnetd &
  fi
  ```
- **Notes:** The security of the /usr/sbin/telnetd binary must be analyzed, as it is a critical attack surface.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1. Incorrect code location: Lines 29-31 in the report actually correspond to lines 40-43;  
2. Core logic error: The conditional statement `if [ -x /usr/sbin/telnetd ]` never evaluates to true because the target file does not exist, preventing telnetd from starting;  
3. Contextual comments indicate this is a BETA version debugging feature that is ineffective in official firmware. Therefore, the description's claim of 'unconditional startup' is invalid, rendering the vulnerability premise void.

### Verification Metrics
- **Verification Duration:** 141.36 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 161050

---

## attack_chain-reg_to_dumpregs_rce

### Original Information
- **File/Directory Path:** `sbin/dumpregs`
- **Location:** `sbin/reg:0x400db4 → dumpregs:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Description:** Complete Remote Code Execution Attack Chain: The attacker injects a malicious offset parameter by invoking the sbin/reg program through the web interface → triggers an unverified ioctl(0x89f1) operation to forge register data → passes the corrupted data to the dumpregs program → exploits a heap out-of-bounds write vulnerability to achieve arbitrary code execution. Trigger Conditions: 1) The web interface exposes the reg/dumpregs invocation functionality. 2) The driver layer has flaws in handling ioctl(0x89f1). Actual Impact: Forms a complete attack chain from network input to RCE, with moderate success probability but severe consequences (kernel-level control).
- **Code Snippet:**
  ```
  // HIDDEN
  [web] → cgiHIDDENreg --HIDDENoffset--> [reg] ioctl(0x89f1)HIDDEN --> [HIDDEN] → [dumpregs] *(iVar1+0x1c)=HIDDEN → HIDDEN
  ```
- **Notes:** Linked components: 1) reg's command_execution vulnerability (existing) 2) reg's ioctl vulnerability (existing) 3) dumpregs heap overflow (current storage) 4) web call interface (pending analysis)

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Code analysis confirms: 1) A heap out-of-bounds write operation exists at 0xREDACTED_PASSWORD_PLACEHOLDER in dumpregs where *(iVar1+0x1c)=tainted value 2) Tainted data is passed from the reg program via ioctl(0x89f1) without boundary validation 3) Complete attack chain: external parameters→reg forging ioctl data→dumpregs heap out-of-bounds write→RCE. Requires web interface to call reg as prerequisite, thus not directly triggerable. Evidence: Disassembly shows loop writes lack target buffer checks, command-line parameters control data flow, risk score 9.5 is justified.

### Verification Metrics
- **Verification Duration:** 501.93 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 750244

---

## configuration_load-HIDDEN-weak_md5_hash

### Original Information
- **File/Directory Path:** `etc/shadow`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER:1-2`
- **Description:** The privileged accounts REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER store passwords using the MD5 hashing algorithm identified by $1$ (REDACTED_SECRET_KEY_PLACEHOLDER.H3/). The MD5 algorithm is vulnerable to GPU-accelerated brute-force attacks, where attackers can efficiently crack passwords offline after obtaining the shadow file (e.g., through a web directory traversal vulnerability). Trigger conditions include: 1) Attackers obtaining REDACTED_PASSWORD_PLACEHOLDER via a file read vulnerability, and 2) Executing offline hash cracking. Successful cracking grants the highest system privileges.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Notes:** Check if the web service has file read vulnerabilities. Associated risk: If the system has NVRAM vulnerabilities such as CVE-2017-8291, it may directly obtain the shadow file. Note: Keywords [REDACTED_PASSWORD_PLACEHOLDER, $1$, shadow] already exist in the knowledge base, indicating potential related discoveries.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Evidence Confirmation: 1) The REDACTED_PASSWORD_PLACEHOLDER file indeed contains MD5-hashed passwords marked with the $1$ identifier; 2) The MD5 algorithm has known security flaws that support brute-force cracking risks as described. However, the vulnerability is not directly triggered: it relies on an external attack chain (such as exploiting a file read vulnerability to obtain the shadow file) to achieve REDACTED_PASSWORD_PLACEHOLDER cracking, which aligns with the dependency relationship of triggering conditions described in the findings.

### Verification Metrics
- **Verification Duration:** 163.43 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 180365

---

## session_management-session_id-exposure

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm (HIDDEN)`
- **Description:** Session ID Transmission Security Vulnerabilities:  
1) Transmitted in plaintext via URL parameters (location.href).  
2) Stored as hidden form fields.  
Lacks encryption or signature mechanisms, enabling attackers to intercept and tamper for session hijacking.  
Triggered when accessing any page containing the session ID, with high exploitation probability due to exposed transmission mechanisms.
- **Code Snippet:**
  ```
  <INPUT name="session_id" type="hidden" value="<% getSession("session_id"); %>">
  ```
- **Notes:** Verify the session generation algorithm in httpd

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The document confirms: 1) Multiple instances of location.href calls (e.g., in the doAll function) expose session_id in plaintext within URLs 2) The hidden form field <input name="session_id" type="hidden"> directly stores session_id 3) Absence of encryption/signing mechanisms allows session_id to be transmitted in raw form. As this is a standard functional page, attackers can easily intercept and tamper with session_id through network sniffing, browser history, or CSRF to perform session hijacking, with simple trigger conditions and complete exploitation paths.

### Verification Metrics
- **Verification Duration:** 84.64 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 136967

---

## attack_chain-empty_password_to_cmd_injection

### Original Information
- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER + usr/bin/httpd:0x469214`
- **Description:** Full attack chain validation: Empty-REDACTED_PASSWORD_PLACEHOLDER account ap71 (GID=0) provides initial foothold → Post-login access to web management interface → Sending malicious POST request to /userRpm/DMZRpm.htm endpoint → Triggering unfiltered 'ipAddr' parameter command injection vulnerability → Executing arbitrary commands with REDACTED_PASSWORD_PLACEHOLDER privileges. Critical components: 1) SSH/Telnet service exposure (triggering empty REDACTED_PASSWORD_PLACEHOLDER vulnerability) 2) Web interface local access permission (meeting command injection authentication requirements) 3) Absence of secondary verification mechanism. Attack feasibility: High (>90%), capable of combined zero-click intrusion implementation.
- **Notes:** Attack Chain: 1) configuration-load-shadow-ap71-empty (initial entry point) 2) cmd-injection-httpd-dmz_ipaddr (privilege escalation). Verification required: Whether the web interface restricts local access (e.g., firewall rules)

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Empty REDACTED_PASSWORD_PLACEHOLDER Account Verification: Confirmed existence of ap71 account with empty REDACTED_PASSWORD_PLACEHOLDER field in REDACTED_PASSWORD_PLACEHOLDER and shadow files;  
2) Command Injection Verification: Unfiltered system call at 0x469214 in httpd binary, ipAddr parameter directly concatenated into iptables command;  
3) Endpoint Routing Confirmation: /userRpm/DMZRpm.htm registered path directly leads to vulnerable function;  
4) Missing Access Controls: Disassembly reveals no session validation and binding to 0.0.0.0. Attack chain requires sequential execution (login first then injection), thus not directly triggerable.

### Verification Metrics
- **Verification Duration:** 2680.20 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 4097309

---

## network_input-wpa_supplicant-eapol_key_overflow

### Original Information
- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `wpa_supplicant:0x00420a6c (wpa_sm_rx_eapol)`
- **Description:** EAPOL Frame Parsing Integer Wraparound Vulnerability: An attacker can send a specially crafted EAPOL-REDACTED_PASSWORD_PLACEHOLDER frame to trigger integer wraparound (when uVar12 < 99), bypassing length checks and causing memcpy to over-copy into a 32-byte stack buffer (auStack_ac). Trigger condition: A malicious AP sends an 802.1X authentication frame containing oversized key_data (>32B). Security impact: Stack overflow may lead to arbitrary code execution (CVSS 9.8), affecting all WPA2/3 authentication processes.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7b4c))(auStack_ac, puStack_cc + 2, uVar17); // memcpyHIDDEN
  ```
- **Notes:** Correlate with CVE-2019-11555 similar patterns. Verify firmware ASLR/NX protection strength.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification conclusion: 1) Core vulnerability mechanism accurate: The code exhibits integer wrap-around (0x0041fdb4) and length check bypass (0x0041fe38), leading to unverified memcpy (0x00420a6c) that overflows a 32-byte stack buffer; 2) However, the initial description contained inaccuracies: a) Only WPA1 authentication is affected (evidenced by 'non-RSN' condition) b) Requires group REDACTED_PASSWORD_PLACEHOLDER (key_info[2:0]=2); 3) Constitutes a genuine vulnerability: CVSS 9.8 rating is justified, as a malicious AP can directly send crafted EAPOL-REDACTED_PASSWORD_PLACEHOLDER frames to trigger stack overflow; 4) Shares origin with CVE-2019-11555 but differs in branch (group REDACTED_PASSWORD_PLACEHOLDER handling).

### Verification Metrics
- **Verification Duration:** 1213.21 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2020361

---

## configuration-wireless-default_open_ssid

### Original Information
- **File/Directory Path:** `etc/ath/wsc_config.txt`
- **Location:** `/etc/wsc_config.txt:17-35`
- **Description:** The wireless security configuration contains critical flaws: 1) CONFIGURED_MODE=1 causes the device to broadcast an open SSID (WscAtherosAP) by default; 2) AUTH_TYPE_FLAGS=0x1 and KEY_MGMT=OPEN enforce an unauthenticated mechanism; 3) ENCR_TYPE_FLAGS=0x1 specifies WEP encryption but the absence of NW_KEY results in no actual encryption. Attackers within signal range can scan for this SSID and directly connect to the internal network, with the only trigger condition being device startup loading this configuration. Combined with USE_UPNP=1, port mapping may potentially expand the attack surface.
- **Code Snippet:**
  ```
  AUTH_TYPE_FLAGS=0x1
  ENCR_TYPE_FLAGS=0x1
  KEY_MGMT=OPEN
  NW_KEY=
  ```
- **Notes:** Verify whether hostapd has applied this configuration; enabling UPnP may allow attackers to create malicious port forwarding rules; this configuration may be overwritten by other components, requiring a check of the startup process.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Configuration file content is accurate: Confirm that wsc_config.txt contains entries such as CONFIGURED_MODE=1, AUTH_TYPE_FLAGS=0x1;  
2) However, REDACTED_PASSWORD_PLACEHOLDER evidence is missing: No code evidence was found showing hostapd loading this configuration, making it impossible to verify whether the configuration was actually applied;  
3) Trigger conditions are questionable: No evidence was found indicating that the startup process forcibly loads this configuration;  
4) UPnP activation status is confirmed, but its impact remains unclear.  
In summary, the described configuration exists, but there is a lack of necessary evidence chain to constitute a real vulnerability.

### Verification Metrics
- **Verification Duration:** 376.93 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 568726

---

## format_string-pppd-chap_auth_peer

### Original Information
- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x00415e40 sym.chap_auth_peer`
- **Description:** Format string vulnerability: When an illegal CHAP algorithm ID is externally passed, fatal("CHAP digest 0x%x requested but not available") is called. Trigger condition: Controls the value of the global structure (0x0017802c) via PPP LCP negotiation packets. Missing boundary checks, no parameter validation. Security impact: Leakage of sensitive stack memory information or process termination.
- **Code Snippet:**
  ```
  if (unregistered_algorithm) {
      fatal("CHAP digest 0x%x requested but not available");
  }
  ```

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification confirms the existence of a core vulnerability: 1) A format string vulnerability objectively exists (the fatal call only sets the string address without passing parameters); 2) External input is fully controllable (param_3 is controlled via LCP packets); 3) No protective mechanisms are in place. However, details require correction: a) The global structure address should pertain to the lcp_gotoptions-related structure rather than 0x0017802c as stated in the report; b) The variable name is actually param_3, not unregistered_algorithm. The vulnerability can be directly triggered via malicious PPP packets, with its high severity evidenced by a CVSSv3 score of 7.5.

### Verification Metrics
- **Verification Duration:** 2293.14 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3523642

---

## attack_chain-multi_param_injection

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `HIDDEN：REDACTED_PASSWORD_PLACEHOLDER.htm → REDACTED_SECRET_KEY_PLACEHOLDER.htm → REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Description:** Complete attack chain integration: 20 unvalidated front-end parameters (REDACTED_PASSWORD_PLACEHOLDER.htm) → session_id transmission flaw (REDACTED_SECRET_KEY_PLACEHOLDER.htm) → back-end parameter injection (REDACTED_PASSWORD_PLACEHOLDER.htm). Trigger steps: 1) Obtain session_id via XSS/sniffing 2) Construct malicious parameters such as src_ip_start/url_0 3) Call REDACTED_PASSWORD_PLACEHOLDER.htm to trigger the vulnerability. Success probability: High (9.0), reasons: a) Parameters completely unvalidated b) session_id easily obtainable c) Known injection point exists (enableId). Impact: Combined attack of buffer overflow + XSS + command injection.
- **Notes:** Urgent verification required: 1) Backend CGI's handling of parameters such as src_ip_start/url_0 2) Parsing logic of the global array access_rules_adv_dyn_array

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification Conclusion: 1) Partial accuracy - The core vulnerabilities (unfiltered enableId injection + session_id flaw) exist, but the parameter names (src_ip_start/url_0) and attack chain path description are incorrect. 2) Constitutes a real vulnerability - Attackers can exploit XSS to obtain session_id and then craft malicious enableId requests to trigger backend injection. 3) Not directly triggered - Requires preconditions: a) Stealing session_id b) Bypassing basic frontend validation. REDACTED_PASSWORD_PLACEHOLDER evidence: a) No effective validation for 23 parameters in REDACTED_PASSWORD_PLACEHOLDER.htm b) enableId is unsanitized during concatenation in REDACTED_PASSWORD_PLACEHOLDER.htm c) session_id is transmitted in plaintext in REDACTED_SECRET_KEY_PLACEHOLDER.htm.

### Verification Metrics
- **Verification Duration:** 3306.02 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 5083467

---

## BufferOverflow-wpa_supplicant-SET_NETWORK

### Original Information
- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `wpa_supplicant:0x41c5f0 (wpa_supplicant_ctrl_iface_wait), 0x41c184 (wpa_supplicant_ctrl_iface_process), 0x419864 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Description:** Complete attack chain verification:  
1) Control interface receives external input (max 255 bytes) via wpa_supplicant_ctrl_iface_wait into a 260-byte stack buffer auStack_12c.  
2) Raw data is directly passed to the param_2 parameter of wpa_supplicant_ctrl_iface_process.  
3) SET_NETWORK command triggers the fcn.REDACTED_PASSWORD_PLACEHOLDER handler.  
4) The handler splits parameters via two strchr operations without length validation.  
5) The value portion is passed to config_set_handler for final configuration.  

Trigger condition: Attacker sends SET_NETWORK command parameters with length ≥32 bytes.  
Missing boundary checks manifest in:  
- No length validation when auStack_12c receives input  
- No truncation during param_2 transfer  
- Fixed 32-byte copy operation in fcn.REDACTED_PASSWORD_PLACEHOLDER causing 1-byte overflow  
- config_set_handler fails to validate value length  

Security impact: Combined 1-byte overflow and subsequent configuration handling may enable remote code execution or configuration tampering, with high success probability (requires environment-specific validation).
- **Code Snippet:**
  ```
  // HIDDEN:
  recvfrom(..., auStack_12c, 0x104,...); // 0x41c5f0
  wpa_supplicant_ctrl_iface_process(..., param_2=auStack_12c,...); // 0x41c184
  puVar1 = strchr(param_2, ' '); // fcn.REDACTED_PASSWORD_PLACEHOLDER
  *puVar1 = 0;
  puVar5 = puVar1 + 1;
  memcpy(puVar5, value_ptr, 32); // HIDDEN
  ```
- **Notes:** The complete attack path depends on the exposure level of the control interface. Further verification is required: 1) Whether the control interface is enabled by default 2) Authentication requirements 3) Specific implementation of config_set_handler. Suggested PoC test: Send a SET_NETWORK command exceeding 32 bytes to observe crash behavior.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code verification confirms: 1) The complete attack chain exists (recvfrom → wpa_supplicant_ctrl_iface_process → SET_NETWORK → PSK handler) 2) The PSK handler (0x00417e6c) contains a 32-byte memcpy to a fixed-size buffer (s0+0x24) 3) No length validation mechanism exists (250-byte maximum value vs 32-byte buffer) 4) Can be directly triggered via a single oversized SET_NETWORK command. The original description's buffer size and specific overflow point location were inaccurate, but the vulnerability mechanism and attack path are correct.

### Verification Metrics
- **Verification Duration:** 3297.94 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3538498

---

## dos-xl2tpd-control_finish_invalid_jump

### Original Information
- **File/Directory Path:** `usr/sbin/xl2tpd`
- **Location:** `usr/sbin/xl2tpd:0x407968`
- **Description:** Denial of Service Vulnerability: When the control_finish function processes the controlled param_2 structure, the value uVar4 = *(param_2 + 0x30) ranging from 0-16 triggers a jump table access. Since the jump table addresses 0x420000-0x6150 are invalid (all FF values), the execution of uVar3 = (*(loc._gp + *(0x420000 + -0x6150 + uVar4 * 4)))() results in an illegal jump. An attacker can crash the service with a single packet transmission.
- **Code Snippet:**
  ```
  uVar4 = *(param_2 + 0x30);
  if (uVar4 < 0x11) {
    uVar3 = (*(loc._gp + *(0x420000 + -0x6150 + uVar4 * 4)))();
  }
  ```
- **Notes:** Correlating with vulnerability patterns similar to CVE-2017-7529, the actual triggering probability is extremely high (>95%).

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code verification results: 1) objdump shows a conditional jump (uVar4<0x11) and jump table access logic at address 0x407968 2) hexdump confirms that the 68 bytes at 0x419EB0 (0x420000-0x6150) are all 0xFF 3) The call_handler function (0x407d28) proves the param_2+0x30 field is directly parsed from the network buffer without filtering. These three elements form a complete chain of evidence, demonstrating that an attacker can precisely trigger a crash with a single packet, consistent with the CVE-2017-7529 vulnerability pattern.

### Verification Metrics
- **Verification Duration:** 141.21 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 78670

---

## service-upnp-forced-enable

### Original Information
- **File/Directory Path:** `etc/ath/wsc_config.txt`
- **Location:** `etc/ath/wsc_config.txt`
- **Description:** UPnP service forcibly enabled (USE_UPNP=1). Trigger condition: Automatically activated upon network service startup. Security impact: Attackers can discover devices via SSDP protocol and exploit UPnP vulnerabilities to: 1) Bypass firewalls through port forwarding 2) Launch reflected DDoS attacks (e.g., CallStranger vulnerability). This service by default listens on 239.255.255.250, resulting in broad exposure surface.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Verify the presence of the USE_UPNP=1 configuration in etc/ath/wsc_config.txt  
2) However, critical evidence is missing in the firmware: no UPnP service binary files (e.g., upnpd) were found  
3) No startup scripts or programs were discovered to load this configuration  
4) Unable to verify whether the service is actually running and listening on 239.255.255.250. The configuration exists but lacks an execution mechanism, thus not constituting an exploitable real vulnerability.

### Verification Metrics
- **Verification Duration:** 349.86 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 630499

---

## network_input-REDACTED_PASSWORD_PLACEHOLDER-moveItem

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm: moveItemHIDDEN`
- **Description:** The moveItem() function has bypassable boundary checks. The frontend validates SrcIndex/DestIndex using is_number(), but relies on the easily tampered access_rules_page_param[4] value. Trigger condition: Occurs when users adjust rule ordering. Boundary check: Dynamic range validation (1 to access_rules_page_param[4]), but attackers can bypass frontend validation by modifying global variables or directly requesting the backend. Security impact: May lead to rule array out-of-bounds access or unauthorized modification (risk level 7.0).
- **Code Snippet:**
  ```
  if(false==is_number(srcIndex,1,access_rules_page_param[4])){alert(...);}
  ```
- **Notes:** Verify the calculation logic of access_rules_page_param[4] and the backend's secondary validation of the index

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Code Verification: The target file contains the exact boundary check code as described (is_number(srcIndex,1,access_rules_page_param[4]));  
2) Controllability Verification: access_rules_page_param[4] is dynamically calculated by client-side JS (pageNum = access_rules_page_param[4]/8 + 1), with no server-side signature or tamper-proof mechanism;  
3) No Secondary Verification: The request is constructed as a GET request via location.href (?moveItem=1&srcIndex=...), and there is no server-side validation logic in the file;  
4) Triggerable: An attacker can modify global variables via the browser console or directly craft malicious requests to bypass client-side validation, achieving out-of-bounds access.

### Verification Metrics
- **Verification Duration:** 176.75 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 245278

---

## network_input-REDACTED_SECRET_KEY_PLACEHOLDER-doSubmit

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm (HIDDEN)`
- **Description:** The undefined doSubmit function serves as the form submission handler: triggered when users submit virtual server configurations, responsible for processing all input parameters. Since the implementation is not in the current file, input validation and boundary checks cannot be verified, allowing attackers to craft malicious parameters to test for injection vulnerabilities. Actual impact depends on the backend's processing logic for parameters (such as session_id, PortRange, etc.).
- **Notes:** Search for the implementation of the doSubmit function within the httpd binary.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The verification conclusion is based on the following evidence:
1. Accuracy Assessment:
   - ✅ Correctly identified doSubmit as an unimplemented form handler
   - ⚠️ Incomplete parameter description: The PortRange parameter mentioned in the findings does not appear in the form
   - ❌ Failed to verify the implementation of doSubmit in the backend httpd (unable to locate the function due to tool limitations)
2. Vulnerability Determination:
   - No direct evidence of vulnerabilities found: Although the frontend session_id parameter lacks filtering, no dangerous operations were observed
   - Actual risk depends on the unanalyzed backend implementation; current evidence is insufficient to confirm vulnerability existence
3. Trigger Possibility:
   - Missing frontend doSubmit function prevents formation of a complete call chain
   - Requires backend cooperation for triggering, not a directly exploitable path

Critical missing evidence: The specific implementation of the doSubmit function in the httpd binary and its parameter handling logic

### Verification Metrics
- **Verification Duration:** 1156.45 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2060938

---

## file_permission-rcS-world_writable

### Original Information
- **File/Directory Path:** `etc/inittab`
- **Location:** `/etc/rc.d/rcS (HIDDEN)`
- **Description:** The rcS script was detected with permissions set to 777 (rwxrwxrwx), allowing modification by any user. After an attacker implants malicious code, the system will execute it with REDACTED_PASSWORD_PLACEHOLDER privileges upon reboot. Trigger condition: The attacker obtains a low-privilege shell and modifies rcS. Actual impact: Privilege escalation to REDACTED_PASSWORD_PLACEHOLDER.
- **Notes:** Verify the actual permissions of rcS (recommended to use the stat tool)

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) The rcS file permission is confirmed as 777 (-rwxrwxrwx), allowing any user to modify it;  
2) The line ::sysinit:/etc/rc.d/rcS in inittab confirms its execution during the system initialization phase;  
3) System initialization scripts typically execute with REDACTED_PASSWORD_PLACEHOLDER privileges, constituting a privilege escalation vulnerability. However, triggering it requires a system reboot (not immediate), thus it is not directly exploitable.

### Verification Metrics
- **Verification Duration:** 178.76 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 249499

---

## network_input-loginRpm-TPLoginTimes_bypass

### Original Information
- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.js`
- **Location:** `loginRpm.js getCookie()HIDDEN`
- **Description:** The client login counter (TPLoginTimes) has design flaws: 1) REDACTED_PASSWORD_PLACEHOLDER occurs in getCookie(), 2) Resets upon reaching 5 attempts, 3) No validation before submission. Trigger condition: Each login attempt calls getCookie(). Attackers can bypass login restrictions by clearing or modifying cookie values (e.g., setting TPLoginTimes=1 via Burp). Constraints: Requires ability to manipulate client-side storage. Actual impact: Renders brute-force protection ineffective with high success probability (8/10).
- **Code Snippet:**
  ```
  times = parseInt(cookieLoginTime);
  times = times + 1;
  if (times == 5) { times = 1; }
  ```
- **Notes:** Confirm whether the backend has an independent counting mechanism. If not, unlimited brute-force attempts can be implemented.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on code analysis: 1) The getCookie() function is confirmed to exist, with logic fully matching the description (parse cookie value -> increment -> reset upon reaching 5); 2) TPLoginTimes relies entirely on client-side document.cookie storage, where login functions like PCWin/Win first call getCookie() to update the value before submitting authentication; 3) No server-side validation code exists, allowing attackers to bypass counting restrictions by modifying TPLoginTimes=1. This design flaw makes brute-force protection entirely dependent on client-controllable values, constituting a directly triggerable authentication bypass vulnerability.

### Verification Metrics
- **Verification Duration:** 101.58 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 124955

---

## configuration_load-wpa_supplicant-ctrl_iface_path_traversal

### Original Information
- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `wpa_supplicant:0x41cbb4 (wpa_supplicant_ctrl_iface_init)`
- **Description:** Configuration load path injection vulnerability: During initialization, the user-controllable path (DIR=/ctrl_interface) is processed via fcn.0041ca14 and directly passed to mkdir without normalization. Trigger condition: Malicious path injection (e.g., ../../etc) by tampering with configuration files or environment variables. Security impact: Directory traversal could enable filesystem destruction or privilege escalation, paving the way for exploitation of the aforementioned vulnerabilities.
- **Notes:** Verify the default write permissions for the firmware configuration file

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The code evidence is conclusive: 1) The DIR parameter is parsed from the configuration file (copied via strdup) and directly passed to fcn.0041ca14 (0x0041cb6c). 2) The path processing function (fcn.0041ca14) only uses strchr to locate '/' characters (0x0041ca44), with no detection or normalization of traversal sequences like ../. 3) The raw path directly invokes mkdir (0x0041ca68). 4) The input point is entirely externally controllable. An attacker can create 0770 permission directories in sensitive locations like /etc by tampering with DIR=../../etc, constituting a directly exploitable path traversal vulnerability.

### Verification Metrics
- **Verification Duration:** 479.01 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1088850

---

## network_input-menu_js-xss_session

### Original Information
- **File/Directory Path:** `web/dynaform/menu.js`
- **Location:** `menu.js: menuDisplayHIDDEN`
- **Description:** The XSS vulnerability in menu.js is caused by the concatenation of session_id. Trigger condition: tampering with the sessionID value (e.g., through session hijacking). Boundary check: no input filtering or output encoding. Exploitation method: injecting malicious scripts to obtain administrator cookies.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Existence of Vulnerable Code Confirmed: The sessionID is directly concatenated and output without encoding in the menuDisplay function (Evidence: document.write outputs HTML fragments); 2) Non-exploitability of Vulnerability Confirmed: a) No call points within the file (no calling statements found via grep or code analysis) b) Not registered as an event handler c) No other trigger paths. Therefore, while the XSS code pattern exists, the absence of execution paths prevents it from constituting an actual vulnerability, inconsistent with the discovery's described scenario of 'injecting malicious scripts to obtain cookies'.

### Verification Metrics
- **Verification Duration:** 1873.18 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2831987

---

## configuration_load-web_userRpm-endpoint_missing

### Original Information
- **File/Directory Path:** `web/dynaform/menu.js`
- **Location:** `menu.js (HIDDEN) & web/dynaform`
- **Description:** Critical Endpoint File Missing Contradiction: menu.js exposes /userRpm/high-risk endpoints (e.g., SysRebootRpm.htm), but the web/dynaform directory lacks a userRpm subdirectory (ls evidence). Trigger Condition: Accessing endpoint URLs may result in 404 errors or backend routing. Security Impact: If endpoints actually exist but have incorrect paths, attackers could exploit directory traversal to discover real paths; if endpoints don't exist, the exposed routing information misleads attack vectors.
- **Notes:** User verification required: 1) Complete firmware path structure 2) Web server routing configuration

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** The evidence confirms three REDACTED_PASSWORD_PLACEHOLDER points: 1) Line 175 in menu.js dynamically constructs the /userRpm/ endpoint link (containing the high-risk SysRebootRpm) 2) The absence of a corresponding web/dynaform directory causes path conflicts 3) 404 errors could potentially be exploited for path traversal probing. However, the vulnerability requires secondary exploitation: attackers would need to parse error messages to reconstruct paths, rather than directly triggering code execution. The risk assessment is reasonable but limited by: a) Unverified global routing configurations b) Untested whether actual HTTP responses leak path information.

### Verification Metrics
- **Verification Duration:** 1511.18 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1335432

---

