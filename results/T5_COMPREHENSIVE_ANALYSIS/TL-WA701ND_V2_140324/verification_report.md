# TL-WA701ND_V2_140324 - Verification Report (5 findings)

---

## Original Information

- **File/Directory Path:** `web/userRpm/WzdEndRpm.htm`
- **Location:** `WzdEndRpm.htm: JavaScript functions loadWlanCfg, loadWlanMbss, loadNetworkCfg, etc.`
- **Description:** Multiple potential DOM-based XSS vulnerabilities were discovered in the 'WzdEndRpm.htm' file. Attackers can inject malicious JavaScript code by modifying NVRAM configuration variables (such as wireless SSID, security key, etc.), which is then executed via `innerHTML` assignment when users visit this configuration summary page. Specific trigger conditions include: the attacker first modifies controllable configuration values through other configuration interfaces (such as the wireless settings page) to contain malicious scripts; then, when the 'WzdEndRpm.htm' page is accessed, the script executes automatically. Potential exploitation methods include stealing session cookies, redirecting users, or performing unauthorized operations. Since the attacker possesses valid login credentials, this attack chain is feasible, but the risk is limited by the user's session permissions. The lack of input validation and output escaping for configuration data in the code leads to the existence of these vulnerabilities.
- **Code Snippet:**
  ```
  Example code snippet from the loadWlanCfg function:
  document.getElementById("localSsid").innerHTML = getWlanCfg("ssid1");
  document.getElementById("localSecText").innerHTML = getWlanCfg("secText");
  document.getElementById("brlSsid").innerHTML = getWlanCfg("brl_ssid");
  // Similar code uses innerHTML to display configuration data in multiple places, lacking escaping
  ```
- **Notes:** The exploitation of this vulnerability relies on the attacker's ability to modify configuration data through other interfaces, which is feasible given the attacker has login credentials. Further verification is needed to confirm whether functions like `getWlanCfg` read data from NVRAM and whether the backend filters input. It is recommended to check related configuration pages (such as wireless settings) to confirm the data flow. The vulnerability may affect session security, but non-root user permissions might limit the scope of damage.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** The alert description is completely accurate. Evidence shows that JavaScript functions (such as loadWlanCfg) in the 'web/userRpm/WzdEndRpm.htm' file use innerHTML assignment to directly output configuration data (e.g., document.getElementById('localSsid').innerHTML = getWlanCfg('ssid1');), lacking any escaping mechanisms (such as escape() or encodeURI()). The attacker model is an authenticated remote user (with valid login credentials) who can modify NVRAM variables (such as ssid1, secText, usrName) through other configuration interfaces (like the wireless settings page) to inject malicious scripts. When a user visits the 'WzdEndRpm.htm' page, the page load automatically calls these functions, reads data from the configuration, and executes the script, leading to DOM-based XSS. The complete attack chain is reproducible: 1. Attacker logs into the system; 2. Modifies configuration variables (e.g., sets SSID to '<script>alert("XSS")</script>'); 3. Accesses 'http://[target]/userRpm/WzdEndRpm.htm'; 4. Script executes, potentially stealing session cookies or performing unauthorized operations. The vulnerability risk is medium because exploitation requires authentication, but once successful, it can cause actual damage (such as session hijacking), and there are no mitigation measures.

## Verification Metrics

- **Verification Duration:** 340.36 s
- **Token Usage:** 134206

---

## Original Information

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `bpalogin:0x004021e4 sym.login`
- **Description:** In the login function, when processing authentication responses, strcpy and strcat are used to copy strings into a fixed-size global buffer, lacking boundary checks. An attacker can provide long strings through a malicious authentication server, causing a buffer overflow. The overflow may overwrite function pointers in the global structure (such as at offset 0x308). When this pointer is called (for example, during error handling), execution flow can be controlled. Trigger condition: The attacker runs bpalogin and specifies the 'authserver' parameter to point to a malicious server, which returns an overly long string in the authentication response. Exploitation method: Carefully craft the response string to overwrite the function pointer to point to shellcode or a ROP chain, achieving code execution.
- **Code Snippet:**
  ```
  0x004021c4      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405310:4]=0x8f998010
  0x004021e4      0320f809       jalr t9
  ; strcpy call, destination address is s1 + a0 (global buffer), source is s7 (stack buffer)
  0x00402200      8f9980f8       lw t9, -sym.imp.strcat(gp)  ; [0x405100:4]=0x8f998010
  0x00402210      0320f809       jalr t9
  ; strcat call, appends string to the same global buffer
  ```
- **Notes:** The vulnerability is in a global buffer, potentially bypassing ASLR; the attack chain requires the attacker to control the authentication server, but as a local user, it can be set via command-line parameters. It is recommended to further analyze the global structure layout and the function pointer usage points.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The security alert description is inaccurate: Code analysis shows that the target buffer for the strcpy and strcat calls is at offset 0x696 in the global structure, while the function pointer is at offset 0x308, with a distance of 910 bytes between them. A buffer overflow cannot overwrite the function pointer, thus the code execution claimed in the alert cannot be achieved. Although a buffer overflow may exist, potentially causing denial of service or data corruption, based on the attacker model (local user controlling the authentication server), the complete attack chain cannot be verified. The vulnerability is not exploitable for code execution, and the risk is low.

## Verification Metrics

- **Verification Duration:** 406.40 s
- **Token Usage:** 255117

---

## Original Information

- **File/Directory Path:** `sbin/wlanconfig`
- **Location:** `wlanconfig:0x004024b0 main+0xc00 (approximate address based on the 'p2pgo_noa' processing logic in the decompiled code)`
- **Description:** There is a stack buffer overflow vulnerability in the 'p2pgo_noa' subcommand processing of 'wlanconfig'. When an attacker provides multiple parameter sets, the program does not correctly check write boundaries while parsing parameters, leading to a stack buffer overflow. Specifically, during the loop processing parameters, the write pointer 'pcVar14' initially points to the stack variable 'cStack_174' (a single character), but increments by 5 bytes each loop iteration. When the loop count reaches the maximum value (iVar4=2), the write position exceeds the boundary of 'cStack_174', overwriting adjacent stack variables such as 'auStack_173' and 'iStack_168'. An attacker can manipulate the written values by controlling command line parameters (such as iteration count, offset value), thereby overwriting the return address or critical stack data. Trigger condition: Use the 'wlanconfig <interface> p2pgo_noa' command and provide at least three sets of parameters (each set containing iteration count, offset, and duration), for example 'wlanconfig wlan0 p2pgo_noa 1 1000 2000 2 2000 3000 3 3000 4000'. Exploitation method: Carefully craft parameter values to overwrite the return address pointing to shellcode or a gadget, achieving arbitrary code execution. Constraints: The number of parameters is limited by the program logic (maximum of three sets), but the value of each parameter is fully controllable, sufficient to complete the attack.
- **Code Snippet:**
  ```
  // Relevant snippet extracted from decompiled code
  pcVar18 = &cStack_174;
  piVar16 = param_2 + 0xc;
  iVar4 = 0;
  iVar3 = *piVar16;
  pcVar14 = pcVar18;
  while( true ) {
      if (iVar3 == 0) break;
      iVar3 = (**(pcVar20 + -0x7fcc))(iVar3); // atoi conversion
      *pcVar14 = iVar3; // Write to stack, potential overflow
      // ... Other operations write to auStack_173
      pcVar14 = pcVar14 + 5; // Pointer increment, potential boundary exceed
      iVar4 = iVar4 + 1;
      if ((iVar3 == 0) || (iVar4 == 2)) break;
  }
  ```
- **Notes:** The vulnerability was verified in the 'p2pgo_noa' subcommand processing; the overflow occurs before the ioctl call, so even if the ioctl fails (e.g., insufficient permissions), the overflow can still be triggered. The attack chain is complete: from untrusted input (command line) to dangerous operation (stack overflow overwriting return address). It is recommended to further verify exploit feasibility, for example through dynamic testing or checking stack layout. Associated files: No other files interact directly, but communication with the kernel wireless driver occurs via ioctl. Future analysis directions: Check if similar vulnerabilities exist in other subcommands (e.g., 'nawds'), and evaluate the presence of ASLR and stack protection mechanisms in the firmware.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The security alert describes a stack buffer overflow vulnerability, but based on decompiled code evidence: 1) The loop processes at most two sets of parameters (exits when iVar4 == 2), not three as stated in the alert; 2) The pcVar14 pointer write locations (cStack_174 + 5 and cStack_174 + 10) are within the bounds of the auStack_173 array (indices 4 and 9), not exceeding the stack frame; 3) In the stack layout, cStack_174 and auStack_173 are contiguous with no gaps, so writes cannot overwrite iStack_168 or the return address; 4) The data buffer used by ioctl (10 bytes starting from &cStack_174) contains expected data, with no overflow. The attacker model is a local user (controlling input via command line parameters), but code execution cannot be achieved. Therefore, the vulnerability does not exist.

## Verification Metrics

- **Verification Duration:** 475.90 s
- **Token Usage:** 301834

---

## Original Information

- **File/Directory Path:** `lib/modules/2.6.31/net/ag7240_mod.ko`
- **Location:** `ag7240_mod.ko:sym.athr_gmac_do_ioctl (address 0x08005b54)`
- **Description:** In the athr_gmac_do_ioctl function, there is a NULL pointer dereference vulnerability when processing ioctl commands. When param_3 (ioctl command) is 0x89f3 or 0x89f7, the function directly calls (*NULL)(), causing a kernel crash. An attacker, as a non-root user, can trigger this vulnerability by accessing the relevant device file and sending these ioctl commands, resulting in a denial of service. Trigger conditions include: device file permissions allow access by non-root users, and the attacker possesses valid login credentials. The exploitation method is simple and direct, requiring no complex input.
- **Code Snippet:**
  ```
  uint sym.athr_gmac_do_ioctl(uint param_1,uint param_2,int32_t param_3)
  {
      uint uVar1;
      
      if (param_3 == 0x89f3) {
          uVar1 = (*NULL)();
          return uVar1;
      }
      if (0x89f3 < param_3) {
          if (param_3 == 0x89f6) {
              halt_baddata();
          }
          if (param_3 == 0x89f7) {
              uVar1 = (*NULL)();
              return uVar1;
          }
      }
      else if (param_3 == 0x89f2) {
          halt_baddata();
      }
      return 0xffffffff;
  }
  ```
- **Notes:** The vulnerability evidence is clear, but further verification is needed regarding whether device file permissions (such as relevant files under /dev/) allow access by non-root users. This vulnerability primarily leads to denial of service and may not be directly usable for privilege escalation. It is recommended to check system configuration to confirm exploitability. No other buffer overflow or memory corruption vulnerabilities were found in this file.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The code vulnerability in athr_gmac_do_ioctl is confirmed: when ioctl commands 0x89f3 or 0x89f7 are used, a NULL pointer dereference occurs, leading to a kernel crash. However, exploitability requires a device file accessible to non-root users. Evidence from static analysis shows no character devices in the filesystem (via 'find . -type c') and no relevant device files in /dev/. Without a device file, the attack path is incomplete, and the vulnerability cannot be triggered. The attacker model assumed a non-root user with login credentials accessing the device file, but no such file exists in this context. Therefore, while the code flaw is real, it does not constitute an exploitable vulnerability in this firmware image.

## Verification Metrics

- **Verification Duration:** 481.62 s
- **Token Usage:** 309641

---

## Original Information

- **File/Directory Path:** `sbin/hostapd`
- **Location:** `hostapd:0x43737c sym.wps_set_ap_ssid_configuration`
- **Description:** A command injection vulnerability was discovered in the 'hostapd' binary, allowing attackers to execute arbitrary commands through malicious WPS messages. Vulnerability trigger condition: WPS function is enabled and the network interface is accessible. Attackers can send WPS messages over the network without requiring specific login credentials, but the user specifies that the attacker has connected to the device (which may include network layer access). Input data flows from WPS messages through multiple functions (such as `sym.eap_wps_config_set_ssid_configuration` and `sym.wps_set_ssid_configuration`), and is ultimately formatted via `sprintf` and passed to the `system` function without sanitization in `sym.wps_set_ap_ssid_configuration`. Exploitation method: Attackers forge WPS messages containing malicious commands (such as shell metacharacters), causing commands to be executed on the device. Boundary checks are missing, and input is directly embedded into the command string.
- **Code Snippet:**
  ```
  // In the sym.wps_set_ap_ssid_configuration function
  (**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4); // uStackX_4 is the user-controlled parameter param_2
  (**(loc._gp + -0x7948))(auStack_498); // Call system to execute the command
  ```
- **Notes:** The vulnerability relies on the availability of the WPS interface; it may be enabled in the default configuration. Attackers may not need login credentials, but the user specified 'connected to the device', so network access might be sufficient. However, the user's core requirement states that attackers must have valid login credentials (non-root user), so the conditions here may not fully match. It is recommended to further verify WPS configuration and network isolation. Other functions (such as main or control interface handling) do not show the complete attack chain.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on evidence verification, a command injection vulnerability exists in the sym.wps_set_ap_ssid_configuration function in sbin/hostapd. Disassembly code shows: at address 0x437360, the string 'cfg wpssave %s' is loaded; at address 0x437368, sprintf is called to format user input (parameter param_2) into a buffer; at address 0x43737c, system is called to execute the command in that buffer. Input controllability: parameter param_2 comes from WPS messages, and attackers can control its content through malicious WPS messages. Path reachability: When the WPS function is enabled and the network interface is accessible, attackers can send WPS messages without authentication to trigger this path. Actual impact: Attackers can inject shell metacharacters (such as ;, |, &) to execute arbitrary commands, leading to complete device compromise. Attacker model: Unauthenticated remote attacker, but with network layer access (connected to the device). PoC: Attackers can forge WPS messages containing malicious payloads, such as '; rm -rf /', causing the command 'cfg wpssave ; rm -rf /' to be executed by system.

## Verification Metrics

- **Verification Duration:** 561.24 s
- **Token Usage:** 367534

---

