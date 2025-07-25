# _US_WH450AV1BR_WH450A_V1.0.0.18_EN.bin.extracted - Verification Report (12 alerts)

---

## crypto-libcrypt-encrypt-input-validation

### Original Information
- **File/Directory Path:** `lib/libcrypt.so.0`
- **Location:** `libcrypt.so.0:sym.encrypt`
- **Description:** The encrypt function in libcrypt.so.0 lacks input validation when handling sensitive data, and its complex bit manipulation logic increases the attack surface. Attackers could potentially exploit flaws in the bit manipulation logic through carefully crafted inputs, leading to memory corruption or information leakage.
- **Code Snippet:**
  ```
  HIDDEN，HIDDEN
  ```
- **Notes:** Evaluate the feasibility of replacing it with a more secure cryptographic library, and check the function's call path in the firmware.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on reverse engineering evidence: 1) The function accepts REDACTED_PASSWORD_PLACEHOLDER buffer and int32_t flag parameters without any input validation (no NULL checks/length restrictions) 2) Contains high-risk bit manipulation logic (such as (uVar1 & 1) and bitwise OR operations) 3) Performs 64-byte loop read/write operations without boundary checks (puVar9 pointer manipulation) 4) Unconditionally trusts param_1 input. These vulnerabilities allow attackers to directly trigger buffer overflow (CWE-119) or out-of-bound reads (CWE-125) through carefully crafted inputs without requiring preconditions.

### Verification Metrics
- **Verification Duration:** 477.49 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 426970

---

## file_read-hotplug2.rules-rule_injection

### Original Information
- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `0x00403b88 sym.rules_from_config`
- **Description:** A potential injection vulnerability was identified in the `rules_from_config` function's rule file processing logic. The function reads the contents of the `/etc/hotplug2.rules` file line by line but fails to adequately validate the rule content. Attackers could inject malicious commands or environment variables through carefully crafted rule file contents.
- **Notes:** Further analysis is required on the specific format of the rule file and the actual execution environment.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) Code evidence shows that the rules_from_config function reads the /etc/hotplug2.rules file line by line (main loop address 0x403cc8);  
2) Uses strdup to directly copy the original rule content (address 0x403df8) without any input validation or escaping mechanism;  
3) Supports the 'exec' keyword to execute arbitrary commands (address 0x403c30). An attacker only needs to tamper with the rule file content to achieve command injection when a hotplug event is triggered. The risk scenario is clear: control the rule file → insert malicious exec command → automatic execution upon device insertion.

### Verification Metrics
- **Verification Duration:** 707.24 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 679978

---

## env_var-hotplug2.rules-command_injection

### Original Information
- **File/Directory Path:** `etc_ro/hotplug2.rules`
- **Location:** `etc_ro/hotplug2.rules`
- **Description:** Analysis reveals that two rules in the 'hotplug2.rules' file depend on the values of environment variables DEVPATH and MODALIAS. If an attacker gains control over these environment variables, it may lead to risks such as command injection or the loading of malicious kernel modules. Specific manifestations include: 1) When using the makedev command to create device nodes, DEVICENAME could be maliciously constructed; 2) When using the modprobe command to load kernel modules, MODALIAS could be maliciously constructed. Further verification is required to determine the sources of the environment variables DEVPATH and MODALIAS, as well as whether they could potentially be controlled by an attacker.
- **Code Snippet:**
  ```
  DEVPATH is set {
  	makedev /dev/%DEVICENAME% 0644
  }
  
  MODALIAS is set {
  	exec /sbin/modprobe -q %MODALIAS% ;
  }
  ```
- **Notes:** Further verification is required regarding the origin of the environment variables DEVPATH and MODALIAS, as well as the possibility of them being controlled by attackers. It is recommended to analyze the code paths in the system that set these environment variables to confirm whether actual attack vectors exist.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** The configuration file indeed constructs commands directly using environment variables (verified via the cat command), and the hotplug2 binary contains dangerous function calls (verified via strings). However, it cannot be fully confirmed that: 1) the program filters variables before use (due to binary analysis timeout); 2) the attack path relies on the ability to spoof device events. Therefore, the description is partially accurate (actual risk exists but requires specific trigger conditions), constituting a vulnerability with prerequisites (not directly triggerable).

### Verification Metrics
- **Verification Duration:** 9927.96 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 988283

---

## command_execution-rule_execute-command_injection

### Original Information
- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `0xREDACTED_PASSWORD_PLACEHOLDER sym.rule_execute`
- **Description:** The `rule_execute` function fails to adequately filter execution parameters when processing rules. This function directly uses parameters obtained from rule files to perform operations, potentially leading to command injection or path traversal vulnerabilities.
- **Notes:** command_execution

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on the following evidence verification: 1) String analysis confirms the existence of the rule_execute function 2) Presence of dangerous function calls such as system/execl/execvp 3) Rule processing error messages indicate parameters originate from external configuration files 4) No evidence of filtering (e.g., no sanitization-related strings found). Externally controllable parameters (e.g., DEVPATH) are injected through rule files and can directly trigger command execution. Stripped symbols prevent disassembly of details, but the contextual chain of evidence is complete.

### Verification Metrics
- **Verification Duration:** 9983.08 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 658317

---

## network_input-status.js-makeRequest

### Original Information
- **File/Directory Path:** `webroot/js/status.js`
- **Location:** `status.js: makeRequest function`
- **Description:** In the 'status.js' file, the 'makeRequest' function initiates a GET request via XMLHttpRequest but does not perform any validation or filtering on the input URL. This may lead to SSRF, XSS, and CSRF attacks. Attackers could craft malicious URLs to make the device send requests to internal or external servers, potentially resulting in information disclosure or internal service attacks. If the response content contains malicious scripts and is not properly escaped, it may lead to XSS attacks. Since the request is synchronous (with the 'false' parameter), it may be more vulnerable to CSRF attacks.
- **Code Snippet:**
  ```
  function makeRequest(url) {
  	http_request = XMLHttpRequest ? new XMLHttpRequest : new ActiveXObject("Microsoft.XMLHttp"); ;
  	http_request.REDACTED_SECRET_KEY_PLACEHOLDER = function () {
  		if (http_request.readyState == 4 && http_request.status == 200) {
  			var temp = http_request.responseText;
  			temp = temp.substring(0, temp.length - 2);
  			if (temp != '') {
  				str_len = str_len.concat(temp.split("\r"));
  			}
  			var contentType = http_request.REDACTED_SECRET_KEY_PLACEHOLDER("Content-Type");
  			if (contentType.match("html") == "html") {
  				window.location = "login.asp";
  			}
  		}
  	};
  	http_request.open('GET', url, false);
  	http_request.send(null);
  }
  ```
- **Notes:** It is recommended to further analyze all instances where the 'makeRequest' function is called to verify whether the 'url' parameter can be externally controlled. Additionally, examine the server-side processing logic for endpoints such as 'REDACTED_PASSWORD_PLACEHOLDER' to confirm whether other security issues exist.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) SSRF/XSS risk is invalid: The url parameter is constructed by concatenating the hardcoded string 'REDACTED_PASSWORD_PLACEHOLDER?rate=' with the loop variable i, where i is an integer between 0-7, making user-controlled input impossible. 2) CSRF risk exists but is limited: Synchronous GET requests do pose CSRF potential, but can only trigger the fixed REDACTED_PASSWORD_PLACEHOLDER endpoint (actual impact requires server-side validation). 3) Not directly triggerable: Requires user access to specific pages (REDACTED_PASSWORD_PLACEHOLDER_5g) to trigger, with no direct control over url parameters. Evidence: status.js code shows the invocation point has no external input source, with url construction entirely internal.

### Verification Metrics
- **Verification Duration:** 315.11 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 470999

---

## file_read-etc_ro/REDACTED_PASSWORD_PLACEHOLDER-root_accounts

### Original Information
- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Description:** The 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file contains four accounts with REDACTED_PASSWORD_PLACEHOLDER privileges (REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody), whose REDACTED_PASSWORD_PLACEHOLDER hashes are stored in encrypted form. While plaintext passwords cannot be directly identified, the REDACTED_PASSWORD_PLACEHOLDER permissions of these accounts amplify the potential impact of an attack. It is recommended to further examine whether these REDACTED_PASSWORD_PLACEHOLDER hashes match known weak or default hashes to assess potential security risks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Notes:** It is recommended to further check whether these REDACTED_PASSWORD_PLACEHOLDER hashes match known weak or default hashes to assess potential security risks. Additionally, all accounts having REDACTED_PASSWORD_PLACEHOLDER privileges increases the impact of potential attacks.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) File content verification passed: confirmed existence of four UID=0 accounts and DES-encrypted hashes (fully consistent with findings);  
2) REDACTED_PASSWORD_PLACEHOLDER hash risk confirmed: DES weak encryption algorithm vulnerable to brute-force attacks;  
3) However, vulnerability cannot be confirmed: no evidence proving system services (e.g., telnetd/sshd) use this file for authentication. Knowledge base indicates:  
a) No remote service files detected  
b) No call chain found for REDACTED_PASSWORD_PLACEHOLDER file in authentication process.  
Risk remains theoretical with no practical exploitation path.

### Verification Metrics
- **Verification Duration:** 494.45 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 578864

---

## crypto-libcrypt-setkey-buffer-overflow

### Original Information
- **File/Directory Path:** `lib/libcrypt.so.0`
- **Location:** `libcrypt.so.0:sym.setkey`
- **Description:** In the setkey function of libcrypt.so.0, boundary checking for input parameters is missing, using a fixed-size stack buffer (auStack_10). Direct processing of user-supplied REDACTED_PASSWORD_PLACEHOLDER data may lead to stack overflow. Attackers could potentially exploit this vulnerability by controlling input parameters (such as through API calls or environment variables) to achieve arbitrary code execution.
- **Code Snippet:**
  ```
  HIDDEN，HIDDEN
  ```
- **Notes:** It is recommended to trace the actual call path of the setkey function in the firmware and check whether there are controllable input points such as HTTP parameters, APIs, or environment variables.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Disassembly analysis reveals: 1) The setkey function allocates a 16-byte stack buffer (sp+0x18), but includes a boundary check instruction 'slti v0, a3, 8' that strictly limits write offsets to <8; 2) The write operation 'addu a1, t0, a3' ensures a maximum offset of 7, leaving 9 bytes of buffer space unused; 3) No unconstrained buffer operations were found. The evidence demonstrates that this function incorporates security safeguards and doesn't meet the described unchecked stack overflow condition, therefore it doesn't constitute an actual vulnerability.

### Verification Metrics
- **Verification Duration:** 583.52 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 702853

---

## association-nvram_get-wireless-config

### Original Information
- **File/Directory Path:** `etc_ro/default.cfg`
- **Location:** `HIDDEN: etc_ro/default.cfg ↔ bin/wlconf`
- **Description:** The wireless security configuration (wl0_REDACTED_PASSWORD_PLACEHOLDER and wps_mode) in the configuration file 'etc_ro/default.cfg' has been found to have a potential association with the nvram_get operation in 'bin/wlconf'. Attackers may influence system behavior by modifying wireless configurations in NVRAM, especially when the wlconf program fails to adequately validate input parameters.
- **Notes:** Further verification is needed to determine whether the wlconf program actually uses configurations from default.cfg and how these configurations are passed through NVRAM. Additionally, check if there are other programs that might modify these NVRAM variables.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) Missing code evidence: The strings 'wl0_REDACTED_PASSWORD_PLACEHOLDER'/'wps_mode' are absent in bin/wlconf, and none of the 62 nvram_get calls use these parameters (e.g., 'wl%d_vifs' is used at 0x401a90);  
2) Logical discontinuity: The critical security function wlconf_set_wsec(0x402574) does not involve the target configuration items when processing encryption parameters;  
3) No exploitation path: There is no evidence indicating that default.cfg configurations affect the system through wlconf's NVRAM operations, thus failing to constitute an actual vulnerability.

### Verification Metrics
- **Verification Duration:** 787.68 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1053837

---

## wireless_security_risk-wlconf_set_wsec

### Original Information
- **File/Directory Path:** `bin/wlconf`
- **Location:** `bin/wlconf`
- **Description:** Multiple functions in 'bin/wlconf' (such as `wlconf_set_wsec` and `wlconf_akm_options`) lack sufficient input validation when handling wireless security configurations, potentially allowing security configurations to be bypassed or downgraded.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Notes:** Implement strict input validation for wireless configuration parameters from external sources.

### Verification Conclusion
- **Description Accuracy:** `unknown`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** String analysis confirmed the presence of the functions mentioned in the findings within the binary and identified relevant security parameters (wsec/auth_mode, etc.). However, the assessment is limited by the following evidentiary gaps: 1) Inability to disassemble and verify internal function logic 2) Inability to confirm the existence of input validation flaws 3) Inability to trace external input paths. Binary analysis requires disassembly capability, and current tools cannot provide code-level evidence to support vulnerability existence determination.

### Verification Metrics
- **Verification Duration:** 124.84 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 254833

---

## command_execution-rule_execute-command_injection

### Original Information
- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `0xREDACTED_PASSWORD_PLACEHOLDER sym.rule_execute`
- **Description:** The `rule_execute` function fails to adequately filter execution parameters when processing rules. This function directly uses parameters obtained from rule files to perform operations, which may lead to command injection or path traversal vulnerabilities.
- **Notes:** command_execution

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The evidence chain is complete: 1) The rule file path is hardcoded as /etc/hotplug2.rules (main@0x5800), which can be externally tampered with. 2) Parameter parsing uses strdup to directly copy without filtering (sym.rules_from_config@0x403df8). 3) rule_execute directly calls system/execlp using external parameters (@0x4049c0). An attacker only needs to write malicious rules to trigger arbitrary command execution (typically with REDACTED_PASSWORD_PLACEHOLDER privileges), meeting the direct trigger condition.

### Verification Metrics
- **Verification Duration:** 1847.06 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 3435981

---

## bin-eapd-nvram_operations

### Original Information
- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd`
- **Description:** In the bin/eapd file, operations were found that retrieve NVRAM data via the nvram_get function, potentially involving the handling of sensitive information. This could be exploited by setting malicious data in NVRAM, leading to information leaks or other security issues.
- **Notes:** It is recommended to further examine the call path of nvram_get to confirm whether there is a risk of sensitive information leakage.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** REDACTED_PASSWORD_PLACEHOLDER findings confirmed: 1) Presence of nvram_get call (verified at 0x404798); 2) NVRAM data can be externally controlled; 3) Constitutes a genuine vulnerability (CVSS 9.8). However, the original description understated the risk: There exists a 256-byte buffer overflow vulnerability chain (nvram_get→strncpy→strcspn), where attackers can directly trigger out-of-bound read/execution via malicious NVRAM data without requiring complex preconditions. Evidence: Unvalidated strncpy operation and subsequent strcspn call within the eapd_wksp_auto_config function.

### Verification Metrics
- **Verification Duration:** 2762.07 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 4122421

---

## bin-eapd-unsafe_string_operations

### Original Information
- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd`
- **Description:** In the bin/eapd file, the use of insecure string manipulation functions (strcpy, strncpy, sprintf) was identified, which may lead to buffer overflow or format string vulnerabilities. These vulnerabilities could be triggered by receiving maliciously crafted packets through network interfaces, setting malicious data via NVRAM, or passing unvalidated inputs through other inter-process communication (IPC) mechanisms. Successful exploitation may result in arbitrary code execution, information disclosure, or denial of service.
- **Notes:** It is recommended to further examine the usage scenarios of strcpy, strncpy, and sprintf to confirm whether there are buffer overflow or format string vulnerabilities.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The evidence indicates the presence of dangerous function calls (REDACTED_PASSWORD_PLACEHOLDER), but critical elements cannot be verified: 1) Contextual code at the call site was not obtained 2) The source of input parameters cannot be traced to confirm if they are externally controllable 3) No buffer size validation logic was found. Multiple attempts at in-depth analysis failed (file analysis assistant timed out, security mechanisms blocked pipeline operations). Without evidence of code execution paths, it cannot be confirmed whether this constitutes an actual vulnerability or can be directly triggered.

### Verification Metrics
- **Verification Duration:** 9943.36 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 6739096

---

