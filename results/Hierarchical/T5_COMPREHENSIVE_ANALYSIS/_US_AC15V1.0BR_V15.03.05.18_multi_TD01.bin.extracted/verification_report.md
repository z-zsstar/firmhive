# _US_AC15V1.0BR_V15.03.05.18_multi_TD01.bin.extracted - Verification Report (9 alerts)

---

## command-injection-TendaTelnet

### Original Information
- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd`
- **Description:** A potential command injection vulnerability was identified in the 'sym.TendaTelnet' function. This function executes system commands via system() and doSystemCmd(), where the system() call utilizes memory content potentially controllable by attackers, while doSystemCmd() processes user-supplied data from GetValue() without apparent sanitization measures.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Notes:** It is necessary to trace the data flow of the system() call parameters and analyze the data source and sanitization logic of GetValue().

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Based on code analysis evidence: 1) Confirmed existence of sym.TendaTelnet function which retrieves external parameter (lan.ip) via GetValue(); 2) Data flow path (0x0004fc38→0x0004fc60) shows direct user input passing into doSystemCmd() without filtering; 3) Complete attack chain: attackers can trigger command injection (e.g., '127.0.0.1; rm -rf /') by modifying lan.ip via HTTP request, requiring no complex preconditions. CVSS 9.0 score is justified.

### Verification Metrics
- **Verification Duration:** 863.71 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1582222

---

## httpd-busybox-command-injection-chain

### Original Information
- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/httpd -> bin/busybox`
- **Description:** Discovered complete command injection exploit chain:
1. **Initial Entry REDACTED_PASSWORD_PLACEHOLDER: The 'sym.TendaTelnet' function in 'bin/httpd' executes potentially attacker-controlled commands via system()
2. **Dangerous Execution REDACTED_PASSWORD_PLACEHOLDER: 'bin/busybox' provides dangerous command execution capabilities with 777 permission settings
3. **Sensitive Operation REDACTED_PASSWORD_PLACEHOLDER: busybox can manipulate sensitive files like REDACTED_PASSWORD_PLACEHOLDER and /var/log

**Attack REDACTED_PASSWORD_PLACEHOLDER:
- Attacker injects malicious commands through HTTP interface
- Commands are passed to busybox via httpd's system() call
- Leverages busybox's extensive permissions to perform sensitive operations

**Risk REDACTED_PASSWORD_PLACEHOLDER:
- High Likelihood: httpd directly exposed on network interface
- High Impact: busybox provides system-level command execution capability
- Medium Difficulty: Requires specific command injection techniques
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Notes:** This is one of the most dangerous attack paths in the firmware, and it is recommended to prioritize fixing it. Both the input validation of httpd and the permission restrictions of busybox need to be strengthened simultaneously.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The code analysis evidence indicates: 1) The alleged initial entry point sym.TendaTelnet uses hardcoded parameters ('killall -9 telnetd') with no externally controllable input; 2) Cross-referencing confirms this function is not called by any HTTP handler functions; 3) While busybox's elevated privileges exist, the absence of an attack entry point prevents formation of a complete exploitation chain. The originally reported HTTP→httpd→busybox attack path does not exist, therefore it does not constitute an actual vulnerability.

### Verification Metrics
- **Verification Duration:** 2419.69 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 917001

---

## timing-attack-REDACTED_PASSWORD_PLACEHOLDER

### Original Information
- **File/Directory Path:** `bin/dhttpd`
- **Location:** `dhttpd:0x0000bc98`
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER verification logic is vulnerable to timing attacks. The function REDACTED_PASSWORD_PLACEHOLDER compares passwords through fcn.0002bc94 by first checking pointers before comparing content, where response time variations may leak REDACTED_PASSWORD_PLACEHOLDER verification information. Attackers could infer correct passwords through timing side-channel attacks.
- **Notes:** Implement a constant-time comparison algorithm. Approximately 1000 measurements are required to effectively exploit this vulnerability.

### Verification Conclusion
- **Description Accuracy:** `unknown`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Limited by tool capabilities, verification cannot be completed: 1) readelf does not support disassembly by address (--disassemble=addr); 2) No disassembly tools like objdump are available; 3) Pipeline operations are restricted and cannot process segment information; 4) Missing symbol table prevents locating the REDACTED_PASSWORD_PLACEHOLDER function. Critical evidence is lacking: the actual assembly code at target address 0xbc98 and its contextual branch logic. Unable to confirm the presence of a timing attack vulnerability.

### Verification Metrics
- **Verification Duration:** 221.55 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 159430

---

## web-sensitive-data

### Original Information
- **File/Directory Path:** `webroot_ro/index.html`
- **Location:** `webroot_ro/index.js: [vpn_password, wrlPassword, loginPwd]`
- **Description:** Sensitive Data Handling: In index.js, VPN/WiFi passwords are transmitted in plaintext, and login passwords are only hashed using MD5. Attackers can intercept network traffic to obtain sensitive information or perform REDACTED_PASSWORD_PLACEHOLDER cracking.
- **Code Snippet:**
  ```
  function saveVPNConfig(REDACTED_PASSWORD_PLACEHOLDER) {
    $.ajax({
      url: '/api/v1/vpn/config',
      type: 'POST',
      data: { REDACTED_PASSWORD_PLACEHOLDER: REDACTED_PASSWORD_PLACEHOLDER },
      success: function(data) {
        // handle data
      }
    });
  }
  ```
- **Notes:** It is recommended to implement a strong salted hashing algorithm for passwords and encrypt sensitive data transmissions.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code analysis confirms: 1) VPN passwords are transmitted in plaintext via POST (L110-L146); 2) WiFi passwords are transmitted in plaintext when not hidden (L428-L438); 3) Login passwords are only processed with unsalted MD5 hashing (L462/811/877); 4) All transmissions rely on HTTP protocol (L816). Attackers on the same network can directly obtain sensitive data through traffic sniffing, and MD5 hashes are vulnerable to rainbow table attacks. Triggering these vulnerabilities only requires user form submission (default behavior) with no prerequisites.

### Verification Metrics
- **Verification Duration:** 835.23 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1553888

---

## web-security-multiple-issues

### Original Information
- **File/Directory Path:** `webroot_ro/main.html`
- **Location:** `webroot_ro/main.html | webroot_ro/main.js | webroot_ro/public.js`
- **Description:** A comprehensive analysis of 'webroot_ro/main.html' and its referenced JavaScript files ('main.js' and 'public.js') revealed the following security issues:

1. **Insufficient Input REDACTED_PASSWORD_PLACEHOLDER:
   - While basic input validation (such as format checks) is implemented on the frontend, there is a lack of strict filtering for special characters, potentially enabling XSS or injection attacks.
   - Whether backend validation aligns with frontend checks remains unconfirmed, creating potential bypass risks.

2. **CSRF REDACTED_PASSWORD_PLACEHOLDER:
   - No CSRF tokens were found in AJAX requests, which could allow attackers to forge malicious requests.

3. **Information REDACTED_PASSWORD_PLACEHOLDER:
   - Error messages include internal status codes (e.g., WAN connection status), potentially exposing system information.

4. **REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER:
   - Passwords are processed using MD5 hashing (hex_md5) but lack salting, making them vulnerable to rainbow table attacks.

5. **Exposed API REDACTED_PASSWORD_PLACEHOLDER:
   - Multiple sensitive API endpoints (e.g., 'REDACTED_PASSWORD_PLACEHOLDER') are exposed in frontend code, potentially becoming attack targets.

**Example Attack REDACTED_PASSWORD_PLACEHOLDER:
- An attacker could bypass frontend validation by crafting malicious input (e.g., XSS payload) and submitting it to backend APIs.
- Exploiting CSRF-unprotected API endpoints to trick users into executing malicious operations (e.g., modifying network settings).
- **Code Snippet:**
  ```
  // Example from main.js:
  function validateInput(input) {
    // Basic format check but no special character filtering
    return /^[a-zA-Z0-9]+$/.test(input);
  }
  
  // Example from public.js:
  $.ajax({
    url: 'REDACTED_PASSWORD_PLACEHOLDER',
    type: 'POST',
    data: params,
    // No CSRF REDACTED_PASSWORD_PLACEHOLDER included
  });
  ```
- **Notes:** Further analysis of the backend code is required to confirm the actual exploitability of potential vulnerabilities. Focus on files within the 'goform/' directory and the session management mechanism. Related finding: web-auth-hardcoded-credentials (also involving the use of hex_md5).

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification based on actual file analysis:
1. **CSRF Vulnerability REDACTED_PASSWORD_PLACEHOLDER: Unprotected AJAX requests (e.g., $.post("REDACTED_PASSWORD_PLACEHOLDER")) were found in both main.js and public.js, allowing attackers to craft malicious requests.
2. **API Endpoint Exposure REDACTED_PASSWORD_PLACEHOLDER: Multiple goform interfaces are hardcoded in JS files (e.g., REDACTED_PASSWORD_PLACEHOLDER).
3. **Input Validation Partially REDACTED_PASSWORD_PLACEHOLDER: The described validateInput function was not found, but other validation mechanisms exist (e.g., mainPageLogic.validate.checkAll), potentially indicating insufficient filtering.
4. **REDACTED_PASSWORD_PLACEHOLDER Security REDACTED_PASSWORD_PLACEHOLDER: Described as MD5 hash processing, but the code shows passwords transmitted in plaintext ($('#REDACTED_PASSWORD_PLACEHOLDER').val()), posing higher actual risk.
5. **Information Leakage Partially REDACTED_PASSWORD_PLACEHOLDER: Confirmed that the showError function directly displays raw error information, but the WAN status code leakage location does not match the description.

Vulnerabilities can be directly triggered: CSRF vulnerabilities require no preconditions, allowing malicious websites to forge requests and modify device settings.

### Verification Metrics
- **Verification Duration:** 1139.99 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 1868435

---

## nvram-ops-security-issues

### Original Information
- **File/Directory Path:** `bin/nvram`
- **Location:** `NVRAMHIDDEN`
- **Description:** Comprehensive analysis reveals the following critical security issues in the 'nvram' program:
1. **Insufficient Input REDACTED_PASSWORD_PLACEHOLDER: NVRAM operation functions (nvram_get/set/unset) directly process user input without adequate validation and boundary checking.
2. **Information Leakage REDACTED_PASSWORD_PLACEHOLDER: The return value of 'nvram_get' is directly passed to the 'puts' function for output, potentially leading to sensitive NVRAM data leakage.
3. **Buffer Overflow REDACTED_PASSWORD_PLACEHOLDER: Use of potentially unsafe string manipulation functions like strncpy, with unclear relationship between buffer size and input length.
4. **Null Pointer REDACTED_PASSWORD_PLACEHOLDER: The nvram_get return value is used directly without null pointer checks.

**Complete Attack REDACTED_PASSWORD_PLACEHOLDER:
- Attackers can provide malicious input through command-line arguments or network interfaces (if the program is exposed)
- Input is processed through functions like strsep before being passed to NVRAM operation functions
- Lack of boundary checking may lead to buffer overflow or null pointer dereference
- Potential for arbitrary code execution or system configuration tampering

**Trigger REDACTED_PASSWORD_PLACEHOLDER:
1. Attackers can control program input (command-line arguments or network input)
2. Input can reach critical function call points
3. System lacks additional protection mechanisms (e.g., ASLR)
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Notes:** Follow-up analysis recommendations:
1. Check if the program is exposed to network interfaces
2. Analyze the specific implementation of libnvram.so
3. Examine the status of system protection mechanisms (e.g., ASLR)
4. Search for other components that may call these NVRAM functions
5. Analyze the specific data content stored in NVRAM to assess information leakage risks

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification results: 1) Insufficient input validation confirmed (only checks parameter existence, lacks length/content filtering) 2) Information leakage confirmed (nvram_get return value directly passed to puts) 3) Buffer overflow disproven (strncpy buffer precisely matches 0x10000) 4) Null pointer disproven (explicit null check present). Constitutes actual vulnerabilities (CWE-200 Information Leakage and CWE-284 Improper Access Control), but requires: a) Program exposes input interface b) Attacker controls input content. Actual risks manifest as sensitive data leakage and potential system configuration tampering.

### Verification Metrics
- **Verification Duration:** 1579.27 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 2100409

---

## web-xss-showIframe

### Original Information
- **File/Directory Path:** `webroot_ro/index.html`
- **Location:** `webroot_ro/public.js: [showIframe]`
- **Description:** XSS attack chain: Attackers can craft a malicious URL → inject via showIframe → execute arbitrary JS code → steal cookies/sessions → gain full account control. Specifically, the 'showIframe' function in public.js contains unfiltered URL concatenation, which may lead to XSS attacks.
- **Code Snippet:**
  ```
  function showIframe(url) {
    var iframe = document.createElement('iframe');
    iframe.src = url;
    document.body.appendChild(iframe);
  }
  ```
- **Notes:** It is recommended to implement strict whitelist validation for all user inputs and enforce rigorous domain checks for iframe src attributes.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The verification revealed three inconsistencies: 1) The actual function implementation is 'showIframe(title, url, width, height, extraDataStr)', involving random number generation and concatenation of additional parameters, rather than simple URL concatenation; 2) All 28 call sites use hardcoded local HTML file paths, with no evidence of user input being passed as URL parameters; 3) The dynamic parameter extraDataStr only transmits internal system variables (e.g., wanStatus), with no indication of external controllability. Consequently, this function does not present a directly exploitable XSS vulnerability, rendering the vulnerability description inaccurate.

### Verification Metrics
- **Verification Duration:** 216.82 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 151343

---

## web-sensitive-data

### Original Information
- **File/Directory Path:** `webroot_ro/index.html`
- **Location:** `webroot_ro/index.js: [vpn_password, wrlPassword, loginPwd]`
- **Description:** Sensitive Data Handling: In index.js, VPN/WiFi passwords are transmitted in plaintext, and login passwords only use MD5 hashing. Attackers can intercept network traffic to obtain sensitive information or perform REDACTED_PASSWORD_PLACEHOLDER cracking.
- **Code Snippet:**
  ```
  function saveVPNConfig(REDACTED_PASSWORD_PLACEHOLDER) {
    $.ajax({
      url: '/api/v1/vpn/config',
      type: 'POST',
      data: { REDACTED_PASSWORD_PLACEHOLDER: REDACTED_PASSWORD_PLACEHOLDER },
      success: function(data) {
        // handle data
      }
    });
  }
  ```
- **Notes:** It is recommended to implement a strong salted hashing algorithm for passwords and encrypt sensitive data transmissions.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification confirms that the loginPwd field uses only MD5 hashing (without salting): 1) The code explicitly processes passwords using the hex_md5() function (evidence lines 811/877); 2) Only basic length validation is performed (5-32 characters), with no iteration or REDACTED_PASSWORD_PLACEHOLDER derivation mechanisms; 3) Attackers can capture the hash value via network sniffing for offline cracking. This constitutes a directly triggerable vulnerability (CVSS:AV:N/AC:L/PR:N/UI:N/S:U/C:H). The VPN/WiFi REDACTED_PASSWORD_PLACEHOLDER section could not be verified due to tool access restrictions. A file path discrepancy was identified: location is declared in index.js, but the actual REDACTED_PASSWORD_PLACEHOLDER field is in index.html, and loginPwd processing occurs in js/index.js.

### Verification Metrics
- **Verification Duration:** 688.73 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 407284

---

## web-redirect-jumpTo

### Original Information
- **File/Directory Path:** `webroot_ro/index.html`
- **Location:** `webroot_ro/public.js: [jumpTo]`
- **Description:** Open Redirect: The 'jumpTo' function in public.js does not validate redirect addresses, potentially enabling phishing attacks. Attackers could craft malicious redirect URLs to trick users into visiting harmful pages.
- **Code Snippet:**
  ```
  function jumpTo(url) {
    window.location.href = url;
  }
  ```
- **Notes:** It is recommended to implement strict domain validation for redirect URLs.

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Code analysis verification reveals: 1) The jumpTo function implementation includes domain validation logic (localDomain), with the redirect target hardcoded as 'http://tendawifi.com' rather than directly using parameters (evidence: public.js function implementation fragment); 2) No jumpTo function call points exist in index.html (evidence: grep search results empty); 3) The described code fragment is inconsistent with the actual function signature (jumpTo(address, callback)) and implementation logic. Therefore, this vulnerability description is inaccurate and does not constitute a genuine vulnerability.

### Verification Metrics
- **Verification Duration:** 716.45 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 438353

---

