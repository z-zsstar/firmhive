# Archer_C3200_V1_150831 - Verification Report (8 alerts)

---

## configuration-REDACTED_PASSWORD_PLACEHOLDER-account_misconfig

### Original Information
- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER.bak file contains high-risk account configurations:  
1) The REDACTED_PASSWORD_PLACEHOLDER account (UID=0) is configured with an interactive /bin/sh, allowing attackers to obtain a full REDACTED_PASSWORD_PLACEHOLDER shell upon gaining access to this account.  
2) The nobody account (UID=0), though locked, carries the risk of being activated.  
3) The home directories of both REDACTED_PASSWORD_PLACEHOLDER and nobody are set to the REDACTED_PASSWORD_PLACEHOLDER directory (/), violating the principle of least privilege. If combined with improper directory permission settings, this could lead to sensitive file exposure.  

Trigger condition: Attackers can execute arbitrary commands after obtaining REDACTED_PASSWORD_PLACEHOLDER credentials through weak REDACTED_PASSWORD_PLACEHOLDER brute-forcing, service vulnerabilities, or middleware vulnerabilities.  

Exploitation method: Log in to the REDACTED_PASSWORD_PLACEHOLDER account via remote services such as SSH/Telnet to directly obtain an interactive shell with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Notes:** Follow-up verification required: 1) REDACTED_PASSWORD_PLACEHOLDER strength of REDACTED_PASSWORD_PLACEHOLDER in REDACTED_PASSWORD_PLACEHOLDER 2) Whether network services allow REDACTED_PASSWORD_PLACEHOLDER remote login 3) REDACTED_PASSWORD_PLACEHOLDER directory permission settings (ls -ld /)

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Low`
- **Detailed Reason:** 1) REDACTED_PASSWORD_PLACEHOLDER.bak evidence confirms: REDACTED_PASSWORD_PLACEHOLDER account with UID=0 configured with /bin/sh can obtain REDACTED_PASSWORD_PLACEHOLDER shell; nobody account with UID=0 is locked but poses activation risk; both home directories set to / violate the principle of least privilege.  
2) REDACTED_PASSWORD_PLACEHOLDER directory permission 777 (drwxrwxrwx) confirms "improper directory permission configuration" risk.  
3) Constitutes an actual vulnerability because: attackers obtaining REDACTED_PASSWORD_PLACEHOLDER credentials can gain full REDACTED_PASSWORD_PLACEHOLDER privileges via /bin/sh.  
4) Not a direct trigger: requires preconditions (e.g., weak REDACTED_PASSWORD_PLACEHOLDER brute-forcing or REDACTED_PASSWORD_PLACEHOLDER theft via service vulnerabilities).  
5) Limitations: shadow REDACTED_PASSWORD_PLACEHOLDER strength and remote service availability were not verified, but core REDACTED_SECRET_KEY_PLACEHOLDER already form the vulnerability basis.

### Verification Metrics
- **Verification Duration:** 260.90 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 168682

---

## untrusted-file-upload-softup

### Original Information
- **File/Directory Path:** `web/main/softup.htm`
- **Location:** `softup.htm:HIDDEN`
- **Description:** The file upload functionality has user-controllable input points:  
1) The HTML form parameter 'filename' accepts arbitrary file uploads to /cgi/softup.  
2) The frontend only validates non-empty inputs (ERR_FIRM_FILE_NONE) without boundary checks for file type, size, or content.  
3) An attacker could craft malicious firmware files to exploit backend vulnerabilities.  
The actual impact depends on how /cgi/softup processes uploaded files: if file signatures are not verified or parsing vulnerabilities exist, it could lead to arbitrary code execution or device bricking.
- **Notes:** Analyze the processing logic of the /cgi/softup binary verification file

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification result: 1) Frontend description accurate: softup.htm contains an unfiltered file upload form (field name filename) with only non-empty validation (ERR_FIRM_FILE_NONE). 2) Backend risk unverifiable: Comprehensive search (cgi-bin, cgi directories and global filesystem) found no /cgi/softup handler. Missing critical evidence: a) File signature check implementation b) Firmware parsing logic c) Potential exploit paths. Therefore, unable to confirm actual vulnerability (e.g., code execution/bricking), vulnerability chain is incomplete and not directly triggerable.

### Verification Metrics
- **Verification Duration:** 461.50 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 361664

---

## weak-creds-ftp-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

### Original Information
- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Description:** The vsftpd REDACTED_PASSWORD_PLACEHOLDER file stores plaintext credentials in a custom format, containing three accounts with weak passwords (REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test). Attackers can launch brute-force attacks (e.g., using tools like hydra) via the FTP service and obtain valid credentials within seconds. Upon successful login: 1) Malicious files (e.g., webshells) can be uploaded to the server; 2) Sensitive files can be downloaded; 3) Higher privileges may be obtained if vsftpd is misconfigured. The trigger condition is that the FTP service is enabled and exposed to the network.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **Notes:** Association found: config-ftp-anonymous-default (located in etc/vsftpd.conf). Follow-up recommendations: 1) Check whether the /etc/vsftpd.conf configuration allows anonymous login or contains directory traversal vulnerabilities; 2) Verify if the FTP service is invoked through the web interface (such as PHP scripts in the www directory).

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** The verification conclusion is based on the following evidence: 1) The /etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER file is confirmed to exist and contains weak passwords such as REDACTED_PASSWORD_PLACEHOLDER:1234 (accurate); 2) The /etc/vsftpd.conf configuration has local_enable=YES and write_enable=YES (accurate). However, critical missing evidence includes: A) No FTP service startup mechanism was found (no startup commands in rcS/inetd.conf); B) The REDACTED_PASSWORD_PLACEHOLDER file loading method was not confirmed (no association found in binary/PAM). Since the prerequisite for vulnerability exploitation (FTP service running) has not been verified, this finding does not constitute an actual exploitable vulnerability.

### Verification Metrics
- **Verification Duration:** 721.86 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 497293

---

## firmware-burn-chain

### Original Information
- **File/Directory Path:** `web/main/softup.htm`
- **Location:** `softup.htm:JSHIDDEN`
- **Description:** Firmware flashing process exposes hazardous operation chain: 1) Frontend asynchronously calls /cgi/softburn via $.cgi 2) Flashing operation lacks secondary confirmation mechanism 3) IGD_DEV_INFO data structure exposes device details. If attackers combine file upload vulnerabilities to control flashing content, complete device hijacking is possible. Trigger conditions: tampering with filename parameter → bypassing frontend validation → exploiting /cgi/softup vulnerability to write malicious firmware → triggering /cgi/softburn execution.
- **Code Snippet:**
  ```
  $('#t_upgrade').click(function(){
    if($("#filename").val() == ""){
      $.alert(ERR_FIRM_FILE_NONE);
      return false;
    }
    // HIDDEN/cgi/softburn
  });
  ```
- **Notes:** Critical attack chain: filename→/cgi/softup→/cgi/softburn. Requires verification of burn signature check. Related: IGD_DEV_INFO device information leak (refer to device-info-leak) assists in constructing targeted malicious firmware.

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification results: 1) Frontend JS logic (softup.htm) confirms the existence of /cgi/softburn call and filename validation can be bypassed - matches the description. 2) REDACTED_PASSWORD_PLACEHOLDER attack chain components (/cgi/softup file upload and /cgi/softburn firmware execution) could not be verified due to missing program files. 3) IGD_DEV_INFO is only used to obtain version numbers on the frontend, with no evidence of complete data structure leakage. 4) Zero evidence proving the existence or absence of firmware signature verification mechanisms. Conclusion: The attack chain description is partially accurate (frontend logic), but due to missing core binary evidence, the complete vulnerability cannot be confirmed. Vulnerability triggering relies on unverified backend operations, thus it is not directly triggerable and does not constitute a verified vulnerability overall.

### Verification Metrics
- **Verification Duration:** 846.06 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 403650

---

## network_input-ethWan-ACT_OP_network_control

### Original Information
- **File/Directory Path:** `web/main/ethWan.htm`
- **Location:** `ethWan.htm (JavaScriptHIDDEN)`
- **Description:** ethWan.htm exposes high-risk network operation interfaces: contains 8 network control endpoints such as ACT_OP_DHCP_RELEASE/ACT_OP_PPP_DISCONN, invoked via $.act(). Contaminated parameters REDACTED_PASSWORD_PLACEHOLDER are directly transmitted through the wan_pppoelistarg object. Trigger conditions include: 1) User submits malicious parameters via form 2) Bypassed or flawed client-side validation 3) Lack of input filtering on the backend. Potential consequences: REDACTED_PASSWORD_PLACEHOLDER theft (via REDACTED_PASSWORD_PLACEHOLDER/pwd), network service disruption (via connection operations), MAC spoofing (via customMacAddr).
- **Notes:** Correlation Discovery: unified-act-framework-vuln (shared $.act framework), network_input-diagnostic_csrf (similar to unprotected ACT_OP operations). Pending verification: 1) Actual handler (CGI path) for $.act() requests not yet identified 2) Backend filtering mechanism for REDACTED_PASSWORD_PLACEHOLDER/pwd parameters not verified 3) Whether ACT_OP operations are subject to permission control not confirmed. Next steps: Analyze files handling ACT_OP requests under cgi-bin directory; Trace usage path of wan_pppoelistarg parameter in backend; Verify whether customMacAddr is directly written to network configuration.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 1) The code confirms the existence of 8 high-risk endpoints such as ACT_OP_DHCP_RELEASE (L126-164) which can be directly invoked via $.act().  
2) Parameters REDACTED_PASSWORD_PLACEHOLDER are indeed passed through the wan_pppoelistarg object (L43-45, 70).  
3) Client-side validation can be bypassed (e.g., by directly crafting requests to skip $.alert validation).  
4) No evidence of backend filtering exists, and the interface lacks CSRF protection (consistent with findings in related notes).  
Conditions met: Contaminated parameters directly passed + no effective server-side protection + ability to directly trigger network operations.

### Verification Metrics
- **Verification Duration:** 109.45 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 91105

---

## xss-parental-control-device-name

### Original Information
- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `www/parentCtrl.htm: REDACTED_PASSWORD_PLACEHOLDERHIDDEN, HIDDEN`
- **Description:** Stored XSS Vulnerability: In the `REDACTED_PASSWORD_PLACEHOLDER` and URL addition logic, user-controlled `deviceName`/`description`/`urlAddr` is directly inserted into the DOM via `innerHTML`. Attackers can inject malicious scripts by modifying device configurations (requiring low privileges), which trigger when administrators view the page. Trigger conditions: 1) Attackers can modify device names/URL lists (CSRF can bypass permissions); 2) Administrators access the parental control page. Actual impact: Full control over administrator sessions, enabling manipulation of all router functions.
- **Code Snippet:**
  ```
  $("#addUrl").append('<div ... value="' + allBlackUrl[blackIndex] + '" ...');
  ```
- **Notes:** The effectiveness of the $.isdomain filter needs to be verified; it is recommended to subsequently test the actual triggering of XSS and analyze the post-session hijacking operations.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Code analysis confirms: 1) User-controlled REDACTED_PASSWORD_PLACEHOLDER parameters are obtained via $("#deviceName").val() and $("#description").val() without HTML encoding or filtering 2) These parameters are directly inserted as HTML content into table cells ($.initTableBody function) 3) Attackers can inject malicious scripts through low-privilege device configuration interfaces 4) Scripts automatically execute when administrators view the parental control page (parentCtrl.htm). No protective measures are observed in the code, with a complete and direct vulnerability trigger path.

### Verification Metrics
- **Verification Duration:** 444.54 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 352546

---

## network_input-login_token_generation-1

### Original Information
- **File/Directory Path:** `web/frame/login.htm`
- **Location:** `web/frame/login.htm`
- **Description:** Network Input Authentication REDACTED_PASSWORD_PLACEHOLDER Generation and Storage Vulnerabilities:  
1) The client generates a 'Basic' authentication REDACTED_PASSWORD_PLACEHOLDER by Base64 encoding the plaintext REDACTED_PASSWORD_PLACEHOLDER, equivalent to plaintext transmission (Base64 is reversible).  
2) The REDACTED_PASSWORD_PLACEHOLDER is stored in a cookie without the HttpOnly attribute, posing an XSS theft risk.  
Trigger Conditions:  
a) The network is unencrypted when the user submits the login form.  
b) The presence of a cross-site scripting vulnerability allows cookie theft.  
Actual Impact: Attackers can intercept or steal the REDACTED_PASSWORD_PLACEHOLDER to directly gain authentication privileges.
- **Code Snippet:**
  ```
  auth = "Basic " + Base64Encoding($REDACTED_PASSWORD_PLACEHOLDER.value + ":" + $REDACTED_PASSWORD_PLACEHOLDER.value);
  document.cookie = "Authorization=" + auth;
  ```
- **Notes:** Verify whether the server enforces HTTPS transmission. Related clues: REDACTED_PASSWORD_PLACEHOLDER keywords appear in historical records, suggesting potential data flow correlation.

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The code evidence fully supports the findings described: 1) The REDACTED_PASSWORD_PLACEHOLDER generation logic of 'Basic ' + Base64Encoding(...) was confirmed in web/frame/login.htm, equivalent to transmitting credentials in plaintext 2) The document.cookie settings indeed lacked HttpOnly/Secure attributes 3) File scanning confirmed the absence of HTTPS enforcement mechanisms. This vulnerability is directly triggered during user login via the PCSubWin() function, allowing attackers to intercept tokens over unencrypted networks or directly obtain authentication privileges by stealing cookies through XSS, with no additional prerequisites required. A CVSS score of 8.5 is justified.

### Verification Metrics
- **Verification Duration:** 487.83 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 388790

---

## wds-bridge-xss-vector

### Original Information
- **File/Directory Path:** `web/main/sysconf.htm`
- **Location:** `web/sysconf.htm WDSHIDDEN`
- **Description:** The WDS bridge configuration submits parameters such as wdsSsid/wdsMac to the LAN_WLAN_WDSBRIDGE endpoint via wdsSave. The SSID field allows arbitrary input of up to 32 bytes (without XSS filtering), which may lead to stored XSS if the backend stores and renders this value. Trigger condition: an attacker submits an SSID field containing malicious scripts. MAC address validation only performs frontend $.mac() format checks, which can be bypassed.
- **Notes:** SSID can be used as a cross-site scripting attack vector, requiring verification of whether the management interface renders this value

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 1. Input validation findings accurate: SSID unfiltered/MAC only frontend-verified confirmed;  
2. Core vulnerability assumption invalid: Evidence shows SSID only injected into input's value attribute (XSS-safe context), no backend storage or dangerous rendering points found;  
3. No complete attack chain: Lacks XSS trigger path, risk should be downgraded to 0.  
Conclusion: Description partially accurate but doesn't constitute an actual vulnerability.

### Verification Metrics
- **Verification Duration:** 406.24 seconds
- **REDACTED_PASSWORD_PLACEHOLDER Usage:** 327641

---

