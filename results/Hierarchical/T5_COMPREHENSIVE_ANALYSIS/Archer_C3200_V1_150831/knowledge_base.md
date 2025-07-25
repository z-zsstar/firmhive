# Archer_C3200_V1_150831 (34 alerts)

---

### command_execution-telnetd-unauthenticated

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `rcS:62`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The telnetd service starts in no-parameter mode without authentication enabled. Trigger condition: Automatically executed during system startup. Security impact: Attackers can directly obtain device shell access via telnet (no credentials required), resulting in complete device compromise.
- **Code Snippet:**
  ```
  telnetd
  ```
- **Keywords:** telnetd
- **Notes:** Further analysis required: 1. Locate the telnetd binary path 2. Verify whether its default configuration enforces authentication

---
### firmware-burn-chain

- **File/Directory Path:** `web/main/softup.htm`
- **Location:** `softup.htm:JSHIDDEN`
- **Risk Score:** 9.5
- **Confidence:** 7.75
- **Description:** Firmware burning process exposes a dangerous operation chain: 1) Frontend asynchronously calls /cgi/softburn via $.cgi 2) No secondary confirmation mechanism for burning operation 3) IGD_DEV_INFO data structure exposes device details. If attackers combine file upload vulnerabilities to control burning content, complete device hijacking is possible. Trigger conditions: tampering with filename parameter → bypassing frontend validation → exploiting /cgi/softup vulnerability to write malicious firmware → triggering /cgi/softburn execution.
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
- **Keywords:** /cgi/softburn, $.cgi, IGD_DEV_INFO, ACT_GET
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER attack chain: filename→/cgi/softup→/cgi/softburn. Requires verification of burning signature check. Related: IGD_DEV_INFO device information leakage (see device-info-leak) assists in constructing targeted malicious firmware.

---
### weak-creds-ftp-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** The vsftpd REDACTED_PASSWORD_PLACEHOLDER file stores plaintext credentials in a custom format, containing three accounts with weak passwords (REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test). Attackers can brute-force the FTP service (e.g., using tools like Hydra) to obtain valid credentials within seconds. Upon successful login: 1) Malicious files (e.g., webshells) can be uploaded to the server; 2) Sensitive files can be downloaded; 3) Improper vsftpd configuration may grant elevated privileges. The trigger condition is the FTP service being enabled and exposed to the network.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, guest, test, FTPHIDDEN, ftp_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Correlation Discovery: config-ftp-anonymous-default (located in etc/vsftpd.conf). Follow-up Recommendations: 1) Check whether the /etc/vsftpd.conf configuration allows anonymous login or contains directory traversal vulnerabilities; 2) Verify if the FTP service is invoked through the web interface (e.g., PHP scripts in the www directory).

---
### file-permission-ftp-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `/etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 9.75
- **Description:** The vsftpd_REDACTED_PASSWORD_PLACEHOLDER file permissions set to 777 (rwxrwxrwx) result in:  
1) Any local user can read plaintext credentials (including weak passwords such as REDACTED_PASSWORD_PLACEHOLDER:1234).  
2) Attackers can write to the file to add malicious accounts (e.g., adding a UID=0 account).  
Trigger condition: An attacker gains a local low-privilege shell (achieved through other vulnerabilities).  
Security impact:  
1) REDACTED_PASSWORD_PLACEHOLDER leakage extends to the local attack surface.  
2) File writability enables privilege escalation.  
Exploitation chain: Low-privilege vulnerability → Read credentials → Log in to FTP → Upload webshell; or directly add a REDACTED_PASSWORD_PLACEHOLDER account.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, guest, test, FTPHIDDEN, file_permission
- **Notes:** Associate with existing weak REDACTED_PASSWORD_PLACEHOLDER records (weak-creds-ftp-vsftpd_REDACTED_PASSWORD_PLACEHOLDER). Verification required: 1) Whether vsftpd.conf enables this file 2) Whether other local vulnerabilities (such as command injection) exist that could trigger this file reading

---
### config-ftp-plaintext

- **File/Directory Path:** `etc/vsftpd.conf`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 9.0
- **Confidence:** 9.75
- **Description:** FTP service does not have SSL/TLS encryption enabled (ssl_enable parameter is missing in the configuration). Trigger condition: Any FTP network communication process. Security impact: All authentication credentials and file contents are transmitted in plaintext, allowing attackers to obtain legitimate user credentials through man-in-the-middle attacks. Exploitation method: Logging into the system after intercepting credentials via ARP spoofing or network sniffing.
- **Keywords:** ssl_enable
- **Notes:** It is necessary to analyze and verify whether other services such as HTTP/API depend on FTP credentials in conjunction with network services.

---
### unified-act-framework-vuln

- **File/Directory Path:** `web/main/sysconf.htm`
- **Location:** `webHIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 9.25
- **Description:** All configuration operations share the $.act(ACT_SET, <ENDPOINT>) framework pattern, making endpoints such as LAN_WLAN/DDOS_CFG/LED_NIGHTMODE a unified attack surface. No server-side request validation logic was observed, allowing attackers to potentially forge requests to modify configurations. REDACTED_PASSWORD_PLACEHOLDER risk: Parameters are directly mapped to system configurations without secondary server-side verification.
- **Keywords:** $.act, ACT_SET, LAN_WLAN, DDOS_CFG, LED_NIGHTMODE
- **Notes:** Core attack path: HTTP parameter → $.act → backend configuration processing. Related findings: cgi-handler-ssrf-potential (unverified ACT_CGI), api-firewall-rule-bypass (unverified ACT_SET), device-info-leak (unverified ACT_GET). Priority audit required for backend processing functions corresponding to each ENDPOINT.

---
### network_input-setPwd-password_cleartext

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `setPwd.htm:194-202`
- **Risk Score:** 9.0
- **Confidence:** 9.15
- **Description:** REDACTED_PASSWORD_PLACEHOLDER Transmission Security Vulnerability: The new REDACTED_PASSWORD_PLACEHOLDER set by the user is Base64-encoded on the client side and transmitted in plaintext via HTTP to the /cgi/setPwd endpoint (without HTTPS encryption). Trigger condition: When the user submits the REDACTED_PASSWORD_PLACEHOLDER form. Attackers can directly obtain the original REDACTED_PASSWORD_PLACEHOLDER after Base64 decoding through a man-in-the-middle attack. Constraints: Only affects communication environments where HTTPS is not enabled. Potential impact: Directly leads to REDACTED_PASSWORD_PLACEHOLDER leakage, with a high probability of successful attack.
- **Code Snippet:**
  ```
  var prePwd = REDACTED_SECRET_KEY_PLACEHOLDER(Base64Encoding($("newPwd").value));
  xmlHttpObj.open("POST", "http://" + window.location.hostname + "/cgi/setPwd?pwd=" + prePwd, true);
  xmlHttpObj.send(null);
  ```
- **Keywords:** doSetPassword, Base64Encoding, xmlHttpObj.open, /cgi/setPwd, prePwd, window.location.hostname
- **Notes:** Verify whether the server-side implementation of the /cgi/setPwd service performs secondary validation. Combined with the client-side validation bypass vulnerability (network_input-setPwd-client_validation_bypass), it can form a complete REDACTED_PASSWORD_PLACEHOLDER reset attack chain.

---
### untrusted-file-upload-softup

- **File/Directory Path:** `web/main/softup.htm`
- **Location:** `softup.htm:HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file upload functionality has user-controllable input points: 1) The HTML form parameter 'filename' accepts arbitrary file uploads to /cgi/softup. 2) The frontend only validates non-empty fields (ERR_FIRM_FILE_NONE) without boundary checks for file type/size/content. 3) Attackers can craft malicious firmware files to trigger backend vulnerabilities. Actual impact depends on /cgi/softup's handling of uploaded files: if file signatures are not verified or parsing vulnerabilities exist, it may lead to arbitrary code execution or device bricking.
- **Keywords:** filename, /cgi/softup, multipart/form-data, ERR_FIRM_FILE_NONE
- **Notes:** Analyze the processing logic of the /cgi/softup binary verification file

---
### http-request-injection

- **File/Directory Path:** `web/index.htm`
- **Location:** `www/js/lib.js:500`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** High-risk HTTP Request Injection Vulnerability: The `$.exe()` function fails to filter CR/LF characters when concatenating the `attrs` parameter, allowing attackers to inject arbitrary HTTP headers or request bodies via controllable `attrs` parameters. Trigger conditions: 1) Frontend calls `$.act()` with user-controlled `attrs` parameters (e.g., from URL parameters); 2) Parameter values contain `%0d%0a` sequences; 3) Triggering `$.exe()` to send requests. Actual impact: May bypass authentication to execute privileged operations (e.g., configuration tampering) or steal sessions.
- **Code Snippet:**
  ```
  data += "[...]" + index + "," + obj[6] + "\r\n" + obj[5];
  ```
- **Keywords:** $.exe, attrs, obj[5], data+=, \r\n, ACT_GET, ACT_SET
- **Notes:** Complete attack path: User input → $.act() call → $.exe() injection → Backend privileged operation

---
### api-firewall-rule-bypass

- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `www/parentCtrl.htm: doSaveHIDDEN, REDACTED_PASSWORD_PLACEHOLDERHIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 7.25
- **Description:** High-risk API call chain: Direct manipulation of core modules such as FIREWALL/EXTERNAL_HOST via $.act(ACT_SET), with parameters like internalHostRef lacking sufficient validation. Attackers can craft malicious requests by combining XSS or CSRF to: 1) Disable parental controls (enable=0) 2) Modify firewall rules. Trigger condition: Sending specially crafted AJAX requests to backend processing modules. Actual impact: Complete bypass of access controls, overriding system security policies.
- **Code Snippet:**
  ```
  $.act(ACT_SET, RULE, this.__stack, null, ["enable=0"]);
  ```
- **Keywords:** $.act, ACT_SET, FIREWALL, EXTERNAL_HOST, RULE, internalHostRef, __stack, REDACTED_SECRET_KEY_PLACEHOLDER, IGD_DEV_INFO
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER Clues: Trace the processing functions of the RULE/FIREWALL module; Verify the structure of the __stack parameter; Need to validate whether $.act(ACT_SET, FIREWALL) shares backend processing logic with the existing IGD_DEV_INFO implementation

---
### network_input-setPwd-client_validation_bypass

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `setPwd.htm:248-312`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Network Input Risk: Client-Side Validation Bypass - REDACTED_PASSWORD_PLACEHOLDER strength validation (checkPwd) and matching verification (PCSubWin) are only performed on the client side. Trigger Condition: An attacker can directly construct a POST request to the /cgi/setPwd endpoint. This allows bypassing REDACTED_PASSWORD_PLACEHOLDER length restrictions (1-15 characters), complexity requirements, and consistency checks to set any REDACTED_PASSWORD_PLACEHOLDER (including empty or excessively long passwords). Constraint: Requires the ability to send HTTP requests to the device. Potential Impact: Combined with missing server-side validation, this could enable REDACTED_PASSWORD_PLACEHOLDER reset attacks.
- **Code Snippet:**
  ```
  function PCSubWin() {
    if ($REDACTED_PASSWORD_PLACEHOLDER.value == "") { /* HIDDEN */ }
    if ($REDACTED_PASSWORD_PLACEHOLDER.value.length > 15) { /* HIDDEN */ }
    if ($confirm.value != $REDACTED_PASSWORD_PLACEHOLDER.value) { /* HIDDEN */ }
  }
  ```
- **Keywords:** checkPwd, PCSubWin, input-error, usrTips, pwdTips, $REDACTED_PASSWORD_PLACEHOLDER.value, $confirm.value
- **Notes:** Full utilization requires verification of the server-side logic for /cgi/setPwd. There is a potential for coordinated attacks with the plaintext REDACTED_PASSWORD_PLACEHOLDER transmission vulnerability (network_input-setPwd-password_cleartext).

---
### configuration-REDACTED_PASSWORD_PLACEHOLDER-account_misconfig

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 8.5
- **Confidence:** 8.65
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER.bak file contains high-risk account configurations:  
1) The REDACTED_PASSWORD_PLACEHOLDER account (UID=0) is configured with an interactive /bin/sh, allowing attackers to obtain a full REDACTED_PASSWORD_PLACEHOLDER shell upon gaining access to this account.  
2) The nobody account (UID=0), though locked, carries the risk of being activated.  
3) The home directories of both REDACTED_PASSWORD_PLACEHOLDER and nobody are set to the REDACTED_PASSWORD_PLACEHOLDER directory (/), violating the principle of least privilege. If combined with improper directory permission settings, this could lead to the exposure of sensitive files.  

Trigger condition: Attackers can execute arbitrary commands after obtaining REDACTED_PASSWORD_PLACEHOLDER credentials through weak REDACTED_PASSWORD_PLACEHOLDER brute-forcing, service vulnerabilities, or middleware vulnerabilities.  

Exploitation method: Log in to the REDACTED_PASSWORD_PLACEHOLDER account via remote services such as SSH/Telnet to directly obtain an interactive shell with REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, nobody, UID=0, GID=0, /bin/sh, HIDDEN=/
- **Notes:** Pending verification:  
1) REDACTED_PASSWORD_PLACEHOLDER strength of REDACTED_PASSWORD_PLACEHOLDER in REDACTED_PASSWORD_PLACEHOLDER  
2) Whether network services allow REDACTED_PASSWORD_PLACEHOLDER remote login  
3) REDACTED_PASSWORD_PLACEHOLDER directory permission settings (ls -ld /)

---
### network_input-ethWan-ACT_OP_network_control

- **File/Directory Path:** `web/main/ethWan.htm`
- **Location:** `ethWan.htm (JavaScriptHIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** ethWan.htm exposes high-risk network operation interfaces: contains 8 network control endpoints such as ACT_OP_DHCP_RELEASE/ACT_OP_PPP_DISCONN, invoked via $.act(). Contaminated parameters REDACTED_PASSWORD_PLACEHOLDER are directly passed through the wan_pppoelistarg object, triggered when: 1) users submit malicious parameters via forms 2) bypassing or flawed client-side validation 3) lack of input filtering on the backend. Potential consequences include: REDACTED_PASSWORD_PLACEHOLDER theft (via REDACTED_PASSWORD_PLACEHOLDER/pwd), network service disruption (via connection operations), MAC spoofing (via customMacAddr).
- **Keywords:** ACT_OP_DHCP_RELEASE, ACT_OP_PPP_DISCONN, wan_pppoelistarg, REDACTED_PASSWORD_PLACEHOLDER, pwd, customMacAddr, $.act
- **Notes:** Correlation Discovery: unified-act-framework-vuln (shared $.act framework), network_input-diagnostic_csrf (similar to unprotected ACT_OP operations). To be verified: 1) Actual handler (cgi path) for $.act() requests not yet identified 2) Backend filtering mechanism for REDACTED_PASSWORD_PLACEHOLDER/pwd parameters not verified 3) Whether ACT_OP operations are subject to permission control not confirmed. Next steps: Analyze files handling ACT_OP requests in the cgi-bin directory; Trace the usage path of wan_pppoelistarg parameter in the backend; Verify if customMacAddr is directly written to network configuration.

---
### network_input-login_token_generation-1

- **File/Directory Path:** `web/frame/login.htm`
- **Location:** `web/frame/login.htm`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Network Input Authentication REDACTED_PASSWORD_PLACEHOLDER Generation and Storage Vulnerabilities:  
1) The client generates a 'Basic' authentication REDACTED_PASSWORD_PLACEHOLDER by Base64 encoding the plaintext REDACTED_PASSWORD_PLACEHOLDER, which is equivalent to plaintext transmission (Base64 is reversible).  
2) The REDACTED_PASSWORD_PLACEHOLDER is stored in a cookie without the HttpOnly attribute, posing an XSS theft risk.  
Trigger Conditions:  
a) The network is unencrypted when the user submits the login form.  
b) The cookie can be stolen if a cross-site scripting vulnerability exists.  
Actual Impact: Attackers can intercept or steal the REDACTED_PASSWORD_PLACEHOLDER to directly gain authentication privileges.
- **Code Snippet:**
  ```
  auth = "Basic " + Base64Encoding($REDACTED_PASSWORD_PLACEHOLDER.value + ":" + $REDACTED_PASSWORD_PLACEHOLDER.value);
  document.cookie = "Authorization=" + auth;
  ```
- **Keywords:** Authorization, document.cookie, Base64Encoding, REDACTED_PASSWORD_PLACEHOLDER, PCSubWin
- **Notes:** Verify whether the server enforces HTTPS transmission. Related clues: REDACTED_PASSWORD_PLACEHOLDER keywords appear in the history, potentially indicating data flow correlation.

---
### xss-jquery_tpMsg-confirm

- **File/Directory Path:** `web/js/jquery.tpMsg.js`
- **Location:** `jquery.tpMsg.js: HIDDEN(confirm)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The DOM-based XSS vulnerability exists in the $.confirm() function. Attackers can inject malicious scripts (such as <img src=x onerror=alert(1)>) by controlling the str or replaceStr parameters. Trigger condition: When confirm() is called, tainted parameters are directly written into the DOM. The absence of any input filtering or boundary checking may lead to arbitrary script execution.
- **Code Snippet:**
  ```
  tmp.find("span.text").html(str);
  ```
- **Keywords:** confirm, str, replaceStr, tmp.find("span.text").html, html(), $.turnqss
- **Notes:** To verify the encoding effect of $.turnqss(), it is recommended to trace all confirm() call points to confirm whether the parameters originate from network input.

---
### xss-parental-control-device-name

- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `www/parentCtrl.htm: REDACTED_PASSWORD_PLACEHOLDERHIDDEN, HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Stored XSS Vulnerability: In the `REDACTED_PASSWORD_PLACEHOLDER` and URL addition logic, user-controlled `deviceName`/`description`/`urlAddr` are directly inserted into the DOM via `innerHTML`. Attackers can inject malicious scripts by modifying device configurations (requiring low privileges), which trigger when administrators view the page. Trigger conditions: 1) Attacker can modify device names/URL lists (CSRF could bypass permissions); 2) Administrator accesses the parental control page. Actual impact: Full control over administrator sessions, enabling manipulation of all router functions.
- **Code Snippet:**
  ```
  $("#addUrl").append('<div ... value="' + allBlackUrl[blackIndex] + '" ...');
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, innerHTML, entryName, description, urlAddr, $.initTableBody
- **Notes:** Verify the effectiveness of the $.isdomain filter; recommend subsequent testing for actual XSS triggering and analysis of post-session-hijacking operations.

---
### parameter-pollution-usb-mount

- **File/Directory Path:** `web/main/usbManage.htm`
- **Location:** `/www/usbManage.htm:488HIDDEN(REDACTED_SECRET_KEY_PLACEHOLDERHIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The USB device operation interface is vulnerable to parameter pollution. Specific manifestation: the fifth parameter 'command' in $.act() accepts user-controlled objects (including enable/force fields). Trigger condition: when calling functions like REDACTED_SECRET_KEY_PLACEHOLDER(). Constraint: physical device presence required but offline devices can be forcibly operated. Security impact: tampering with command.force=1 may cause abnormal mounting and filesystem corruption. Exploitation method: forging command={enable:1,force:1} parameters combined with CSRF.
- **Code Snippet:**
  ```
  $.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack, null, command);
  ```
- **Keywords:** command, command.enable, command.force, REDACTED_SECRET_KEY_PLACEHOLDER, USB_DEVICE, LOGICAL_VOLUME
- **Notes:** Track the usage of the command object in the backend. Associated file: /cgi-bin/usb_manage.cgi

---
### wifi-adv-param-injection

- **File/Directory Path:** `web/main/sysconf.htm`
- **Location:** `web/sysconf.htm JavaScriptHIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The wireless advanced configuration form collects parameters (such as beaconInterval/rts) through the wlAdvSave function and submits them via $.act(ACT_SET, LAN_WLAN). The frontend only validates numerical ranges (without filtering special characters), allowing attackers to craft malicious parameters to exploit backend vulnerabilities. Trigger condition: submitting an HTTP request to modify wireless configuration. The actual impact depends on the backend's handling of LAN_WLAN, potentially leading to command injection or buffer overflow.
- **Keywords:** wlAdvSave, beaconInterval, rts, frag, LAN_WLAN, ACT_SET, X_TP_BeaconInterval
- **Notes:** Critical taint parameters: beaconInterval/rts. Need to verify the LAN_WLAN processing function in the backend cgibin.

---
### configuration_load-rcS-global_writable_dirs

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `rcS:8-21,24`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** rcS creates 13 globally writable directories (0777 permissions), including sensitive locations such as /var/run and /var/tmp/dropbear. Trigger condition: Automatically executed during system startup. Security impact: Attackers can implant malicious files or tamper with runtime data like PIDs, potentially leading to privilege escalation (e.g., through symlink attacks or service configuration file tampering) when combined with service vulnerabilities.
- **Code Snippet:**
  ```
  /bin/mkdir -m 0777 -p /var/run
  /bin/mkdir -m 0777 -p /var/tmp/dropbear
  ```
- **Keywords:** mkdir, 0777, /var/run, /var/tmp/dropbear, /var/samba/private
- **Notes:** Follow-up analysis required: 1. Check whether services such as telnetd/cos/rttd are using these directories 2. Verify whether the directories are exposed to network services

---
### input-validation-command-injection

- **File/Directory Path:** `web/main/usbManage.htm`
- **Location:** `/www/usbManage.htm:1040(server_nameHIDDEN),1115(shareNameHIDDEN),1582(commandHIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Network input validation flaws may lead to injection attacks. Specific manifestations: 1) The server_name parameter only undergoes frontend validation for 15-character length and certain special characters; 2) The shareName parameter does not filter Shell metacharacters; 3) Hidden fields like command.force lack validation. Trigger condition: When submitting USB configuration forms. Constraints: Frontend uses regex filtering (/[\/:*?"<>|\[\]+ ]+/) but doesn't cover all dangerous characters. Security impact: Maliciously crafted shareName could trigger backend command injection. Exploitation method: Bypass filtering to inject characters like ;|$() for arbitrary command execution.
- **Code Snippet:**
  ```
  if ((/[\\\/:\*?"<>|\[\]\+ ]+/).test(newStr)) { $.alert(ERR_USB_INVALID_CHAR_IN_FOLDER_NAME); }
  ```
- **Keywords:** server_name, shareName, command.force, ERR_USB_INVALID_CHAR_IN_FOLDER_NAME, CMM_USB_SERVER_NAME_LENGTH
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER risk point: The command.force parameter is directly passed to the backend. Related file: /cgi-bin/usb_manage.cgi

---
### network_input-MiniDLNA-HIDDEN

- **File/Directory Path:** `etc/minidlna.conf`
- **Location:** `etc/minidlna.conf`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The MiniDLNA service is exposed on port 8200 (br0 interface) without access control. Attackers can exploit vulnerabilities by sending malicious DLNA requests over the network. If the service runs as REDACTED_PASSWORD_PLACEHOLDER (with the user configuration commented out), successful exploitation would grant complete control of the device. Verification is required to determine whether sbin/minidlnad contains vulnerabilities such as buffer overflows.
- **Code Snippet:**
  ```
  port=8200
  network_interface=br0
  #user=jmaggard
  ```
- **Keywords:** port=8200, network_interface=br0, #user
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER next step: Analyze the protocol parsing function in sbin/minidlnad

---
### csrf-factory-reset-chain

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `backNRestore.htm:38-53`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The factory reset function has a CSRF vulnerability: 1) The user clicks the 'Factory Restore' button to trigger the $.act(ACT_OP_FACTORY_RESET) operation. 2) Only a $.confirm dialog is used for user confirmation, with no session/cookie verification mechanism. 3) It shares the execution framework with ACT_OP_REBOOT. Upon successful reset, authentication credentials are cleared ($.deleteCookie("Authorization")) and a device reboot is immediately triggered. Trigger condition: An attacker induces an authenticated user to visit a malicious page. Actual impact: The device is restored to factory settings + forced reboot forms a dual denial-of-service attack chain, resulting in complete configuration loss and service interruption.
- **Code Snippet:**
  ```
  $("#resetBtn").click(function() {
      $.confirm(c_str.cdefaults, function() {
          $.act(ACT_OP, ACT_OP_FACTORY_RESET);
          $.exe(function(err) {
              if (!err) {
                  $.guage([...], function() {
                      window.location.reload();
                  });
              }
              $.act(ACT_OP, ACT_OP_REBOOT);
              $.exe(function(err) {
                  if (!err) $.deleteCookie("Authorization");
              }, true);
          });
      })
  });
  ```
- **Keywords:** ACT_OP_FACTORY_RESET, $.act, ACT_OP_REBOOT, $.deleteCookie, Authorization, resetBtn, ACT_REBOOT
- **Notes:** Vulnerability chain correlation: 1) Forms a continuous attack chain with the unauthorized reboot vulnerability (unauthorized-reboot) 2) Backend verification required: whether ACT_OP_FACTORY_RESET calls mtd erase 3) Device state after clearing authentication credentials

---
### config-ftp-unsafe-upload

- **File/Directory Path:** `etc/vsftpd.conf`
- **Location:** `etc/vsftpd.conf:0 (global) 0x0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The FTP service configuration allows authenticated users to upload files (write_enable=YES) but does not restrict file types or implement a security sandbox. Attackers with valid credentials can upload malicious files (e.g., webshells) via FTP. If the web service can access FTP directories, this creates an RCE attack chain. Trigger conditions: 1) Attackers obtain local user credentials (e.g., weak passwords) 2) The system runs a web service overlapping with FTP user directories. Constraints: The chroot_local_user configuration may restrict directory access, requiring verification of the actual directory structure.
- **Keywords:** write_enable, local_enable, chroot_local_user
- **Notes:** It is necessary to verify the risk of weak user passwords in conjunction with REDACTED_PASSWORD_PLACEHOLDER and check whether the /www directory overlaps with the FTP user directory.

---
### network_input-diagnostic_command_injection

- **File/Directory Path:** `web/main/diagnostic.htm`
- **Location:** `diagnostic.htm:80-230 (startDiag function)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The target address input ($("#l_addr")) is directly used to construct diagnostic requests (ipping.host/tracert.host) without format validation. Trigger condition: The user submits a diagnostic request with an address containing special characters. Security impact: If the backend directly concatenates system commands (e.g., ping/traceroute), it could lead to command injection. Exploitation method: Inject command separators (e.g., '; rm -rf /').
- **Code Snippet:**
  ```
  if ($("#l_addr").prop("value") == "") {...}
  ...
  ipping.host = $("#l_addr").prop("value");
  tracert.host = $("#l_addr").prop("value");
  ```
- **Keywords:** startDiag, $("#l_addr"), ipping.host, tracert.host, ACT_OP_IPPING, ACT_OP_TRACERT
- **Notes:** It is necessary to combine backend CGI to verify the command execution method. Related files: backend programs handling ACT_OP_IPPING/ACT_OP_TRACERT requests.

---
### device-info-leak

- **File/Directory Path:** `web/index.htm`
- **Location:** `www/frame/bot.htm:12`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Device Information Disclosure Vulnerability: bot.htm retrieves and displays hardware/software versions in plaintext via $.act(ACT_GET, IGD_DEV_INFO). Trigger Condition: Accessing any page containing this script (no authentication required). Security Impact: Exposes precise device versions, enabling attackers to match vulnerability exploitation chains.
- **Code Snippet:**
  ```
  var devInfo = $.act(ACT_GET, IGD_DEV_INFO...);
  $("#bot_sver").html(...devInfo.softwareVersion);
  ```
- **Keywords:** $.act, ACT_GET, IGD_DEV_INFO, devInfo.softwareVersion, #bot_sver

---
### csrf-missing-usb-operation

- **File/Directory Path:** `web/main/usbManage.htm`
- **Location:** `/www/usbManage.htm: HIDDEN [HIDDEN]`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The lack of CSRF protection in forms poses a risk of USB state tampering. Specific manifestation: All form operations trigger AJAX requests through $.loadMain/$.act without using CSRF tokens. Trigger condition: When users click the 'Save'/'Scan' buttons. Constraint: Requires a valid user session but lacks secondary verification. Security impact: Attackers can craft malicious pages to trick administrators into clicking, resulting in forced unmounting or mounting of USB devices. Exploitation method: Social engineering attacks + malicious HTML pages triggering $.act(ACT_SET, USB_DEVICE).
- **Keywords:** $.loadMain, $.act, ACT_SET, USB_DEVICE, handleUsb, mountUsb
- **Notes:** Verify whether the backend /cgi-bin/ related programs validate CSRF tokens. Associated file: /js/common.js (implements $.act)

---
### config-ftp-unsafe-upload

- **File/Directory Path:** `etc/vsftpd.conf`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Global write permissions enabled (write_enable=YES) with local user login activated (local_enable=YES). Trigger condition: when an attacker obtains valid credentials. Security impact: permits arbitrary file uploads, combined with chroot isolation (chroot_local_user=YES) but lacking an exception list, potentially enabling code execution by uploading malicious scripts to executable directories (e.g., /www).
- **Keywords:** write_enable, local_enable, chroot_local_user
- **Notes:** Update: Added analysis of the /www directory path; forms a complete attack chain with config-ftp-plaintext (REDACTED_PASSWORD_PLACEHOLDER interception → malicious file upload → code execution)

---
### network_input-diagnostic_csrf

- **File/Directory Path:** `web/main/diagnostic.htm`
- **Location:** `diagnostic.htm:112, 200`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** Sensitive endpoints (ACT_OP_IPPING/ACT_OP_TRACERT) are exposed via $.act() without CSRF protection. Trigger condition: Directly constructing malicious POST requests. Security impact: Bypassing frontend interface to execute unauthorized diagnostic operations. Exploitation method: Forging request packets to manipulate tracert/ipping object parameters.
- **Code Snippet:**
  ```
  $.act(ACT_OP, ACT_OP_IPPING);
  $.act(ACT_OP, ACT_OP_TRACERT);
  ```
- **Keywords:** $.act, ACT_OP, ACT_OP_IPPING, ACT_OP_TRACERT, IPPING_DIAG, TRACEROUTE_DIAG
- **Notes:** Verify backend authentication mechanism. Attack path starting point: network interface (HTTP POST)

---
### wds-bridge-xss-vector

- **File/Directory Path:** `web/main/sysconf.htm`
- **Location:** `web/sysconf.htm WDSHIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** The WDS bridge configuration submits parameters such as wdsSsid/wdsMac to the LAN_WLAN_WDSBRIDGE endpoint via wdsSave. The SSID field allows arbitrary input of up to 32 bytes (without XSS filtering), which may lead to stored XSS if the backend stores and renders this value. Trigger condition: an attacker submits an SSID field containing malicious scripts. MAC address validation only performs frontend format checking via $.mac(), which can be bypassed.
- **Keywords:** wdsSave, wdsSsid, wdsMac, LAN_WLAN_WDSBRIDGE, BridgeSSID, BridgeBSSID
- **Notes:** The SSID can serve as a cross-site scripting attack vector; it is necessary to check whether the management interface renders this value.

---
### cgi-handler-ssrf-potential

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `web/js/lib.js:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The file contains a CGI invocation mechanism (ACT_CGI) but does not define its specific implementation. User input obtained via $.io($.params) may be passed to the ACT_CGI operation, with no observed input validation logic. Potential risk: If the $.act function does not filter path parameters, attackers could craft malicious paths to perform server-side request forgery (SSRF). Trigger condition: Controlling the value of the $.params parameter. Associated attack chain: Combined with existing $.act implementations (e.g., device-info-leak), it could form a complete exploitation path of 'network input → ACT_CGI → backend CGI'.
- **Keywords:** ACT_CGI, $.act, $.io, $.params, /cgi/info, ACT_GET, ACT_OP
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER correlation points: 1) Shares the $.act mechanism with device-info-leak/unauthorized-reboot 2) The /cgi endpoint requires combined analysis with NVRAM recommendations from xss-potential-bothtm-version 3) Complete attack path: Contaminate $.params → Trigger ACT_CGI → SSRF

---
### format-string-httpd-0xb514

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0xb514 (fcn.0000b3b4)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the handling of HTTP 401 responses, a hardcoded JS template (0x10038) and unvalidated authentication attempts (uVar1) and ban duration (uVar7) are used to execute sprintf. Trigger conditions: 1) Accessing a restricted URL triggers an HTTP 401 status code. 2) The global structure (*0xb5ac)[0x10] is non-zero. Vulnerability manifestation: The template contains 4 placeholders but only 2 parameters are provided, leading to reading data outside the stack. Missing boundary checks: The target buffer of 512 bytes does not verify parameter count matching. Security impact: Attackers triggering 401 responses via unauthorized access may leak sensitive stack data (e.g., memory addresses), with no direct evidence of code execution. Exploit probability is moderate: Requires precise control of the global structure state.
- **Code Snippet:**
  ```
  sym.imp.sprintf(puVar9 + -0x480, *0xb5bc, uVar1, uVar7);  // *0xb5bc=0x10038
  ```
- **Keywords:** fcn.0000b3b4, sprintf, 0x10038, uVar1, uVar7, *0xb5ac, param_1=0x191, /userRpm/LoginRpm.htm
- **Notes:** Contradiction: The initial report requires the path to include '/frame', but the actual triggered path is a restricted URL. Dynamic testing recommendation: Verify memory leaks in 401 responses. Additional conclusion: This file shows no NVRAM/environment variable operations or command execution function calls.

---
### command_execution-telnetd-unauthenticated_start

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `rcS:62`
- **Risk Score:** 7.0
- **Confidence:** 9.5
- **Description:** The telnetd service is started without authentication parameters (command: 'telnetd'). Trigger condition: The rcS script is automatically executed during system startup. Constraint: Relies on the default authentication mechanism /bin/login. Security impact: If /bin/login contains hardcoded credentials or authentication logic vulnerabilities, attackers can directly gain system privileges through network access. Exploitation method: Attempt authentication bypass by remotely connecting to the telnet service.
- **Code Snippet:**
  ```
  telnetd
  ```
- **Keywords:** telnetd, rcS, /bin/login
- **Notes:** Related knowledge base record #telnetd. Requires further verification: 1) Reverse analysis of /bin/login 2) Testing default credentials (e.g., REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER)

---
### js-analysis-REDACTED_PASSWORD_PLACEHOLDER.js

- **File/Directory Path:** `web/js/str.js`
- **Location:** `web/js/str.js`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Due to limitations in tool capabilities, the content of the 'web/js/str.js' file cannot be retrieved, thus preventing code-level analysis. File reading tool support is required to verify the following potential risks: 1) Whether sensitive information leakage exists (such as hardcoded credentials); 2) Whether it contains unfiltered user input processing logic (e.g., eval()/innerHTML); 3) Whether dangerous API endpoints are exposed.
- **Keywords:** web/js/str.js, js_analysis
- **Notes:** It is recommended to add a file content reading tool in the future to support JS file analysis, with a focus on patterns such as DOM manipulation functions, network request handling, and hardcoded encryption keys.

---
### xss-jquery_tpMsg-alertAsnyc

- **File/Directory Path:** `web/js/jquery.tpMsg.js`
- **Location:** `jquery.tpMsg.js: jQuery.extend.alertAsnyc`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The multi-source pollution XSS vulnerability exists in the alertAsnyc() function. Script injection can be achieved by controlling the errno or str parameters. Trigger condition: When polluted data from errno/str is concatenated (m_str.errno + ":" + errno + "<br>" + str) and then written to the DOM via html(). Absence of security isolation measures allows combining multiple pollution sources to execute attacks.
- **Code Snippet:**
  ```
  tmp.find("span.text").css(...).html($.turnqss(m_str.errno + ":"+ errno + "<br>" + str));
  ```
- **Keywords:** alertAsnyc, errno, str, tmp.find("span.text").html, html(), $.turnqss, m_str.errno
- **Notes:** m_str.errno may originate from the language pack file, and if this file can be tampered with, it would expand the attack surface.

---
