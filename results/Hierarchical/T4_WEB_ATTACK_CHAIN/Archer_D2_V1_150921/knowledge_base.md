# Archer_D2_V1_150921 (3 alerts)

---

### web-http_libjs-script_injection

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The file 'lib.js' contains multiple functions (tpAjax, io, cgi, exe) that handle HTTP requests and process user input without proper sanitization. These functions can execute scripts from the response text when 'bScript' is true, equivalent to 'eval' in risk. This behavior allows arbitrary script execution if the response text is malicious. The vulnerability is triggered when: 1) The response text contains malicious scripts, and 2) 'bScript' is set to true. This could lead to remote code execution or session hijacking if an attacker controls the response text (e.g., via server compromise or MITM attacks).
- **Code Snippet:**
  ```
  var REDACTED_SECRET_KEY_PLACEHOLDER = function() {
      if (xhr.readyState == 4) {
          if (s.bScript)
              $.script(xhr.responseText);
          if (s.success)
              s.success(s.bScript ? 0 : xhr.responseText);
      }
  };
  ```
- **Keywords:** tpAjax, io, cgi, exe, XMLHttpRequest, eval, exec, script, responseText, bScript
- **Notes:** The functions should be modified to sanitize the response text before execution. Additionally, the use of 'bScript' should be reviewed to ensure it is only enabled when absolutely necessary and with trusted sources. Further analysis of the server-side components generating the responses is recommended to ensure they are not vulnerable to injection attacks.

---
### web-http_libjs-script_injection

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Location:** `lib.js`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The file 'lib.js' contains multiple functions (tpAjax, io, cgi, exe) that handle HTTP requests and process user input without proper sanitization. These functions can execute scripts from the response text when 'bScript' is true, equivalent to 'eval' in risk. This behavior allows arbitrary script execution if the response text is malicious. The vulnerability is triggered when: 1) The response text contains malicious scripts, and 2) 'bScript' is set to true. This could lead to remote code execution or session hijacking if an attacker controls the response text (e.g., via server compromise or MITM attacks).
- **Code Snippet:**
  ```
  var REDACTED_SECRET_KEY_PLACEHOLDER = function() {
      if (xhr.readyState == 4) {
          if (s.bScript)
              $.script(xhr.responseText);
          if (s.success)
              s.success(s.bScript ? 0 : xhr.responseText);
      }
  };
  ```
- **Keywords:** tpAjax, io, cgi, exe, XMLHttpRequest, eval, exec, script, responseText, bScript
- **Notes:** The functions should be modified to sanitize the response text before execution. Additionally, the use of 'bScript' should be reviewed to ensure it is only enabled when absolutely necessary and with trusted sources. Further analysis of the server-side components generating the responses is recommended to ensure they are not vulnerable to injection attacks.

---
### web-WANConfig-$.act()

- **File/Directory Path:** `web/main/wanBasic.htm`
- **Location:** `web/main/wanBasic.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** In the 'web/main/wanBasic.htm' file, a complex WAN configuration interface was discovered, which interacts with the backend through JavaScript's $.act() method. REDACTED_PASSWORD_PLACEHOLDER findings include: 1) All backend communication is performed using the $.act() method; 2) Handling multiple WAN connection types (PPPoE, static IP, etc.); 3) Processing sensitive data such as REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER. Although CGI paths are not directly exposed, there are potential security risks: user input is directly used for system configuration without sufficient validation.
- **Code Snippet:**
  ```
  N/A (JavaScript file)
  ```
- **Keywords:** $.act(), doSave(), WAN_PPP_CONN, WAN_IP_CONN, saveBtn, usrPPPoE, pwdPPPoE
- **Notes:** Further analysis is required: 1) The specific implementation of $.act(); 2) Whether backend interfaces have command injection risks; 3) Whether input validation is sufficient. It is recommended to examine how the relevant CGI scripts or binary files handle these requests.

---
