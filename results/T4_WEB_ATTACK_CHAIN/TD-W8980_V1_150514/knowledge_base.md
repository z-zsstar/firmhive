# TD-W8980_V1_150514 (6 alerts)

---

### vulnerability-cgi-ansi-strcpy

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `0x004086e0`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** A high-risk strcpy vulnerability was identified in the '/cgi/ansi' handler function (0x004086e0). The function directly copies user-controllable data into a fixed-size stack buffer (sp+0x10) without length restriction checks, potentially leading to arbitrary code execution.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** strcpy, /cgi/ansi, 0x004086e0, sp+0x10
- **Notes:** Since the binary file has been stripped of its symbol table, some of the analysis is based on heuristic methods. It is recommended to validate these findings with dynamic analysis.

---
### xss-script-function-code-injection

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js:322-335`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The `$.script()` function poses a code injection risk. This function directly receives and executes incoming JavaScript code strings. If the parameters originate from unverified user input (such as HTTP parameters), it may lead to XSS attacks. The dangerous operation occurs when dynamically creating script tags and executing the incoming code. It is necessary to check whether all call points (e.g., lines 288, 375, 997) pass user input.
- **Code Snippet:**
  ```
  script: function(data) {
      if (data && /\S/.test(data)) {
          var script = $.d.createElement("script");
          script.type = "text/javascript";
          if (script.text === undefined)
              script.appendChild($.d.createTextNode(data));
          else
              script.text = data;
          $.head.insertBefore(script, $.head.firstChild);
          $.head.removeChild(script);
      }
  }
  ```
- **Keywords:** $.script, data, script, textContent, innerHTML
- **Notes:** Check all call points (e.g., lines 288, 375, 997) to verify whether user input is being passed

---
### web-cgi_target-setPwd

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `HIDDEN：/cgi/setPwd`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Confirmed that '/cgi/setPwd' is a backend CGI program requiring REDACTED_PASSWORD_PLACEHOLDER analysis. This program receives a Base64-encoded REDACTED_PASSWORD_PLACEHOLDER passed via URL parameters from the frontend 'setPwd.htm'. Further analysis is needed to determine whether this CGI program passes HTTP parameters to dangerous functions (such as system, strcpy, etc.).
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** /cgi/setPwd, pwd, Base64Encoding
- **Notes:** High-priority analysis objectives: 1) Examine how /cgi/setPwd handles the pwd parameter 2) Verify whether command injection or buffer overflow risks exist 3) Analyze the processing flow after REDACTED_PASSWORD_PLACEHOLDER decoding

---
### vulnerability-cgi-log-memcpy

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `0x00406ab0`
- **Risk Score:** 7.8
- **Confidence:** 7.25
- **Description:** Two unsafe memcpy calls (0x406aec and 0x406b20) were identified in the '/cgi/log' handler function. The function copies data from fixed addresses (0x41bed4 and 0x41af20) to stack buffers without proper bounds checking, potentially leading to buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** memcpy, /cgi/log, 0x406aec, 0x406b20, 0x41bed4, 0x41af20
- **Notes:** Since the binary file has its symbol table stripped, some analysis is based on heuristic methods. It is recommended to validate these findings with dynamic analysis.

---
### web-password_setting-http_parameter

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `setPwd.htmHIDDENdoSetPassword()HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A REDACTED_PASSWORD_PLACEHOLDER setting feature was discovered in the file 'setPwd.htm', which sends a POST request to '/cgi/setPwd' via XMLHttpRequest. The REDACTED_PASSWORD_PLACEHOLDER parameter 'pwd' is Base64-encoded and directly appended to the URL. This implementation presents the following security issues: 1) Passwords appear in plaintext (Base64-encoded) in URLs, potentially being recorded in browser history or proxy logs; 2) The absence of HTTPS makes the transmission vulnerable to eavesdropping; 3) Direct concatenation of user input into URLs may introduce injection risks.
- **Code Snippet:**
  ```
  xmlHttpObj.open("POST", "http://192.168.1.1/cgi/setPwd?pwd=" + Base64Encoding($("newPwd").value) , true);
  ```
- **Keywords:** setPassword(), doSetPassword(), Base64Encoding, newPwd, /cgi/setPwd, xmlHttpObj.open
- **Notes:** It is recommended to further analyze the /cgi/setPwd backend handler to confirm whether more severe security issues such as command injection exist. Additionally, it is advised to switch to using POST request bodies for transmitting sensitive data instead of URL parameters.

---
### vulnerability-cgi-softup-sprintf

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `0x4065f0`
- **Risk Score:** 7.0
- **Confidence:** 5.75
- **Description:** A sprintf format string vulnerability was identified in the '/cgi/softup' handler function (0x4065f0). This function uses a fixed format string without checking output length, potentially leading to stack buffer overflow. Attackers could potentially exploit this vulnerability by crafting a malicious Content-Length header.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** sprintf, /cgi/softup, 0x4065f0, Content-Length, sp+0x21c
- **Notes:** Since the binary file has been stripped of its symbol table, some analysis is based on heuristic methods. It is recommended to validate these findings with dynamic analysis.

---
