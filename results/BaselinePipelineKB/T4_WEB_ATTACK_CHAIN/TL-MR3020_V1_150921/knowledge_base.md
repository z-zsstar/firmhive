# TL-MR3020_V1_150921 (3 alerts)

---

### vuln-httpd-goform_process-system

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x40d12c (fcn.0040d12c)`
- **Risk Score:** 9.5
- **Confidence:** 8.25
- **Description:** In function fcn.0040d12c, it was found that the POST parameters 'goformId' and 'lucknum' are directly used in system calls without validation, which may lead to command injection. This function processes the /goform/goform_process request. Trigger condition: Send a POST request to /goform/goform_process containing the goformId and lucknum parameters.
- **Code Snippet:**
  ```
  system(command); // commandHIDDENgoformIdHIDDENlucknum
  ```
- **Keywords:** fcn.0040d12c, system, goform_process, goformId, lucknum
- **Notes:** High-risk vulnerability, immediate remediation recommended

---
### vuln-httpd-login_asp-sprintf

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x40b8a4 (fcn.0040b8a4)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In function fcn.0040b8a4, unvalidated HTTP GET parameters are directly passed to the sprintf function, potentially leading to a format string vulnerability. This function processes the /login.asp request, where the 'user' and 'psw' parameters are used unfiltered to construct the response. Trigger condition: Access the /login.asp page and submit the user and psw parameters.
- **Code Snippet:**
  ```
  sprintf(buffer, "Welcome %s", user_input);
  ```
- **Keywords:** fcn.0040b8a4, sprintf, login.asp, user, psw
- **Notes:** Need to verify if the sprintf buffer size is sufficient

---
### vuln-httpd-dialup-fopen

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x40e740 (fcn.0040e740)`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** In function fcn.0040e740, it was found that the XML request parameter 'Action' is used directly for file operations without validation, which may lead to path traversal. This function processes the /api/dialup/dial request. Trigger condition: sending an XML request to /api/dialup/dial containing the Action parameter.
- **Code Snippet:**
  ```
  fopen(user_supplied_path, "r");
  ```
- **Keywords:** fcn.0040e740, fopen, dialup/dial, Action
- **Notes:** Check file path restrictions

---
