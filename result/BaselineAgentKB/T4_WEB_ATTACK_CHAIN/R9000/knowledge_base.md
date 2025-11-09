# R9000 (2 alerts)

---

### web-RMT_invite-eval-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The RMT_invite.cgi script uses eval to process the output of proccgi, which may lead to command injection vulnerabilities. Attackers could potentially inject malicious commands through carefully crafted HTTP parameters.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ```
- **Keywords:** eval, proccgi, FORM_submit_flag, FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further analysis is needed to determine how proccgi processes input parameters in order to assess injection possibilities.

---
### web-RMT_invite-unvalidated-input

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:12,14`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** RMT_invite.cgi directly operates using unvalidated FORM variables (FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER), which could potentially be exploited for injection attacks.
- **Code Snippet:**
  ```
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"REDACTED_PASSWORD_PLACEHOLDER\":\"$FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER\"}"|REQUEST_METHOD=PUT PATH_REDACTED_PASSWORD_PLACEHOLDER /www/cgi-bin/readycloud_control.cgi > /dev/console &
  ```
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER, readycloud_control.cgi, nvram
- **Notes:** It is necessary to check how readycloud_control.cgi processes these inputs.

---
