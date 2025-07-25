# Archer_D2_V1_150921 (1 alerts)

---

### web-cgi-multiple_paths

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** Multiple CGI processing paths were discovered in the httpd binary, including '/cgi/conf.bin', '/cgi/confup', '/cgi/bnr', etc. These paths are registered via the fcn.REDACTED_PASSWORD_PLACEHOLDER function and handled by fcn.0040560c. Although no directly obvious dangerous function calls were identified, these CGI interfaces may process user input, posing potential security risks. Further dynamic analysis of these CGI interfaces is required to check for vulnerabilities such as command injection and path traversal. Special attention should be given to interfaces handling sensitive operations, such as '/cgi/setPwd' and '/cgi/auth'.
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.0040560c, /cgi/conf.bin, /cgi/confup, /cgi/bnr, /cgi/softup, /cgi/softburn, /cgi/log, /cgi/info, /cgi/lanMac, /cgi/auth, /cgi/setPwd, /cgi/pvc, /cgi/ansi
- **Notes:** Further dynamic analysis of these CGI interfaces is required to check for vulnerabilities such as command injection and path traversal. Special attention should be paid to interfaces handling sensitive operations, particularly /cgi/setPwd and /cgi/auth.

---
