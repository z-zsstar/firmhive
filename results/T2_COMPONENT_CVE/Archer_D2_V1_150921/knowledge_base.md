# Archer_D2_V1_150921 (2 alerts)

---

### thirdparty-jQuery-1.8.3

- **File/Directory Path:** `web/js/jquery-1.8.3.min.js`
- **Location:** `web/js/jquery-1.8.3.min.js:1`
- **Risk Score:** 8.0
- **Confidence:** 8.45
- **Description:** The file 'web/js/jquery-1.8.3.min.js' contains the jQuery component and its version information, along with identified high-risk vulnerabilities. It is recommended to upgrade to jQuery 3.5.0 or later to address these vulnerabilities. These vulnerabilities can only be exploited if an attacker gains control over the HTML content passed to jQuery DOM manipulation methods.
- **Code Snippet:**
  ```
  /*! jQuery v1.8.3 jquery.com | jquery.org/license */
  ```
- **Keywords:** jQuery, 1.8.3, CVE-2020-11022, CVE-2020-11023, DOM manipulation
- **Notes:** Version evidence: web/js/jquery-1.8.3.min.js Line 1. High-risk vulnerabilities: CVE-2020-11022 (CVSS 6.9), CVE-2020-11023 (CVSS 6.9). Recommended to upgrade to jQuery 3.5.0 or later.

---
### component-vsftpd-version-unknown

- **File/Directory Path:** `etc/vsftpd.conf`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The file 'etc/vsftpd.conf' contains a TP-LINK customized FTP server configuration, but no explicit version information is included. The 'ftpd_banner' configuration item in the file displays 'Welcome to TP-LINK FTP server'. Multiple CVE vulnerabilities related to vsftpd were identified through searching the NVD database, but due to the lack of specific version information, it cannot be confirmed whether these vulnerabilities apply to the current system.
- **Keywords:** vsftpd.conf, ftpd_banner, TP-LINK FTP server
- **Notes:** It is recommended to further inspect other parts of the system (such as binary files or log files related to the FTP service) to obtain more accurate version information. The discovered relevant CVEs:
- CVE-2017-8218: vsftpd on TP-Link C2 and C20i devices through firmware 0.9.1 4.2 v0032.0 Build 160706 Rel.37961n has a backdoor REDACTED_PASSWORD_PLACEHOLDER account (CVSS: 9.8)
- CVE-2011-2523: vsftpd 2.3.4 contains a backdoor which opens a shell on port 6200/tcp (CVSS: 9.8)
- CVE-2021-30047: VSFTPD 3.0.3 allows DoS due to limited connections (CVSS: 7.5)

---
