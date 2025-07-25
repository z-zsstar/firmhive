# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (3 alerts)

---

### vsftpd-3.0.2

- **File/Directory Path:** `bin/vsftpd`
- **Location:** `bin/vsftpd (HIDDEN 'vsftpd: version 3.0.2')`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The firmware was found to contain vsftpd version 3.0.2. This version has a known vulnerability (CVE-2015-1419), where remote attackers can bypass access restrictions via an unknown vector related to deny_file parsing.
- **Code Snippet:**
  ```
  vsftpd: version 3.0.2
  ```
- **Keywords:** vsftpd, 3.0.2, deny_file, tunable_deny_file
- **Notes:** It is recommended to upgrade to the latest version to mitigate known vulnerabilities.

---
### MiniUPnPd-1.4

- **File/Directory Path:** `bin/miniupnpd`
- **Location:** `bin/miniupnpd (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** MiniUPnPd version 1.4 was found in the firmware. This version has a known vulnerability (CVE-2013-0229) which may lead to denial of service attacks. The version information was extracted from the binary's strings.
- **Code Snippet:**
  ```
  FH1209/1.0.0.0 UPnP/1.0 MiniUPnPd/1.4
  ```
- **Keywords:** miniupnpd, MiniUPnPd/1.4, REDACTED_SECRET_KEY_PLACEHOLDER, minissdp.c
- **Notes:** Recommend upgrading to the latest version of MiniUPnPd to fix the known vulnerability. The binary is stripped, limiting further analysis.

---
### nginx-1.2.2

- **File/Directory Path:** `usr/bin/nginx`
- **Location:** `usr/bin/nginx (HIDDENstringsHIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** nginx version 1.2.2 was found in the firmware, compiled with gcc 4.5.3 (Buildroot 2012.02). This is an older version and may contain unpatched vulnerabilities not listed in the NVD. The binary is stripped, making analysis more difficult.
- **Code Snippet:**
  ```
  nginx/1.2.2 built by gcc 4.5.3 (Buildroot 2012.02)
  ```
- **Keywords:** nginx/1.2.2, built by gcc 4.5.3 (Buildroot 2012.02), stripped
- **Notes:** sbom

---
