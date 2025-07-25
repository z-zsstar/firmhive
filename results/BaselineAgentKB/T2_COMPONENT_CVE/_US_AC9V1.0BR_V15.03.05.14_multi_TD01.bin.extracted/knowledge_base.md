# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (3 alerts)

---

### nginx-version

- **File/Directory Path:** `N/A`
- **Location:** `./usr/bin/nginx (version string)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Detected nginx version 1.2.2, compiled with gcc 4.5.3 (Buildroot 2012.02). This is the firmware's web server component.
- **Code Snippet:**
  ```
  nginx version: nginx/1.2.2
  built by gcc 4.5.3 (Buildroot 2012.02)
  ```
- **Keywords:** nginx, web server
- **Notes:** Version found via strings command output

---
### vsftpd-version

- **File/Directory Path:** `N/A`
- **Location:** `./bin/vsftpd (version string)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** network_input
- **Code Snippet:**
  ```
  vsftpd: version 3.0.2
  ```
- **Keywords:** vsftpd, FTP server
- **Notes:** Identify the version found through string command output

---
### busybox-version

- **File/Directory Path:** `N/A`
- **Location:** `./bin/busybox (version string)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** command_execution
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-11-13 22:58:50 CST)
  ```
- **Keywords:** busybox, multi-call binary
- **Notes:** The version discovered through the strings command output

---
