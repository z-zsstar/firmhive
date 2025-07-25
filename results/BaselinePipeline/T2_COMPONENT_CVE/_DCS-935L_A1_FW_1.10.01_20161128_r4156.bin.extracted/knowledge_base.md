# _DCS-935L_A1_FW_1.10.01_REDACTED_PASSWORD_PLACEHOLDER_r4156.bin.extracted (4 alerts)

---

### OpenSSL-1.0.1t

- **File/Directory Path:** `usr/lib/libssl.so.1.0.0`
- **Location:** `usr/lib/libssl.so.1.0.0`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** The version string 'OpenSSL 1.0.1t May 3, 2016' was found in usr/lib/libssl.so.1.0.0. This version contains multiple critical vulnerabilities, including CVE-2016-6304 (memory leak), CVE-2016-6303 (OCSP crash), and CVE-2016-6302 (memory allocation).
- **Code Snippet:**
  ```
  Version evidence from strings output: 'OpenSSL 1.0.1t 3 May 2016'
  ```
- **Keywords:** OpenSSL 1.0.1t, SSLv3_method, TLSv1_method, CVE-2016-6304, CVE-2016-6303, CVE-2016-6302
- **Notes:** library

---
### uClibc-0.9.33.2

- **File/Directory Path:** `/lib/ld-uClibc.so.0`
- **Location:** `/lib/ld-uClibc.so.0`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** Discovered in /lib/ld-uClibc.so.0 (linked by httpd-manager). This version contains multiple critical vulnerabilities, including CVE-2017-9728 (out-of-bounds read in get_subexp function) and CVE-2022-29503 (memory corruption in libpthread).
- **Code Snippet:**
  ```
  Version evidence from binary linking and strings output
  ```
- **Keywords:** uClibc, 0.9.33.2, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** library

---
### UPnP-1.0

- **File/Directory Path:** `usr/sbin/upnp`
- **Location:** `usr/sbin/upnp (0x0000c37c)`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** A service with the version string 'SERVER: Linux, UPnP/1.0 USB Server/1.0' was discovered in the /usr/sbin/upnp directory. This implementation may be vulnerable to multiple critical CVE vulnerabilities, including CVE-2019-14363 (buffer overflow) and CVE-2019-17621 (remote code execution).
- **Code Snippet:**
  ```
  Version evidence from string: 'SERVER: Linux, UPnP/1.0 USB Server/1.0'
  ```
- **Keywords:** UPnP, 1.0, CVE-2019-14363, CVE-2019-17621, CVE-2017-3882
- **Notes:** service

---
### libcurl-7.37.0

- **File/Directory Path:** `./lib/libcurl.so.4.3.0`
- **Location:** `./lib/libcurl.so.4.3.0`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The version string 'libcurl/7.37.0' was found in ./lib/libcurl.so.4.3.0. This version contains the CVE-2015-3144 vulnerability (hostname fix function flaw, potentially leading to out-of-bounds read/write).
- **Code Snippet:**
  ```
  Version evidence from strings output: 'libcurl/7.37.0'
  ```
- **Keywords:** libcurl.so.4.3.0, libcurl/7.37.0, fix_hostname, CVE-2015-3144
- **Notes:** library

---
