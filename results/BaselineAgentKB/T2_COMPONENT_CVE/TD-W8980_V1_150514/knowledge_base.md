# TD-W8980_V1_150514 (4 alerts)

---

### openssl-0.9.7-cve-2003-0545

- **File/Directory Path:** `N/A`
- **Location:** `lib/libcrypto.so.0.9.7`
- **Risk Score:** 9.8
- **Confidence:** 5.0
- **Description:** OpenSSL 0.9.7 contains the CVE-2003-0545 vulnerability (CVSS 9.8), which allows remote attackers to cause a double-free condition via a specially crafted SSL client certificate, potentially leading to denial of service or arbitrary code execution.
- **Keywords:** OpenSSL, 0.9.7, CVE-2003-0545
- **Notes:** High-risk vulnerability, requires immediate attention

---
### openssl-0.9.7-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libcrypto.so.0.9.7`
- **Risk Score:** 9.0
- **Confidence:** 5.0
- **Description:** The detected OpenSSL library version is 0.9.7, which is a very old version and may contain multiple known vulnerabilities.
- **Keywords:** OpenSSL, 0.9.7
- **Notes:** Need to query the CVE database immediately

---
### openssl-0.9.7-cve-2004-0079

- **File/Directory Path:** `N/A`
- **Location:** `lib/libcrypto.so.0.9.7`
- **Risk Score:** 7.5
- **Confidence:** 5.0
- **Description:** OpenSSL 0.9.7 is affected by CVE-2004-0079 vulnerability (CVSS 7.5), which allows remote attackers to cause a NULL pointer dereference via a crafted SSL/TLS handshake, resulting in denial of service.
- **Keywords:** OpenSSL, 0.9.7, CVE-2004-0079
- **Notes:** medium and high-risk vulnerabilities

---
### busybox-1.19.2-version

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 7.0
- **Confidence:** 5.0
- **Description:** Confirmed BusyBox version is v1.19.2, compiled on 2015-05-11. This version may contain known vulnerabilities and requires further querying of the NVD database.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2
- **Notes:** Need to query the CVE database

---
