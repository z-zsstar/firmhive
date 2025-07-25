# R8000-V1.0.4.4_1.1.42 (2 alerts)

---

### wget-cve-2010-2252

- **File/Directory Path:** `N/A`
- **Location:** `bin/wget`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** GNU Wget 1.12 and earlier versions determine the target filename using the server-provided filename instead of the original URL, allowing remote servers to create/overwrite arbitrary files through carefully crafted redirects, potentially leading to arbitrary code execution.
- **Code Snippet:**
  ```
  GNU Wget 1.12
  ```
- **Keywords:** wget, 1.12, CVE-2010-2252, arbitrary file write
- **Notes:** binary

---
### wget-cve-2009-3490

- **File/Directory Path:** `N/A`
- **Location:** `bin/wget`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Versions of GNU Wget prior to 1.12 failed to properly handle domain names containing '\0' characters in the Common Name field of X.509 certificates, allowing remote man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate.
- **Code Snippet:**
  ```
  GNU Wget 1.12
  ```
- **Keywords:** wget, 1.12, CVE-2009-3490, SSL spoofing
- **Notes:** binary

---
