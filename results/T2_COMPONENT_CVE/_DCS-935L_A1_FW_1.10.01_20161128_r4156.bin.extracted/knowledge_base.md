# _DCS-935L_A1_FW_1.10.01_REDACTED_PASSWORD_PLACEHOLDER_r4156.bin.extracted (8 alerts)

---

### SBOM-uClibc-unknown

- **File/Directory Path:** `lib/libthread_db-0.9.30.3.so`
- **Location:** `libthread_db-0.9.30.3.so`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** uClibc component, version cannot be precisely determined, confirmed present through dynamic linker reference 'ld-uClibc.so.0' in file libthread_db-0.9.30.3.so. Associated critical CVEs: CVE-2017-9728 (regex out-of-bounds read, CVSS 9.8) and CVE-2022-29503 (thread allocation memory corruption, CVSS 9.8).
- **Code Snippet:**
  ```
  Dynamic linker reference found: 'ld-uClibc.so.0'
  ```
- **Keywords:** libthread_db-0.9.30.3.so, ld-uClibc.so.0, libc.so.0
- **Notes:** configuration_load

---
### SBOM-OpenSSL-1.0.1t

- **File/Directory Path:** `bin/stunnel-smtps-test`
- **Location:** `bin/stunnel-smtps-test:0 (strings output)`
- **Risk Score:** 8.2
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Found in strings output: 'OpenSSL 1.0.1t  3 May 2016'
  ```
- **Keywords:** OpenSSL, OpenSSL 1.0.1t, ELF, MIPS, uClibc
- **Notes:** configuration_load

---
### component-OpenSSL-1.0.1t

- **File/Directory Path:** `bin/stunnel-smtps`
- **Location:** `bin/stunnel-smtps:0 (strings output)`
- **Risk Score:** 8.2
- **Confidence:** 9.0
- **Description:** The third-party component OpenSSL 1.0.1t was found in the file 'bin/stunnel-smtps'. Version evidence comes from the binary strings: 'OpenSSL 1.0.1t  3 May 2016' and 'Compiled with OpenSSL 1.0.1t  3 May 2016'. This version contains multiple high-risk vulnerabilities:
- CVE-2016-2176 (CVSS 8.2): Buffer over-read in X509_NAME_oneline function
- CVE-2016-2105 (CVSS 7.5): Integer overflow in EVP_EncodeUpdate function
- CVE-2016-2106 (CVSS 7.5): Integer overflow in EVP_EncryptUpdate function
- CVE-2016-2109 (CVSS 7.5): Memory consumption in asn1_d2i_read_bio function
- CVE-2016-2107 (CVSS 5.9): Padding oracle attack in AES-NI implementation
It is recommended to upgrade to version 1.0.2h or higher.
- **Code Snippet:**
  ```
  OpenSSL 1.0.1t  3 May 2016
  Compiled with OpenSSL 1.0.1t  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.1t, X509_NAME_oneline, EVP_EncodeUpdate, EVP_EncryptUpdate, asn1_d2i_read_bio, AES-NI
- **Notes:** configuration_load

---
### thirdparty-openssl-1.0.1t

- **File/Directory Path:** `bin/stunnel`
- **Location:** `bin/stunnel`
- **Risk Score:** 8.2
- **Confidence:** 8.6
- **Description:** The file 'bin/stunnel' contains OpenSSL version 1.0.1t, which has multiple high-risk CVE vulnerabilities: CVE-2016-2176 (CVSS 8.2), CVE-2016-2105 (CVSS 7.5), CVE-2016-2106 (CVSS 7.5), CVE-2016-2109 (CVSS 7.5), CVE-2016-2107 (CVSS 5.9). These vulnerabilities affect versions prior to 1.0.1t. It is recommended to verify the exact patch status.
- **Code Snippet:**
  ```
  HIDDEN 'OpenSSL 1.0.1t  3 May 2016'
  ```
- **Keywords:** OpenSSL, 1.0.1t, CVE-2016-2176, CVE-2016-2105, CVE-2016-2106, CVE-2016-2109, CVE-2016-2107
- **Notes:** These vulnerabilities affect versions prior to 1.0.1t. It is recommended to verify the exact patch status.

---
### SBOM-OpenSSL-1.0.1t

- **File/Directory Path:** `bin/stunnel-smtps-snapshot`
- **Location:** `bin/stunnel-smtps-snapshot: strings output`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The binary file has been detected to contain OpenSSL component version 1.0.1t with multiple CVE vulnerabilities. Version string evidence shows: 'OpenSSL 1.0.1t  3 May 2016'. The existing vulnerabilities include:
- CVE-2016-2176 (CVSS 8.2): Buffer over-read vulnerability in the X509_NAME_oneline function
- CVE-2016-2105 (CVSS 7.5): Integer overflow vulnerability in the EVP_EncodeUpdate function
- CVE-2016-2106 (CVSS 7.5): Integer overflow vulnerability in the EVP_EncryptUpdate function
- CVE-2016-2109 (CVSS 7.5): Memory exhaustion vulnerability in the asn1_d2i_read_bio function
- CVE-2016-2107 (CVSS 5.9): Padding oracle attack vulnerability in the AES-NI implementation
- **Keywords:** OpenSSL 1.0.1t, X509_NAME_oneline, EVP_EncodeUpdate, EVP_EncryptUpdate, asn1_d2i_read_bio, AES-NI
- **Notes:** configuration_load

---
### SBOM-libcurl-7.37.0

- **File/Directory Path:** `lib/libcurl.so.4.3.0`
- **Location:** `lib/libcurl.so.4.3.0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The libcurl component was found in the file 'lib/libcurl.so.4.3.0', with version 7.37.0. Evidence source: The string 'libcurl/7.37.0' is directly present in the binary file. Known high-risk vulnerability: CVE-2015-3144 - The fix_hostname function fails to correctly calculate the index, allowing remote attackers to cause out-of-bounds read/write and crashes by providing a zero-length hostname.
- **Code Snippet:**
  ```
  libcurl/7.37.0
  ```
- **Keywords:** libcurl, CVE-2015-3144, libcurl.so.4.3.0
- **Notes:** It is recommended to upgrade libcurl to version 7.42.0 or later to fix CVE-2015-3144

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `lib/libcurl.so.4.3.0`
- **Location:** `lib/libcurl.so.4.3.0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The OpenSSL component was detected in the file 'lib/libcurl.so.4.3.0', with version 1.0.0. Evidence sources: dynamically linked libraries 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0', along with OpenSSL-related function calls. Known high-risk vulnerabilities: CVE-2014-0224 - allows man-in-the-middle attacks; CVE-2009-1379, CVE-2009-1387, CVE-2009-4355, CVE-2010-0742, CVE-2010-1633, CVE-2010-2939, CVE-2010-3864, CVE-2010-4180, CVE-2010-4252 - unspecified vulnerabilities.
- **Code Snippet:**
  ```
  libssl.so.1.0.0, libcrypto.so.1.0.0
  ```
- **Keywords:** OpenSSL, libssl.so.1.0.0, libcrypto.so.1.0.0, CVE-2014-0224
- **Notes:** It is recommended to upgrade OpenSSL to version 1.0.1 or higher to fix multiple known vulnerabilities. Further investigation is required for certain OpenSSL vulnerabilities to determine their exact impact. It is advisable to consult the NVD database for complete details of each CVE.

---
### thirdparty-curl-7.37.0

- **File/Directory Path:** `bin/curl`
- **Location:** `Found in strings output of bin/curl`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Evidence of curl version 7.37.0 was found in the 'bin/curl' file. This version contains a known critical vulnerability CVE-2015-3144, which may be triggered when parsing URLs with zero-length hostnames, leading to out-of-bounds read/write operations and potential system crashes.
- **Code Snippet:**
  ```
  curl 7.37.0 (mips-unknown-linux-gnu) %s
  ```
- **Keywords:** curl 7.37.0, CVE-2015-3144, fix_hostname
- **Notes:** The vulnerability affects curl versions 7.37.0 through 7.41.0. Although the impact of the vulnerability may extend beyond DoS attacks, its specific exploitability likely depends on how the binary is utilized within the firmware.

---
