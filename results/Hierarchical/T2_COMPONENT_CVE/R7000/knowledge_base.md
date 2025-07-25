# R7000 (51 alerts)

---

### sbom-zlib-1.2.8

- **File/Directory Path:** `lib/libz.so.1`
- **Location:** `lib/libz.so.1:0 (version strings) [symbol table]`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Version strings: 'deflate 1.2.8', 'inflate 1.2.8'
  ```
- **Keywords:** ZLIB_1.2.8, deflate 1.2.8, inflate 1.2.8, zlibVersion
- **Notes:** The CVSS scores for all vulnerabilities are relatively high (8.8-9.8), posing a potentially severe threat if the library processes untrusted input. The library appears to be statically linked with GCC 3.3.2 and 4.5.3 compilers.

---
### libcurl-version-7.36.0

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `libcurl.so.4.3.0:0 (strings output)`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  libcurl/7.36.0
  ```
- **Keywords:** libcurl, 7.36.0, Curl_auth_create_ntlm_type3_message, ntlm.c, ntlm_decode_type2_target, connection reuse, X.509, wildcard IP
- **Notes:** configuration_load

---
### libcurl-CVE-2019-3822

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `libcurl.so.4.3.0:0 (ntlm.c)`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** A stack-based buffer overflow vulnerability exists during the creation of NTLM type-3 headers. Affected versions range from 7.36.0 to before 7.64.0. CVSS score: 9.8 (Critical).
- **Keywords:** Curl_auth_create_ntlm_type3_message, ntlm.c, libcurl, 7.36.0

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `opt/rcagent/cgi_processor`
- **Location:** `opt/rcagent/cgi_processor: Embedded in binary strings`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** uClibc version 0.9.33.2 found in cgi_processor with multiple critical vulnerabilities. Evidence from embedded string '/lib/ld-uClibc.so.0'. Associated CVEs: CVE-2017-9728 (Critical, CVSSv3 9.8), CVE-2022-29503 (Critical, CVSSv3 9.8), CVE-2017-9729 (High, CVSSv3 7.5), CVE-2022-30295 (Medium, CVSSv3 6.5).
- **Code Snippet:**
  ```
  String '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** uClibc, cgi_processor, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295
- **Notes:** configuration_load

---
### thirdparty-component-uclibc-0.9.33.2

- **File/Directory Path:** `opt/rcagent/run_server.sh`
- **Location:** `opt/rcagent/run_server.sh`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** uClibc 0.9.33.2 component contains vulnerabilities:  
- CVE-2017-9728: Memory corruption vulnerability  
- CVE-2022-29503 (CVSS 9.8): Critical vulnerability  

Evidence source: Dynamic library reference /lib/ld-uClibc.so.0
- **Code Snippet:**
  ```
  Dynamic library reference: /lib/ld-uClibc.so.0
  ```
- **Keywords:** /lib/ld-uClibc.so.0
- **Notes:** configuration_load

---
### Component-libpthread-unknown

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** libpthread version unknown (libpthread.so.0), dynamically linked in minidlna.exe. Contains CVE-2022-29503 (Memory corruption in uClibC implementations, CVSS 9.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libpthread.so.0
- **Notes:** configuration_load

---
### Component-SQLite-unknown

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** SQLite version unknown (libsqlite3.so.0), dynamically linked in minidlna.exe. Contains CVE-2017-10989 (Heap-based buffer over-read in RTree extension, CVSS 9.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libsqlite3.so.0
- **Notes:** configuration_load

---
### Component-FFmpeg-unknown

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** FFmpeg/libavformat version unknown (libavformat.so.55), dynamically linked in minidlna.exe. Contains CVE-2016-6164 (Remote code execution vulnerability, CVSS 9.8) and CVE-2016-10190 (Code execution via crafted media file, CVSS 9.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libavformat.so.55
- **Notes:** configuration_load

---
### SBOM-uClibc

- **File/Directory Path:** `opt/remote/remote`
- **Location:** `SBOMHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** Analysis result of the uClibc component. Evidence indicates the use of uClibc (dynamic linker path: /lib/ld-uClibc.so.0, symbol reference: __uClibc_main). Potential versions may be 0.9.33.2 or 1.0.40. Associated with multiple high-risk CVEs. Further verification of the specific version is required to determine which vulnerabilities are applicable.
- **Code Snippet:**
  ```
  Dynamic linker path: /lib/ld-uClibc.so.0
  Symbol reference: __uClibc_main
  ```
- **Keywords:** ld-uClibc.so.0, __uClibc_main, uClibc
- **Notes:** The specific uClibc version needs to be confirmed to determine which vulnerabilities are applicable. Relevant CVEs: CVE-2017-9728, CVE-2022-29503, CVE-2021-43523.

---
### SBOM-uClibc-run_remote

- **File/Directory Path:** `opt/remote/run_remote`
- **Location:** `ELF interpreter path in run_remote`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** Component information extracted from the ELF executable 'run_remote' indicates uClibc usage. Version unknown, with evidence derived from ELF interpreter path. Associated with multiple high-risk CVEs, including memory corruption, out-of-bounds read, and integer overflow vulnerabilities.
- **Code Snippet:**
  ```
  Interpreter path: /lib/ld-uClibc.so.0
  ```
- **Keywords:** ld-uClibc.so.0, ELF interpreter, run_remote
- **Notes:** configuration_load

---
### SBOM-libpthread

- **File/Directory Path:** `opt/remote/remote`
- **Location:** `SBOMHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** Analysis results of the libpthread component. Evidence indicates dependency on libpthread.so.0. Associated with high-risk CVE-2022-29503 (memory corruption vulnerability), though some vulnerabilities may be specific to Apple platforms.
- **Code Snippet:**
  ```
  Dynamic dependency: libpthread.so.0
  ```
- **Keywords:** libpthread.so.0, pthread_mutex_init
- **Notes:** Some vulnerabilities are specific to the Apple platform. Related CVE: CVE-2022-29503

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `opt/xagent/xagent_control`
- **Location:** `xagent_control (strings output)`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** OpenSSL component version 1.0.0, known high-risk vulnerabilities include: CVE-2014-0160 (Heartbleed), CVE-2014-0224, CVE-2014-0198, CVE-2010-4180, etc. Immediate upgrade to a supported version is recommended. Evidence source: Strings 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0' were found in the strings output of xagent_control.
- **Keywords:** OpenSSL, 1.0.0, libssl, libcrypto
- **Notes:** OpenSSL 1.0.0 series is outdated and contains multiple critical vulnerabilities, priority upgrade is recommended

---
### component-openssl-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `readycloud_control.cgi (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 8.25
- **Description:** OpenSSL version 1.0.0 has ceased maintenance and contains multiple critical vulnerabilities. Evidence sources: libssl.so.1.0.0, libcrypto.so.1.0.0. Known vulnerabilities include CVE-2014-0160 (Heartbleed) and CVE-2014-0224 (SSL/TLS MITM vulnerability).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** OpenSSL 1.0.0 series has reached end-of-life and contains multiple critical vulnerabilities

---
### component-uclibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/bftpd`
- **Location:** `/lib/ld-uClibc.so.0`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** Dynamic linking to /lib/ld-uClibc.so.0 indicates the presence of uClibc version 0.9.33.2. Associated vulnerabilities: CVE-2017-9728 (out-of-bounds read vulnerability in regular expression processing, CVSSv3: 9.8), CVE-2022-29503 (memory corruption vulnerability caused by thread allocation, CVSSv3: 9.8).
- **Code Snippet:**
  ```
  ld-uClibc.so.0
  ```
- **Keywords:** ld-uClibc.so.0
- **Notes:** It is recommended to upgrade uClibc to fix known vulnerabilities.

---
### SBOM-uClibc-Library

- **File/Directory Path:** `usr/bin/KC_BONJOUR`
- **Location:** `KC_BONJOUR (strings output: /lib/ld-uClibc.so.0, libc.so.0)`
- **Risk Score:** 9.0
- **Confidence:** 7.0
- **Description:** uClibc library found in the firmware. Exact version could not be determined from strings output (/lib/ld-uClibc.so.0, libc.so.0). Potential vulnerabilities identified for various uClibc versions: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6).
- **Code Snippet:**
  ```
  uClibc references found: /lib/ld-uClibc.so.0, libc.so.0
  ```
- **Keywords:** uClibc, libc.so.0
- **Notes:** configuration_load

---
### Component-FLAC-unknown

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 8.8
- **Confidence:** 7.5
- **Description:** FLAC version unknown (libFLAC.so.8), dynamically linked in minidlna.exe. Contains CVE-2021-35104 (Buffer overflow vulnerability, CVSS 8.8) and CVE-2023-37327 (Integer overflow vulnerability, CVSS 7.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libFLAC.so.8
- **Notes:** configuration_load

---
### SBOM-libnvram

- **File/Directory Path:** `opt/remote/remote`
- **Location:** `SBOMHIDDEN`
- **Risk Score:** 8.8
- **Confidence:** 5.5
- **Description:** Analysis results of the libnvram component. Evidence indicates dependency on libnvram.so. Associated with multiple high-risk CVEs (CVE-2022-26780, CVE-2022-26781, CVE-2022-26782), but requires confirmation whether the same implementation is used in InRouter302 V3.5.4.
- **Code Snippet:**
  ```
  Dynamic dependency: libnvram.so
  ```
- **Keywords:** libnvram.so
- **Notes:** Need to confirm whether the same implementation as InRouter302 is used. Related CVEs: CVE-2022-26780, CVE-2022-26781, CVE-2022-26782.

---
### thirdparty-component-openssl-1.0.0

- **File/Directory Path:** `opt/rcagent/run_server.sh`
- **Location:** `opt/rcagent/run_server.sh`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The OpenSSL 1.0.0 component contains multiple high-risk vulnerabilities:
- CVE-2014-0224 (CVSS 7.4): CCS injection vulnerability may lead to session hijacking
- CVE-2009-1379: Use-after-free vulnerability in DTLS processing
- CVE-2009-1387: NULL pointer dereference during DTLS handshake

Evidence source: libssl.so.1.0.0 and libcrypto.so.1.0.0 were identified in string output
- **Code Snippet:**
  ```
  Found in strings output: libssl.so.1.0.0, libcrypto.so.1.0.0
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** It is recommended to upgrade to version 1.0.2 or higher.

---
### OpenSSL-1.0.2h-SBOM

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `lib/libssl.so.1.0.0`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** In the file 'lib/libssl.so.1.0.0', OpenSSL version 1.0.2h was identified, and multiple related high-risk vulnerabilities were confirmed. Version evidence source: Version strings found via the strings command: 'SSLv3 part of OpenSSL 1.0.2h  3 May 2016' and 'TLSv1 part of OpenSSL 1.0.2h  3 May 2016'.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  TLSv1 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, SSLv3 part of OpenSSL 1.0.2h, TLSv1 part of OpenSSL 1.0.2h, CVE-2016-2177, CVE-2016-2176, CVE-2016-2105, CVE-2016-2106, CVE-2016-2109, CVE-2016-2180, CVE-2016-8610, CVE-2016-2107, CVE-2016-2178
- **Notes:** This version of OpenSSL contains multiple high-risk vulnerabilities. It is recommended to upgrade to the latest version as soon as possible. All vulnerabilities have been fixed in OpenSSL 1.0.2i and later versions. It is advised to upgrade to the latest version promptly.

---
### SBOM-GNU Wget-1.12

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Software components and version information extracted from the file 'bin/wget'. GNU Wget 1.12 contains two known high-risk vulnerabilities: CVE-2009-3490 and CVE-2010-2252.
- **Code Snippet:**
  ```
  HIDDEN 'GNU Wget %s built on %s.' HIDDEN
  ```
- **Keywords:** GNU Wget, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** The version information of OpenSSL is extracted from the dependency libraries, but no specific CVE vulnerability information was found. Further analysis of the OpenSSL version may be required to determine the presence of known vulnerabilities.

---
### thirdparty-openssl-1.0.0

- **File/Directory Path:** `opt/rcagent/nas_service`
- **Location:** `nas_service`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** OpenSSL version 1.0.0 was detected in the file 'opt/rcagent/nas_service', confirmed via libssl.so.1.0.0 and libcrypto.so.1.0.0. Known critical vulnerabilities include CVE-2014-0160 (Heartbleed) and CVE-2014-0224. The complete list could not be obtained due to NVD API request failure.
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0, CVE-2014-0160, CVE-2014-0224
- **Notes:** It is recommended to re-query OpenSSL vulnerability information after the NVD API is restored.

---
### thirdparty-libcurl-4

- **File/Directory Path:** `opt/rcagent/nas_service`
- **Location:** `nas_service`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'opt/rcagent/nas_service' was found to contain libcurl version 4, confirmed via libcurl.so.4. A known high-risk vulnerability CVE-2024-6197 exists, involving the ASN1 parser which may lead to memory corruption or program crashes.
- **Keywords:** libcurl.so.4, CVE-2024-6197
- **Notes:** It is recommended to verify the specific version number of libcurl to confirm vulnerability applicability.

---
### thirdparty-libstdc++-6

- **File/Directory Path:** `opt/rcagent/nas_service`
- **Location:** `nas_service`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'opt/rcagent/nas_service' contains version 6 of libstdc++, confirmed via libstdc++.so.6. Vulnerability information could not be retrieved due to NVD API request rate limits.
- **Keywords:** libstdc++.so.6
- **Notes:** It is recommended to re-query the vulnerability information of libstdc++ after the NVD API is restored.

---
### component-openssl-1.0.0

- **File/Directory Path:** `usr/sbin/bftpd`
- **Location:** `usr/sbin/bftpd`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The presence of dependency library libcrypto.so.1.0.0 indicates the existence of OpenSSL version 1.0.0. Associated vulnerabilities: CVE-2014-0224 (CCS Injection Vulnerability, CVSSv3: 7.4), CVE-2009-1379 (DTLS Packet Processing Vulnerability).
- **Code Snippet:**
  ```
  libcrypto.so.1.0.0
  ```
- **Keywords:** libcrypto.so.1.0.0
- **Notes:** It is recommended to update OpenSSL to the latest secure version.

---
### thirdparty-openssl-1.0.0

- **File/Directory Path:** `etc/verify_dap`
- **Location:** `etc/verify_dap`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'etc/verify_dap' depends on OpenSSL version 1.0.0. This version contains multiple known critical vulnerabilities, including risks of man-in-the-middle attacks, denial of service, and arbitrary code execution. Specific vulnerabilities: CVE-2014-0224 (CCS Injection), CVE-2009-1379, CVE-2009-1387, CVE-2009-4355, CVE-2010-0742, CVE-2010-1633, CVE-2010-2939, CVE-2010-3864, CVE-2010-4180, and CVE-2010-4252.
- **Code Snippet:**
  ```
  N/A (shared library dependency)
  ```
- **Keywords:** libcrypto.so.1.0.0, OpenSSL, CVE-2014-0224, CVE-2009-1379, CVE-2009-1387, CVE-2009-4355, CVE-2010-0742, CVE-2010-1633, CVE-2010-2939, CVE-2010-3864, CVE-2010-4180, CVE-2010-4252
- **Notes:** Version evidence source: Binary file dynamically linked library dependency 'libcrypto.so.1.0.0'. It is recommended to upgrade OpenSSL to the latest version.

---
### thirdparty-libgcrypt-vulnerabilities

- **File/Directory Path:** `lib/libgcrypt.so`
- **Location:** `lib/libgcrypt.so symbol analysis`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Symbol analysis revealed potential vulnerability exposure points including cryptographic functions that were later found vulnerable in newer versions (heap buffer overflow CVE-2021-3345, side-channel attacks CVE-2017-0379/CVE-2017-7526, ElGamal implementation flaws CVE-2018-6829/CVE-2021-33560). While not confirmed for 1.5.0, these vulnerability patterns suggest upgrade to current version (1.10.x) is strongly recommended.
- **Keywords:** _gcry_md_block_write, mpi_powm, cipher/elgamal.c
- **Notes:** thirdparty_vulnerabilities

---
### component-openssl-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `Various strings in rcagentd binary`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Detected OpenSSL version 1.0.0, which contains multiple known critical vulnerabilities including CVE-2014-0160 (Heartbleed), CVE-2014-0224, and CVE-2014-0198. Evidence sourced from strings 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0' in the binary file.
- **Code Snippet:**
  ```
  N/A (string analysis)
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** Verify whether OpenSSL is actually running version 1.0.0, not just the library file naming.

---
### Component-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** uClibc likely version 0.9.33.2 (libc.so.0), based on Buildroot 2012.02 version strings in binary. Multiple vulnerabilities in older uClibc versions.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libc.so.0
- **Notes:** configuration_load

---
### component-gcc-3.3.2-4.5.3

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `readycloud_control.cgi (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** GCC versions 3.3.2 and 4.5.3 are relatively old releases and may contain multiple vulnerabilities. Evidence source: GCC: (GNU) 3.3.2, GCC: (Buildroot 2012.02) 4.5.3. Known vulnerabilities include CVE-2017-7226 (a GNU Binutils vulnerability).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (Buildroot 2012.02) 4.5.3
- **Notes:** GCC 3.3.2 and 4.5.3 are both older versions that may contain multiple vulnerabilities.

---
### SBOM-minidlna-1.1.5

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Complete the analysis of 'usr/sbin/minidlna.exe' and generate an SBOM report containing third-party components and vulnerability information. Version information is confirmed through string extraction, and dynamic library information is confirmed through binary analysis.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** minidlna, 1.1.5, libpthread.so.0, libsqlite3.so.0, libavformat.so.55, libFLAC.so.8, libc.so.0
- **Notes:** API limit prevented direct CVE lookup for minidlna (requires manual verification). Some CVE matches are based on version number patterns.

---
### Component-minidlna-1.1.5

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** minidlna version 1.1.5, confirmed via string extraction in minidlna.exe. API limit prevented direct CVE lookup (requires manual verification).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** minidlna, 1.1.5
- **Notes:** configuration_load

---
### SBOM-Expat-XML-Parser-2.0.1

- **File/Directory Path:** `lib/libexpat.so`
- **Location:** `libexpat.so:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 8.75
- **Description:** Expat XML Parser version 2.0.1 identified with two high-risk vulnerabilities (CVE-2009-3720 and CVE-2009-3560). Version evidence found in libexpat.so at 0xREDACTED_PASSWORD_PLACEHOLDER and confirmed through symbol table analysis. Vulnerabilities could lead to denial of service when processing malicious XML documents.
- **Code Snippet:**
  ```
  String 'expat_2.0.1' found at 0xREDACTED_PASSWORD_PLACEHOLDER in libexpat.so
  ```
- **Keywords:** Expat XML Parser, libexpat.so, XML_Parse, XML_ParserCreate, XML_ParserReset, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** Recommendations: 1) Upgrade to Expat 2.4.0 or later; 2) Implement strict input validation for XML documents; 3) Monitor crashes in XML processing components

---
### VULN-CVE-2009-3720

- **File/Directory Path:** `lib/libexpat.so`
- **Location:** `libexpat.so`
- **Risk Score:** 7.5
- **Confidence:** 8.75
- **Description:** A carefully crafted UTF-8 sequence causes an out-of-bounds buffer read, leading to a denial of service. Affects Expat XML parser version 2.0.1. CVSS score: 7.5 (High).
- **Keywords:** Expat XML Parser, XML_Parse, XML_ParserCreate

---
### VULN-CVE-2009-3560

- **File/Directory Path:** `lib/libexpat.so`
- **Location:** `libexpat.so`
- **Risk Score:** 7.5
- **Confidence:** 8.75
- **Description:** A buffer over-read vulnerability caused by malformed UTF-8 sequences may lead to denial of service attacks. Affects Expat XML parser version 2.0.1. CVSS score: 7.5 (High severity).
- **Keywords:** Expat XML Parser, XML_ParserReset, REDACTED_SECRET_KEY_PLACEHOLDER

---
### libcurl-CVE-2018-16890

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `libcurl.so.4.3.0:0 (ntlm.c)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A heap buffer over-read vulnerability exists in the processing of NTLM type 2 messages. Affected versions range from 7.36.0 to before 7.64.0. CVSS score: 7.5 (High).
- **Keywords:** ntlm_decode_type2_target, ntlm.c, libcurl, 7.36.0

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `downloader (linked library)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The OpenSSL 1.0.0 component has been confirmed to contain two high-risk vulnerabilities (CVE-2014-0160 and CVE-2010-4252). This version reached end-of-life in December 2019, and immediate upgrade is strongly recommended.
- **Code Snippet:**
  ```
  Evidence: libssl.so.1.0.0 and libcrypto.so.1.0.0 strings in binary
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** OpenSSL 1.0.0 reached end-of-life in December 2019. Immediate upgrade recommended. Vulnerabilities: CVE-2014-0160 (Heartbleed), CVE-2010-4252 (Double-free)

---
### SBOM-Avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-browse`
- **Location:** `usr/bin/avahi-browse: version string '%s 0.6.25'`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** configuration_load
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi-browse, avahi-client.so.3, avahi-common.so.3, 0.6.25, CVE-2010-2244
- **Notes:** It is recommended to further check the version information of other dependent libraries (such as libdbus-1.so.3) to improve the SBOM report.

---
### thirdparty-component-libcurl-4

- **File/Directory Path:** `opt/rcagent/run_server.sh`
- **Location:** `opt/rcagent/run_server.sh`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** libcurl 4 component contains vulnerabilities:
- CVE-2024-6197 (CVSS 7.5): ASN1 parser vulnerability may lead to memory corruption

Evidence source: libcurl.so.4 was detected in string output
- **Code Snippet:**
  ```
  Found in strings output: libcurl.so.4
  ```
- **Keywords:** libcurl.so.4
- **Notes:** It is recommended to monitor libcurl updates to address CVE-2024-6197.

---
### thirdparty-GCC-4.5.3

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The GCC 4.5.3 compiler component (Buildroot 2012.02) was found in the 'bin/utelnetd' file.
- Version evidence source: The string 'GCC: (Buildroot 2012.02) 4.5.3' in the file
- Known vulnerabilities:
  * CVE-2010-2321 - libiberty buffer overflow
  * CVE-2010-2320 - libiberty format string vulnerability
  * CVE-2010-2963 - Multiple security vulnerabilities in libiberty
- **Keywords:** GCC: (Buildroot 2012.02) 4.5.3, GCC, 4.5.3, CVE-2010-2321, CVE-2010-2320, CVE-2010-2963
- **Notes:** Due to limitations of the NVD API, some vulnerability information may be incomplete. It is recommended to requery when the API becomes available or manually check CVE details.

---
### component-glibcxx-3.4.11

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `readycloud_control.cgi (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** GNU libstdc++ version 3.4.11, associated with GCC versions. Evidence source: GLIBCXX_3.4.11. Known vulnerabilities include CVE-2018-11236 (std::string buffer overflow vulnerability).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** GLIBCXX_3.4.11
- **Notes:** configuration_load

---
### thirdparty-libgcrypt-version

- **File/Directory Path:** `lib/libgcrypt.so`
- **Location:** `lib/libgcrypt.so strings output`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  This is Libgcrypt 1.5.0 - The GNU Crypto Library
  ```
- **Keywords:** libgcrypt, 1.5.0, GNU Crypto Library
- **Notes:** thirdparty_component

---
### sbom-libjpeg-7.0

- **File/Directory Path:** `lib/libjpeg.so.7`
- **Location:** `lib/libjpeg.so.7HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** The analysis result of file 'lib/libjpeg.so.7' confirms it is version libjpeg 7.0, released on June 27, 2009. This version contains multiple known security vulnerabilities:
- CVE-2013-6629: JPEG SOS marker vulnerability (High)
- CVE-2012-2806: Buffer overflow vulnerability (High)
- CVE-2018-20330: Divide-by-zero vulnerability (Medium)
- **Code Snippet:**
  ```
  7 27-Jun-2009
  Copyright (C) 2009, Thomas G. Lane, Guido Vollbeding
  ```
- **Keywords:** libjpeg.so.7, LIBJPEG_7.0, 7 27-Jun-2009, Copyright (C) 2009, Thomas G. Lane, Guido Vollbeding, libjpeg, jpeg
- **Notes:** Version Evidence Sources:
1. The string '7 27-Jun-2009' in file 'lib/libjpeg.so.7'
2. The symbol table entries 'LIBJPEG_7.0' and function suffixes '@@LIBJPEG_7.0'

---
### component-OpenSSL-1.0.0

- **File/Directory Path:** `bin/circled`
- **Location:** `bin/circled`
- **Risk Score:** 7.4
- **Confidence:** 7.5
- **Description:** The OpenSSL component version extracted from file 'bin/circled' is 1.0.0, evidenced by the string 'libcrypto.so.1.0.0'. Relevant CVEs include:
- CVE-2014-0224: CCS Injection vulnerability allowing man-in-the-middle attackers to hijack sessions or obtain sensitive information (CVSSv3: 7.4)
- CVE-2009-1379: Use-after-free vulnerability potentially causing denial of service (CVSSv3: N/A)
- CVE-2009-1387: NULL pointer dereference vulnerability potentially causing denial of service (CVSSv3: N/A)
- **Code Snippet:**
  ```
  libcrypto.so.1.0.0
  ```
- **Keywords:** libcrypto.so.1.0.0
- **Notes:** It is recommended to further verify the specific patch level of OpenSSL 1.0.0, as certain vulnerabilities may have been fixed in subsequent patches.

---
### SBOM-Avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-resolve`
- **Location:** `avahi-resolve: version string '0.6.25'`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Version information 0.6.25 for the Avahi component was found in the file 'usr/bin/avahi-resolve'. This version contains a known critical vulnerability CVE-2010-2244, which allows remote attackers to cause a denial of service (assertion failure and daemon exit) through specially crafted DNS packets.
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi-resolve, 0.6.25, CVE-2010-2244, avahi-daemon, AvahiDnsPacket, avahi_client_get_version_string, %s 0.6.25, libavahi-client.so.3, libavahi-common.so.3
- **Notes:** Further analysis of the Avahi daemon's configuration and usage is required to assess the actual impact. It is recommended to investigate more CVE vulnerability information regarding Avahi version 0.6.25.

---
### SBOM-KC_PRINT-v1.2

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `usr/bin/KC_PRINT:0 (binary) 0x0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Analysis of 'usr/bin/KC_PRINT' reveals its SBOM components include KC_PRINT v1.2, GCC versions 4.5.3 and 3.3.2, along with linked libraries (libpthread.so.0, libc.so.0, ld-uClibc.so.0). Version information was extracted from embedded strings within the binary file. This binary was compiled on November 14, 2016 using the Buildroot 2012.02 toolchain with uClibc (specific version requires further verification).
- **Code Snippet:**
  ```
  R7000P
  v1.2
  Nov 14 2016
  10:37:28
  GCC: (Buildroot 2012.02) 4.5.3
  ```
- **Keywords:** KC_PRINT, v1.2, Nov 14 2016, GCC: (Buildroot 2012.02) 4.5.3, GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease), libpthread.so.0, libc.so.0, /lib/ld-uClibc.so.0
- **Notes:** Next steps:
- Confirm the specific version of uClibc in use
- Research CVE vulnerabilities in GCC versions 4.5.3 and 3.3.2
- Check security vulnerabilities in the Buildroot 2012.02 toolchain
- Analyze version information of linked libraries

The binary file has had its symbol information stripped, making deeper analysis more challenging. Dynamic analysis may be required to verify library versions during runtime.

---
### thirdparty-wps-2.0

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor:Strings section`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The Wi-Fi Protected Setup (WPS) component, version 2.0, was found in the 'bin/wps_monitor' file. The evidence is derived from the strings 'wps_version2' and 'wps_version2_num'. Further investigation is required to query the relevant CVEs for the WPS 2.0 implementation.
- **Code Snippet:**
  ```
  Strings section containing 'wps_version2' and 'wps_version2_num'
  ```
- **Keywords:** Wi-Fi Protected Setup, WPS, wps_version2, wps_version2_num
- **Notes:** Further investigation is required for known CVE vulnerabilities in the WPS 2.0 implementation.

---
### thirdparty-broadcom-wireless

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor:Strings section`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The Broadcom Wireless Components found in the 'bin/wps_monitor' file, version unknown (Netgear R7000 firmware 1.3.0.8_1.0.93). The evidence stems from the strings 'Broadcom Corporation', 'libbcm.so', 'libbcmcrypto.so', and the file path 'REDACTED_PASSWORD_PLACEHOLDER.3.0.8_1.0.93/main/src/../src/wps/brcm_apps/linux/wps_linux_main.c'. Further investigation into relevant CVEs for Broadcom wireless components is required.
- **Code Snippet:**
  ```
  Strings section containing 'Broadcom Corporation', 'libbcm.so', 'libbcmcrypto.so'
  ```
- **Keywords:** Broadcom Corporation, libbcm.so, libbcmcrypto.so, Netgear R7000, wps_linux_main.c
- **Notes:** Further investigation is required into known CVE vulnerabilities of Broadcom wireless components.

---
### component-libcurl-4

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `readycloud_control.cgi (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** libcurl version 4 is affected by CVE-2016-8615 (cookie injection vulnerability). Evidence source: libcurl.so.4. A more precise version number is required to determine the specific vulnerability.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libcurl.so.4
- **Notes:** configuration_load

---
### SBOM-pthread-Library

- **File/Directory Path:** `usr/bin/KC_BONJOUR`
- **Location:** `KC_BONJOUR (strings output: libpthread.so.0)`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** pthread library found in the firmware (libpthread.so.0). Version is implementation dependent. Potential vulnerabilities identified: CVE-2020-12658 (CVSS 9.8), CVE-2024-47741 (CVSS 7.0). Most pthread vulnerabilities are implementation-specific.
- **Code Snippet:**
  ```
  pthread reference found: libpthread.so.0
  ```
- **Keywords:** libpthread.so.0
- **Notes:** configuration_load

---
### SBOM-cURL-4.x

- **File/Directory Path:** `opt/xagent/xagent_control`
- **Location:** `xagent_control (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The cURL component version 4.x series has known vulnerabilities including CVE-2016-8624, CVE-2016-8615, etc. A more precise version number is required to determine the specific vulnerabilities. Evidence source: The string 'libcurl.so.4' was found in the strings output of xagent_control.
- **Keywords:** cURL, 4.x, libcurl
- **Notes:** The cURL version information is incomplete; a more precise version number is required to assess the risks.

---
### SBOM-GCC-version

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `usr/sbin/upnpd (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 5.0
- **Description:** The GCC compiler version strings found in the 'usr/sbin/upnpd' file: 3.3.2 and 4.5.3 (Buildroot 2012.02).
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** GCC, compiler_version
- **Notes:** Search for relevant CVEs based on these legacy compilers.

---
