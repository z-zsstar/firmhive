# R7500 (106 alerts)

---

### component-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libuClibc-0.9.33.2.so`
- **Location:** `lib/libuClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** uClibc version 0.9.33.2 with NPTL support. This version has four critical vulnerabilities associated with it.
- **Code Snippet:**
  ```
  Embedded string 'NPTL 0.9.33'
  ```
- **Keywords:** libuClibc-0.9.33.2.so, NPTL 0.9.33, uClibc, 0.9.33.2, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295, get_subexp, regexec.c
- **Notes:** configuration_load

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** uClibc version 0.9.33.2 identified with multiple critical vulnerabilities. Evidence found in lib/ld-uClibc-0.9.33.2.so filename and internal strings. Vulnerabilities include:
- CVE-2017-9728: Out-of-bounds read in regex processing (CVSS 9.8)
- CVE-2022-29503: Memory corruption in libpthread (CVSS 9.8)
- CVE-2017-9729: Stack exhaustion in regex processing (CVSS 7.5)
- CVE-2022-30295: Predictable DNS transaction IDs (CVSS 6.5)
- **Code Snippet:**
  ```
  N/A (version identified through filename and strings)
  ```
- **Keywords:** ld-uClibc.so.0, libc.so.0
- **Notes:** configuration_load

---
### component-hostapd-version

- **File/Directory Path:** `usr/sbin/hostapd`
- **Location:** `usr/sbin/hostapd:0`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** The hostapd component information found in the /usr/sbin/hostapd file indicates version v2.2-devel. This version may be affected by multiple high-risk CVEs, including CVE-2022-23303 (score 9.8) and CVE-2022-23304 (score 9.8). The version information is directly derived from the string 'hostapd v2.2-devel' within the file content.
- **Keywords:** hostapd, v2.2-devel, CVE-2022-23303, CVE-2022-23304, CVE-2019-9497
- **Notes:** configuration_load

Since v2.2-devel is a development version, it is recommended to check specific code commit times for more accurate vulnerability impact assessment. At least 8 high-risk CVEs may affect this version. Dynamic dependency analysis failed - please provide correct file paths or change the working directory.

---
### SBOM-uClibc-consolidated

- **File/Directory Path:** `usr/sbin/athdiag`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** Comprehensive analysis confirms the uClibc C standard library (libc.so.0) version as 0.9.33.2, containing multiple critical vulnerabilities:
1. CVE-2017-9728: Out-of-bounds read vulnerability in regular expression processing (CVSS 9.8)
2. CVE-2022-29503: Memory corruption vulnerability in libpthread linuxthreads functionality (CVSS 9.8)
3. CVE-2017-9729: Stack exhaustion vulnerability in regular expression processing (CVSS 7.5)
4. CVE-2022-30295: DNS cache poisoning vulnerability due to predictable DNS transaction IDs (CVSS 6.5)

Version information is confirmed based on the /lib/ld-uClibc-0.9.33.2.so filename and internal version strings.
- **Code Snippet:**
  ```
  uClibc 0.9.33.2 (from strings output)
  ```
- **Keywords:** libc.so.0, ld-uClibc.so.0, uClibc, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295
- **Notes:** SBOM

---
### SBOM-uClibc-dynamic-linker-consolidated

- **File/Directory Path:** `usr/sbin/athdiag`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** Comprehensive analysis confirms that the uClibc dynamic linker (ld-uClibc.so.0) version 0.9.33.2 contains multiple critical vulnerabilities:
1. CVE-2017-9728: Out-of-bounds read vulnerability in regular expression processing (CVSS 9.8)
2. CVE-2022-29503: Memory corruption vulnerability in libpthread linuxthreads functionality (CVSS 9.8)
3. CVE-2017-9729: Stack exhaustion vulnerability in regular expression processing (CVSS 7.5)
4. CVE-2022-30295: DNS cache poisoning vulnerability due to predictable DNS transaction IDs (CVSS 6.5)

Version information was confirmed based on the /lib/ld-uClibc-0.9.33.2.so filename and internal version strings.
- **Code Snippet:**
  ```
  uClibc 0.9.33.2 (from strings output)
  ```
- **Keywords:** ld-uClibc.so.0, uClibc, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295
- **Notes:** SBOM

---
### SBOM-uClibc-libc.so.0

- **File/Directory Path:** `usr/sbin/remote_fsize`
- **Location:** `usr/sbin/remote_fsize`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** Analysis results of the uClibc component. Confirmed version: 0.9.33.2, evidence sources: filename of lib/ld-uClibc-0.9.33.2.so and internal version string confirmation, as well as usr/sbin/aclctl referencing the specific version file through shared library link /lib/ld-uClibc.so.0. Associated vulnerabilities: CVE-2017-9728 (out-of-bounds read vulnerability in regex processing, CVSS 9.8), CVE-2022-29503 (memory corruption vulnerability in libpthread linuxthreads functionality, CVSS 9.8), CVE-2017-9729 (stack exhaustion vulnerability in regex processing, CVSS 7.5), CVE-2022-30295 (DNS cache poisoning vulnerability due to predictable DNS transaction IDs, CVSS 8.1). Prioritize patching these critical vulnerabilities.
- **Keywords:** libc.so.0, ld-uClibc.so.0, ld-uClibc-0.9.33.2.so
- **Notes:** These vulnerabilities affect uClibc version 0.9.33.2, and it is recommended to prioritize their remediation. The version information has been confirmed through multiple sources with high credibility.

---
### SBOM-uClibc-0.9.33.2-Consolidated

- **File/Directory Path:** `usr/sbin/radvdump`
- **Location:** `Multiple locations: lib/ld-uClibc-0.9.33.2.so, usr/sbin/radvdump, etc.`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** SBOM
- **Code Snippet:**
  ```
  uClibc 0.9.33.2 (from strings output)
  ```
- **Keywords:** uClibc, ld-uClibc-0.9.33.2.so, libc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295, CVE-2021-43523
- **Notes:** SBOM

---
### vulnerability-CVE-2017-9728

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** An out-of-bounds read vulnerability exists in the get_subexp function of the misc/regex/regexec.c file when processing specially crafted regular expressions.
- **Keywords:** uClibc, get_subexp, regexec.c
- **Notes:** Affects uClibc version 0.9.33.2

---
### vulnerability-CVE-2022-29503

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** Memory corruption vulnerability in the libpthread linuxthreads functionality. Thread allocation may lead to memory corruption.
- **Keywords:** uClibc, libpthread, linuxthreads
- **Notes:** Affects uClibc version 0.9.33.2

---
### SBOM-uClibc-link

- **File/Directory Path:** `usr/sbin/ozker`
- **Location:** `readelfHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** The binary file dynamically links to libc.so.0 with an unknown version. Known critical vulnerabilities include: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libc.so.0
- **Notes:** It is recommended to prioritize updating the uClibc component due to the presence of multiple critical vulnerabilities.

---
### component-OpenVPN-2.3.2

- **File/Directory Path:** `usr/sbin/build-inter`
- **Location:** `./pkitool:HIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** OpenVPN component detected, version 2.3.2. Contains critical vulnerability CVE-2017-12166 (buffer overflow vulnerability, CVSS 9.8), which may be triggered when using REDACTED_PASSWORD_PLACEHOLDER-method 1 and could lead to code execution. Recommended to upgrade to OpenVPN 2.3.3 or later.
- **Code Snippet:**
  ```
  OpenVPN -- An application to securely tunnel IP networks
               over a single TCP/UDP port, with support for SSL/TLS-based
               session authentication and REDACTED_PASSWORD_PLACEHOLDER exchange,
               packet encryption, packet authentication, and
               packet compression.
    Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
  ```
- **Keywords:** pkitool, OpenVPN, build-inter
- **Notes:** OpenVPN 2.3.2 contains a critical buffer overflow vulnerability (CVE-2017-12166), immediate upgrade is strongly recommended.

---
### component-uClibc-version

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Keywords:** ld-uClibc-0.9.33.2.so, ld.so-1.7.0, uClibc, get_subexp, check_dst_limits_calc_pos_1, libpthread
- **Notes:** configuration_load

---
### thirdparty-component-uClibc-updated

- **File/Directory Path:** `usr/sbin/athstats`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Verify the uClibc version as 0.9.33.2 by checking the filename /lib/ld-uClibc-0.9.33.2.so and internal version string. This version contains multiple critical vulnerabilities:
1. CVE-2017-9728: Out-of-bounds read vulnerability in regular expression processing
2. CVE-2022-29503: Memory corruption vulnerability in libpthread linuxthreads functionality
3. CVE-2017-9729: Stack exhaustion vulnerability in regular expression processing
4. CVE-2022-30295: DNS cache poisoning vulnerability due to predictable DNS transaction IDs
- **Keywords:** libgcc_s.so.1, libc.so.0, /lib/ld-uClibc.so.0, ELF32, ARM, uClibc, ld-uClibc-0.9.33.2.so
- **Notes:** Version evidence source: /lib/ld-uClibc-0.9.33.2.so file name and internal version strings. It is recommended to prioritize fixing high-risk vulnerabilities.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/aclctl`
- **Location:** `lib/ld-uClibc-0.9.33.2.so (linked to usr/sbin/aclctl)`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** uClibc version 0.9.33.2 identified through filename and internal version strings in 'lib/ld-uClibc-0.9.33.2.so'. This version is linked to 'usr/sbin/aclctl' through the shared library reference '/lib/ld-uClibc.so.0'. Several high-severity CVEs affect this version of uClibc.
- **Keywords:** ld-uClibc-0.9.33.2.so, ld-uClibc.so.0, libc.so.0, uClibc, aclctl
- **Notes:** Version evidence: filename 'ld-uClibc-0.9.33.2.so' and internal version strings. Linked to aclctl through shared library reference. Note possible version mixing with 'ld.so-1.7.0' reference.

---
### sbom-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/sb_set_priority`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The uClibc component version 0.9.33.2 found in the firmware contains known critical vulnerabilities. Evidence source: Filename and embedded strings in the lib/ld-uClibc-0.9.33.2.so file confirm the version. Related CVEs: CVE-2017-9728 (CVSS 9.8, out-of-bounds read vulnerability in regexec.c), CVE-2022-29503 (CVSS 9.8, memory corruption vulnerability in libpthread linuxthreads functionality).
- **Code Snippet:**
  ```
  Filename and embedded strings confirm version 0.9.33.2
  ```
- **Keywords:** ld-uClibc.so.0, __uClibc_main
- **Notes:** Although these version details were not directly extracted from the 'usr/sbin/sb_set_priority' file, the component versions were confirmed through firmware-wide analysis. It is recommended to further verify the actual runtime versions of these components to ensure accuracy.

---
### third-party-component-uClibc

- **File/Directory Path:** `usr/sbin/iwspy`
- **Location:** `usr/sbin/iwspy`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** uClibc component found in 'usr/sbin/iwspy'. Multiple CVEs identified (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523, etc.) covering memory corruption, DoS, and information disclosure. Exact version not explicitly stated.
- **Code Snippet:**
  ```
  Found in string: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** ld-uClibc.so.0, uClibc
- **Notes:** configuration_load

---
### SBOM-libcurl-link

- **File/Directory Path:** `usr/sbin/ozker`
- **Location:** `readelfHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** The binary file dynamically links to libcurl.so.4 with an unknown version. Known critical vulnerabilities include: CVE-2016-7134 (CVSS 9.8), CVE-2016-7167 (CVSS 9.8), CVE-2017-8816 (CVSS 9.8), CVE-2017-8817 (CVSS 9.8), CVE-2017-1000257 (CVSS 9.1).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libcurl.so.4
- **Notes:** It is recommended to check the /lib or /usr/lib directories of the firmware for the actual shared library files.

---
### SBOM-libavformat-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `Strings output ('libavformat.so.54', 'LIBAVFORMAT_54')`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** libavformat version 54.x with critical vulnerabilities: CVE-2016-10190 (Heap-based buffer overflow), CVE-2016-6164 (Integer overflow).
- **Code Snippet:**
  ```
  libavformat.so.54
  ```
- **Keywords:** libavformat, FFmpeg, media_parsing
- **Notes:** configuration_load

---
### thirdparty-component-uClibc

- **File/Directory Path:** `usr/sbin/fw-checking`
- **Location:** `Dynamic section of fw-checking`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  Linked library: libc.so.0 and /lib/ld-uClibc.so.0
  ```
- **Keywords:** libc.so.0, ld-uClibc.so.0, uClibc, fw-checking
- **Notes:** thirdparty_component

---
### SBOM-ozker-poll_set_priority

- **File/Directory Path:** `usr/sbin/poll_set_priority`
- **Location:** `/cgi-bin/ozker/api/nodes`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** Analysis revealed the presence of the ozker component in the path '/cgi-bin/ozker/api/nodes', with an unknown version. This component contains a critical command injection vulnerability (CVE-2017-15226, CVSS score 9.8). Due to improper handling of the beginIndex and endIndex parameters, command injection can be achieved through popen calls.
- **Code Snippet:**
  ```
  Found in path /cgi-bin/ozker/api/nodes
  ```
- **Keywords:** ozker, popen
- **Notes:** command_execution

---
### SBOM-FastCGI-link

- **File/Directory Path:** `usr/sbin/ozker`
- **Location:** `readelfHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** The binary file dynamically links to libfcgi.so.0 and contains multiple FCGX API calls, with an unknown version. Known critical vulnerabilities include: CVE-2018-5347 (CVSS 9.8), CVE-2010-3872 (CVSS 7.5).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libfcgi.so.0, FCGX_InitRequest, FCGX_Accept_r
- **Notes:** It is recommended to contact the supplier for accurate version information.

---
### SBOM-uClibc-poll_set_priority

- **File/Directory Path:** `usr/sbin/poll_set_priority`
- **Location:** `usr/sbin/poll_set_priority (dynamic section)`
- **Risk Score:** 9.8
- **Confidence:** 7.75
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Found in dynamic section of poll_set_priority binary
  ```
- **Keywords:** libc.so.0, ld-uClibc.so.0
- **Notes:** configuration_load

---
### sbom-component-libjson.so.0

- **File/Directory Path:** `bin/ubus`
- **Location:** `bin/ubus`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The dependent component libjson.so.0 (possibly the json-c library) was identified during analysis of the 'bin/ubus' file. Dependency was confirmed via the 'readelf -d ubus' command, but version information could not be determined. Known vulnerabilities: CVE-2021-32292 (CVSSv3: 9.8) - stack buffer overflow, CVE-2020-12762 (CVSSv3: 7.8) - integer overflow and out-of-bounds write, CVE-2013-6370 - buffer overflow, CVE-2013-6371 - denial of service. It is strongly recommended to verify the specific version of libjson.so.0 to confirm vulnerability applicability.
- **Keywords:** libjson.so.0, json-c, ubus
- **Notes:** It is strongly recommended to verify the specific version of libjson.so.0 to confirm vulnerability applicability.

---
### SBOM-uClibc-component

- **File/Directory Path:** `usr/sbin/nandtest`
- **Location:** `usr/sbin/nandtest (linked dependency)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** configuration_load
- **Keywords:** uClibc, ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** The exact version of uClibc could not be determined from the binary strings alone. Further investigation of the actual library files in the firmware would be needed for precise version identification.

---
### SBOM-uClibc-internet

- **File/Directory Path:** `usr/sbin/internet`
- **Location:** `usr/sbin/internet:0x000000f4 (HIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The uClibc component was found referenced in the file 'usr/sbin/internet', with an unknown version (referenced as /lib/ld-uClibc.so.0). Three critical vulnerabilities were identified:  
1. CVE-2017-9728: Out-of-bounds read vulnerability when processing crafted regular expressions (risk score 9.8)  
2. CVE-2022-29503: Memory corruption vulnerability in the libpthread linuxthreads functionality (risk score 9.8)  
3. CVE-2021-43523: Incorrect handling of special characters returned by DNS servers, potentially leading to domain hijacking or remote code execution (risk score 9.6)  

Further analysis of library files in the firmware filesystem is required to obtain precise version information.
- **Code Snippet:**
  ```
  HIDDEN: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** uClibc, /lib/ld-uClibc.so.0
- **Notes:** 1. Further analysis of library files in the firmware filesystem is required to obtain the exact version information of uClibc.  
2. Due to incomplete version information, the applicability of certain vulnerabilities needs additional verification.

---
### SBOM-uClibc-unknown

- **File/Directory Path:** `usr/sbin/athssd`
- **Location:** `usr/sbin/athssd:0 (Embedded in binary strings)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The version information of the third-party component uClibc is unknown, evidenced by the string output '/lib/ld-uClibc.so.0'. Multiple high-risk CVE vulnerabilities were detected: CVE-2017-9728 (CVSSv3 9.8), CVE-2022-29503 (CVSSv3 9.8), CVE-2021-43523 (CVSSv3 8.1).
- **Code Snippet:**
  ```
  Found in strings output: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** ld-uClibc.so.0
- **Notes:** configuration_load

---
### SBOM-hiredis-link

- **File/Directory Path:** `usr/sbin/ozker`
- **Location:** `readelfHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 7.25
- **Description:** The binary file dynamically links to libhiredis.so.0.10, with a potential version of 0.10 (requires verification). Known critical vulnerabilities include: CVE-2023-31654 (CVSS 9.8), CVE-2021-32765 (CVSS 8.8), CVE-2020-7105 (CVSS 7.5).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libhiredis.so.0.10
- **Notes:** The version information requires further verification.

---
### vulnerability-CVE-2020-28951

- **File/Directory Path:** `lib/libuci.so`
- **Location:** `lib/libuci.so`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** libuci in OpenWrt versions prior to 18.06.9 and 19.x versions before 19.07.5 may contain a use-after-free vulnerability.
- **Keywords:** libuci.so, CVE-2020-28951
- **Notes:** CVSS score 9.8, critical vulnerability

---
### SBOM-SQLite-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `Strings output ('SQLite library is old. Please use version 3.5.1 or newer')`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** SQLite library with version requirement ≥3.5.1. Potential vulnerability to CVE-2017-10989 (Heap-based buffer over-read).
- **Code Snippet:**
  ```
  SQLite library is old. Please use version 3.5.1 or newer
  ```
- **Keywords:** SQLite, database
- **Notes:** configuration_load

---
### sbom-uclibc-cve-2017-9728

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 9.8
- **Confidence:** 5.5
- **Description:** CVE-2017-9728 (CVSS 9.8): Out-of-bounds read vulnerability in the get_subexp function of uClibc. Affected versions: 0.9.33.2.
- **Keywords:** libc.so.0, uClibc, CVE-2017-9728
- **Notes:** Potential vulnerability if uClibc version matches affected versions.

---
### sbom-uclibc-cve-2022-29503

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 9.8
- **Confidence:** 5.5
- **Description:** CVE-2022-29503 (CVSS 9.8): Memory corruption in libpthread linuxthreads in uClibc. Affected versions: 0.9.33.2, 1.0.40.
- **Keywords:** libc.so.0, uClibc, CVE-2022-29503
- **Notes:** configuration_load

---
### thirdparty-component-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/wpc`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 5.0
- **Description:** The third-party component uClibc, version 0.9.33.2, was found in the file 'usr/sbin/wpc'. This version contains multiple high-risk vulnerabilities, and it is recommended to upgrade to the latest version. Other dependent libraries (librt.so.0, libm.so.0, libgcc_s.so.1, libc.so.0) require the complete firmware directory structure to proceed with further analysis.
- **Keywords:** ld-uClibc.so.0, uClibc, 0.9.33.2, lib/ld-uClibc-0.9.33.2.so
- **Notes:** Related CVE vulnerabilities of this component:  
- CVE-2017-9728: Out-of-bounds read in the get_subexp function in misc/regex/regexec.c when processing a crafted regular expression. (Risk: 9.8)  
- CVE-2022-29503: Memory corruption vulnerability in the libpthread linuxthreads functionality. Thread allocation can lead to memory corruption. (Risk: 9.8)  
- CVE-2017-9729: Stack exhaustion (uncontrolled recursion) in the check_dst_limits_calc_pos_1 function in misc/regex/regexec.c when processing a crafted regular expression. (Risk: 7.5)  
- CVE-2022-30295: Use of predictable DNS transaction IDs that may lead to DNS cache poisoning. (Risk: 6.5)

---
### sbom-uclibc-cve-2021-43523

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 9.6
- **Confidence:** 5.5
- **Description:** CVE-2021-43523 (CVSS 9.6): DNS domain name handling vulnerability in uClibc. Affected versions: <1.0.39.
- **Keywords:** libc.so.0, uClibc, CVE-2021-43523
- **Notes:** Potential vulnerability (if the uClibc version matches the affected versions).

---
### security-RSA_private_key_exposure

- **File/Directory Path:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The file 'etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER' contains a complete RSA private REDACTED_PASSWORD_PLACEHOLDER (in PEM format), which poses a serious security risk. Private REDACTED_PASSWORD_PLACEHOLDER leakage may lead to: 1) Man-in-the-middle attacks - attackers can decrypt encrypted communications; 2) Server identity impersonation; 3) Sensitive data leakage. This private REDACTED_PASSWORD_PLACEHOLDER is currently in an unprotected state, and any user with access to this file can obtain the private REDACTED_PASSWORD_PLACEHOLDER content.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----...-----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  ```
- **Keywords:** uhttpd.REDACTED_PASSWORD_PLACEHOLDER, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Urgent Recommendations: 1) Immediately check whether this private REDACTED_PASSWORD_PLACEHOLDER is being used in the uhttpd service; 2) If no longer needed, securely delete the file; 3) If still required for use, strict file permissions (such as 400) must be set; 4) Consider regenerating the REDACTED_PASSWORD_PLACEHOLDER pair and updating all related configurations. This finding is directly relevant to SBOM analysis as it represents a common security REDACTED_SECRET_KEY_PLACEHOLDER in embedded systems.

---
### sbom-openssl-version

- **File/Directory Path:** `usr/sbin/openvpn`
- **Location:** `usr/sbin/openvpn:0 (library dependency)`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** OpenSSL version 1.0.0 identified through linked library 'libssl.so.1.0.0' and SSL-related function calls. This is a very old version known to have multiple critical vulnerabilities (e.g., Heartbleed). Immediate attention required.
- **Code Snippet:**
  ```
  Dynamic library dependency: libssl.so.1.0.0
  ```
- **Keywords:** libssl.so.1.0.0, SSL_CTX_set_client_CA_list, SSL_free, OpenSSL, 1.0.0
- **Notes:** OpenSSL 1.0.0 is known to be vulnerable. Need to confirm exact version through library analysis and check all associated CVEs.

---
### component-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/update_afp`
- **Location:** `/lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.0
- **Confidence:** 9.25
- **Description:** The uClibc 0.9.33.2 component has been confirmed to contain multiple critical vulnerabilities:
1. CVE-2017-9728 - Out-of-bounds read vulnerability in regular expression processing (CVSS 9.8)
2. CVE-2022-29503 - Memory corruption vulnerability in libpthread linuxthreads functionality (CVSS 9.8)
Version evidence is confirmed through filename and internal build string verification
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libc.so.0, ld-uClibc-0.9.33.2.so, uClibc
- **Notes:** It is recommended to conduct a priority assessment for the remediation of confirmed uClibc vulnerabilities.

---
### SBOM-OpenSSL-0.9.8

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** OpenSSL version 0.9.8 contains multiple critical vulnerabilities, including certificate forgery, predictable random number generator, and protocol version rollback attacks. Evidence source: strings in the fbwifi binary (libssl.so.0.9.8, libcrypto.so.0.9.8).
- **Code Snippet:**
  ```
  N/A (SBOMHIDDEN)
  ```
- **Keywords:** OpenSSL, libssl.so.0.9.8, libcrypto.so.0.9.8
- **Notes:** Contains the following CVE vulnerabilities: CVE-2005-2946, CVE-2008-0166, CVE-2005-2969, CVE-2006-4339, CVE-2006-2937, CVE-2006-2940, CVE-2006-3738, CVE-2006-4343, CVE-2007-3108, CVE-2007-5135

---
### openssl-version-1.0.2h

- **File/Directory Path:** `usr/bin/openssl`
- **Location:** `usr/bin/openssl: version string`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** OpenSSL version 1.0.2h was found in the usr/bin/openssl file. This version contains multiple high-risk vulnerabilities, including CVE-2016-2107, CVE-2016-2105, CVE-2016-2106, CVE-2016-2109, and CVE-2016-2176.
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.2h, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** Version information is confirmed through direct string extraction. Immediate upgrade is recommended to fix known vulnerabilities. Evidence source: version string 'OpenSSL 1.0.2h 3 May 2016' is directly present in the binary file.

---
### thirdparty-openssl-1.0.2h

- **File/Directory Path:** `usr/bin/curl`
- **Location:** `usr/bin/openssl: version string`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.2h, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** third_party_component

---
### openssl-sbom-entry

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `usr/bin/openssl: version string`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.2h, libssl.so.1.0.0, libcrypto.so.1.0.0, SBOM
- **Notes:** third_party_component

---
### thirdparty-e2fsprogs-version

- **File/Directory Path:** `usr/sbin/mkfs.ext3`
- **Location:** `usr/sbin/mkfs.ext3 HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The third-party software component e2fsprogs version information found in the file 'usr/sbin/mkfs.ext3'. The version number is 1.42, released on 29-Nov-2011. The evidence sources are the strings 'mke2fs %s (%s)', '1.42', and '29-Nov-2011' within the file. This version contains two high-risk vulnerabilities, CVE-2015-0247 and CVE-2015-1572, and it is recommended to upgrade to version 1.42.12 or higher.
- **Code Snippet:**
  ```
  mke2fs %s (%s)
  ```
- **Keywords:** mke2fs, 1.42, 29-Nov-2011
- **Notes:** Upgrade to e2fsprogs 1.42.12 or later is required to fix vulnerabilities CVE-2015-0247 and CVE-2015-1572.

---
### SBOM-Netatalk-afpd

- **File/Directory Path:** `usr/sbin/afpd`
- **Location:** `usr/sbin/afpd`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** configuration_load
- **Keywords:** 2.2.1, Netatalk%s, libavahi-client.so.3, libgcrypt.so.11
- **Notes:** configuration_load

---
### component-GCC_runtime-acfg_tool

- **File/Directory Path:** `usr/sbin/acfg_tool`
- **Location:** `usr/sbin/acfg_tool (symbol analysis)`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  String found: GCC_3.5
  ```
- **Keywords:** libgcc_s.so.1, GCC_3.5
- **Notes:** GCC 3.5 is extremely outdated and known to have multiple vulnerabilities. Recommended to search CVE databases for GCC 3.5 vulnerabilities.

---
### SBOM-uClibc-unknown

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `usr/sbin/chat (string '/lib/ld-uClibc.so.0')`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** configuration_load
- **Code Snippet:**
  ```
  String '/lib/ld-uClibc.so.0' found in binary analysis
  ```
- **Keywords:** uClibc, /lib/ld-uClibc.so.0, libc.so.0
- **Notes:** Version evidence: The string '/lib/ld-uClibc.so.0' was found during binary analysis. Based on CVE records, the version is presumed to be 0.9.33.2. The existing vulnerabilities include:
- CVE-2017-9728 (CVSS 9.8): Out-of-bounds read vulnerability in the get_subexp function
- CVE-2022-29503 (CVSS 9.8): Memory corruption vulnerability in libpthread linuxthreads
- CVE-2021-43523 (CVSS 9.6): Improper handling of special characters in DNS responses vulnerability
- CVE-2016-6264 (CVSS 7.5): Integer sign error in the memset function
- CVE-2016-2224 (CVSS 7.5): Denial of service vulnerability in the __decode_dotted function

---
### SBOM-Transmission-2.76

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Risk Score:** 8.8
- **Confidence:** 8.75
- **Description:** Transmission version 2.76 (build 13786) identified with path traversal vulnerability (CVE-2010-0012, CVSS 8.8). Version found in binary strings of REDACTED_PASSWORD_PLACEHOLDER-daemon.
- **Code Snippet:**
  ```
  N/A (version identified through binary strings)
  ```
- **Keywords:** transmission-remote
- **Notes:** network_input

---
### thirdparty-Transmission-version

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `transmission-daemonHIDDEN`
- **Risk Score:** 8.8
- **Confidence:** 8.25
- **Description:** The version information 'Transmission 2.76 (13786)' was found in the transmission-daemon binary. A search through NVD revealed the high-risk vulnerability CVE-2010-0012, which exists in REDACTED_PASSWORD_PLACEHOLDER.c, allowing remote attackers to overwrite arbitrary files via path traversal (..) in .torrent files. Although the CVE report refers to version 1.76, a similar vulnerability may exist in version 2.76.
- **Code Snippet:**
  ```
  Transmission 2.76 (13786)  http://www.transmissionbt.com/
  ```
- **Keywords:** Transmission 2.76, REDACTED_PASSWORD_PLACEHOLDER.c, CVE-2010-0012, .torrent
- **Notes:** Version evidence source: Version string in the binary file. It is recommended to check whether the metainfo.c file has been patched for this vulnerability.

---
### thirdparty-transmission-2.76

- **File/Directory Path:** `usr/bin/curl`
- **Location:** `Version string in transmission-daemon binary`
- **Risk Score:** 8.8
- **Confidence:** 8.25
- **Description:** Version information 'Transmission 2.76 (13786)' was detected in the transmission-daemon binary. Through NVD search, a related high-risk vulnerability CVE-2010-0012 was identified in REDACTED_PASSWORD_PLACEHOLDER.c, which allows remote attackers to overwrite arbitrary files via path traversal (..) in .torrent files. Although the CVE report refers to version 1.76, similar vulnerabilities may exist in version 2.76.
- **Code Snippet:**
  ```
  Transmission 2.76 (13786)  http://www.transmissionbt.com/
  ```
- **Keywords:** Transmission 2.76, REDACTED_PASSWORD_PLACEHOLDER.c, CVE-2010-0012, .torrent
- **Notes:** Version evidence source: version string in binary file. Recommend checking if the metainfo.c file has fixed this vulnerability.

---
### thirdparty-component-transmission

- **File/Directory Path:** `usr/sbin/dlclient`
- **Location:** `greendownload binary (references)`
- **Risk Score:** 8.8
- **Confidence:** 5.5
- **Description:** Analysis of 'greendownload' binary revealed references to Transmission (BitTorrent client). Version is currently unknown but if version 1.22, 1.34, 1.75 or 1.76 is used, it may be vulnerable to CVE-2010-0012 (CVSS 8.8, directory traversal). Binary analysis did not find the actual Transmission files in analyzed set.
- **Code Snippet:**
  ```
  Binary strings show references to 'transmission-remote'
  ```
- **Keywords:** transmission-remote, greendownload, green_download.sh
- **Notes:** network_input

---
### SBOM-hostapd_cli-v2.2-devel

- **File/Directory Path:** `usr/sbin/hostapd_cli`
- **Location:** `usr/sbin/hostapd_cli (HIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The 'hostapd_cli' component was found in the file 'usr/sbin/hostapd_cli', version v2.2-devel. Known vulnerability: CVE-2014-3686 - When using specific configurations and action scripts, it allows remote attackers to execute arbitrary commands via specially crafted frames. Requires configuration using action scripts.
- **Code Snippet:**
  ```
  HIDDEN'hostapd_cli v2.2-devel\nCopyright (c) 2004-2014, Jouni Malinen <j@w1.fi> and contributors'
  ```
- **Keywords:** hostapd_cli, v2.2-devel, Jouni Malinen, BSD license, action scripts
- **Notes:** Although only one CVE was found, '2.2-devel' indicates a development version, which may contain undisclosed security vulnerabilities. It is recommended to examine the complete version history of hostapd and its related configurations.

---
### sbom-e2fsprogs-1.42

- **File/Directory Path:** `usr/sbin/mkfs.ext2`
- **Location:** `usr/sbin/mkfs.ext2`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The e2fsprogs version 1.42 component found in the usr/sbin/mkfs.ext2 file, released on November 29, 2011. This version contains two known high-risk vulnerabilities: CVE-2015-0247 (heap buffer overflow in openfs.c) and CVE-2015-1572 (heap buffer overflow in closefs.c), which may lead to local code execution. Version information evidence source: binary string 'mke2fs 1.42 (29-Nov-2011)'.
- **Code Snippet:**
  ```
  Version information extracted from binary strings: 'mke2fs 1.42 (29-Nov-2011)'
  ```
- **Keywords:** e2fsprogs, libext2fs, openfs.c, closefs.c, block group descriptor
- **Notes:** Unable to verify dependency library version information due to missing related library files. It is recommended to upgrade e2fsprogs to version 1.42.12 or later to fix known vulnerabilities. SBOM details: {'components': [{'name': 'e2fsprogs', 'version': '1.42', 'release_date': '29-Nov-2011', 'evidence_source': 'mke2fs binary strings output', 'vulnerabilities': [{'cve_id': 'CVE-2015-0247', 'description': 'Heap-based buffer overflow in openfs.c in the libext2fs library', 'impact': 'Local code execution via crafted filesystem image', 'affected_versions': 'before 1.42.12'}, {'cve_id': 'CVE-2015-1572', 'description': 'Heap-based buffer overflow in closefs.c in the libext2fs library', 'impact': 'Local code execution via crafted block group descriptor', 'affected_versions': 'before 1.42.12'}]}]}

---
### sbom-uclibc-version

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 8.5
- **Confidence:** 5.5
- **Description:** uClibc (libc.so.0) version unknown. Found reference to libc.so.0 in binary strings. Multiple high severity CVEs potentially affecting this component.
- **Code Snippet:**
  ```
  libc.so.0
  ```
- **Keywords:** libc.so.0, uClibc
- **Notes:** Exact uClibc version not identified in binary. All relevant CVEs for uClibc/uClibc-ng included. Further version analysis recommended.

---
### component-wpa_cli-2.2-devel

- **File/Directory Path:** `usr/sbin/wpa_cli`
- **Location:** `wpa_cli binary: Embedded version string 'wpa_cli v2.2-devel'`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** version_information
- **Code Snippet:**
  ```
  Embedded version string: 'wpa_cli v2.2-devel'
  ```
- **Keywords:** wpa_cli, hostapd_cli, action scripts, CVE-2014-3686
- **Notes:** version_information

---
### sbom-ftptop-version

- **File/Directory Path:** `usr/sbin/ftptop`
- **Location:** `usr/sbin/ftptop:0 (from strings output)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Version information and related clues found in the 'usr/sbin/ftptop' file. The version number is 'ftptop/0.9', extracted from the output of the 'strings ftptop' command. Clues related to proftpd include 'ScoreboardFile', the configuration file '/etc/proftpd.conf', and the file path '/var/run/proftpd.scoreboard'.
- **Code Snippet:**
  ```
  version: ftptop/0.9
  usage: ftptop [options]
  ScoreboardFile /var/run/proftpd.scoreboard
  ```
- **Keywords:** ftptop/0.9, ScoreboardFile, /etc/proftpd.conf, /var/run/proftpd.scoreboard
- **Notes:** Further verification is required regarding the relationship between ftptop version 0.9 and proftpd, along with searching for relevant CVE vulnerabilities. It is recommended to examine the /lib and /usr/lib directories to gather additional dependency information.

---
### thirdparty-component-Netatalk-2.2.1

- **File/Directory Path:** `usr/sbin/check_time_machine`
- **Location:** `usr/sbin/check_time_machine`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Netatalk version 2.2.1 identified in the firmware. This version has known vulnerabilities including CVE-2015-4463 (buffer overflow) and CVE-2015-4464 (authentication bypass). Evidence found in afpd binary strings output.
- **Keywords:** 2.2.1, libavahi-client.so.3, libavahi-common.so.3, libc.so.0, libgcrypt.so.11, libgpg-error.so.0, Netatalk
- **Notes:** Known CVEs for Netatalk 2.2.1 include CVE-2015-4463, CVE-2015-4464, and other vulnerabilities related to buffer overflow and authentication bypass. Evidence source: afpd binary string output.

---
### third-party-OpenVPN-pkitool

- **File/Directory Path:** `usr/sbin/pkitool`
- **Location:** `pkitool HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** OpenVPN component information was found in the file 'usr/sbin/pkitool'. The script header contains OpenVPN's copyright notice, but version information is not explicitly provided. Associated known high-risk vulnerabilities include:  
1. CVE-2017-7521 - OpenVPN Authentication Bypass Vulnerability (CVSSv3: 9.8)  
2. CVE-2018-7715 - PrivateVPN 2.0.31 Privilege Escalation Vulnerability (CVSSv3: 9.8)  
3. CVE-2018-7716 - PrivateVPN 2.0.31 Configuration Injection Vulnerability (CVSSv3: 9.8)  
4. CVE-2019-14929 - ME-RTU Device Cleartext REDACTED_PASSWORD_PLACEHOLDER Disclosure Vulnerability (CVSSv3: 9.8)  
5. CVE-2018-7311 - PrivateVPN 2.0.31 Binary Replacement Vulnerability (CVSSv3: 8.8)  

Note: These CVEs are primarily related to OpenVPN 2.0, but some actually target other products.
- **Code Snippet:**
  ```
  VERSION=2.0
  OPENSSL="openssl"
  PKCS11TOOL="pkcs11-tool"
  ```
- **Keywords:** PROGNAME=pkitool, VERSION=2.0, OPENSSL="openssl", PKCS11TOOL="pkcs11-tool", OpenVPN Technologies, Inc.
- **Notes:** 1. It is recommended to further confirm the specific version number of OpenVPN.  
2. The actual versions of openssl and pkcs11-tool need to be checked.  
3. Some CVEs may not be fully applicable to the current environment and require further verification.

---
### component-libcurl-unknown

- **File/Directory Path:** `usr/sbin/aperture`
- **Location:** `usr/sbin/aperture: Dynamic linking strings`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  libcurl.so.4
  ```
- **Keywords:** libcurl.so.4
- **Notes:** Dynamic library dependency: 'libcurl.so.4'. Need to research CVEs for libcurl versions around 2016.

---
### component-libxml2-unknown

- **File/Directory Path:** `usr/sbin/aperture`
- **Location:** `usr/sbin/aperture: Dynamic linking strings`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** libxml2 dynamic library (libxml2.so.2) found in dynamic linking strings. Need to research CVEs for libxml2 versions around 2016.
- **Code Snippet:**
  ```
  libxml2.so.2
  ```
- **Keywords:** libxml2.so.2
- **Notes:** Dynamic library dependency: 'libxml2.so.2'. Need to research CVEs for libxml2 versions around 2016.

---
### thirdparty-jq-version-analysis

- **File/Directory Path:** `usr/sbin/jq`
- **Location:** `Strings output`
- **Risk Score:** 8.0
- **Confidence:** 6.0
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  jq - commandline JSON processor [version %s]
  ```
- **Keywords:** jq, commandline JSON processor, jv_parse.c, tokenadd, jv_dump_term
- **Notes:** thirdparty_component

---
### SBOM-FFmpeg-54.59.100

- **File/Directory Path:** `usr/sbin/forked-daapd`
- **Location:** `usr/sbin/forked-daapd (libavcodec.so.54)`
- **Risk Score:** 8.0
- **Confidence:** 4.25
- **Description:** The FFmpeg (libavcodec) version is suspected to be 54.59.100, which is part of a series known to contain multiple codec vulnerabilities (such as CVE-2013-7009).
- **Keywords:** libavcodec.so.54
- **Notes:** This series of versions contains multiple codec vulnerabilities (CVE-2013-7009, etc.)

---
### SBOM-GCC-3.5

- **File/Directory Path:** `usr/sbin/i_potd`
- **Location:** `usr/sbin/i_potd (HIDDEN)`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** GCC compiler version 3.5 contains a known vulnerability CVE-2022-25265 (CVSS 7.8), which involves security issues in binaries built with GCC versions around 2003. Version evidence comes from the 'GCC_3.5' marker in the string table.
- **Code Snippet:**
  ```
  GCC_3.5
  ```
- **Keywords:** GCC_3.5
- **Notes:** The version number is an estimated value and requires further verification.

---
### SBOM-GCC-3.5-Consolidated

- **File/Directory Path:** `usr/sbin/radvdump`
- **Location:** `Multiple locations: usr/sbin/radvdump, lib/libgcc_s.so.1, usr/sbin/athtestcmd, etc.`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** SBOM
- **Code Snippet:**
  ```
  Multiple instances of 'GCC_3.5' string found in binaries
  ```
- **Keywords:** GCC_3.5, libgcc_s.so.1, CVE-2008-1685, CVE-2022-48422, CVE-2006-3619, CVE-2005-1689, CVE-2022-25265, uClibc, libc.so.0
- **Notes:** Recommendations:  
1. Prioritize fixing CVE-2022-48422 (highest CVSS score)  
2. Consider upgrading the compiler if possible  
3. Analyze vulnerability patterns in the compiled code  
4. Search for other CVEs affecting GCC 3.5  

Evidence Sources:  
1. Direct string evidence from multiple binary files  
2. Compatibility symbols in libgcc_s.so.1  
3. CVE database research

---
### SBOM-GCC_Runtime_Library-consolidated

- **File/Directory Path:** `usr/sbin/athdiag`
- **Location:** `lib/libgcc_s.so.1`
- **Risk Score:** 7.8
- **Confidence:** 7.5
- **Description:** Comprehensive analysis confirms the GCC runtime library (libgcc_s.so.1) version range is 3.0-4.3.0, containing two known vulnerabilities:
1. CVE-2008-1685: Pointer arithmetic optimization may remove security checks vulnerability (CVSS 6.5)
2. CVE-2022-48422: Privilege escalation vulnerability via malicious libgcc_s.so.1 (CVSS 7.8)

Version information is confirmed based on compatibility symbols in the /lib/libgcc_s.so.1 file and references from multiple binary files.
- **Code Snippet:**
  ```
  GCC_4.3.0 (from strings output)
  ```
- **Keywords:** libgcc_s.so.1, GCC_3.0, GCC_3.5, GCC_4.3.0, CVE-2008-1685, CVE-2022-48422
- **Notes:** SBOM

---
### SBOM-libgcc-internet

- **File/Directory Path:** `usr/sbin/internet`
- **Location:** `usr/sbin/internet:0x000003d5 (HIDDEN)`
- **Risk Score:** 7.8
- **Confidence:** 6.5
- **Description:** The referenced libgcc component was found in file 'usr/sbin/internet' with unknown version (referenced as libgcc_s.so.1). 2 security vulnerabilities were identified:
1. CVE-2021-26807: Security issue related to how the application loads libgcc library (risk score 7.8)
2. CVE-2022-48422: Security issue related to how the application loads libgcc library (risk score 7.8)

Further analysis of library files in the firmware filesystem is required to obtain exact version information.
- **Code Snippet:**
  ```
  HIDDEN: 'libgcc_s.so.1'
  ```
- **Keywords:** libgcc, libgcc_s.so.1
- **Notes:** 1. Further analysis of the library files in the firmware file system is required to obtain the exact version information of libgcc.
2. Due to incomplete version information, the applicability of some vulnerabilities needs further verification.

---
### thirdparty-component-libgcc_s.so.1

- **File/Directory Path:** `usr/sbin/athdiag`
- **Location:** `usr/sbin/athdiag`
- **Risk Score:** 7.8
- **Confidence:** 6.0
- **Description:** The third-party component libgcc_s.so.1 found in the file 'usr/sbin/athdiag' has a known high-risk vulnerability CVE-2022-48422, described as privilege escalation in ONLYOFFICE Docs via malicious libgcc_s.so.1, with a CVSS score of 7.8. Due to limitations of the NVD API, complete CVE information for other components cannot be obtained. The version information of the components is also incomplete.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libgcc_s.so.1, libc.so.0, ld-uClibc.so.0, GCC_3.5, athdiag
- **Notes:** It is recommended to re-query CVE information after the NVD API restrictions are lifted, or manually check at https://nvd.nist.gov. Additionally, alternative methods for obtaining component version information can be attempted, such as package manifests or build logs.

---
### SBOM-libgcc_s.so.1-unknown

- **File/Directory Path:** `usr/sbin/athssd`
- **Location:** `usr/sbin/athssd:0 (Dynamic section)`
- **Risk Score:** 7.8
- **Confidence:** 5.5
- **Description:** The version information of the third-party component libgcc_s.so.1 is unknown, with evidence derived from dynamic dependencies. A related CVE vulnerability was identified: CVE-2022-48422 (CVSSv3 7.8), but this vulnerability is not inherent to libgcc_s.so.1 itself, rather it pertains to how ONLYOFFICE Docs utilizes it.
- **Code Snippet:**
  ```
  Dynamic dependency
  ```
- **Keywords:** libgcc_s.so.1
- **Notes:** configuration_load

---
### SBOM-GCC-Runtime-Library-unknown

- **File/Directory Path:** `usr/sbin/ntgrddns`
- **Location:** `usr/sbin/ntgrddns (HIDDEN)`
- **Risk Score:** 7.8
- **Confidence:** 2.5
- **Description:** A dependency on GCC Runtime Library (libgcc_s.so.1) was found in the file usr/sbin/ntgrddns, but the exact version could not be determined. Potentially related CVEs include: CVE-2023-29404 (CVSS 9.8), CVE-2023-29405 (CVSS 9.8), CVE-2014-9799 (CVSS 7.8). Further verification of applicability is required.
- **Code Snippet:**
  ```
  HIDDEN: libgcc_s.so.1
  ```
- **Keywords:** libgcc_s.so.1
- **Notes:** Since the exact version of the GCC library cannot be determined, the listed CVEs are for reference only, and further verification of applicability is required.

---
### thirdparty-OpenSSL-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER: Dynamic linking to libcrypto.so.1.0.0`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** third_party_component
- **Keywords:** libcrypto.so.1.0.0, CVE-2015-1789, CVE-2014-0224
- **Notes:** third_party_component

---
### vulnerability-CVE-2017-9729

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The text translates to English as:

command_execution
- **Keywords:** uClibc, check_dst_limits_calc_pos_1, regexec.c
- **Notes:** Affects uClibc version 0.9.33.2

---
### SBOM-GCC-3.5

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `radardetect binary strings`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The GCC 3.5 compiler component was identified within the firmware. This version contains multiple critical vulnerabilities, including CVE-2006-3619 (C++ demangler buffer overflow) and CVE-2005-1689 (C++ frontend integer overflow), both of which could potentially lead to arbitrary code execution.
- **Code Snippet:**
  ```
  Evidence from strings output showing 'GCC_3.5'
  ```
- **Keywords:** GCC_3.5
- **Notes:** GCC 3.5 is outdated and has known vulnerabilities. Upgrade recommended. Vulnerabilities: CVE-2006-3619 (Buffer overflow in the C++ demangler, CVSS 7.5), CVE-2005-1689 (Integer overflow in C++ front end, CVSS 7.5)

---
### thirdparty-ez-ipupdate-3.0.10

- **File/Directory Path:** `usr/sbin/ez-ipupdate`
- **Location:** `Binary strings output`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Analysis identified the third-party component 'ez-ipupdate' version 3.0.10 with known vulnerability CVE-2004-0980 (format string vulnerability when running in daemon mode with certain service types, allowing remote code execution). Version evidence was found in binary strings showing '3.0.10' and copyright information from Angus Mackay.
- **Code Snippet:**
  ```
  ez-ipupdate Version %s
  Copyright (C) 1999-2000 Angus Mackay.
  ...
  3.0.10
  ```
- **Keywords:** ez-ipupdate, 3.0.10, ez-ipupdate.c, CVE-2004-0980, third-party, SBOM
- **Notes:** third_party_component

---
### SBOM-GCC_Runtime_Library-libgcc_s.so.1

- **File/Directory Path:** `usr/sbin/dev-scan`
- **Location:** `lib/libgcc_s.so.1`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The GCC runtime library (libgcc_s.so.1) version range 3.0 to 4.3.0 (compatibility symbols) was detected in the 'dev-scan' binary file. Contains known vulnerability CVE-2008-1685 (pointer arithmetic optimization that may remove safety checks).
- **Code Snippet:**
  ```
  No direct version strings in 'dev-scan' binary. Version identification based on compatibility symbols in libgcc_s.so.1
  ```
- **Keywords:** libgcc_s.so.1, GCC Runtime Library, CVE-2008-1685
- **Notes:** configuration_load

---
### SBOM-libid3tag-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `Strings output showing linkage to libid3tag.so.0`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** libid3tag linked as libid3tag.so.0 with multiple vulnerabilities: CVE-2004-2779 (Memory exhaustion), CVE-2017-11550 (NULL pointer dereference), CVE-2017-11551 (Memory exhaustion).
- **Code Snippet:**
  ```
  libid3tag.so.0
  ```
- **Keywords:** libid3tag, ID3, MP3
- **Notes:** configuration_load

---
### SBOM-GCC-3.5-consolidated

- **File/Directory Path:** `usr/sbin/athtestcmd`
- **Location:** `Multiple locations: usr/sbin/athtestcmd, lib/libgcc_s.so.1, usr/sbin/Qcmbr, etc.`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** Consolidated SBOM entry for GCC 3.5 compiler runtime based on multiple findings across the firmware. Version evidence comes from: 1) 'GCC_3.5' strings in multiple binaries (usr/sbin/athtestcmd, usr/sbin/Qcmbr, usr/sbin/acfg_tool, etc.) 2) Compatibility symbols in libgcc_s.so.1. Known vulnerabilities include: CVE-2008-1685 (pointer arithmetic optimization issue) and CVE-2022-48422 (potential privilege escalation via libgcc_s.so.1). GCC 3.5 is quite old (released ~2004) and likely has additional vulnerabilities requiring further research.
- **Code Snippet:**
  ```
  Multiple instances of 'GCC_3.5' string found in binaries
  ```
- **Keywords:** GCC_3.5, libgcc_s.so.1, CVE-2008-1685, CVE-2022-48422, uClibc, libc.so.0
- **Notes:** SBOM

---
### sbom-component-libubox.so

- **File/Directory Path:** `bin/ubus`
- **Location:** `bin/ubus`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** The dependency component libubox.so was identified during the analysis of the 'bin/ubus' file. The dependency was confirmed using the 'readelf -d ubus' command, but version information could not be determined. Known vulnerability: CVE-2020-7248 (CVSSv3: 7.5) - a stack buffer overflow vulnerability affecting OpenWrt versions prior to 18.06.7 and versions 19.x prior to 19.07.1. It is recommended to verify the specific version of libubox.so to assess vulnerability applicability.
- **Keywords:** libubox.so, ubus
- **Notes:** It is recommended to verify the specific version of libubox.so to confirm the vulnerability applicability.

---
### component-libuci-version

- **File/Directory Path:** `lib/libuci.so`
- **Location:** `lib/libuci.so`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** No explicit version information string was directly extracted from the lib/libuci.so file. Through CVE correlation analysis, it is inferred that this component may belong to the OpenWrt 18.06.9 or 19.07.5 version range. Two related high-risk vulnerabilities were identified: 1) CVE-2020-28951 - Use-after-free vulnerability (CVSS 9.8); 2) CVE-2019-15513 - File locking handling issue (CVSS 7.5).
- **Keywords:** libuci.so, OpenWrt, CVE-2020-28951, CVE-2019-15513
- **Notes:** Insufficient version information evidence, it is recommended to verify the exact OpenWrt version through other system files (such as /etc/openwrt_release).

---
### vulnerability-CVE-2019-15513

- **File/Directory Path:** `lib/libuci.so`
- **Location:** `lib/libuci.so`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** OpenWrt libuci has an issue with locking in /tmp/.uci/network
- **Keywords:** libuci.so, CVE-2019-15513
- **Notes:** CVSS score 7.5, medium-high risk vulnerability

---
### version-OpenWrt-dynamic-version

- **File/Directory Path:** `etc/openwrt_release`
- **Location:** `etc/openwrt_release, etc/openwrt_version`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** The files 'etc/openwrt_release' and 'etc/openwrt_version' contain version information placeholders (such as %D, %C, %R, etc.) rather than actual version numbers. This suggests that the version information may be dynamically generated during runtime. Although knowledge base analysis based on CVE information of related components (e.g., lib/libuci.so) speculates potential relevance to OpenWrt versions 18.06.9 or 19.07.5, no definitive version information has been found in the current files.
- **Code Snippet:**
  ```
  DISTRIB_ID="%D"
  DISTRIB_RELEASE="%C"
  DISTRIB_REVISION="%R"
  DISTRIB_TARGET="%S"
  DISTRIB_DESCRIPTION="%D %N %V"
  ```
- **Keywords:** DISTRIB_ID, DISTRIB_RELEASE, DISTRIB_REVISION, DISTRIB_TARGET, DISTRIB_DESCRIPTION, openwrt_version, OpenWrt, CVE-2019-15513, CVE-2020-28951
- **Notes:** Further analysis of other system files or firmware metadata is required to obtain precise version information. The knowledge base has identified two high-risk CVEs (CVE-2020-28951 and CVE-2019-15513) that may be associated with the inferred OpenWrt version.

---
### sbom-uclibc-cve-2016-6264

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** CVE-2016-6264 (CVSS 7.5): Integer signedness error in memset function within uClibc. Affected versions: prior to 1.0.16.
- **Keywords:** libc.so.0, uClibc, CVE-2016-6264
- **Notes:** Potential vulnerability if uClibc version matches affected versions.

---
### sbom-uclibc-cve-2016-2224

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** CVE-2016-2224 (CVSS 7.5): DNS denial of service (infinite loop) in uClibc. Affected versions: <1.0.12.
- **Keywords:** libc.so.0, uClibc, CVE-2016-2224
- **Notes:** Potential vulnerability if uClibc version matches affected versions.

---
### sbom-uclibc-cve-2016-2225

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** CVE-2016-2225 (CVSS 7.5): DNS denial of service (infinite loop) in uClibc. Affected versions: <1.0.12.
- **Keywords:** libc.so.0, uClibc, CVE-2016-2225
- **Notes:** configuration_load

---
### sbom-uclibc-cve-2017-9729

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** CVE-2017-9729 (CVSS 7.5): Stack exhaustion in regex processing in uClibc. Affected versions: 0.9.33.2.
- **Keywords:** libc.so.0, uClibc, CVE-2017-9729
- **Notes:** configuration_load

---
### SBOM-miniupnpd-version

- **File/Directory Path:** `usr/sbin/miniupnpd`
- **Location:** `usr/sbin/miniupnpd`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** In the file 'usr/sbin/miniupnpd', version 1.0 of the miniUPnP component was identified, which is associated with three known CVE vulnerabilities. The version information was sourced from HTTP header data within the binary file. Further verification is required to determine the specific CVE identifiers and their respective impact scopes.
- **Keywords:** miniupnpd, HTTP headers, version 1.0
- **Notes:** Further verification is required for specific CVE numbers and their impact scope. It is recommended to analyze additional files subsequently to obtain more comprehensive SBOM information.

---
### SBOM-pppd-version

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `usr/sbin/pppd (HIDDENstringsHIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** Explicit version evidence was found in the 'usr/sbin/pppd' file. REDACTED_PASSWORD_PLACEHOLDER findings include: 1) The string 'pppd version %s' indicates this is a PPP implementation with dynamically inserted version numbers; 2) The path '/usr/lib/pppd/2.4.3' clearly specifies version 2.4.3. This is the standard implementation version of the PPPoE protocol. The pppd 2.4.3 version is known to contain multiple critical vulnerabilities, including but not limited to: CVE-2015-3310 (privilege escalation vulnerability), CVE-2014-3158 (memory corruption vulnerability), CVE-2012-4925 (information disclosure vulnerability).
- **Code Snippet:**
  ```
  /usr/lib/pppd/2.4.3
  ```
- **Keywords:** pppd version %s, /usr/lib/pppd/2.4.3
- **Notes:** The pppd version 2.4.3 is known to contain multiple high-risk vulnerabilities, including but not limited to: CVE-2015-3310 (privilege escalation vulnerability), CVE-2014-3158 (memory corruption vulnerability), and CVE-2012-4925 (information disclosure vulnerability). It is recommended to obtain the complete CVE list through the NVD database or vulnerability scanning tools. Due to API limitations, this analysis was unable to automatically retrieve the full CVE list.

---
### thirdparty-OpenSSL-1.0.0

- **File/Directory Path:** `bin/opkg`
- **Location:** `bin/opkg:HIDDEN`
- **Risk Score:** 7.4
- **Confidence:** 8.7
- **Description:** The third-party component OpenSSL, version 1.0.0, was found in the file 'bin/opkg'. Known vulnerability: CVE-2014-0224 (CVSSv3 score 7.4), which allows man-in-the-middle attackers to hijack sessions or obtain sensitive information.
- **Code Snippet:**
  ```
  HIDDEN'libssl.so.1.0.0'HIDDEN'libcrypto.so.1.0.0'
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** configuration_load

---
### component-OpenSSL-1.0.0

- **File/Directory Path:** `usr/sbin/build-inter`
- **Location:** `./pkitool:HIDDENOPENSSLHIDDEN`
- **Risk Score:** 7.4
- **Confidence:** 8.25
- **Description:** OpenSSL component detected, version 1.0.0. Multiple vulnerabilities exist:
1. CVE-2014-0224 (CCS Injection vulnerability, CVSS 7.4), allows session hijacking
2. CVE-2009-1379 (Use-after-free vulnerability, CVSS 7.0)
Recommend upgrading to OpenSSL 1.0.0m or later version.
- **Code Snippet:**
  ```
  [ -n "$OPENSSL" ] || export OPENSSL="openssl"
  ```
- **Keywords:** pkitool, OpenSSL, build-inter
- **Notes:** OpenSSL 1.0.0 contains multiple vulnerabilities, with the most severe being CVE-2014-0224 (session hijacking). These component versions are outdated, and it is recommended to upgrade to the latest stable version to obtain security fixes.

---
### sbom-uclibc-cve-2021-27419

- **File/Directory Path:** `usr/sbin/ubidetach`
- **Location:** `usr/sbin/ubidetach:0 (ubidetach) library reference`
- **Risk Score:** 7.3
- **Confidence:** 5.5
- **Description:** CVE-2021-27419 (CVSS 7.3): Integer wrap-around vulnerability in malloc-simple within uClibc. Affected versions: prior to 1.0.37.
- **Keywords:** libc.so.0, uClibc, CVE-2021-27419
- **Notes:** Potential vulnerability if uClibc version matches affected versions.

---
### SBOM-libmicrohttpd-0.9.31

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** GNU libmicrohttpd version 0.9.31 contains out-of-bounds read and stack buffer overflow vulnerabilities. Evidence source: string (0.9.31) in fbwifi binary.
- **Code Snippet:**
  ```
  N/A (SBOMHIDDEN)
  ```
- **Keywords:** libmicrohttpd, 0.9.31
- **Notes:** Contains the following CVE vulnerabilities: CVE-2013-7038, CVE-2013-7039

---
### SBOM-PPP-2.4.3

- **File/Directory Path:** `usr/sbin/remote_user_conf`
- **Location:** `usr/sbin/remote_user_conf`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** network_input
- **Keywords:** PPP 2.4.3
- **Notes:** network_input

---
### SBOM-net-wall-2.0

- **File/Directory Path:** `usr/sbin/remote_user_conf`
- **Location:** `usr/sbin/remote_user_conf`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The string 'net-wall 2.0' was found, indicating the use of a firewall component named 'net-wall' version 2.0. This version should be checked against known vulnerabilities (CVEs).
- **Keywords:** net-wall 2.0
- **Notes:** network_input

---
### SBOM-PPP-2.4.3

- **File/Directory Path:** `usr/sbin/usb_cfg`
- **Location:** `sbin/pppd:0 (version string)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Point-to-Point Protocol (PPP) version 2.4.3 component, a widely used network protocol implementation. Special attention should be paid to its security updates. Version evidence source: 'pppd version 2.4.3' string in the sbin/pppd file. Due to NVD API limitations, no relevant CVE information has been obtained yet; manual verification is recommended.
- **Code Snippet:**
  ```
  'pppd version 2.4.3'
  ```
- **Keywords:** pppd, PPP 2.4.3
- **Notes:** This is a widely used network protocol implementation, and it is recommended to pay special attention to its security updates. Due to NVD API limitations, relevant CVE information has not been retrieved yet; manual verification is advised.

---
### component-uClibc-acfg_tool

- **File/Directory Path:** `usr/sbin/acfg_tool`
- **Location:** `usr/sbin/acfg_tool (strings analysis)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Dynamic linker path: /lib/ld-uClibc.so.0
  ```
- **Keywords:** /lib/ld-uClibc.so.0, libc.so.0, __uClibc_main
- **Notes:** configuration_load

---
### SBOM-OpenSSL-Unknown

- **File/Directory Path:** `usr/sbin/build-req`
- **Location:** `/usr/sbin/pkitool`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The use of OpenSSL was detected in the firmware, but the specific version could not be determined. Evidence comes from the OPENSSL variable declaration in the '/usr/sbin/pkitool' file. Further analysis is required to identify the exact version.
- **Code Snippet:**
  ```
  [ -n "$OPENSSL" ] || export OPENSSL="openssl"
  ```
- **Keywords:** OPENSSL, pkitool
- **Notes:** The OpenSSL version is unknown; it is necessary to check the system package manager or other configuration files to determine the version.

---
### component-shell-potval

- **File/Directory Path:** `usr/sbin/potval`
- **Location:** `usr/sbin/potval`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The file 'usr/sbin/potval' is a shell script primarily used to invoke the 'i_potval' executable. 'i_potval' is a 32-bit ARM architecture ELF executable, dynamically linked to uClibc. This program is related to POT (Proof of Transit) functionality, involving NTP time synchronization and MAC address recording. Although no direct version information was found, correlation analysis reveals it utilizes the uClibc library, which contains multiple known vulnerabilities.
- **Code Snippet:**
  ```
  #!/bin/sh
  [ -f /dni-gconfig ] && . /dni-gconfig
  if [ "x$DGC_MTD_POT" = "x" ]; then
  	echo "!!!! POT MTD defined MISS!!!!"
  	exit 1
  fi
  
  i_potval $* -d $DGC_MTD_POT
  ```
- **Keywords:** i_potval, uClibc, GCC_3.5, POT, NTP, MAC
- **Notes:** 1. No explicit version information was found in the file.  
2. Multiple high-risk CVE vulnerabilities related to uClibc were identified.  
3. It is recommended to further analyze the binary code of 'i_potval' for additional information.

---
### SBOM-avahi-dnsconfd-0.6.31

- **File/Directory Path:** `usr/sbin/avahi-dnsconfd`
- **Location:** `usr/sbin/avahi-dnsconfd`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  '%s 0.6.31' version string found in binary
  ```
- **Keywords:** avahi-dnsconfd, 0.6.31
- **Notes:** configuration_load

---
### SBOM-PPP

- **File/Directory Path:** `usr/sbin/remote_smb_conf`
- **Location:** `usr/sbin/remote_smb_conf:0 (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The third-party component PPP, version 2.4.3, was found in the file 'usr/sbin/remote_smb_conf'. Related CVE identified: CVE-2006-5749 - ISDN PPP CCP reset state timer vulnerability in Linux kernel versions before 2.4.34-rc4.
- **Code Snippet:**
  ```
  Found in strings output: 'PPP 2.4.3'
  ```
- **Keywords:** PPP 2.4.3, nc_vpn_info
- **Notes:** Affects Linux kernel versions prior to 2.4.34-rc4

---
### thirdparty-uclibc-cves

- **File/Directory Path:** `usr/sbin/ubinize`
- **Location:** `usr/sbin/ubinize`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Keywords:** uClibc, libc.so.0, ld-uClibc.so.0
- **Notes:** uClibc CVEs:  
- CVE-2017-9728 (CVSS 9.8)  
- CVE-2022-29503 (CVSS 9.8)  
- CVE-2021-43523 (CVSS 9.6)  
- CVE-2016-6264 (CVSS 7.5)  
- CVE-2016-2224/2225 (CVSS 7.5)  
- CVE-2017-9729 (CVSS 7.5)  
- CVE-2021-27419 (CVSS 7.3)  
- CVE-2022-30295 (CVSS 6.5)  
- CVE-2024-40090 (CVSS 4.3)  

Outstanding issue: Need to verify exact uClibc version by accessing '/lib/ld-uClibc.so.0'

---
### SBOM-radvdump-components

- **File/Directory Path:** `usr/sbin/radvdump`
- **Location:** `usr/sbin/radvdump`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Analysis of 'usr/sbin/radvdump' revealed the following SBOM components:
1. uClibc (version unknown) - Evidence found in binary strings, but no version information within current scope
2. GCC runtime (version 3.5) - Identified through embedded strings 'GCC_3.5' and 'libgcc_s.so.1'

Security considerations:
- GCC version 3.5 is outdated (released circa 2005) and may contain multiple CVE vulnerabilities
- The vulnerability status of uClibc cannot be determined due to unknown version
- **Code Snippet:**
  ```
  Embedded strings in radvdump binary: 'GCC_3.5', 'libgcc_s.so.1'
  ```
- **Keywords:** libc.so.0, libgcc_s.so.1, uClibc, GCC, GCC_3.5, /lib/ld-uClibc.so.0, __uClibc_main
- **Notes:** configuration_load

---
### component-Aperture-build-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `usr/sbin/aperture`
- **Location:** `usr/sbin/aperture: Embedded in binary strings`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Aperture application version build-REDACTED_PASSWORD_PLACEHOLDER found in binary strings. Need to research CVEs for this version.
- **Code Snippet:**
  ```
  Aperture aperture build-REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** Aperture aperture build-REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration_load

---
### component-C_stdlib-acfg_tool

- **File/Directory Path:** `usr/sbin/acfg_tool`
- **Location:** `usr/sbin/acfg_tool (strings analysis)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Library reference: libc.so.0
  ```
- **Keywords:** libc.so.0, __uClibc_main
- **Notes:** configuration_load

---
### SBOM-hostapd-wifitool

- **File/Directory Path:** `usr/sbin/wifitool`
- **Location:** `usr/sbin/wifitool: Reference in usage strings`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The string referencing hostapd was found in the usage string of the file 'usr/sbin/wifitool'. Hostapd integration is confirmed, but no version is specified.
- **Code Snippet:**
  ```
  Reference in usage strings
  ```
- **Keywords:** hostapd, /var/run/hostapd
- **Notes:** configuration_load

---
### SBOM-e2fsck-1.42

- **File/Directory Path:** `usr/sbin/e2fsck`
- **Location:** `usr/sbin/e2fsck`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Found in strings output of 'usr/sbin/e2fsck'
  ```
- **Keywords:** e2fsck, 1.42, libext2fs.so.2, libcom_err.so.2, libblkid.so.1, libuuid.so.1, libe2p.so.2
- **Notes:** configuration_load

---
### thirdparty-samba-nmbd

- **File/Directory Path:** `usr/sbin/nmbd`
- **Location:** `usr/sbin/nmbd`
- **Risk Score:** 7.0
- **Confidence:** 5.75
- **Description:** Analysis confirms that 'nmbd' belongs to the Samba software suite. The copyright string indicates it originates from the 1992-2006 period. This older version range is highly likely to contain multiple known vulnerabilities. Static analysis cannot determine the specific version—dynamic analysis in a simulated environment is required to obtain more precise version identification.
- **Code Snippet:**
  ```
  Copyright Andrew Tridgell and the Samba Team 1992-2006
  ```
- **Keywords:** samba_version_string, nmbd, Copyright Andrew Tridgell
- **Notes:** thirdparty_component

---
### component-uClibc-aclhijackdns

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** Analysis of 'REDACTED_PASSWORD_PLACEHOLDER' identified dependencies on uClibc with undetermined version. The binary is dynamically linked with 'libgcc_s.so.1' and 'libc.so.0' (uClibc implementation). The interpreter path '/lib/ld-uClibc.so.0' suggests the use of uClibc. Several known uClibc vulnerabilities may affect this component, including CVE-2017-9728 (Out-of-bounds read in regex processing, CVSS 9.8), CVE-2022-29503 (Memory corruption in thread allocation, CVSS 9.8), and CVE-2021-43523 (DNS response validation flaws, CVSS 9.6). Exact version could not be determined from the binary - further analysis of the filesystem's libc implementation needed for precise version identification.
- **Code Snippet:**
  ```
  Interpreter path: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** libgcc_s.so.1, libc.so.0, ld-uClibc.so.0, uClibc
- **Notes:** configuration_load

---
### component-libevent-version

- **File/Directory Path:** `usr/sbin/jigglyp0f`
- **Location:** `usr/sbin/jigglyp0f: strings output`
- **Risk Score:** 7.0
- **Confidence:** 5.0
- **Description:** Identified version '2.0.5' of libevent library from shared object reference in binary. This is an event notification library.
- **Code Snippet:**
  ```
  libevent-2.0.so.5
  ```
- **Keywords:** libevent-2.0.so.5
- **Notes:** configuration_load

---
### thirdparty-proftpd-1.3.3

- **File/Directory Path:** `usr/sbin/proftpd`
- **Location:** `usr/sbin/proftpd: Embedded version string in binary`
- **Risk Score:** 7.0
- **Confidence:** 4.5
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  Compile-time Settings:
    Version: 1.3.3 (stable)
    Platform: LINUX [%s %s %s]
    Built: Sat Jul 15 2017 19:44:44 CST
  ```
- **Keywords:** proftpd, Version: 1.3.3, Compile-time Settings, FTP server
- **Notes:** thirdparty_component

---
### SBOM-SQLite-3.7.17

- **File/Directory Path:** `usr/sbin/forked-daapd`
- **Location:** `usr/sbin/forked-daapd (libsqlite3.so.0)`
- **Risk Score:** 7.0
- **Confidence:** 4.25
- **Description:** Suspecting SQLite version 3.7.17, which contains vulnerabilities such as CVE-2015-3414. The exact version needs to be confirmed.
- **Keywords:** libsqlite3.so.0
- **Notes:** This version contains vulnerabilities such as CVE-2015-3414, and the exact version needs to be confirmed.

---
