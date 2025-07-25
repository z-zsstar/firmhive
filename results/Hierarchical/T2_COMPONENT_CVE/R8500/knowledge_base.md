# R8500 (12 alerts)

---

### sbom-component-uClibc-0.9.33.2

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `wps_monitor (strings output)`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** uClibc 0.9.33.2 component and its associated vulnerability information. Evidence source: '/lib/ld-uClibc.so.0' string. This version contains multiple high-risk vulnerabilities, including CVE-2017-9728 (regular expression out-of-bounds read) and CVE-2022-29503 (memory corruption).
- **Code Snippet:**
  ```
  Found in string: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** libuClibc.so.0, get_subexp, regexec.c, libpthread, linuxthreads, check_dst_limits_calc_pos_1, DNS, transaction IDs
- **Notes:** configuration_load

---
### openssl-version-libssl.so

- **File/Directory Path:** `lib/libssl.so`
- **Location:** `libssl.so (version strings found in binary)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  SSLv2 part of OpenSSL 1.0.0g 18 Jan 2012
  SSLv3 part of OpenSSL 1.0.0g 18 Jan 2012
  ```
- **Keywords:** OpenSSL 1.0.0g, SSLv2, SSLv3, libssl.so
- **Notes:** third_party_component

---
### SBOM-BusyBox-1.7.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `BusyBox binary .rodata section`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The version string 'BusyBox v1.7.2 (2017-09-23 22:21:40 CST)' was found in the .rodata section of the BusyBox binary. This version is outdated (released in 2017) and may be affected by multiple high-risk vulnerabilities, including CVE-2019-5138, CVE-2016-2148 (DHCP client overflow), CVE-2016-5791, CVE-2018-1000517 (wget buffer overflow), and CVE-2021-42377 (command injection), among others.
- **Code Snippet:**
  ```
  BusyBox v1.7.2 (2017-09-23 22:21:40 CST)
  ```
- **Keywords:** BusyBox v1.7.2, CVE-2019-5138, CVE-2016-2148, CVE-2016-5791, CVE-2018-1000517, CVE-2017-8415, CVE-2018-14494, CVE-2019-13473, CVE-2021-37555, CVE-2021-42377, CVE-2022-48174
- **Notes:** It is strongly recommended to conduct a thorough security review and upgrade to a newer version, as version 1.7.2 predates the fixes for these CVEs. Special attention should be paid to vulnerabilities related to the DHCP client, wget, and command injection.

---
### thirdparty-component-wget-1.12

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget: HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The file 'bin/wget' contains definitive evidence of GNU Wget version 1.12. This version has multiple known critical vulnerabilities:
1. CVE-2009-3490 - Man-in-the-middle attack vulnerability
2. CVE-2010-2252 - Arbitrary file overwrite/creation vulnerability

These vulnerabilities could potentially be exploited to conduct man-in-the-middle attacks or compromise system file integrity.
- **Code Snippet:**
  ```
  GNU Wget %s, a non-interactive network retriever.
  ```
- **Keywords:** GNU Wget 1.12, libssl.so.1.0.0, libcrypto.so.1.0.0, CVE-2009-3490, CVE-2010-2252
- **Notes:** It is recommended to upgrade to the latest version of Wget to fix these security vulnerabilities. Further checks are needed to determine whether the system is using vulnerable features.

---
### VULN-GCC-4.5.3-CVE-2012-2139

- **File/Directory Path:** `bin/ookla`
- **Location:** `CVE database reference`
- **Risk Score:** 8.5
- **Confidence:** 4.5
- **Description:** GCC 4.5.3 has a known vulnerability (CVE-2012-2139) which is a code execution vulnerability in the DWARF unwinder. This could potentially affect binaries built with this compiler version.
- **Keywords:** GCC, 4.5.3, CVE-2012-2139
- **Notes:** vulnerability_reference

---
### SBOM-GCC-4.5.3

- **File/Directory Path:** `bin/ookla`
- **Location:** `strings output`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** GCC compiler version 4.5.3 was identified from build strings. This is an older version of GCC with known vulnerabilities including code execution vulnerabilities (e.g., CVE-2012-2139, CVE-2012-0152). Further investigation needed to determine if these affect the binary.
- **Code Snippet:**
  ```
  GCC: (Buildroot 2012.02) 4.5.3
  ```
- **Keywords:** GCC, 4.5.3, Buildroot
- **Notes:** GCC 4.5.3 has multiple known CVEs including code execution vulnerabilities (e.g., CVE-2012-2139, CVE-2012-0152). Further investigation needed to determine if these affect the binary.

---
### VULN-GCC-4.5.3-CVE-2012-0152

- **File/Directory Path:** `bin/ookla`
- **Location:** `CVE database reference`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** GCC 4.5.3 has a known vulnerability (CVE-2012-0152) which is a heap-based buffer overflow in the genattrtab.c component. This could potentially affect binaries built with this compiler version.
- **Keywords:** GCC, 4.5.3, CVE-2012-0152
- **Notes:** vulnerability_reference

---
### SBOM-FLAC-1.2.1

- **File/Directory Path:** `lib/libFLAC.so.8`
- **Location:** `lib/libFLAC.so.8`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Keywords:** FLAC__VERSION_STRING, reference libFLAC 1.2.1 REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration_load

---
### SBOM-Buildroot-2012.02

- **File/Directory Path:** `bin/ookla`
- **Location:** `strings output`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Buildroot 2012.02
  ```
- **Keywords:** Buildroot, 2012.02
- **Notes:** configuration_load

---
### component-WPS

- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The WPS (Wi-Fi Protected Setup) version information found in the 'bin/eapd' file. The strings 'WFA-SimpleConfig-Enrollee-1-0' and 'WFA-SimpleConfig-Registrar-1-0' indicate a possible implementation of WPS version 1.0. Further verification is needed to confirm the specific version of the WPS implementation and any known vulnerabilities.
- **Code Snippet:**
  ```
  WFA-SimpleConfig-Enrollee-1-0
  WFA-SimpleConfig-Registrar-1-0
  ```
- **Keywords:** WFA-SimpleConfig-Enrollee-1-0, WFA-SimpleConfig-Registrar-1-0
- **Notes:** Further verification is required regarding the specific version of WPS implementation and known vulnerabilities.

---
### sbom-component-UPnP-unknown

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `wps_monitor (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** UPnP component (libupnp.so), version information unknown. Potential vulnerability CVE-2016-8863 (Portable UPnP SDK before 1.6.21), but version confirmation is required.
- **Code Snippet:**
  ```
  Found references to libupnp.so and UPnP-related strings
  ```
- **Keywords:** libupnp.so, urn:schemas-wifialliance-org
- **Notes:** network_input

---
### thirdparty-libexif-version

- **File/Directory Path:** `lib/libexif.so.12`
- **Location:** `lib/libexif.so.12`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** Analysis of the file 'lib/libexif.so.12' reveals it is an ARM shared library (ELF 32-bit LSB) with stripped symbols and version information. While direct version string extraction is not possible, CVE vulnerability data suggests this library is likely libexif 0.6.21 or earlier. REDACTED_PASSWORD_PLACEHOLDER evidence includes: 1) CVE-2017-7544 affects versions 0.6.21 and prior; 2) CVE-2020-13112 impacts versions before 0.6.22. The file dynamically links to libm.so.0 and libc.so.0.
- **Keywords:** libexif.so.12, libm.so.0, libc.so.0, ELF, ARM, stripped, exif_data_save_data, exif_mnote_data_ref
- **Notes:** Since the file has been stripped of symbols and version information, it is recommended to obtain more accurate version details through the following methods: 1) Check the package manager or dependencies; 2) Review build information or source code; 3) Upgrade to libexif 0.6.22 or later to address known vulnerabilities.

---
