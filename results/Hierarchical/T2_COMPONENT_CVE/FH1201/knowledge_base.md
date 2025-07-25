# FH1201 (83 alerts)

---

### vulnerability-CVE-2018-6692

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `usr/lib/libupnp.so:HIDDEN`
- **Risk Score:** 10.0
- **Confidence:** 7.75
- **Description:** Stack-based Buffer Overflow vulnerability in libUPnPHndlr.so (CVSS: 10.0)
- **Keywords:** libUPnPHndlr.so, Stack-based Buffer Overflow
- **Notes:** Verify whether the vulnerability affects UPnP Stack version 6.37.14.9.

---
### SBOM-zlib

- **File/Directory Path:** `bin/logserver`
- **Location:** `bin/logserver`
- **Risk Score:** 9.8
- **Confidence:** 9.75
- **Description:** SBOM analysis results for the third-party component zlib (libz.so) referenced in file 'bin/logserver'. Multiple critical vulnerabilities were identified, which may allow attackers to execute arbitrary code, cause heap buffer overflows, or exploit improper pointer arithmetic. Version information is unknown.
- **Keywords:** zlib, libz.so, CVE-2002-0059, CVE-2016-9841, CVE-2016-9843, CVE-2019-12874, CVE-2022-37434, CVE-2023-45853, CVE-2016-9840, CVE-2016-9842, CVE-2023-48106, CVE-2023-48107
- **Notes:** Further confirmation of the specific version of zlib is required to determine which vulnerabilities are applicable.

---
### thirdparty-BusyBox-v1.13.0

- **File/Directory Path:** `bin/ate`
- **Location:** `bin/ate`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** The BusyBox component was found in the file 'bin/ate', version v1.13.0 (released in 2009). Multiple high-risk vulnerabilities (CVE-2016-2148, CVE-2016-5791, CVE-2017-16544, CVE-2022-48174) exist, with CVSS scores ranging from 8.8 to 9.8. The vulnerabilities include: Heap-based buffer overflow in the DHCP client (udhcpc), undocumented BusyBox Linux shell accessible over TELNET without authentication, tab autocomplete feature does not sanitize filenames, and stack overflow vulnerability in ash.c.
- **Code Snippet:**
  ```
  Found in strings output: 'BusyBox v1.13.0 (2013-08-29 17:44:59 CST)'
  ```
- **Keywords:** BusyBox, v1.13.0
- **Notes:** BusyBox 1.13.0 is a version released in 2009 and contains multiple critical vulnerabilities. It is recommended to upgrade to a supported version (currently 1.36.x).

---
### component-uClibc-0.9.29

- **File/Directory Path:** `bin/dhcps`
- **Location:** `bin/dhcps`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The file 'bin/dhcps' contains uClibc component version 0.9.29 (inferred), which has multiple critical vulnerabilities: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6). Evidence source: dynamically linked to '/lib/ld-uClibc.so.0', with version string '0.9.29' found in other files.
- **Code Snippet:**
  ```
  HIDDEN '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** uClibc, /lib/ld-uClibc.so.0, libpthread.so.0
- **Notes:** The version information of uClibc is inferred based on indirect evidence. For precise analysis, it is necessary to examine the specific library files. It is recommended to prioritize updating this component.

---
### SBOM-libcommon.so

- **File/Directory Path:** `bin/logserver`
- **Location:** `bin/logserver`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** SBOM analysis results of the third-party component libcommon.so referenced in file 'bin/logserver'. 7 critical CVE vulnerabilities were identified, primarily involving remote command execution and buffer overflow issues. These vulnerabilities allow attackers to execute arbitrary system commands with REDACTED_PASSWORD_PLACEHOLDER privileges or cause denial of service. Version information is unknown.
- **Keywords:** libcommon.so, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, GetValue
- **Notes:** Since the specific version of libcommon.so cannot be determined, this vulnerability information is for reference only. It is recommended to further analyze the actual functional implementation of libcommon.so in the firmware to confirm the existence of vulnerabilities.

---
### component-uclibc-unknown

- **File/Directory Path:** `bin/tqu`
- **Location:** `bin/tqu (HIDDEN readelf HIDDEN: NEEDED library [libc.so.0] HIDDEN: interpreter /lib/ld-uClibc.so.0 HIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** Found uClibc library (version unknown) in file 'bin/tqu', linked to /lib/ld-uClibc.so.0. Multiple critical vulnerabilities exist in uClibc/uClibC-ng (10 CVEs identified), risk level: 9.8 (CRITICAL).
- **Code Snippet:**
  ```
  interpreter /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523, CVE-2016-6264, CVE-2016-2224, CVE-2016-2225, CVE-2017-9729, CVE-2021-27419, CVE-2022-30295, CVE-2024-40090
- **Notes:** Version information evidence source: readelf output: NEEDED library [libc.so.0] and strings output: interpreter /lib/ld-uClibc.so.0. Further analysis is required to confirm the specific version and vulnerability applicability.

---
### third-party-uClibc

- **File/Directory Path:** `bin/unmkpkg`
- **Location:** `bin/unmkpkg`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Dynamic linking information
  ```
- **Keywords:** uClibc, /lib/ld-uClibc.so.0, CVE
- **Notes:** configuration_load

---
### openssl-cve-2003-0545

- **File/Directory Path:** `bin/ses`
- **Location:** `bin/ses`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** OpenSSL version 0.9.7 contains a double-free vulnerability where remote attackers can cause denial of service (crash) and potentially execute arbitrary code by sending SSL client certificates with specially crafted invalid ASN.1 encodings.
- **Code Snippet:**
  ```
  DH_generate_key
  DH_compute_key
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** DH_generate_key, DH_compute_key, GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** CVE-2003-0545 affects OpenSSL version 0.9.7 and may be related to the OpenSSL version used in bin/ses.

---
### SBOM-uClibc-CVEs

- **File/Directory Path:** `usr/sbin/wlconf`
- **Location:** `usr/sbin/wlconf`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** uClibc vulnerability assessment. Multiple critical CVEs exist (CVSSv3 score 9.8) for this embedded C library. Exact version could not be determined from binary.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** /lib/ld-uClibc.so.0, uClibc, CVE
- **Notes:** configuration_load

---
### sbom-component-libupnp

- **File/Directory Path:** `usr/sbin/igd`
- **Location:** `usr/sbin/igd:0 (reference to libupnp.so)`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** References to the libupnp component (libupnp.so) were found in the igd binary file, which contains multiple high-risk vulnerabilities, including remote code execution and denial-of-service vulnerabilities. Further analysis of the libupnp.so file is required to determine the exact version and verify the applicability of the vulnerabilities.
- **Code Snippet:**
  ```
  Found reference to libupnp.so in igd binary
  ```
- **Keywords:** libupnp.so, igd
- **Notes:** Known CVEs: CVE-2018-6692 (stack overflow, CVSS 9.8), CVE-2016-8863 (heap overflow, CVSS 9.8), CVE-2020-13848 (null pointer dereference, CVSS 7.5), CVE-2016-6255 (arbitrary file write, CVSS 8.8)

---
### sbom-component-uClibc

- **File/Directory Path:** `usr/sbin/igd`
- **Location:** `usr/sbin/igd:0 (reference to ld-uClibc.so.0)`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** References to the uClibc component (ld-uClibc.so.0) were found in the igd binary file, containing multiple critical vulnerabilities including remote code execution and DNS spoofing vulnerabilities. Further analysis of /lib/ld-uClibc.so.0 is required to determine the exact version.
- **Code Snippet:**
  ```
  Found reference to ld-uClibc.so.0 in igd binary
  ```
- **Keywords:** ld-uClibc.so.0, igd
- **Notes:** Known CVEs: CVE-2017-9728 (out-of-bounds read, CVSS 9.8), CVE-2022-29503 (memory corruption, CVSS 9.8), CVE-2021-43523 (DNS spoofing, CVSS 9.6), CVE-2016-6264 (integer sign error, CVSS 7.5)

---
### vulnerability-CVE-2016-8863

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `usr/lib/libupnp.so:HIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 7.75
- **Description:** Heap-based buffer overflow in the create_url_list function (CVSS: 9.8)
- **Keywords:** create_url_list, Heap-based buffer overflow
- **Notes:** Verify whether this vulnerability affects the UPnP Stack version 6.37.14.9.

---
### thirdparty-zlib-netctrl

- **File/Directory Path:** `bin/netctrl`
- **Location:** `bin/netctrl`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The zlib library found in the 'bin/netctrl' file is linked to libz.so. Multiple critical vulnerabilities exist: CVE-2002-0059 (CVSS 9.8, double-free vulnerability), CVE-2016-9841 (CVSS 9.8, pointer arithmetic issue), and CVE-2022-37434 (CVSS 9.8, heap buffer over-read/overflow). The version is unknown and requires further verification.
- **Code Snippet:**
  ```
  Linked library: libz.so
  ```
- **Keywords:** libz.so, zlib
- **Notes:** Since the exact version information of zlib cannot be obtained, it is recommended to check for the presence of the libz.so file in the firmware to determine the specific version.

---
### SBOM-zlib-libz.so

- **File/Directory Path:** `bin/envram`
- **Location:** `bin/envram`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The zlib component (libz.so) found in the file 'bin/envram' has an unspecified version. Multiple high-risk CVE vulnerabilities are present, including CVE-2002-0059 (Double free), CVE-2016-9841 (Pointer arithmetic issue), CVE-2016-9843 (CRC calculation issue), CVE-2022-37434 (Heap-based buffer overflow), and CVE-2023-45853 (Integer overflow in MiniZip). Further verification of the specific version is required to determine which vulnerabilities are applicable.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libz.so
- **Notes:** Verify the specific version of zlib to determine which vulnerabilities are applicable.

---
### SBOM-Broadcom-WiFi-6.37.14.34

- **File/Directory Path:** `webroot/nvram_default.cfg`
- **Location:** `webroot/nvram_default.cfg (wl_version)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The Broadcom Wi-Fi driver/firmware version 6.37.14.34 (r415984) was detected in the file 'nvram_default.cfg', which is associated with multiple critical CVE vulnerabilities.  
- CVE-2016-0801 (CVSS 9.8): Memory corruption vulnerability allowing remote code execution  
- CVE-2017-0561 (CVSS 9.8): Wi-Fi firmware remote code execution vulnerability  
- CVE-2017-9417 (CVSS 9.8): Broadpwn vulnerability affecting BCM43xx chips  
Although the version number does not directly match, these critical vulnerabilities indicate severe risks in the Broadcom component.
- **Keywords:** nvram_default.cfg, wl_version, Broadcom Wi-Fi Driver/Firmware
- **Notes:** Version evidence source: wl_version field in nvram_default.cfg

---
### sbom-libz-unknown

- **File/Directory Path:** `bin/arptool`
- **Location:** `bin/arptool`
- **Risk Score:** 9.8
- **Confidence:** 7.0
- **Description:** libz version unknown (needs verification) found via string 'libz.so'. Multiple critical CVEs potentially affecting: CVE-2002-0059 (zlib 1.1.3 and earlier, CVSS 9.8), CVE-2022-37434 (through 1.2.12, CVSS 9.8), CVE-2023-45853 (through 1.3, CVSS 9.8).
- **Code Snippet:**
  ```
  String 'libz.so'
  ```
- **Keywords:** libz, libz.so, CVE-2002-0059, CVE-2022-37434, CVE-2023-45853
- **Notes:** configuration_load

---
### thirdparty-rp-pppoe-potential_vulnerabilities

- **File/Directory Path:** `bin/pppoeconfig.sh`
- **Location:** `pppoeconfig.sh`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** The pppoeconfig.sh script was found to reference the pppd and rp-pppoe.so components. A CVE search revealed that the rp-pppoe component has two known critical vulnerabilities: CVE-2022-24029 (CVSSv3: 9.8) and CVE-2001-0026. Further version verification is required to confirm the vulnerability impact.
- **Keywords:** pppd_wan0, rp-pppoe.so, CVE-2022-24029, CVE-2001-0026
- **Notes:** It is recommended to check the following files for precise version information: 1. /bin/pppd or REDACTED_PASSWORD_PLACEHOLDER 2. /lib/rp-pppoe.so 3. Other configuration files that may contain version information. Further analysis of these files is required to confirm whether vulnerabilities exist.

---
### SBOM-uClibc-Unknown

- **File/Directory Path:** `bin/et`
- **Location:** `bin/et (strings output)`
- **Risk Score:** 9.5
- **Confidence:** 8.0
- **Description:** The use of the uClibc library was detected in the file bin/et, but the exact version could not be determined. This library contains multiple critical vulnerabilities: CVE-2017-9728 (out-of-bounds read vulnerability in regular expression processing, CVSS 9.8), CVE-2022-29503 (memory corruption vulnerability caused by thread allocation, CVSS 9.8), and CVE-2021-43523 (domain name validation vulnerability in DNS resolution, CVSS 9.6).
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** bcm57, /lib/ld-uClibc.so.0
- **Notes:** Further analysis of other files is required to determine the exact version of uClibc.

---
### SBOM-MiniUPnPd-1.4

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** MiniUPnPd 1.4 component. Known vulnerabilities include:
- CVE-2013-0229: Buffer over-read vulnerability in the REDACTED_SECRET_KEY_PLACEHOLDER function, which may cause service crashes
Affected versions are MiniUPnPd before 1.4. Verification is required to determine whether the current version has been patched.
- **Code Snippet:**
  ```
  HIDDEN: 'R9/1.0.0 UPnP/1.0 MiniUPnPd/1.4'
  ```
- **Keywords:** MiniUPnPd/1.4
- **Notes:** It is recommended to verify whether the CVE-2013-0229 vulnerability has been fixed

---
### component-matrixssl-unknown

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The MatrixSSL component was found in the 'bin/httpd' file, with an unspecified version but containing relevant function calls. Known related vulnerabilities include: CVE-2016-6890 (memory corruption vulnerability potentially leading to remote code execution) and CVE-2017-2780 (flaws in TLS/DTLS implementation).
- **Code Snippet:**
  ```
  HIDDEN'bin/httpd'HIDDEN'REDACTED_SECRET_KEY_PLACEHOLDER'HIDDEN
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, matrixSslOpen, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to further confirm the specific version of MatrixSSL to assess the impact of the vulnerability.

---
### thirdparty-zlib-delay_reboot

- **File/Directory Path:** `bin/delay_reboot`
- **Location:** `bin/delay_reboot`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** A reference to the zlib dynamic link library was found in the 'bin/delay_reboot' file, but no specific version information was identified. Known related high-risk vulnerabilities include: CVE-2002-0059 (Double free vulnerability, CVSS 9.8), CVE-2016-9841 (pointer arithmetic error in inffast.c, CVSS 9.8), CVE-2016-9843 (issue in the crc32_big function, CVSS 9.8), and CVE-2022-37434 (heap buffer overflow, CVSS 9.8). Evidence source: The dynamic link library reference 'libz.so' was discovered via the strings command.
- **Code Snippet:**
  ```
  HIDDENstringsHIDDEN：libz.so
  ```
- **Keywords:** libz.so
- **Notes:** Further confirmation of the specific version of zlib is required to determine which vulnerabilities apply.

---
### SBOM-uClibc-Unknown

- **File/Directory Path:** `bin/igs`
- **Location:** `bin/igs: Dynamic library linkage (/lib/ld-uClibc.so.0)`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** uClibc was detected in dynamic library linking, but the specific version could not be determined. Multiple critical vulnerabilities (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523) were identified, all with CVSS scores above 9.6.
- **Code Snippet:**
  ```
  Evidence from strings output in 'bin/igs' (references to /lib/ld-uClibc.so.0)
  ```
- **Keywords:** uClibc, libc.so.0, /lib/ld-uClibc.so.0, igs, IGMP, MIPS
- **Notes:** configuration_load

---
### thirdparty-component-uClibc

- **File/Directory Path:** `bin/ddostool`
- **Location:** `bin/ddostool`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** References to the third-party component uClibc were found in the file 'bin/ddostool', but the specific version could not be determined. Multiple high-risk CVEs may affect this component.
- **Code Snippet:**
  ```
  HIDDEN '/lib/ld-uClibc.so.0' HIDDEN '__uClibc_main' HIDDEN
  ```
- **Keywords:** /lib/ld-uClibc.so.0, __uClibc_main, libc.so.0
- **Notes:** Since the specific version of uClibc cannot be determined, all related CVEs should be considered potentially relevant. It is recommended to obtain the actual uClibc library file to identify its exact version. The related CVEs include: CVE-2017-9728 (9.8), CVE-2022-29503 (9.8), CVE-2021-43523 (9.6), CVE-2016-6264 (7.5), CVE-2021-27419 (7.3)

---
### SBOM-libnvram.so

- **File/Directory Path:** `bin/logserver`
- **Location:** `bin/logserver`
- **Risk Score:** 8.8
- **Confidence:** 8.5
- **Description:** The SBOM analysis results of the third-party component libnvram.so referenced in the file 'bin/logserver' reveal 3 high-risk vulnerabilities. These vulnerabilities exist in the InHand Networks InRouter302 V3.5.4 version. The vulnerabilities involve the nvram_import function of libnvram.so, enabling attackers to achieve remote code execution through specially crafted files. Version information is unknown.
- **Keywords:** libnvram.so, nvram_import, user_define_init, user_define_print, user_define_set_item, user_define_timeout
- **Notes:** Unable to directly access the libnvram.so file, version information cannot be confirmed. It is recommended to verify whether the firmware uses InRouter302 V3.5.4 version. Includes CVE-2022-26780, CVE-2022-26781, CVE-2022-26782.

---
### thirdparty-libnvram.so

- **File/Directory Path:** `bin/ate`
- **Location:** `bin/ate`
- **Risk Score:** 8.8
- **Confidence:** 8.0
- **Description:** The third-party component libnvram.so was found in the file 'bin/ate', with an unknown version (from InRouter302 V3.5.4). Multiple high-risk vulnerabilities (CVE-2022-26780, CVE-2022-26781, CVE-2022-26782) exist, all with a CVSS score of 8.8. Vulnerability description: Multiple improper input validation vulnerabilities exist in the libnvram.so nvram_import functionality. A specially-crafted file can lead to remote code execution.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** libnvram.so, nvram_import
- **Notes:** The exact version of the library in the current firmware needs to be confirmed to assess the actual risk. Source of evidence: Strings in the 'bin/ate' file and NVD database search.

---
### thirdparty-libnvram.so

- **File/Directory Path:** `usr/sbin/igdnat`
- **Location:** `usr/sbin/igdnat (HIDDEN)`
- **Risk Score:** 8.8
- **Confidence:** 8.0
- **Description:** The third-party component libnvram.so, identified during the analysis of 'usr/sbin/igdnat' and its dependent libraries, may belong to InRouter302 version V3.5.4. Known high-risk vulnerabilities include:
- CVE-2022-26780: Input validation vulnerability in the nvram_import function of libnvram.so (CVSS 8.8, remote code execution)
- CVE-2022-26781: Input validation vulnerability in the nvram_import function of libnvram.so (CVSS 8.8, remote code execution)
- CVE-2022-26782: Input validation vulnerability in the nvram_import function of libnvram.so (CVSS 8.8, remote code execution)
Evidence source: Confirmed through string analysis and NVD database comparison
- **Keywords:** libnvram.so, nvram_import, InRouter302 V3.5.4
- **Notes:** It is recommended to check all components that use libnvram.so

---
### SBOM-libnvram.so

- **File/Directory Path:** `bin/wlconf`
- **Location:** `bin/wlconf (strings output)`
- **Risk Score:** 8.8
- **Confidence:** 7.0
- **Description:** The libnvram.so library, version unspecified, with evidence derived from string analysis of the 'bin/wlconf' file. Known CVEs include: CVE-2022-26780 (CVSS 8.8), CVE-2022-26781 (CVSS 8.8), CVE-2022-26782 (CVSS 8.8), all involving input validation issues that may lead to remote code execution.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** libnvram.so
- **Notes:** The vulnerability information for libnvram.so is sourced from known CVE databases. It is recommended to further verify the presence of this file in the firmware and its specific version.

---
### component-libnvram.so

- **File/Directory Path:** `usr/sbin/acsd`
- **Location:** `acsd (HIDDENstringsHIDDEN)`
- **Risk Score:** 8.8
- **Confidence:** 5.0
- **Description:** References to the libnvram.so dynamic library were found in the binary file acsd. Potential vulnerabilities include CVE-2022-26780, CVE-2022-26781, and CVE-2022-26782, which involve improper input validation in the nvram_import function, potentially leading to remote code execution. The exact version of libnvram.so needs to be confirmed to determine vulnerability applicability.
- **Code Snippet:**
  ```
  HIDDENstringsHIDDEN
  ```
- **Keywords:** libnvram.so, nvram_get
- **Notes:** Confirming the exact version of libnvram.so is required to determine vulnerability applicability.

---
### component-http_server-2.1.8

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The HTTP Server component was found in the 'bin/httpd' file, version 2.1.8. Further research is needed to determine whether this version of the HTTP server has any known vulnerabilities.
- **Code Snippet:**
  ```
  HIDDEN'bin/httpd'HIDDEN
  ```
- **Keywords:** Http Server 2.1.8
- **Notes:** It is recommended to further investigate the known vulnerabilities in HTTP Server version 2.1.8.

---
### SBOM-Linux-Kernel-2.6.22

- **File/Directory Path:** `lib/libChipApi.so`
- **Location:** `libChipApi.so (strings output: /lib/modules/2.6.22/)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Linux Kernel version 2.6.22 component, containing multiple high-risk CVE vulnerabilities (total of 22 related CVEs, the most severe 3 being: CVE-2008-2931 - privilege check vulnerability, CVSS 7.8; CVE-2017-2634 - memory corruption vulnerability, CVSS 7.5; CVE-2008-4302 - denial of service vulnerability, CVSS 5.5). Evidence source: libChipApi.so (strings output: /lib/modules/2.6.22/)
- **Keywords:** Linux Kernel 2.6.22, /lib/modules/2.6.22/
- **Notes:** A total of 22 related CVEs were found, with the top 3 most severe ones listed above. Please refer to the analysis results for the complete list.

---
### SBOM-uClibc-0.9.29

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `lib/libpthread.so.0`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The uClibc 0.9.29 version is extremely outdated and may contain undocumented security vulnerabilities. Potential issues include:  
- Memory corruption  
- Regex processing flaws  
- DNS-related vulnerabilities  
These could lead to remote code execution or denial of service.
- **Code Snippet:**
  ```
  HIDDEN: '0.9.29'
  ```
- **Keywords:** uClibc 0.9.29
- **Notes:** It is recommended to upgrade uClibc to a newer version to address potential security issues.

---
### thirdparty-libm-uClibc

- **File/Directory Path:** `lib/libm.so.0`
- **Location:** `lib/libm.so.0`
- **Risk Score:** 8.5
- **Confidence:** 6.75
- **Description:** Analysis of 'lib/libm.so.0' reveals it is a MIPS32 architecture dynamic link library, linked with uClibc (SONAME: libm.so.0) and compiled by GCC 4.2.3. While the specific version of the math library cannot be determined from the binary, the uClibc version used by this system contains multiple known vulnerabilities. The most critical security flaws affect uClibc versions around 0.9.33.2, including memory corruption issues, regular expression processing defects, and DNS-related vulnerabilities, which could potentially lead to remote code execution or denial-of-service attacks.
- **Code Snippet:**
  ```
  GCC: (GNU) 4.2.3
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** libm.so.0, uClibc, GCC 4.2.3, libc.so.0, ld-uClibc.so.0
- **Notes:** configuration_load

---
### SBOM-BusyBox-1.13.0

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** BusyBox 1.13.0 component, released in 2008. Known vulnerabilities include:
- CVE-2011-5325: Directory traversal vulnerability affecting tar implementation
- CVE-2016-2147: DHCP client integer overflow
- CVE-2016-2148: DHCP client heap overflow
- CVE-2016-6301: NTP service denial of service
Since version 1.13.0 predates the discovery of these vulnerabilities, theoretically all of them could affect the 1.13.0 version.
- **Code Snippet:**
  ```
  HIDDEN: 'BusyBox v1.13.0 (2013-08-29 17:44:59 CST)'
  ```
- **Keywords:** BusyBox v1.13.0
- **Notes:** It is recommended to upgrade BusyBox to the latest version to fix multiple high-risk vulnerabilities.

---
### thirdparty-bzip2-version-info

- **File/Directory Path:** `bin/unbzip2`
- **Location:** `bin/unbzip2: HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Version information 1.0.6 of the bzip2/libbzip2 component was detected in the file bin/unbzip2. This version contains multiple known critical vulnerabilities, including CVE-2019-12900 (score 9.8), CVE-2016-3189 (score 6.5), and CVE-2010-0405. It is recommended to upgrade to the latest version to fix these vulnerabilities. The version evidence originates from the version string in the file.
- **Code Snippet:**
  ```
  bzip2/libbzip2: internal error number %d.
  This is a bug in bzip2/libbzip2, %s.
  Please report it to me at: jseward@bzip.org...1.0.6, 6-Sept-2010
  ```
- **Keywords:** bzip2/libbzip2, 1.0.6, BZ2_decompress, BZ2_bzlibVersion
- **Notes:** It is recommended to upgrade to the latest version of bzip2 to fix these vulnerabilities. Related CVEs: CVE-2019-12900, CVE-2016-3189, CVE-2010-0405

---
### thirdparty-uClibc-unknown

- **File/Directory Path:** `bin/cfm_check`
- **Location:** `bin/cfm_check`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The uClibc component was identified in the file 'bin/cfm_check', but the version is unknown, with evidence being the string '/lib/ld-uClibc.so.0'. Multiple high-risk vulnerabilities were detected, including CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6), etc. It is recommended to further analyze the '/lib/ld-uClibc.so.0' file to obtain precise version information.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, ld-uClibc.so.0
- **Notes:** Unable to determine the specific version of uClibc, it is recommended to further analyze the '/lib/ld-uClibc.so.0' file to obtain accurate version information.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `bin/pptp_callmgr`
- **Location:** `pptp_callmgr binary`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The uClibc 0.9.33.2 component contains multiple critical vulnerabilities:
1. CVE-2017-9728: Out-of-bounds read vulnerability in regular expression processing (CVSS 9.8)
2. CVE-2022-29503: Memory corruption vulnerability caused by thread allocation (CVSS 9.8)
3. CVE-2021-43523: Domain name processing vulnerability potentially leading to remote code execution (CVSS 9.6)
The version number is estimated based on references to /lib/ld-uClibc.so.0
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** The version number is an estimated value; it is recommended to check the /lib directory to confirm the exact version.

---
### component-UPnP_Stack-6.37.14.9

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `usr/lib/libupnp.so:HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Version information for the UPnP Stack component (6.37.14.9) was found in the 'usr/lib/libupnp.so' file. While no CVEs directly matching this version were identified, multiple potentially applicable generic vulnerabilities exist. It is recommended to further verify whether these vulnerabilities affect this specific version.
- **Code Snippet:**
  ```
  Server: POSIX, UPnP/1.0 %s/%s
  UPnP Stack
  6.37.14.9
  ```
- **Keywords:** libupnp.so, UPnP Stack, 6.37.14.9, GCC 4.2.3, CVE-2018-6692, CVE-2016-8863, CVE-2016-6255, CVE-2020-13848
- **Notes:** Further verification is required to confirm whether this version is affected by these vulnerabilities. It is recommended to conduct more in-depth binary analysis to validate version information and vulnerability applicability.

---
### sbom-GLIBC-2.0

- **File/Directory Path:** `bin/arptool`
- **Location:** `libgcc_s.so.1`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** GLIBC version 2.0 required by libgcc_s.so.1. CVE-2010-0830 (elf_get_dynamic_info integer signedness error) affecting GLIBC 2.0.1-2.11.1 with CVSS 8.0. Requires user-assisted attack vector.
- **Code Snippet:**
  ```
  Required by libgcc_s.so.1
  ```
- **Keywords:** GLIBC, 2.0, libgcc_s.so.1, CVE-2010-0830
- **Notes:** configuration_load

---
### openssl-library-bin-ses

- **File/Directory Path:** `bin/ses`
- **Location:** `bin/ses`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The file 'bin/ses' is an executable that utilizes the OpenSSL library and was compiled with GCC 3.3.2 and 4.2.3. Although the OpenSSL version number was not directly identified, it can be inferred that the OpenSSL version is likely compatible with these compiler versions based on the GCC versions. It is recommended to further analyze the specific version of OpenSSL to more accurately match relevant CVE vulnerabilities. Additional version information can be obtained by examining the shared libraries the file depends on, such as libbcmcrypto.so.
- **Code Snippet:**
  ```
  DH_generate_key
  DH_compute_key
  SHA1Reset
  SHA1Input
  SHA1Result
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** DH_generate_key, DH_compute_key, SHA1Reset, SHA1Input, SHA1Result, GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** It is recommended to further analyze the specific version number of OpenSSL to more accurately match relevant CVE vulnerabilities. Additional version information can be obtained by examining the shared libraries (such as libbcmcrypto.so) on which the file depends.

---
### thirdparty-uClibc-netctrl

- **File/Directory Path:** `bin/netctrl`
- **Location:** `bin/netctrl`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The uClibc library found in the 'bin/netctrl' file, evidence string: /lib/ld-uClibc.so.0. Vulnerabilities present: CVE-2017-9728 (memory corruption), CVE-2022-29503 (DNS issue). Version unknown, requires further verification.
- **Code Snippet:**
  ```
  String found: /lib/ld-uClibc.so.0
  ```
- **Keywords:** ld-uClibc.so.0, uClibc
- **Notes:** It is recommended to further confirm the specific version of uClibc for a more precise vulnerability match.

---
### SBOM-uClibc-Unknown

- **File/Directory Path:** `bin/cfmd`
- **Location:** `bin/cfmd strings output`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The uClibc component was detected in the file 'bin/cfmd', with an unknown version (confirmed by the presence of '/lib/ld-uClibc.so.0'). Known critical vulnerabilities include: CVE-2022-29503 (memory corruption vulnerability, high CVSS score), CVE-2017-9728 (out-of-bounds read vulnerability, high CVSS score), and CVE-2021-43523 (multiple vulnerabilities, medium CVSS score). It is recommended to inspect the firmware filesystem for version-specific files.
- **Keywords:** uClibc, CVE-2022-29503, CVE-2017-9728, CVE-2021-43523
- **Notes:** configuration_load

---
### sbom-component-GCC_Compiler-3.3.2

- **File/Directory Path:** `bin/lld2d`
- **Location:** `bin/lld2d:0 (compiler string) 'GCC: (GNU) 3.3.2'`
- **Risk Score:** 8.0
- **Confidence:** 5.5
- **Description:** GCC Compiler version 3.3.2 identified in binary 'bin/lld2d'. Evidence found in multiple 'GCC: (GNU)' version strings. GCC 3.3.2 is a very old version with known vulnerabilities.
- **Code Snippet:**
  ```
  Compiler version string in binary: 'GCC: (GNU) 3.3.2'
  ```
- **Keywords:** lld2d, GCC: (GNU) 3.3.2, GCC Compiler
- **Notes:** configuration_load

---
### sbom-component-GCC_Compiler-4.2.3

- **File/Directory Path:** `bin/lld2d`
- **Location:** `bin/lld2d:0 (compiler string) 'GCC: (GNU) 4.2.3'`
- **Risk Score:** 8.0
- **Confidence:** 5.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Compiler version string in binary: 'GCC: (GNU) 4.2.3'
  ```
- **Keywords:** lld2d, GCC: (GNU) 4.2.3, GCC Compiler
- **Notes:** configuration_load

---
### third-party-GCC-3.3.2

- **File/Directory Path:** `bin/emf`
- **Location:** `bin/emf`
- **Risk Score:** 7.8
- **Confidence:** 7.9
- **Description:** The GCC compiler version 3.3.2 was found in the file 'bin/emf', confirmed by the string 'GCC: (GNU) 3.3.2'. Due to NVD API limitations, CVE information for this version could not be retrieved; manual query is recommended.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** GCC 3.3.2
- **Notes:** It is recommended to manually query the CVE information for 'GCC 3.3.2' further.

---
### third-party-GCC-4.2.3

- **File/Directory Path:** `bin/emf`
- **Location:** `bin/emf`
- **Risk Score:** 7.8
- **Confidence:** 7.9
- **Description:** The GCC compiler version 4.2.3 was detected in the file 'bin/emf', confirmed by the string 'GCC: (GNU) 4.2.3'. Due to NVD API limitations, CVE information for this version could not be retrieved. Manual query is recommended.
- **Code Snippet:**
  ```
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** GCC 4.2.3
- **Notes:** It is recommended to further manually query the CVE information for 'GCC 4.2.3'.

---
### third-party-uClibc

- **File/Directory Path:** `bin/emf`
- **Location:** `bin/emf`
- **Risk Score:** 7.8
- **Confidence:** 7.9
- **Description:** The uClibc library was identified in the file 'bin/emf', confirmed by the strings '/lib/ld-uClibc.so.0' and 'libc.so.0'. Due to NVD API limitations, CVE information for this component could not be retrieved. Manual query is recommended.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc
- **Notes:** It is recommended to further manually check the CVE information for 'uClibc'.

---
### third-party-libgcc_s.so.1

- **File/Directory Path:** `bin/emf`
- **Location:** `bin/emf`
- **Risk Score:** 7.8
- **Confidence:** 7.9
- **Description:** The libgcc library was found in the file 'bin/emf', identified by the string 'libgcc_s.so.1'. Known high-risk vulnerability: CVE-2022-48422 (privilege escalation issue in ONLYOFFICE Docs).
- **Code Snippet:**
  ```
  libgcc_s.so.1
  ```
- **Keywords:** libgcc_s.so.1, CVE-2022-48422
- **Notes:** configuration_load

---
### sbom-component-dnrd-2.20.3

- **File/Directory Path:** `bin/dnrd`
- **Location:** `Embedded in binary strings`
- **Risk Score:** 7.5
- **Confidence:** 8.75
- **Description:** DNRD DNS relay daemon version 2.20.3 identified through binary strings analysis. This version contains two known vulnerabilities: CVE-2022-33992 (High severity, DNSSEC bypass) and CVE-2022-33993 (Medium severity, cache poisoning).
- **Code Snippet:**
  ```
  Version string 'dnrd version 2.20.3' found in binary strings
  ```
- **Keywords:** dnrd, 2.20.3, dnrd version %s, DNS relay, DNRD 2.20.3
- **Notes:** Version was confirmed through binary string analysis. Two critical vulnerabilities were discovered: CVE-2022-33992 (DNSSEC bypass) and CVE-2022-33993 (cache poisoning).

---
### vulnerability-CVE-2022-33992

- **File/Directory Path:** `bin/dnrd`
- **Location:** `Embedded in binary strings`
- **Risk Score:** 7.5
- **Confidence:** 8.75
- **Description:** DNRD 2.20.3 forwards and caches DNS queries with the CD (checking disabled) bit set to 1, disabling DNSSEC protection. CVSS score: 7.5 (High severity). Affects versions 2.20.3 and earlier. Mitigation: Check DNSSEC configuration and consider upgrading to a patched version.
- **Keywords:** dnrd, 2.20.3, DNSSEC, CVE-2022-33992, DNS security
- **Notes:** This vulnerability allows bypassing DNSSEC protection. Strongly recommend upgrading dnrd.

---
### component-gcc-3.3.2

- **File/Directory Path:** `bin/tqu`
- **Location:** `bin/tqu (HIDDEN 'GCC: (GNU) 3.3.2' HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The file 'bin/tqu' contains GCC version 3.3.2, which has the following critical vulnerabilities:
- CVE-2004-0174: Buffer overflow in libiberty/pexecute.c allows arbitrary code execution via crafted object files (CVSS 7.5 HIGH)
- CVE-2004-0997: The cpplib component may cause denial of service or arbitrary code execution when processing certain macros (CVSS 7.5 HIGH)
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** GCC, 3.3.2, CVE-2004-0174, CVE-2004-0997
- **Notes:** version information evidence source: strings output: 'GCC: (GNU) 3.3.2'

---
### thirdparty-zlib-1.1.4

- **File/Directory Path:** `lib/libz.so`
- **Location:** `libz.so (version strings in binary)`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** Explicit evidence of zlib version 1.1.4 was found in the file 'lib/libz.so'. This version contains the known critical vulnerability CVE-2003-0107, which may lead to denial of service or arbitrary code execution. Due to NVD API limitations, complete CVE information for this version could not be obtained. It is recommended to manually check for other known vulnerabilities in zlib 1.1.4 subsequently. Exploitation of this vulnerability requires specific compilation conditions or input truncation, and further analysis of compilation flags and usage context would help determine actual exploitability.
- **Code Snippet:**
  ```
  1.1.4
  deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly
  inflate 1.1.4 Copyright 1995-2002 Mark Adler
  ```
- **Keywords:** libz.so, zlib, 1.1.4, deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly, inflate 1.1.4 Copyright 1995-2002 Mark Adler, gzprintf, CVE-2003-0107
- **Notes:** Version evidence source: version string in libz.so. Due to NVD API limitations, complete CVE information for this version could not be obtained. It is recommended to manually check for other known vulnerabilities in zlib 1.1.4 subsequently.

---
### thirdparty-component-MiniUPnPd-1.4

- **File/Directory Path:** `bin/miniupnpd`
- **Location:** `bin/miniupnpd`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The third-party software components and their version information found in the file 'bin/miniupnpd':
- Component Name: MiniUPnPd
- Version: 1.4
- Evidence Source: String 'R9/1.0.0 UPnP/1.0 MiniUPnPd/1.4'

Related library files:
- libCfm.so
- libcommon.so
- libChipApi.so
- libnvram.so
- libshared.so
- libz.so
- libgcc_s.so.1
- libc.so.0

Known high-risk vulnerabilities:
- CVE-2013-0229 (CVSSv3 score: N/A)
  - Description: The REDACTED_SECRET_KEY_PLACEHOLDER function in minissdp.c in the SSDP handler in MiniUPnP MiniUPnPd before 1.4 allows remote attackers to cause a denial of service (service crash) via a crafted request that triggers a buffer over-read.
  - Impact: Remote attackers may cause service crashes (denial of service) through specially crafted requests.
- **Code Snippet:**
  ```
  R9/1.0.0 UPnP/1.0 MiniUPnPd/1.4
  ```
- **Keywords:** MiniUPnPd/1.4, libCfm.so, libcommon.so, libChipApi.so, libnvram.so, libshared.so, libz.so, libgcc_s.so.1, libc.so.0, REDACTED_SECRET_KEY_PLACEHOLDER, minissdp.c
- **Notes:** It is recommended to further verify whether MiniUPnPd 1.4 has fixed this vulnerability or if there are other undiscovered vulnerabilities.

---
### SBOM-pppd-2.4.5

- **File/Directory Path:** `bin/pppd`
- **Location:** `bin/pppd`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The PPPD component information extracted from the file 'bin/pppd'. Version 2.4.5 is confirmed by the string 'ppp-2.4.5'. A potential vulnerability CVE-2004-1002 exists: Integer underflow in pppd in cbcp.c for ppp 2.4.1 allows remote attackers to cause a denial of service (daemon crash) via a CBCP packet with an invalid length value. Although the vulnerability report targets version 2.4.1, similar issues may exist in version 2.4.5.
- **Code Snippet:**
  ```
  HIDDEN'ppp-2.4.5'HIDDEN
  ```
- **Keywords:** ppp-2.4.5, pppd
- **Notes:** While there is no direct CVE match for ppp 2.4.5 in the NVD, a vulnerability affecting similar versions (CVE-2004-1002) was identified. It is recommended to further inspect the code for similar issues.

---
### openssl-cve-2004-0079

- **File/Directory Path:** `bin/ses`
- **Location:** `bin/ses`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The do_change_cipher_spec function in OpenSSL 0.9.6c to 0.9.6k, and 0.9.7a to 0.9.7c, allows remote attackers to cause a denial of service (crash) via a crafted SSL/TLS handshake that triggers a null dereference.
- **Code Snippet:**
  ```
  DH_generate_key
  DH_compute_key
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** DH_generate_key, DH_compute_key, GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** CVE-2004-0079 affects OpenSSL versions 0.9.6c through 0.9.6k and 0.9.7a through 0.9.7c, potentially relating to the OpenSSL version used in bin/ses.

---
### openssl-cve-2005-2946

- **File/Directory Path:** `bin/ses`
- **Location:** `bin/ses`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** OpenSSL versions prior to 0.9.8 used MD5 by default for generating message digests instead of employing REDACTED_SECRET_KEY_PLACEHOLDER stronger algorithms, making it easier for remote attackers to forge certificates with valid certification authority signatures.
- **Code Snippet:**
  ```
  DH_generate_key
  DH_compute_key
  SHA1Reset
  SHA1Input
  SHA1Result
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** DH_generate_key, DH_compute_key, SHA1Reset, SHA1Input, SHA1Result, GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** CVE-2005-2946 affects OpenSSL versions prior to 0.9.8 and may be related to the OpenSSL version used in bin/ses.

---
### SBOM-zlib

- **File/Directory Path:** `lib/libcommon.so`
- **Location:** `libz.so`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** zlib component found, version 1.1.4. Evidence source: version strings in libz.so: 'deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly' and 'inflate 1.1.4 Copyright 1995-2002 Mark Adler'. Related CVE: CVE-2003-0107 - A buffer overflow vulnerability exists in the gzprintf function when zlib is compiled without vsnprintf or when vsnprintf is used to truncate long inputs.
- **Code Snippet:**
  ```
  deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly
  inflate 1.1.4 Copyright 1995-2002 Mark Adler
  ```
- **Keywords:** zlib, libz.so, CVE-2003-0107
- **Notes:** Check whether the gzprintf function is used in the firmware and evaluate whether its input is controllable

---
### vulnerability-CVE-2016-6255

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `usr/lib/libupnp.so:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Allows remote attackers to write to arbitrary files in the webroot (CVSS: 7.5)
- **Keywords:** webroot, arbitrary file write
- **Notes:** It is necessary to verify whether this vulnerability affects the UPnP Stack version 6.37.14.9.

---
### vulnerability-CVE-2020-13848

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `usr/lib/libupnp.so:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** NULL pointer dereference in the functions REDACTED_PASSWORD_PLACEHOLDER (CVSS: 7.5)
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, NULL pointer dereference
- **Notes:** It is necessary to verify whether this vulnerability affects the UPnP Stack version 6.37.14.9.

---
### openssl-cve-2008-0166

- **File/Directory Path:** `bin/ses`
- **Location:** `bin/ses`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.
- **Code Snippet:**
  ```
  DH_generate_key
  DH_compute_key
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** DH_generate_key, DH_compute_key, GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** CVE-2008-0166 affects OpenSSL versions 0.9.8c-1 through 0.9.8g-9 on specific Debian systems and may be related to the OpenSSL version used in bin/ses.

---
### SBOM-PPTP-multiWAN

- **File/Directory Path:** `bin/multiWAN`
- **Location:** `bin/multiWAN: pptp.so reference`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** References to PPTP components were found in the multiWAN binary file, version unknown. The PPTP protocol itself has known security vulnerabilities, and it is recommended to use more secure VPN protocols.
- **Code Snippet:**
  ```
  pptp.so
  ```
- **Keywords:** pptp.so, PPTP
- **Notes:** The PPTP protocol itself has security vulnerabilities, and it is recommended to replace it with a more secure VPN protocol.

---
### SBOM-GCC-4.2.3

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** GCC 4.2.3 compiler. Known vulnerabilities include:
- CVE-2008-1685: Behavior issue in the compiler when handling pointer and integer addition, which may lead to incorrect optimization of security protection code
Affected versions range from 4.2.0 to 4.3.0, thus potentially affecting version 4.2.3 as well.
- **Code Snippet:**
  ```
  HIDDEN: 'GCC: (GNU) 4.2.3'
  ```
- **Keywords:** GCC: (GNU) 4.2.3
- **Notes:** configuration_load

---
### thirdparty-uclibc-version

- **File/Directory Path:** `bin/igd`
- **Location:** `bin/igd: dynamic linking section`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Detected the use of the uClibc library, dynamically linked to '/lib/ld-uClibc.so.0'. Further identification of the specific version is required to correlate with CVEs.

**Version Evidence REDACTED_PASSWORD_PLACEHOLDER:
- File: 'bin/igd'
- Location: Dynamic linking section

**Potential REDACTED_PASSWORD_PLACEHOLDER:
- Older versions of uClibc may contain unpatched security vulnerabilities
- Further verification of the specific version is necessary
- **Keywords:** ld-uClibc.so.0
- **Notes:** Further verification of specific version information is required to accurately correlate with CVEs. It is recommended to use more detailed version detection tools or consult vendor documentation.

---
### thirdparty-libupnp-impl

- **File/Directory Path:** `bin/igd`
- **Location:** `bin/igd: UPnP implementation section`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The use of the libupnp library was detected, with the file containing UPnP functionality implementation. No explicit version number was mentioned.

**Version Evidence REDACTED_PASSWORD_PLACEHOLDER:
- File: 'bin/igd'
- Location: String and functionality implementation sections

**Known REDACTED_PASSWORD_PLACEHOLDER:
- CVE-2013-0229: UPnP SSDP protocol stack buffer overflow vulnerability
- CVE-2013-0230: UPnP SOAP protocol stack buffer overflow vulnerability

**Potential REDACTED_PASSWORD_PLACEHOLDER:
- Common UPnP implementation vulnerabilities may apply
- **Keywords:** libupnp.so, REDACTED_PASSWORD_PLACEHOLDER.xml, urn:schemas-upnp-org:service:REDACTED_SECRET_KEY_PLACEHOLDER:1
- **Notes:** Further clarification is needed regarding the specific version of libupnp. It is recommended to examine known vulnerabilities within the UPnP implementation.

---
### thirdparty-pptp-1.7.1

- **File/Directory Path:** `bin/pptp`
- **Location:** `bin/pptp (HIDDENstringsHIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Version information 'pptp version 1.7.1' was found in the file 'bin/pptp'. Although no CVEs directly targeting version 1.7.1 were found in NVD, multiple high-risk vulnerabilities related to the PPTP protocol were identified, which may affect any version using this protocol.
- **Code Snippet:**
  ```
  pptp version 1.7.1
  ```
- **Keywords:** pptp, pptp version 1.7.1, PPTP protocol
- **Notes:** Although no CVEs directly targeting version 1.7.1 were found, the PPTP protocol itself contains multiple high-risk vulnerabilities. It is recommended to consider upgrading or replacing it with a more secure VPN protocol. Related CVEs: CVE-2003-0356, CVE-2013-7055, CVE-2020-22724, CVE-2018-0234, CVE-2019-15261, CVE-2020-15173, CVE-2019-6611, CVE-2017-15614, CVE-2017-15615, CVE-2017-15618

---
### hardware-broadcom-model

- **File/Directory Path:** `bin/igd`
- **Location:** `bin/igd: UPnP device description XML`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Detected Broadcom hardware information: Model number '947xx'.

**Version Evidence REDACTED_PASSWORD_PLACEHOLDER:
- File: 'bin/igd'
- Location: UPnP device description XML

**Known REDACTED_PASSWORD_PLACEHOLDER:
- CVE-2018-16333: Buffer overflow vulnerability in Broadcom chipset Wi-Fi firmware

**Potential REDACTED_PASSWORD_PLACEHOLDER:
- Broadcom-specific vulnerabilities may apply
- **Keywords:** modelNumber>947xx</modelNumber
- **Notes:** Investigate specific vulnerabilities in Broadcom hardware. It is recommended to check the vendor's security bulletins.

---
### component-GCC-4.2.3

- **File/Directory Path:** `bin/nas`
- **Location:** `bin/nasHIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The GCC compiler component, version 4.2.3 (released in 2008), was identified in the file 'bin/nas'. Source of evidence: string 'GCC: (GNU) 4.2.3'. GCC 4.2.3 may contain multiple known vulnerabilities.
- **Keywords:** GCC: (GNU) 4.2.3
- **Notes:** Query known CVE vulnerabilities for GCC 4.2.3

---
### component-GCC-3.3.2

- **File/Directory Path:** `bin/nas`
- **Location:** `bin/nasHIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The GCC compiler component, version 3.3.2 (released in 2003), was identified in the file 'bin/nas'. Source of evidence: string 'GCC: (GNU) 3.3.2'. GCC 3.3.2 may contain multiple known vulnerabilities.
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** Query known CVE vulnerabilities for GCC 3.3.2

---
### SBOM-GCC-3.3.2

- **File/Directory Path:** `bin/et`
- **Location:** `bin/et (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The use of GCC version 3.3.2 was detected in the file bin/et. This version has a known vulnerability, CVE-2000-1219, which affects the -ftrapv compiler option.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** bcm57, GCC: (GNU) 3.3.2
- **Notes:** It is recommended to check whether the -ftrapv compiler option is used in the firmware.

---
### SBOM-GCC-3.3.2

- **File/Directory Path:** `usr/sbin/ufilter`
- **Location:** `ufilter (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The GCC compiler version 3.3.2 was detected in the 'usr/sbin/ufilter' file. This version is outdated and may contain security vulnerabilities. Further investigation into known vulnerabilities (CVEs) is required.
- **Code Snippet:**
  ```
  References found in strings output
  ```
- **Keywords:** GCC, 3.3.2, uClibc, ld-uClibc.so.0, libgcc_s.so.1
- **Notes:** Further investigation is required into known vulnerabilities (CVEs) of GCC 3.3.2.

---
### SBOM-GCC-4.2.3

- **File/Directory Path:** `usr/sbin/ufilter`
- **Location:** `ufilter (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The GCC compiler version 4.2.3 was detected in the 'usr/sbin/ufilter' file. This version is outdated and may contain security vulnerabilities. Further investigation into known vulnerabilities (CVEs) is required.
- **Code Snippet:**
  ```
  References found in strings output
  ```
- **Keywords:** GCC, 4.2.3, uClibc, ld-uClibc.so.0, libgcc_s.so.1
- **Notes:** Further investigation is required into the known vulnerabilities (CVEs) of GCC 4.2.3.

---
### SBOM-uClibc

- **File/Directory Path:** `usr/sbin/ufilter`
- **Location:** `ufilter (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** References to the uClibc dynamic library were detected in the 'usr/sbin/ufilter' file. Further identification of its exact version is required to assess the security status.
- **Code Snippet:**
  ```
  References found in strings output
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, libgcc_s.so.1
- **Notes:** Further confirmation of the exact version of uClibc is required to assess its security status.

---
### SBOM-libgcc_s.so.1

- **File/Directory Path:** `usr/sbin/ufilter`
- **Location:** `ufilter (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A reference to libgcc_s.so.1 was found in the 'usr/sbin/ufilter' file. Further verification is required to determine its exact version for security assessment purposes.
- **Code Snippet:**
  ```
  References found in strings output
  ```
- **Keywords:** libgcc_s.so.1, uClibc, ld-uClibc.so.0
- **Notes:** Further verification is required to determine the exact version of libgcc_s.so.1 in order to assess its security status.

---
### component-GCC-3.3.2

- **File/Directory Path:** `usr/sbin/acs_cli`
- **Location:** `usr/sbin/acs_cli`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** GCC version 3.3.2 was found in usr/sbin/acs_cli. This version is relatively old and may contain known vulnerabilities.
- **Code Snippet:**
  ```
  Found in strings within 'usr/sbin/acs_cli'
  ```
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** configuration_load

---
### component-GCC-4.2.3

- **File/Directory Path:** `usr/sbin/acs_cli`
- **Location:** `usr/sbin/acs_cli`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Found GCC version 4.2.3 in usr/sbin/acs_cli. This version is also old and may have known vulnerabilities.
- **Code Snippet:**
  ```
  Found in strings within 'usr/sbin/acs_cli'
  ```
- **Keywords:** GCC: (GNU) 4.2.3
- **Notes:** This version of GCC is also outdated and may contain known vulnerabilities.

---
### thirdparty-GCC-delay_reboot

- **File/Directory Path:** `bin/delay_reboot`
- **Location:** `bin/delay_reboot`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** GCC compiler version information found in the 'bin/delay_reboot' file. Version 3.3.2 is extremely outdated (released in 2003) and known to contain multiple vulnerabilities that were fixed in subsequent versions; version 4.2.3 has no reports of critical vulnerabilities found in NVD. Evidence source: Compiler version strings identified in the binary file via the strings command.
- **Code Snippet:**
  ```
  HIDDENstringsHIDDEN：GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (GNU) 4.2.3
- **Notes:** The GCC 3.3.2 version is extremely outdated, and upgrading the compiler should be considered.

---
### third-party-GCC-3.3.2

- **File/Directory Path:** `bin/unmkpkg`
- **Location:** `bin/unmkpkg`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** analysis identified GCC compiler version 3.3.2 in binary 'bin/unmkpkg'. Version strings found in binary. Known vulnerabilities could not be retrieved due to NVD API rate limiting (requires manual verification at https://nvd.nist.gov/).
- **Code Snippet:**
  ```
  Version strings found in binary
  ```
- **Keywords:** GCC 3.3.2, CVE
- **Notes:** For complete vulnerability assessment: Manually verify GCC vulnerabilities at https://nvd.nist.gov/

---
### third-party-GCC-4.2.3

- **File/Directory Path:** `bin/unmkpkg`
- **Location:** `bin/unmkpkg`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Analysis identified GCC compiler version 4.2.3 in binary 'bin/unmkpkg'. Version strings found in binary. Known vulnerabilities could not be retrieved due to NVD API rate limiting (requires manual verification at https://nvd.nist.gov/).
- **Code Snippet:**
  ```
  Version strings found in binary
  ```
- **Keywords:** GCC 4.2.3, CVE
- **Notes:** For complete vulnerability assessment: Manually verify GCC vulnerabilities at https://nvd.nist.gov/

---
### component-uclibc-unknown

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The uClibc component was found in the 'bin/httpd' file, but the version is not explicitly stated. Further confirmation of the specific uClibc version is required to check for known vulnerabilities.
- **Code Snippet:**
  ```
  HIDDEN'bin/httpd'HIDDEN'/lib/ld-uClibc.so.0'HIDDEN
  ```
- **Keywords:** uClibc
- **Notes:** Further confirmation is required for the specific version of uClibc.

---
### SBOM-GCC-3.3.2

- **File/Directory Path:** `usr/sbin/wlconf`
- **Location:** `usr/sbin/wlconf (strings)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** GCC compiler version 3.3.2 found in wlconf binary strings. Older GCC version with potential vulnerabilities that should be checked against known CVEs.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** configuration_load

---
### SBOM-GCC-3.3.2-CVEs

- **File/Directory Path:** `usr/sbin/wlconf`
- **Location:** `usr/sbin/wlconf (strings)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** GCC compiler version 3.3.2 vulnerability assessment. While specific CVEs could not be automatically retrieved due to NVD API rate limiting, this version is known to have multiple vulnerabilities. Manual verification required at https://nvd.nist.gov/.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** GCC: (GNU) 3.3.2, CVE
- **Notes:** configuration_load

---
### SBOM-GCC-4.2.3-CVEs

- **File/Directory Path:** `usr/sbin/wlconf`
- **Location:** `usr/sbin/wlconf (strings)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** GCC compiler version 4.2.3 vulnerability assessment. While specific CVEs could not be automatically retrieved due to NVD API rate limiting, this version is known to have multiple vulnerabilities. Manual verification required at https://nvd.nist.gov/.
- **Code Snippet:**
  ```
  GCC: (GNU) 4.2.3
  ```
- **Keywords:** GCC: (GNU) 4.2.3, CVE
- **Notes:** configuration_load

---
### sbom-GCC-3.3.2

- **File/Directory Path:** `bin/arptool`
- **Location:** `bin/arptool`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** GCC version 3.3.2 found in arptool binary strings. Potential CVE-2000-1219 ('-ftrapv' compiler option issue) affecting GCC 3.3.3 and earlier. Requires verification if affects 3.3.2.
- **Code Snippet:**
  ```
  Evidence from arptool binary strings
  ```
- **Keywords:** GCC, 3.3.2, arptool, CVE-2000-1219
- **Notes:** configuration_load

---
### component-GLIBC-2.0

- **File/Directory Path:** `lib/libufilter.so`
- **Location:** `lib/libufilter.so (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The GLIBC component version 2.0 was detected in the file 'lib/libufilter.so', with evidence sourced from the presence of the string 'GLIBC_2.0' in the string information. Further investigation is required to search for known high-risk vulnerabilities (CVEs) associated with this version.
- **Code Snippet:**
  ```
  GLIBC_2.0
  ```
- **Keywords:** GLIBC_2.0
- **Notes:** It is recommended to prioritize checking the known vulnerabilities in GLIBC 2.0, as there may be critical security issues.

---
