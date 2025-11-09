# R6200v2-V1.0.3.12_10.1.11 (23 alerts)

---

### SBOM-bzip2-1.0.6

- **File/Directory Path:** `usr/sbin/bzip2`
- **Location:** `usr/sbin/bzip2`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** Analysis of 'usr/sbin/bzip2' identified the bzip2 component version as 1.0.6, with an embedded version string of '1.0.6, 6-Sept-2010'. This version is affected by multiple CVEs, including the critical vulnerability CVE-2019-12900 (an out-of-bounds write issue in BZ2_decompress). The file is an ELF 32-bit LSB executable for ARM architecture, dynamically linked to uClibc libraries, and has been stripped of its symbol table.
- **Code Snippet:**
  ```
  bzip2: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
  ```
- **Keywords:** bzip2, 1.0.6, BZ2_decompress, bzip2recover, libbzip2, ELF, ARM, uClibc
- **Notes:** configuration_load

---
### sbom-libsqlite3-0

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe:linked library`
- **Risk Score:** 9.8
- **Confidence:** 6.75
- **Description:** The linked library libsqlite3.so.0, version 0 (version may be incomplete), contains a high-risk vulnerability CVE-2017-10989 (heap buffer out-of-bounds read, CVSS 9.8).
- **Code Snippet:**
  ```
  Linked library: 'libsqlite3.so.0'
  ```
- **Keywords:** libsqlite3.so.0
- **Notes:** The version information is incomplete, which may affect the accuracy of vulnerability assessment.

---
### sbom-libexif-12

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe:linked library`
- **Risk Score:** 9.1
- **Confidence:** 6.75
- **Description:** The library libexif.so.12, version 12 (exact version uncertain), contains a critical vulnerability CVE-2017-7544 (out-of-bounds read, CVSS 9.1).
- **Code Snippet:**
  ```
  Linked library: 'libexif.so.12'
  ```
- **Keywords:** libexif.so.12
- **Notes:** The version information is incomplete, which may affect the accuracy of vulnerability assessment.

---
### thirdparty-GCC-3.3.2

- **File/Directory Path:** `usr/bin/vmstat`
- **Location:** `vmstat:strings output`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Discovered in the vmstat binary file was GCC 3.3.2 (released in 2003). This version is extremely outdated and contains numerous known vulnerabilities, though specific CVE enumeration would require external research.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)
  ```
- **Keywords:** GCC: (GNU) 3.3.2, vmstat, GCC
- **Notes:** configuration_load

---
### component-WPS-1.0-updated

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor: strings output`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Discovered WPS implementation version 1.0. The WPS protocol contains known security vulnerabilities, including REDACTED_PASSWORD_PLACEHOLDER brute-force vulnerabilities (CVE-2011-5053, CVE-2014-9486) and design flaws. These vulnerabilities may lead to network authentication bypass.
- **Code Snippet:**
  ```
  Found references to 'WFA-SimpleConfig-Enrollee-1-0' and 'WFA-SimpleConfig-Registrar-1-0'
  ```
- **Keywords:** WFA-SimpleConfig-Enrollee-1-0, WFA-SimpleConfig-Registrar-1-0, WPS, CVE-2011-5053, CVE-2014-9486
- **Notes:** The WPS protocol has design flaws, and it is recommended to disable the WPS function to mitigate risks.

---
### thirdparty-component-unzip

- **File/Directory Path:** `usr/sbin/unzip`
- **Location:** `usr/sbin/unzip`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Analysis of 'usr/sbin/unzip' reveals it's an Info-ZIP UnZip implementation likely from 2007-2009 timeframe (version 6.0 or earlier based on compilation evidence). The binary contains multiple high-severity vulnerabilities (CVSS 7.8-9.1) including:
1. Out-of-bounds reads (CVE-2018-1000033/34)
2. Heap buffer overflows (CVE-2018-1000031/32/35)
3. CRC32 verification flaws (CVE-2014-8139/40/41)

These vulnerabilities can be triggered by processing malicious zip files, potentially leading to:
- Memory disclosure
- Denial of service
- Remote code execution

Evidence sources:
- Version indicators: 'UnZip %d.%d%d%s of %s, by Info-ZIP' string (usr/sbin/unzip)
- Compilation markers: GCC 4.5.3 and 2017 timestamps
- **Code Snippet:**
  ```
  Version indicators: 'UnZip %d.%d%d%s of %s, by Info-ZIP'
  ```
- **Keywords:** UnZip, Info-ZIP, CRC32, getZip64Data, test_compr_eb, list_files
- **Notes:** thirdparty_component

---
### sbom-minidlna-1.0.25

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe:.rodata section (0x000277dc, 0xREDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** The file 'usr/sbin/minidlna.exe' contains details of minidlna version 1.0.25 and its associated components. Analysis has confirmed multiple high-risk vulnerabilities that may affect this software.
- **Code Snippet:**
  ```
  Version 1.0.25
  Linux 2.6 DLNADOC/1.50 UPnP/1.0 ReadyDLNA/1.0.25
  ```
- **Keywords:** Version 1.0.25, ReadyDLNA/1.0.25, minidlna, libexif.so.12, libjpeg.so.7, libsqlite3.so.0
- **Notes:** Contains multiple critical vulnerabilities: CVE-2013-2738 (SQL injection), CVE-2020-28926 (remote code execution), CVE-2022-43648 (heap buffer overflow)

---
### component-libnvram.so

- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd`
- **Risk Score:** 8.8
- **Confidence:** 8.5
- **Description:** libnvram.so library, version unknown. Associated with multiple high-risk CVE vulnerabilities (CVE-2022-26780, CVE-2022-26781, CVE-2022-26782), which may lead to remote code execution.
- **Keywords:** libnvram.so, nvram_import, CVE-2022-26780, CVE-2022-26781, CVE-2022-26782
- **Notes:** Version evidence: 'libnvram.so' is listed in the import library of the file bin/eapd. Related CVEs: CVE-2022-26780, CVE-2022-26781, CVE-2022-26782

---
### sbom-libjpeg-7

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe:linked library`
- **Risk Score:** 8.8
- **Confidence:** 6.75
- **Description:** The library libjpeg.so.7, version 7 (exact version uncertain), contains a critical vulnerability CVE-2018-20330 (buffer overflow, CVSS 8.8).
- **Code Snippet:**
  ```
  Linked library: 'libjpeg.so.7'
  ```
- **Keywords:** libjpeg.so.7
- **Notes:** The version information is incomplete, which may affect the accuracy of vulnerability assessment.

---
### SBOM-BusyBox-v1.7.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox: strings output`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** SBOM Report for BusyBox v1.7.2. Includes version information, related vulnerabilities, and their potential impacts. Version evidence comes from the string 'BusyBox v1.7.2 (2017-01-10 11:53:04 CST)' found in the file 'bin/busybox'. Known vulnerabilities include:
- CVE-2016-2148: Heap-based buffer overflow in the DHCP client (udhcpc)
- CVE-2016-5791: Improper Authentication in BusyBox Linux shell accessible over TELNET
- CVE-2017-16544: Tab autocomplete feature does not sanitize filenames
- CVE-2011-5325: Directory traversal vulnerability in BusyBox tar

Due to the lack of CVE records specifically targeting version 1.7.2, it is recommended to further verify the actual components and functionalities included in BusyBox 1.7.2. Many vulnerabilities affect long-standing core components of BusyBox (such as udhcpc, wget, and shell functionalities), so even if version 1.7.2 is not explicitly listed, these vulnerabilities may still pose risks. It is advised to check the specific compilation configuration of BusyBox 1.7.2 to determine which applets are included.
- **Code Snippet:**
  ```
  BusyBox v1.7.2 (2017-01-10 11:53:04 CST)
  ```
- **Keywords:** BusyBox, v1.7.2, udhcpc, wget, ash.c, hush, telnet, authentication
- **Notes:** Due to the lack of direct CVE records for version 1.7.2, it is recommended to further verify the actual components and functionalities included in BusyBox 1.7.2. Many vulnerabilities affect long-standing core components of BusyBox (such as udhcpc, wget, and shell functionalities), so even if version 1.7.2 is not explicitly listed, these vulnerabilities may still pose risks. It is advisable to examine the specific compilation configuration of BusyBox 1.7.2 to determine which applets are included.

---
### thirdparty-GCC-4.5.3

- **File/Directory Path:** `usr/bin/vmstat`
- **Location:** `vmstat:strings output`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** GCC 4.5.3 (2011 release) found in vmstat binary. This version has known CVEs including code execution vulnerabilities (e.g., CVE-2014-1263, CVE-2014-1266).
- **Code Snippet:**
  ```
  GCC: (Buildroot 2012.02) 4.5.3
  ```
- **Keywords:** GCC: (Buildroot 2012.02) 4.5.3, vmstat, GCC
- **Notes:** configuration_load

---
### thirdparty-wget-1.12

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** configuration_load
- **Keywords:** GNU Wget, wget, X.509 certificate, SSL spoofing, file overwrite, 3xx redirect
- **Notes:** configuration_load

---
### component-Broadcom-libraries-unknown

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor: strings output`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple Broadcom libraries (libbcm.so, libbcmcrypto.so, libnvram.so, libshared.so) were detected but with unknown version information. The versions of these libraries are typically tied to the firmware version. Among them, libnvram.so is known to be associated with multiple high-risk CVE vulnerabilities (CVE-2022-26780, CVE-2022-26781, CVE-2022-26782), which may lead to remote code execution.
- **Code Snippet:**
  ```
  Found references to 'libbcm.so', 'libbcmcrypto.so', 'libnvram.so', 'libshared.so' in strings output
  ```
- **Keywords:** libbcm.so, libbcmcrypto.so, libnvram.so, libshared.so, CVE-2022-26780, CVE-2022-26781, CVE-2022-26782
- **Notes:** Check the firmware release notes or documentation for Broadcom library version information. The libnvram.so is known to be associated with high-risk CVE vulnerabilities.

---
### sbom-bftpd-1.6.6

- **File/Directory Path:** `usr/sbin/bftpd`
- **Location:** `usr/sbin/bftpd:0xREDACTED_PASSWORD_PLACEHOLDER (RODATA segment) 0xREDACTED_PASSWORD_PLACEHOLDER (code reference)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Version string '1.6.6' found in RODATA segment at 0xREDACTED_PASSWORD_PLACEHOLDER, referenced in code at 0xREDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** bftpd, 1.6.6, str.1.6.6, 0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Related CVEs in other versions: CVE-2020-6835 (heap-based off-by-one error), CVE-2020-6162 (out-of-bounds read), CVE-2017-16892 (memory leak), CVE-2001-0065 (buffer overflow), CVE-2007-2010 (double free), CVE-2007-2051 (buffer overflow), CVE-2009-4593 (missing null terminator). Manual verification is recommended.

---
### component-WPS-1.0

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor: strings output`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Discovered WPS implementation version 1.0. Evidence source: Found references to 'WFA-SimpleConfig-Enrollee-1-0' and 'WFA-SimpleConfig-Registrar-1-0' in string output.
- **Code Snippet:**
  ```
  Found references to 'WFA-SimpleConfig-Enrollee-1-0' and 'WFA-SimpleConfig-Registrar-1-0'
  ```
- **Keywords:** WFA-SimpleConfig-Enrollee-1-0, WFA-SimpleConfig-Registrar-1-0
- **Notes:** The WPS protocol is known to have security vulnerabilities, and relevant CVEs need to be checked.

---
### SBOM-OpenSSL-1.0.0g

- **File/Directory Path:** `lib/libssl.so`
- **Location:** `lib/libssl.so: strings output`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Clear evidence of OpenSSL version 1.0.0g was found in the file 'lib/libssl.so'. This version contains multiple potentially high-risk vulnerabilities. Although no CVEs are directly labeled for this specific version, it may be affected based on version range inference.
- **Code Snippet:**
  ```
  Multiple references to 'OpenSSL 1.0.0g 18 Jan 2012' in SSLv2, SSLv3, TLSv1 and DTLSv1 implementation sections
  ```
- **Keywords:** OpenSSL 1.0.0g 18 Jan 2012, SSLv2 part of OpenSSL 1.0.0g, SSLv3 part of OpenSSL 1.0.0g, TLSv1 part of OpenSSL 1.0.0g, DTLSv1 part of OpenSSL 1.0.0g, CVE-2003-0545, CVE-2010-1378, CVE-2004-0079, CVE-2005-2946, CVE-2008-0166
- **Notes:** configuration_load

---
### SBOM-GCC-3.3.2

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd:Embedded in binary strings`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** GCC compiler version information found in the binary file. Version 3.3.2 (Debian prerelease) may contain known vulnerabilities. Further investigation of CVE records for this version is required.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)
  ```
- **Keywords:** GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease), GCC
- **Notes:** These compiler versions may introduce specific behaviors or vulnerabilities in the compiled binaries. It is recommended to further investigate known high-risk vulnerabilities (CVEs) in these GCC versions.

---
### SBOM-GCC-4.5.3

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd:Embedded in binary strings`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** GCC compiler version information found in the binary file. Version 4.5.3 (Buildroot 2012.02) may contain known vulnerabilities. The Buildroot version indicates this might be part of an embedded system build environment.
- **Code Snippet:**
  ```
  GCC: (Buildroot 2012.02) 4.5.3
  ```
- **Keywords:** GCC: (Buildroot 2012.02) 4.5.3, GCC
- **Notes:** The Buildroot version suggests this may be part of an embedded system build environment. It is recommended to further investigate known high-risk vulnerabilities (CVEs) for these GCC versions.

---
### SBOM-Info-ZIP-Zip-3.0

- **File/Directory Path:** `usr/sbin/zip`
- **Location:** `usr/sbin/zip`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the file 'usr/sbin/zip', Info-ZIP Zip version 3.0 was found, compiled on July 5, 2008. This version contains a high-severity vulnerability CVE-2018-13410, involving an off-by-one error when using the -T and -TT command-line options, which may lead to denial of service or other impacts.
- **Code Snippet:**
  ```
  Copyright (c) 1990-2008 Info-ZIP - Type '%s "-L"' for software license.
  This is %s %s (%s), by Info-ZIP.
  [encryption, version %d.%d%s of %s] (modified for Zip 3)
  ```
- **Keywords:** Zip 3.0, July 5th 2008, Info-ZIP, CVE-2018-13410, -T, -TT
- **Notes:** This is an older version of Zip (2008) that may contain other unpatched vulnerabilities. The binary was recompiled on January 10, 2017 using gcc 4.5.3, indicating possible recompilation from source code at that time.

---
### component-UPnP-unknown

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor: strings output`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** UPnP component detected but version information unknown. Evidence source: 'libupnp.so' and UPnP-related strings found in string output. UPnP implementation version requires further analysis.
- **Code Snippet:**
  ```
  Found references to 'libupnp.so' and UPnP-related strings in output
  ```
- **Keywords:** libupnp.so, urn:schemas-wifialliance-org:device:WFADevice, WFAWLANConfig
- **Notes:** Check other binary files or configuration files to obtain the UPnP implementation version

---
### thirdparty-uClibc-unknown

- **File/Directory Path:** `usr/bin/vmstat`
- **Location:** `vmstat:strings output`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** uClibc library found in vmstat binary but exact version could not be determined from strings output. Requires analysis of linked library files for version identification.
- **Code Snippet:**
  ```
  References to '/lib/ld-uClibc.so.0' and 'libc.so.0'
  ```
- **Keywords:** uClibc, vmstat, /lib/ld-uClibc.so.0, libc.so.0
- **Notes:** configuration_load

---
### thirdparty-libgcc-unknown

- **File/Directory Path:** `usr/bin/vmstat`
- **Location:** `vmstat:strings output`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The libgcc library was identified in the vmstat binary, but the version could not be determined from the string output. Analysis of the actual library file is required.
- **Code Snippet:**
  ```
  Reference to 'libgcc_s.so.1'
  ```
- **Keywords:** libgcc_s.so.1, vmstat, libgcc
- **Notes:** configuration_load

---
### openssl-version-conflict

- **File/Directory Path:** `lib/libcrypto.so`
- **Location:** `lib/libssl.so vs lib/libcrypto.so`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** Inconsistency in OpenSSL component versions detected:
- lib/libssl.so explicitly contains version information 'OpenSSL 1.0.0g 18 Jan 2012'
- lib/libcrypto.so has a modification timestamp from late 2017, potentially belonging to a newer version

This indicates the firmware may have mixed OpenSSL components from different versions, which could lead to compatibility issues and security risks. Further verification of libcrypto.so's actual version is required.
- **Keywords:** libcrypto.so, libssl.so, OpenSSL, version conflict
- **Notes:** Mixing different versions of OpenSSL components may lead to unpredictable behavior and security vulnerabilities. Recommendations:
1. Verify the actual version of libcrypto.so
2. Check compatibility between the two library files
3. List all OpenSSL-related CVE vulnerabilities, including potential vulnerabilities in version 1.0.0g and the 2017 version

---
