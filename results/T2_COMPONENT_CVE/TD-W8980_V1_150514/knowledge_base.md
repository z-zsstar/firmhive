# TD-W8980_V1_150514 (21 alerts)

---

### component-BusyBox-v1.19.2

- **File/Directory Path:** `bin/umount`
- **Location:** `bin/umount: HIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** The file bin/umount contains BusyBox component version v1.19.2 information. It is associated with multiple high-risk CVE vulnerabilities, including severe security issues such as command injection, heap buffer overflow, and hardcoded passwords. It is recommended to upgrade to the latest version to obtain security fixes.
- **Code Snippet:**
  ```
  BusyBox v1.19.2
  ```
- **Keywords:** BusyBox, umount, v1.19.2
- **Notes:** Although no CVEs specifically targeting BusyBox 1.19.2 were found, general high-risk vulnerabilities for BusyBox are listed. Associated CVEs include: CVE-2019-5138 (9.9), CVE-2016-2148 (9.8), CVE-2016-5791 (9.8), CVE-2018-1000517 (9.8), CVE-2017-8415 (9.8)

---
### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `bin/tar`
- **Location:** `bin/tar: strings output 'BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)'`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** BusyBox v1.19.2 component, found in the bin/tar file. Contains multiple critical CVE vulnerabilities: CVE-2016-2148 (Heap-based buffer overflow in DHCP client), CVE-2016-5791 (Improper Authentication in TELNET shell), CVE-2018-1000517 (Buffer Overflow in wget), CVE-2021-42377 (Attacker-controlled pointer free in hush applet). Actual risk depends on the specific BusyBox applets included.
- **Code Snippet:**
  ```
  Found in strings output: 'BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)'
  ```
- **Keywords:** busybox, v1.19.2, tar, symbolic link
- **Notes:** configuration_load

---
### component-BusyBox-1.19.2

- **File/Directory Path:** `bin/cat`
- **Location:** `bin/cat`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The BusyBox 1.19.2 component contains a version string in the bin/cat file. This version is affected by three potential high-risk vulnerabilities: CVE-2016-2148 (heap buffer overflow), CVE-2016-2147 (integer overflow), and CVE-2011-5325 (directory traversal).
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, CVE-2016-2148, CVE-2016-2147, CVE-2011-5325
- **Notes:** It is recommended to further verify whether these vulnerabilities indeed affect version 1.19.2 and check if the affected components (such as DHCP client or tar) are used in the firmware. Source of version string evidence: bin/cat file.

---
### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `bin/ping6`
- **Location:** `bin/cat`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** BusyBox v1.19.2 component, released in 2015, contains multiple critical vulnerabilities: CVE-2016-2148 (heap buffer overflow), CVE-2016-2147 (integer overflow), and CVE-2011-5325 (directory traversal). Version string evidence source: bin/cat file.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2, CVE-2016-2148, CVE-2016-2147, CVE-2011-5325
- **Notes:** It is recommended to further verify whether these vulnerabilities indeed affect version 1.19.2 and check if affected components (such as DHCP client or tar) are used in the firmware. Source of version string evidence: bin/cat file.

---
### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `bin/ping6`
- **Location:** `bin/busybox:0 (HIDDEN) 0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** BusyBox v1.19.2 component, released in 2015, contains multiple critical vulnerabilities: CVE-2016-2148 (heap buffer overflow), CVE-2016-2147 (integer overflow), CVE-2011-5325 (directory traversal), CVE-2016-5791 (Telnet service authentication issue), and CVE-2017-16544 (Tab autocompletion vulnerability). Version string evidence sources: bin/busybox and bin/cat files.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2, CVE-2016-2148, CVE-2016-2147, CVE-2011-5325, CVE-2016-5791, CVE-2017-16544
- **Notes:** Version Evidence Source: String analysis. Although no direct CVE records were found for version 1.19.2, considering the age of this version, there may be undisclosed vulnerabilities. It is recommended to conduct more in-depth security testing.

---
### SBOM-Linux_Kernel-2.6.32

- **File/Directory Path:** `sbin/iwconfig`
- **Location:** `iwconfig binary strings`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Linux Kernel component, version 2.6.32. Evidence source: Build path references in iwconfig binary strings. Contains multiple critical vulnerabilities including remote code execution and privilege escalation vulnerabilities.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER_REDACTED_PASSWORD_PLACEHOLDER_dir/toolchain-mips_r2_gcc-4.3.3+cs_uClibc-0.9.30.1_2_6_32
  ```
- **Keywords:** Linux Kernel, 2.6.32, kernel
- **Notes:** Related CVEs: CVE-2017-1000251 (CVSSv3 8.0), CVE-2009-4004 (CVSSv3 7.8), CVE-2011-2189 (CVSSv3 7.5), CVE-2017-1000407 (CVSSv3 7.4)

---
### thirdparty-uClibc-sbin/usbp

- **File/Directory Path:** `sbin/usbp`
- **Location:** `sbin/usbp: ELF header`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Dynamic linker reference in ELF header: /lib/ld-uClibc.so.0
  ```
- **Keywords:** /lib/ld-uClibc.so.0, ELF header, dynamic linker, uClibc
- **Notes:** configuration_load

---
### SBOM-libwpa_common.so

- **File/Directory Path:** `sbin/wpatalk`
- **Location:** `sbin/wpatalk`
- **Risk Score:** 9.0
- **Confidence:** 6.5
- **Description:** Information about the libwpa_common.so component extracted from the 'sbin/wpatalk' file. As the specific version cannot be determined, three potentially relevant known high-risk vulnerabilities were identified: CVE-2022-23303 (side-channel attack vulnerability in SAE implementation), CVE-2022-23304 (side-channel attack vulnerability in EAP-pwd implementation), and CVE-2019-9497 (EAP-PWD authentication bypass vulnerability).
- **Code Snippet:**
  ```
  HIDDEN 'libwpa_common.so' HIDDEN 'sbin/wpatalk' HIDDEN
  ```
- **Keywords:** libwpa_common.so, wpa_supplicant, hostapd, WPS, SAE, EAP-PWD
- **Notes:** Since the specific version of libwpa_common.so cannot be determined, it is recommended to assume the worst-case scenario and consider all listed vulnerabilities.

---
### component-BusyBox-v1.19.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0 (HIDDEN) 0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** BusyBox component analysis results. Version v1.19.2 (2015-05-11 18:35:09 HKT) contains multiple potential high-risk vulnerabilities. Version evidence source: strings in the BusyBox binary file. Potential vulnerabilities include:
1. CVE-2016-2148: DHCP client heap overflow vulnerability (CVSS 7.8 HIGH)
2. CVE-2016-5791: Telnet service authentication issue (CVSS 8.1 HIGH)
3. CVE-2017-16544: Tab autocomplete vulnerability (CVSS 7.8 HIGH)
Recommendation: Upgrade to the latest stable version or disable vulnerable features.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2, CVE-2016-2148, CVE-2016-5791, CVE-2017-16544
- **Notes:** Version Evidence Source: String analysis. While no direct CVE records were found for version 1.19.2, considering the age of this version, there may be undisclosed vulnerabilities. It is recommended to conduct more in-depth security testing.

---
### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `bin/ping`
- **Location:** `strings output`
- **Risk Score:** 8.0
- **Confidence:** 5.0
- **Description:** SBOM_entry
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2, ping, SBOM
- **Notes:** Version string found directly in binary: 'BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)'. This version is quite old (2015) and likely contains multiple vulnerabilities.

---
### SBOM-BusyBox-1.19.2

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** BusyBox v1.19.2 (2015-05-11) is a multi-call binary functioning as a symbolic link to /bin/sh. The version information is directly embedded within the binary string. No known CVE records were identified for this specific version, but potential security risks exist due to its outdated release date (2015).
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox v1.19.2, multi-call binary, sh -> busybox
- **Notes:** 1. Although no CVE records were found, a comprehensive security audit is recommended.  
2. The implementations of other BusyBox applets need to be checked.  
3. Other instances of BusyBox across the entire firmware should be considered.

---
### SBOM-uClibc-0.9.30.1

- **File/Directory Path:** `sbin/iwconfig`
- **Location:** `iwconfig binary strings`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** uClibc library component, version 0.9.30.1. Evidence source: Build path reference in iwconfig binary strings. Although no direct CVEs were found for version 0.9.30.1, multiple high-risk vulnerabilities affect similar versions.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  REDACTED_PASSWORD_PLACEHOLDER_REDACTED_PASSWORD_PLACEHOLDER_dir/toolchain-mips_r2_gcc-4.3.3+cs_uClibc-0.9.30.1_2_6_32
  ```
- **Keywords:** uClibc, 0.9.30.1, C library
- **Notes:** Related CVEs: CVE-2022-29503 (CVSS 9.8), CVE-2022-30295 (CVSS 6.5), CVE-2017-9728 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6)

---
### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `bin/df`
- **Location:** `bin/df -> busybox`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** The version information of BusyBox v1.19.2 was found in the 'bin/df' file. Although no direct CVEs for version 1.19.2 were identified, general vulnerabilities of BusyBox may still apply.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-05-11 18:35:09 HKT)
  ```
- **Keywords:** BusyBox, v1.19.2, df, symbolic link
- **Notes:** Although no direct CVEs were found for version 1.19.2, general vulnerabilities in BusyBox may still apply. It is recommended to verify whether these CVEs affect version 1.19.2.

---
### SBOM-wpa_supplicant-v0.5.9

- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `sbin/wpa_supplicant:0 (strings output) 'wpa_supplicant v0.5.9'`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Configuration information for the wpa_supplicant component extracted from the 'sbin/wpa_supplicant' file. Version v0.5.9 may contain known security vulnerabilities, requiring further queries to the CVE database.
- **Code Snippet:**
  ```
  wpa_supplicant v0.5.9
  ```
- **Keywords:** wpa_supplicant v0.5.9, Wi-Fi Protected Setup
- **Notes:** Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi> and contributors. It is necessary to query the CVE database to verify vulnerability information.

---
### SBOM-WiFi_Protected_Setup-sony_r5.7

- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `sbin/wpa_supplicant:0 (strings output) "Version 'sony_r5.7'"`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Wi-Fi Protected Setup Reference Application component information, version sony_r5.7, modified by Sony. Known security vulnerabilities may exist, requiring further queries to the CVE database.
- **Code Snippet:**
  ```
  Version 'sony_r5.7', modified by Sony.
  ```
- **Keywords:** Wi-Fi Protected Setup Reference Application, Version 'sony_r5.7'
- **Notes:** Copyright (c) 2007, Sony Corporation and contributors. It is necessary to query the CVE database to verify vulnerability information.

---
### SBOM-hostapd-v0.5.9

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0 (version string)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd v0.5.9, Wi-Fi Protected Setup Reference Application, sony_r5.7, libwpa_common.so, libos.so, libpthread.so.0, librt.so.0, libgcc_s.so.1, libc.so.0
- **Notes:** configuration_load

---
### VULN-CVE-2017-13086

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** TDLS REDACTED_PASSWORD_PLACEHOLDER Reinstallation Vulnerability in hostapd v0.5.9
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd v0.5.9, CVE-2017-13086
- **Notes:** network_input

---
### VULN-CVE-2016-4824

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** WPS REDACTED_PASSWORD_PLACEHOLDER brute-force vulnerability in hostapd v0.5.9.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd v0.5.9, CVE-2016-4824
- **Notes:** network_input

---
### VULN-CVE-2011-5053

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** hostapd v0.5.9 REDACTED_PASSWORD_PLACEHOLDER Discovery via EAP-NACK Vulnerability
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd v0.5.9, CVE-2011-5053
- **Notes:** network_input

---
### VULN-CVE-2012-1922

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** CSRF vulnerabilities in hostapd v0.5.9.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd v0.5.9, CVE-2012-1922
- **Notes:** network_input

---
### SBOM-uClibc-0.9.30.1

- **File/Directory Path:** `sbin/iwpriv`
- **Location:** `sbin/iwpriv (from strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Evidence from binary strings
  ```
- **Keywords:** uClibc, 0.9.30.1, libc.so.0
- **Notes:** The uClibc vulnerabilities are not explicitly confirmed for version 0.9.30.1 but are likely due to version proximity.

---
