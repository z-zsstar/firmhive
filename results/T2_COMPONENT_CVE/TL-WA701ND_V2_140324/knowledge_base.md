# TL-WA701ND_V2_140324 (26 alerts)

---

### SBOM-uClibc-pktlogconf

- **File/Directory Path:** `sbin/pktlogconf`
- **Location:** `sbin/pktlogconf: HIDDEN: /lib/ld-uClibc.so.0`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The uClibc component has been detected in the file 'sbin/pktlogconf'. Associated CVEs include:
1. CVE-2017-9728: An out-of-bounds read vulnerability exists in the get_subexp function in misc/regex/regexec.c of uClibc 0.9.33.2 when processing specially crafted regular expressions (CVSS 9.8)
2. CVE-2022-29503: A memory corruption vulnerability exists in the libpthread linuxthreads functionality of uClibC 0.9.33.2 and uClibC-ng 1.0.40 (CVSS 9.8)
3. CVE-2021-43523: Improper handling of special characters in domain names returned by DNS servers in uClibc and uClibc-ng prior to version 1.0.39 (CVSS 9.6)
The specific version number of uClibc needs to be confirmed for more accurate vulnerability matching
- **Code Snippet:**
  ```
  HIDDEN: /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, libgcc_s.so.1, ld-uClibc.so.0
- **Notes:** Confirm the specific version of uClibc to more accurately match the vulnerability.

---
### component-uClibc-sbin/wlanconfig

- **File/Directory Path:** `sbin/wlanconfig`
- **Location:** `sbin/wlanconfig`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** Analysis of 'sbin/wlanconfig' identified the third-party component uClibc with version unknown. uClibc has multiple high-risk vulnerabilities (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523). The version could not be determined from the binary, making it difficult to precisely assess the impact of the vulnerabilities.
- **Code Snippet:**
  ```
  Dynamic linker path: /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, libgcc_s.so.1, GCC: (GNU) 3.3.2
- **Notes:** configuration_load

---
### SBOM-uClibc-unknown

- **File/Directory Path:** `sbin/athstats`
- **Location:** `sbin/athstats`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The uClibc library information found in the sbin/athstats file is referenced from the '/lib/ld-uClibc.so.0' string. It is associated with multiple high-risk CVE vulnerabilities.
- **Code Snippet:**
  ```
  interpreter /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, /lib/ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** The exact version of uClibc needs to be further verified by checking the /lib/ld-uClibc.so.0 file.

---
### VULN-CVE-2017-9728

- **File/Directory Path:** `sbin/athstats`
- **Location:** `sbin/athstats`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** Out-of-bounds read vulnerability when processing crafted regular expressions in uClibc, CVSS score 9.8.
- **Keywords:** uClibc, get_subexp, regexec.c, CVE-2017-9728
- **Notes:** The exact version of uClibc needs to be confirmed to assess the vulnerability impact.

---
### VULN-CVE-2022-29503

- **File/Directory Path:** `sbin/athstats`
- **Location:** `sbin/athstats`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** Memory corruption vulnerability in the libpthread linuxthreads functionality of uClibC, with a CVSS score of 9.8.
- **Keywords:** uClibc, libpthread, linuxthreads, CVE-2022-29503
- **Notes:** The exact version of uClibc needs to be confirmed to assess the vulnerability impact.

---
### SBOM-uClibc-libc.so.0

- **File/Directory Path:** `sbin/iwpriv`
- **Location:** `sbin/iwpriv (strings output)`
- **Risk Score:** 9.8
- **Confidence:** 4.0
- **Description:** Dynamic library dependency uClibc (libc.so.0) discovered in the 'sbin/iwpriv' file. Version unknown, but associated with multiple high-risk CVE vulnerabilities:
- CVE-2017-9728 (CVSS 9.8): Out-of-bounds read in get_subexp function
- CVE-2022-29503 (CVSS 9.8): Memory corruption in libpthread
- CVE-2021-43523 (CVSS 9.6): Incorrect handling of special characters in domain names
- **Code Snippet:**
  ```
  Found in strings output of iwpriv as dynamic library dependency
  ```
- **Keywords:** uClibc, libc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** configuration_load

---
### VULN-CVE-2021-43523

- **File/Directory Path:** `sbin/athstats`
- **Location:** `sbin/athstats`
- **Risk Score:** 9.6
- **Confidence:** 7.5
- **Description:** Vulnerability in the incorrect handling of special characters in domain names returned by DNS servers, CVSS score 9.6.
- **Keywords:** uClibc, gethostbyname, getaddrinfo, DNS, CVE-2021-43523
- **Notes:** Confirm the exact version of uClibc to assess the vulnerability impact.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `sbin/80211stats`
- **Location:** `80211statsHIDDEN：/lib/ld-uClibc.so.0`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** The uClibc library component was identified in the 80211stats binary file, version 0.9.33.2. The version information was obtained from the linked library reference: /lib/ld-uClibc.so.0. This version contains multiple critical vulnerabilities, including:
- CVE-2017-9728: Out-of-bounds read in get_subexp function (CVSS 9.8)
- CVE-2022-29503: Memory corruption in libpthread linuxthreads (CVSS 9.8)
- CVE-2021-43523: Incorrect handling of special characters in domain names (CVSS 9.6)
- CVE-2016-6264: Integer signedness error in memset function (CVSS 7.5)
- CVE-2016-2224: Denial of service via compressed DNS items (CVSS 7.5)
- **Code Snippet:**
  ```
  HIDDEN：/lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, 0.9.33.2, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523, CVE-2016-6264, CVE-2016-2224
- **Notes:** It is strongly recommended to upgrade uClibc to the latest secure version to fix critical vulnerabilities.

---
### thirdparty-uClibc-vulnerabilities

- **File/Directory Path:** `sbin/reg`
- **Location:** `sbin/reg:HIDDENstringsHIDDENRadare2HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The firmware was found to utilize the uClibc library, which contains multiple critical CVE vulnerabilities, including:
- CVE-2017-9728 (CVSSv3: 9.8): Out-of-bounds read vulnerability in regular expression processing
- CVE-2022-29503 (CVSSv3: 9.8): Memory corruption vulnerability caused by thread allocation
- CVE-2021-43523 (CVSSv3: 9.6): Domain name validation flaw in DNS resolution
- CVE-2016-6264 (CVSSv3: 7.5): Integer sign error in memset function
- CVE-2016-2224 (CVSSv3: 7.5): Infinite loop vulnerability in DNS resolution

These vulnerabilities may compromise system security and stability. It is recommended to further examine the specific version number of uClibc to determine which vulnerabilities actually affect the current system.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** GCC: (GNU) 3.3.2, /lib/ld-uClibc.so.0, uClibc
- **Notes:** It is recommended to further verify the specific version number of uClibc to determine which vulnerabilities actually affect the current system. Version information evidence source: the string '/lib/ld-uClibc.so.0' in the sbin/reg file.

---
### thirdparty-component-uClibc

- **File/Directory Path:** `sbin/pktlogdump`
- **Location:** `sbin/pktlogdump`
- **Risk Score:** 9.0
- **Confidence:** 4.0
- **Description:** The uClibc component found in the 'sbin/pktlogdump' file does not explicitly display its version but references '/lib/ld-uClibc.so.0'. Related high-risk vulnerabilities:  
- CVE-2017-9728 (CVSSv3: 9.8): Out-of-bounds read vulnerability in regular expression processing  
- CVE-2022-29503 (CVSSv3: 9.8): Memory corruption vulnerability caused by thread allocation  
- CVE-2021-43523 (CVSSv3: 9.6): Missing domain name validation vulnerability in DNS resolution  
- CVE-2016-6264 (CVSSv3: 7.5): Integer sign error in memset function  
- CVE-2016-2224 (CVSSv3: 7.5): Infinite loop vulnerability in DNS resolution
- **Keywords:** /lib/ld-uClibc.so.0
- **Notes:** 1. It is recommended to further confirm the specific version number of uClibc.  
2. These vulnerabilities may affect system security, and it is advisable to consider upgrading the relevant components.

---
### thirdparty-uClibc-vulnerable

- **File/Directory Path:** `sbin/athstatsclr`
- **Location:** `sbin/athstatsclr`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Analysis of third-party C library information found in file 'sbin/athstatsclr'.
- Software Name: uClibc
- Version Evidence: Binary file linkage information '/lib/ld-uClibc.so.0'
- Related High-Risk Vulnerabilities:
   - CVE-2017-9728 (CVSSv3: 9.8): Out-of-bounds read in regular expression processing
   - CVE-2022-29503 (CVSSv3: 9.8): Memory corruption caused by thread allocation
   - CVE-2021-43523 (CVSSv3: 9.6): DNS resolution vulnerability potentially leading to remote code execution
   - CVE-2016-6264 (CVSSv3: 7.5): Integer sign error in memset function causing denial of service
   - CVE-2016-2224 (CVSSv3: 7.5): Infinite loop vulnerability in DNS resolution
- **Keywords:** /lib/ld-uClibc.so.0, uClibc
- **Notes:** Although no version information was found in the file itself, the use of uClibc was confirmed by analyzing the linked library information. It is recommended to further verify the specific version of uClibc to more accurately assess the vulnerability impact.

---
### component-GCC-3.3.2_and_4.3.3

- **File/Directory Path:** `sbin/iwconfig`
- **Location:** `iwconfig strings output`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** GCC component information extracted from the 'sbin/iwconfig' file. Multiple GCC version references suggest possible cross-compilation usage. These versions are outdated and may contain known vulnerabilities.
- **Code Snippet:**
  ```
  Multiple 'GCC: (GNU) X.X.X' strings found in output
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (GNU) 4.3.3
- **Notes:** Multiple GCC version references indicate potential use of cross-compilation. These versions are outdated and may contain known vulnerabilities.

---
### thirdparty-component-GCC-3.3.2

- **File/Directory Path:** `sbin/pktlogdump`
- **Location:** `sbin/pktlogdump`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** GCC compiler version 3.3.2 found in the 'sbin/pktlogdump' file. Source of evidence: string 'GCC: (GNU) 3.3.2'.
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** Check the GCC version information in other binary files.

---
### thirdparty-component-GCC-4.3.3

- **File/Directory Path:** `sbin/pktlogdump`
- **Location:** `sbin/pktlogdump`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** The GCC compiler version 4.3.3 was found in the 'sbin/pktlogdump' file. Source of evidence: string 'GCC: (GNU) 4.3.3'.
- **Keywords:** GCC: (GNU) 4.3.3, libgcc_s.so.1
- **Notes:** Check the GCC version information in other binary files

---
### SBOM-GCC-pktlogconf

- **File/Directory Path:** `sbin/pktlogconf`
- **Location:** `sbin/pktlogconf: HIDDEN: 'GCC: (GNU) 3.3.2', 'GCC: (GNU) 4.3.3'`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** The GCC component was detected in the file 'sbin/pktlogconf', with a possible version of 3.3.2 or 4.3.3. Associated CVEs include:
CVE-2022-25265: Affects binaries compiled with GCC 3.2.2 (CVSS 7.8)
Although not an exact match, GCC 3.3.2 is similarly outdated and may pose similar risks
It is recommended to upgrade to a supported GCC version to obtain security updates
- **Code Snippet:**
  ```
  HIDDEN: 'GCC: (GNU) 3.3.2', 'GCC: (GNU) 4.3.3'
  ```
- **Keywords:** GCC, GCC 3.3.2, GCC 4.3.3
- **Notes:** configuration_load

---
### SBOM-LinuxKernel-2.6.31

- **File/Directory Path:** `etc/inittab`
- **Location:** `/etc/rc.d/rcS`
- **Risk Score:** 7.8
- **Confidence:** 7.5
- **Description:** Linux Kernel 2.6.31 component information, containing the following CVE vulnerabilities:
1. CVE-2009-2768: NULL pointer dereference in flat subsystem (CVSS 7.8)
2. CVE-2009-3620: ATI Rage 128 driver privilege escalation (CVSS 7.8)
3. CVE-2009-4272: IPv4 routing hash table collision DoS (CVSS 7.5)
4. CVE-2009-3939: World-writable megaraid_sas driver file (CVSS 7.1)
5. CVE-2009-3621: AF_UNIX socket DoS (CVSS 5.5)

Evidence source: '/etc/rc.d/rcS' script reference
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** 2.6.31, rcS, Linux Kernel
- **Notes:** configuration_load

---
### SBOM-LinuxKernel-2.6.15

- **File/Directory Path:** `etc/inittab`
- **Location:** `/etc/rc.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Linux Kernel 2.6.15 component information, containing the following CVE vulnerabilities:
1. CVE-2006-7229: skge driver vulnerability allowing DoS via network traffic flood (CVSS 7.5)
2. CVE-2005-3784: Child process auto-reap vulnerability leading to privilege escalation
3. CVE-2005-3807: Memory leak in VFS file lease handling
4. CVE-2005-3857: Denial of service via broken leases log consumption
5. CVE-2005-3358: Denial of service via set_mempolicy call

Evidence source: '/etc/rc.d/rcS' script reference
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** 2.6.15, rcS, Linux Kernel
- **Notes:** configuration_load

---
### component-libiw-29

- **File/Directory Path:** `sbin/iwconfig`
- **Location:** `iwconfig strings output`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The libiw component information extracted from the 'sbin/iwconfig' file. libiw is the wireless tools library. Version 29 may correspond to wireless-tools 29 or later.
- **Code Snippet:**
  ```
  Found reference to 'libiw.so.29' in strings output
  ```
- **Keywords:** libiw.so.29
- **Notes:** libiw is the wireless tools library. Version 29 may correspond to wireless-tools 29 or later. Further verification is needed to confirm the exact version.

---
### thirdparty-GCC-3.3.2

- **File/Directory Path:** `sbin/apstart`
- **Location:** `sbin/apstart`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The GCC 3.3.2 version information was found in the file 'sbin/apstart'. GCC 3.3.2 is an older version that may contain known vulnerabilities. The version information appears directly in the strings output.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** Further investigation is required to identify known vulnerabilities (CVEs) in GCC 3.3.2. The version information may only reflect the compilation environment, necessitating verification of its impact on runtime security.

---
### thirdparty-GCC-4.3.3

- **File/Directory Path:** `sbin/apstart`
- **Location:** `sbin/apstart`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** GCC 4.3.3 version information was found in the file 'sbin/apstart'. GCC 4.3.3 is an older version that may contain known vulnerabilities. The version information appears directly in the strings output.
- **Code Snippet:**
  ```
  GCC: (GNU) 4.3.3
  ```
- **Keywords:** GCC: (GNU) 4.3.3
- **Notes:** Further investigation is required to identify known vulnerabilities (CVEs) in GCC 4.3.3. The version information may only reflect the compilation environment, necessitating verification of its impact on runtime security.

---
### thirdparty-uClibc

- **File/Directory Path:** `sbin/apstart`
- **Location:** `sbin/apstart`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The uClibc dynamic library was detected in the file 'sbin/apstart' with the path /lib/ld-uClibc.so.0. The specific version is unspecified, requiring further analysis to determine the presence of any known critical vulnerabilities (CVEs). The version information originates from dynamic linking dependencies.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** /lib/ld-uClibc.so.0
- **Notes:** Further verification is required for the specific version of uClibc, along with searching for related known high-risk vulnerabilities (CVEs).

---
### thirdparty-WPA

- **File/Directory Path:** `sbin/apstart`
- **Location:** `sbin/apstart`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The WPA-related library libwpa_common.so was detected in the file 'sbin/apstart'. The specific version is not explicitly stated, requiring further analysis to determine the presence of any known critical vulnerabilities (CVEs). The version information was obtained from dynamic linking dependencies.
- **Code Snippet:**
  ```
  libwpa_common.so
  ```
- **Keywords:** libwpa_common.so
- **Notes:** Further verification of the specific version of the WPA library is required, along with identifying any known high-risk vulnerabilities (CVEs).

---
### SBOM-hostapd-v0.5.9

- **File/Directory Path:** `sbin/hostapd`
- **Location:** `sbin/hostapd`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The hostapd component was identified in the SBOM analysis, version v0.5.9. This is a modified version, requiring further investigation into its vulnerability status. Version evidence stems from the string output containing 'hostapd v0.5.9'.
- **Code Snippet:**
  ```
  hostapd v0.5.9
  ```
- **Keywords:** hostapd v0.5.9
- **Notes:** configuration_load

---
### sbom-uClibc-dumpregs

- **File/Directory Path:** `sbin/dumpregs`
- **Location:** `sbin/dumpregs`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** A reference to uClibc was found in the 'sbin/dumpregs' file, with unclear version information but multiple high-risk vulnerabilities present (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523). Further analysis of the '/lib/ld-uClibc.so.0' file is required to confirm the exact version.
- **Code Snippet:**
  ```
  Dynamic linker reference in binary: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** /lib/ld-uClibc.so.0, uClibc, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** It is recommended to further analyze the '/lib/ld-uClibc.so.0' file to confirm the precise version of uClibc. Relevant CVEs include: CVE-2017-9728 (9.8 score), CVE-2022-29503 (9.8 score), CVE-2021-43523 (9.6 score).

---
### SBOM-GCC-3.3.2-4.3.3

- **File/Directory Path:** `sbin/iwspy`
- **Location:** `Build toolchain references in sbin/iwspy`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (GNU) 4.3.3
- **Notes:** configuration_load

---
### thirdparty-component-GLIBC-2.0

- **File/Directory Path:** `sbin/pktlogdump`
- **Location:** `sbin/pktlogdump`
- **Risk Score:** 7.0
- **Confidence:** 4.0
- **Description:** The GLIBC version 2.0 dependency was found in the 'sbin/pktlogdump' file. Source of evidence: GLIBC_2.0 dependency confirmed via 'readelf -V'.
- **Keywords:** libc.so.0, GLIBC_2.0
- **Notes:** Due to NVD API request limitations, the CVE information for GLIBC 2.0 could not be retrieved. It is recommended to check later.

---
