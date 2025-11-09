# TL-WR1043ND_V3_150514 (22 alerts)

---

### SBOM-uClibc-component

- **File/Directory Path:** `sbin/iwlist`
- **Location:** `Dynamic linker reference`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Binary uses /lib/ld-uClibc.so.0 as interpreter
  ```
- **Keywords:** uClibc, /lib/ld-uClibc.so.0
- **Notes:** configuration_load

---
### SBOM-uClibc-athstats

- **File/Directory Path:** `sbin/athstats`
- **Location:** `sbin/athstats binary headers`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** SBOM analysis for uClibc library linked with athstats binary. Found multiple critical vulnerabilities including memory corruption (CVE-2017-9728), denial of service (CVE-2022-29503), and DNS cache poisoning (CVE-2021-43523). Exact version could not be determined from binary analysis.
- **Keywords:** uClibc, ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** configuration_load

---
### thirdparty-component-uClibc-unknown

- **File/Directory Path:** `sbin/pktlogconf`
- **Location:** `sbin/pktlogconf (dynamic linker reference)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Not applicable (version info from dynamic linker reference)
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** The exact version of uClibc could not be determined from this file alone. Further analysis of other files (particularly /lib/ld-uClibc.so.0) would be needed to get the exact version. Only the top 3 most severe CVEs are shown. Additional CVEs were found but not included in this report.

---
### Linux-Kernel-2.6.15-rc.modules

- **File/Directory Path:** `etc/rc.d/rc.modules`
- **Location:** `rc.modules`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** An outdated Linux kernel version 2.6.15 was detected in the rc.modules file, which contains multiple known critical vulnerabilities:
- CVE-2006-7229 (CVSS 7.5): skge driver vulnerability may lead to remote denial of service
- CVE-2005-3784: ptrace reference issue may result in local privilege escalation
- CVE-2005-3807: Memory leak in VFS file lease handling
It is recommended to upgrade to a secure kernel version.
- **Keywords:** 2.6.15, Linux Kernel
- **Notes:** These kernel versions are outdated and contain multiple critical vulnerabilities, particularly the CVE-2005-3784 local privilege escalation vulnerability which poses an extremely high risk. The version information is sourced from the rc.modules file.

---
### Linux-Kernel-2.6.31-rc.modules

- **File/Directory Path:** `etc/rc.d/rc.modules`
- **Location:** `rc.modules`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The rc.modules file was found to contain the outdated Linux kernel version 2.6.31, which has multiple known critical vulnerabilities:
- CVE-2009-2768 (CVSS 7.8): NULL pointer dereference in the flat subsystem
- CVE-2009-3620 (CVSS 7.8): Privilege escalation vulnerability in ATI Rage 128 driver
- CVE-2009-4272 (CVSS 7.5): IPv4 routing hash table deadlock vulnerability
It is recommended to upgrade to a secure kernel version.
- **Keywords:** 2.6.31, Linux Kernel
- **Notes:** These kernel versions are outdated and contain multiple critical vulnerabilities, particularly the CVE-2009-3620 local privilege escalation vulnerability which poses an extremely high risk. The version information is sourced from the rc.modules file.

---
### thirdparty-uClibc-ld-uClibc

- **File/Directory Path:** `sbin/pktlogdump`
- **Location:** `sbin/pktlogdump: (HIDDENr2HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** The uClibc component was found in the 'sbin/pktlogdump' file, with the dynamic linker path being '/lib/ld-uClibc.so.0'. The version is unknown and requires further confirmation. Relevant high-risk CVEs include: CVE-2017-9728 (CVSSv3: 9.8), CVE-2022-29503 (CVSSv3: 9.8), CVE-2021-43523, etc.
- **Code Snippet:**
  ```
  HIDDEN：/lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, ld-uClibc.so.0, libc.so.0
- **Notes:** The version information of uClibc needs to be further verified to accurately assess the impact of related vulnerabilities.

---
### kernel-Linux-tphotplug

- **File/Directory Path:** `sbin/tphotplug`
- **Location:** `sbin/tphotplug (strings output)`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** The binary file was found to reference Linux kernel version 2.6.31. This version is outdated and contains numerous known vulnerabilities. Evidence stems from strings related to kernel operations and version numbers.
- **Code Snippet:**
  ```
  2.6.31
  NetUSB.ko
  ```
- **Keywords:** 2.6.31, NetUSB.ko, Linux kernel, tphotplug
- **Notes:** This kernel version is outdated and has numerous known vulnerabilities that could affect the system security.

---
### SBOM-uClibc-unknown

- **File/Directory Path:** `sbin/athstatsclr`
- **Location:** `sbin/athstatsclr (HIDDENstringsHIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 7.0
- **Description:** uClibc dynamic library, version unknown, identified via dynamic library path /lib/ld-uClibc.so.0. Potential vulnerabilities include: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6). Due to unknown version, it is recommended to check the /lib/ld-uClibc.so.x file for exact version information.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** /lib/ld-uClibc.so.0, uClibc
- **Notes:** Since the version is unknown, it is recommended to check the /lib/ld-uClibc.so.x file for the exact version, assuming the worst-case scenario (all listed uClibc vulnerabilities may exist).

---
### SBOM-BusyBox-v1.01-Consolidated

- **File/Directory Path:** `bin/cat`
- **Location:** `Multiple locations: bin/cat, bin/msh, bin/ls, bin/ps, bin/hostname, bin/mount, bin/ip, bin/kill`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** third_party_component
- **Code Snippet:**
  ```
  Multiple instances of: 'BusyBox v1.01 (2015.05.14-11:58+0000) multi-call binary'
  ```
- **Keywords:** BusyBox, v1.01, 2015.05.14-11:58+0000, SBOM, third-party
- **Notes:** third_party_component

---
### SBOM-BusyBox-v1.01

- **File/Directory Path:** `bin/cat`
- **Location:** `strings output from 'bin/cat'`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** BusyBox v1.01 (2015.05.14-11:58+0000) identified in 'bin/cat' with known CVEs: CVE-2016-2147, CVE-2016-2148, CVE-2016-6301. These vulnerabilities are associated with this specific version of BusyBox.
- **Code Snippet:**
  ```
  Evidence from strings output showing BusyBox version
  ```
- **Keywords:** BusyBox, v1.01, bin/cat
- **Notes:** BusyBox v1.01 is known to have several vulnerabilities. Further analysis of the actual BusyBox binary is recommended for complete CVE coverage.

---
### thirdparty-BusyBox-kill

- **File/Directory Path:** `bin/kill`
- **Location:** `bin/kill → busybox`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'bin/kill' is a symbolic link to BusyBox version 1.01 (built on May 14, 2015). The BusyBox 1.x series contains multiple high-risk vulnerabilities, including remote code execution (CVE-2019-5138, CVE-2022-48174), stack overflow (CVE-2016-2148), and command injection (CVE-2017-16544). Although no specific CVEs were found for version 1.01, this version may have similar security risks.
- **Code Snippet:**
  ```
  BusyBox v1.01 (2015.05.14-11:58+0000) multi-call binary
  ```
- **Keywords:** BusyBox, v1.01, 2015.05.14, kill, symbolic link
- **Notes:** Although no specific CVEs were found for version 1.01, the BusyBox 1.x series contains multiple high-risk vulnerabilities. It is recommended to upgrade to the latest version. Further verification is needed to determine whether these vulnerabilities affect version 1.01.

---
### component-iptables-version

- **File/Directory Path:** `sbin/iptables`
- **Location:** `strings output of iptables`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The iptables version information found in 'sbin/iptables'. Version 1.4.5 was confirmed through the strings 'iptables multi-purpose version: unknown subcommand "%s"' and '# Generated by iptables-save v%s on %s'. Further investigation is required to identify CVEs associated with this version.
- **Code Snippet:**
  ```
  iptables multi-purpose version: unknown subcommand "%s"
  # Generated by iptables-save v%s on %s
  ```
- **Keywords:** iptables, iptables-save, 1.4.5
- **Notes:** configuration_load

---
### SBOM-uClibc-component

- **File/Directory Path:** `sbin/apstats`
- **Location:** `sbin/apstats:0 (Dynamic linker reference)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The uClibc component was found in the 'sbin/apstats' file, version unknown. Evidence comes from dynamic linker reference: '/lib/ld-uClibc.so.0'. Associated known high-risk vulnerabilities: CVE-2017-9728, CVE-2022-29503, CVE-2021-43523.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** uClibc, libc.so.0, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** Further confirmation is required for the exact version of uClibc.

---
### compiler-GCC-tphotplug

- **File/Directory Path:** `sbin/tphotplug`
- **Location:** `sbin/tphotplug (strings output)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Analysis of 'sbin/tphotplug' revealed embedded GCC compiler versions 3.3.2 and 4.3.3. These are very old versions with known vulnerabilities. The evidence comes from version strings embedded in the binary.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.3.3
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (GNU) 4.3.3, tphotplug, compiler
- **Notes:** configuration_load

---
### SBOM-NTFS-3G-unknown

- **File/Directory Path:** `bin/ntfs-3g`
- **Location:** `bin/ntfs-3g`
- **Risk Score:** 7.8
- **Confidence:** 7.0
- **Description:** The NTFS-3G component was identified in the file 'bin/ntfs-3g', but no explicit version number string could be found. According to CVE search results, this component contains multiple high-risk vulnerabilities (CVSSv3 score 7.8), particularly affecting NTFS-3G versions prior to 2021.8.22. These vulnerabilities may lead to privilege escalation, memory leaks, denial of service, or even code execution. Since the specific version cannot be determined, it is recommended to assume this component is vulnerable to these flaws.
- **Keywords:** ntfs-3g, libntfs-3g.so.83, fuse, ntfs_get_attribute_value, ntfs_inode_real_open, ntfs_attr_setup_flag, ntfs_attr_pread_i
- **Notes:** It is recommended to confirm the exact version through other methods (such as checking package manager logs or build information). All discovered CVEs affect versions prior to 2021.8.22, indicating this component may contain multiple high-risk vulnerabilities.

---
### SBOM-libgcc-iwpriv

- **File/Directory Path:** `sbin/iwpriv`
- **Location:** `sbin/iwpriv`
- **Risk Score:** 7.8
- **Confidence:** 6.5
- **Description:** The SBOM information of the libgcc component found in the file 'sbin/iwpriv'. The version number is 1, confirmed by the 'libgcc_s.so.1' string in the strings output. There is a potential vulnerability CVE-2022-48422 (local users can elevate privileges by placing a malicious libgcc_s.so.1 file in the current working directory, CVSS 7.8).
- **Code Snippet:**
  ```
  libgcc_s.so.1
  ```
- **Keywords:** libgcc_s.so.1
- **Notes:** Verify whether the firmware is running on the affected Linux distribution

---
### SBOM-LinuxKernel-2.6.15

- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `/etc/rc.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A Linux Kernel component found in the '/etc/rc.d/rcS' file, version 2.6.15. The related module path is '/lib/modules/2.6.15/net/'. This version contains multiple high-risk vulnerabilities, including CVE-2006-7229 (CVSS 7.5), CVE-2005-3784, and CVE-2005-3807, totaling 20 CVEs.
- **Code Snippet:**
  ```
  Found in '/etc/rc.d/rcS' file, referenced module paths '/lib/modules/2.6.15/net/'
  ```
- **Keywords:** /etc/rc.d/rcS, /lib/modules/2.6.15/net/, Linux Kernel
- **Notes:** configuration_load

---
### component-BusyBox-v1.01

- **File/Directory Path:** `bin/msh`
- **Location:** `bin/msh: Found in strings output as 'BusyBox v1.01 (2015.05.14-11:58+0000)'`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The BusyBox component found in the bin/msh file, version v1.01 (2015.05.14-11:58+0000). Known high-risk vulnerabilities include: CVE-2019-5138, CVE-2016-2148, CVE-2016-5791, CVE-2018-1000517, CVE-2017-8415, CVE-2018-14494, CVE-2019-13473, CVE-2021-37555, CVE-2021-42377, CVE-2022-48174.
- **Code Snippet:**
  ```
  BusyBox v1.01 (2015.05.14-11:58+0000)
  ```
- **Keywords:** BusyBox, v1.01
- **Notes:** Further verification is required to determine whether the BusyBox vulnerability applies to the specific usage scenarios of the current firmware.

---
### SBOM-httpd-Unknown

- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `/etc/rc.d/rcS`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The httpd component found in the '/etc/rc.d/rcS' file has an execution path of '/usr/bin/httpd' with an unknown version. This component contains multiple high-risk vulnerabilities, including CVE-1999-0236 (CVSS 7.5), CVE-2002-1850 (CVSS 7.5), and CVE-1999-0071, totaling 10 CVEs.
- **Code Snippet:**
  ```
  Found in '/etc/rc.d/rcS' file, execution path '/usr/bin/httpd'
  ```
- **Keywords:** /etc/rc.d/rcS, /usr/bin/httpd, httpd
- **Notes:** A total of 10 CVE vulnerabilities targeting httpd were discovered. Displaying the 3 most severe vulnerabilities. Precise version determination requires analysis of the httpd binary file.

---
### component-GCC-radartool

- **File/Directory Path:** `sbin/radartool`
- **Location:** `radartool: strings output`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** GCC compiler information found in the 'sbin/radartool' file. Evidence sources include the strings 'GCC: (GNU) 3.3.2' and 'GCC: (GNU) 4.3.3'. These compiler versions may contain known vulnerabilities, and it is recommended to query the CVE database.
- **Code Snippet:**
  ```
  N/A (HIDDENstringsHIDDEN)
  ```
- **Keywords:** GCC: (GNU) 3.3.2, GCC: (GNU) 4.3.3
- **Notes:** These compiler versions may have known vulnerabilities; it is recommended to check the CVE database.

---
### SBOM-GCC-wifitool

- **File/Directory Path:** `sbin/wifitool`
- **Location:** `sbin/wifitool:HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The file 'sbin/wifitool' contains information identifying GCC versions 3.3.2 and 4.3.3. These versions are outdated and may contain known vulnerabilities. The evidence source is the string table within the file.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  GCC: (GNU) 4.3.3
  ```
- **Keywords:** GCC, GNU, 3.3.2, 4.3.3
- **Notes:** GCC 3.3.2 and 4.3.3 are both older versions that may contain known vulnerabilities. Further vulnerability scanning is required.

---
### SBOM-libcrypt.so.0-bin/ln

- **File/Directory Path:** `bin/ln`
- **Location:** `bin/ln`
- **Risk Score:** 7.0
- **Confidence:** 3.0
- **Description:** The libcrypt.so.0 component was found in the bin/ln file with an unknown version. Potential vulnerabilities include CVE-2024-10068, CVE-2016-9939, and CVE-2023-26031. Verification is required to confirm the exact version and whether it originates from OpenSSL.
- **Code Snippet:**
  ```
  Evidence source: readelf -d output from 'bin/ln'
  ```
- **Keywords:** libcrypt.so.0
- **Notes:** configuration_load

---
