# Archer_C50 (12 alerts)

---

### cve-dropbear-CVE-2016-7406

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Dropbear SSH versions prior to 2016.74 contain a format string vulnerability that allows attackers to achieve remote code execution by inserting format string specifiers in the REDACTED_PASSWORD_PLACEHOLDER or host parameters.
- **Keywords:** dropbear, ssh, 2012.55, CVE-2016-7406
- **Notes:** Status: Potentially affects (version 2012.55 is older than vulnerable version)

---
### cve-dropbear-CVE-2016-7407

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** The dropbearconvert command allows arbitrary code execution via crafted OpenSSH REDACTED_PASSWORD_PLACEHOLDER file
- **Keywords:** dropbear, ssh, 2012.55, CVE-2016-7407
- **Notes:** file_read

---
### cve-vsftpd-CVE-2011-2523

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/vsftpd`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** vsftpd 2.3.4 downloaded between REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER contains a backdoor which opens a shell on port 6200/tcp
- **Keywords:** vsftpd, 2.3.2, CVE-2011-2523, backdoor
- **Notes:** Although this system is version 2.3.2, vigilance against similar backdoor risks remains necessary.

---
### sbom-dropbear-ssh-2012.55

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** SBOM analysis results for Dropbear SSH component version 2012.55. This version is outdated (released in 2012) and contains multiple high-risk vulnerabilities. Version evidence comes from string matching in binary files.
- **Keywords:** dropbear, ssh, 2012.55, dropbearmulti
- **Notes:** Version evidence: Found version string '2012.55' in binary strings output. Security recommendations: Upgrade to latest version, restrict SSH access, disable unused features.

---
### cve-dropbear-CVE-2016-7408

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.8
- **Confidence:** 8.0
- **Description:** dbclient allows remote code execution via crafted -m or -c argument
- **Keywords:** dropbear, ssh, 2012.55, CVE-2016-7408
- **Notes:** command_execution

---
### sbom-vsftpd-2.3.2

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/vsftpd .rodata section (offset: 0x00025a50)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Analysis results of the SBOM for the vsftpd component version 2.3.2. Version evidence is derived from string matches in the .rodata section of the binary file.
- **Keywords:** vsftpd, 2.3.2, ftp, server
- **Notes:** Version evidence: 'vsftpd: version 2.3.2\n' found in the .rodata section. Security recommendations: Check kernel version, restrict anonymous access, monitor port 6200, consider upgrading.

---
### sbom-ntfs-3g-2012.1.15

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/ntfs-3g`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Analysis results of the SBOM for NTFS-3g component version 2012.1.15. This version is outdated (released in 2012) and significantly older than the known vulnerable version (2021.8.22), potentially containing more undisclosed vulnerabilities.
- **Keywords:** ntfs-3g, 2012.1.15, libntfs-3g.so.83, fuse_version
- **Notes:** Version Evidence: The version string '2012.1.15' and copyright information in the file. Recommendations: 1. Upgrade to the latest version 2. Restrict write access 3. Monitor abnormal mounting behavior

---
### sbom-libntfs-3g-unknown

- **File/Directory Path:** `N/A`
- **Location:** `libntfs-3g.so.83.0.0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Analysis results of the NTFS-3G library file libntfs-3g.so.83.0.0. Although no version number was directly extracted, the presence of multiple high-risk CVE vulnerabilities (CVSSv3 7.8) has been confirmed, affecting versions prior to 2021.8.22.
- **Keywords:** libntfs-3g.so.83, libntfs-3g.so.83.0.0, ntfs_get_attribute_value, ntfs_inode_real_open
- **Notes:** Discovered 10 high-risk CVE vulnerabilities (heap/stack buffer overflows, null pointer dereferences, etc.). Recommendations: 1. Verify the version via the package manager. 2. Upgrade if the version is earlier than 2021.8.22. 3. Avoid mounting untrusted NTFS partitions.

---
### cve-dropbear-CVE-2021-36369

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Non-RFC compliant authentication method checks may lead to bypassing of security measures
- **Keywords:** dropbear, ssh, 2012.55, CVE-2021-36369
- **Notes:** network_input

---
### cve-vsftpd-CVE-2011-2189

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/vsftpd`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** Network namespace handling issue in Linux kernel 2.6.32 and earlier versions, which when combined with daemons like vsftpd that require separate namespaces for each connection, may lead to denial of service
- **Keywords:** vsftpd, 2.3.2, CVE-2011-2189, kernel
- **Notes:** Check the system kernel version

---
### sbom-httpd-custom

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (main binary)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** custom HTTP server implementation, version information not available
- **Keywords:** httpd, webserver, custom
- **Notes:** It might be a customized HTTP server implementation. The binary file has been stripped of symbols, increasing the difficulty of analysis.

---
### sbom-mt7620ap-v15

- **File/Directory Path:** `N/A`
- **Location:** `etc/MT7620_AP_2T2R-4L_V15.BIN`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** MT7620_AP firmware, filename indicates version V15, but vendor-specific vulnerability database confirmation required for risk assessment
- **Keywords:** mt7620, firmware, v15, wireless
- **Notes:** Check the manufacturer's firmware updates and security bulletins. The filename indicates version V15.

---
