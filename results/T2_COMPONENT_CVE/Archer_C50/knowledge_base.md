# Archer_C50 (17 alerts)

---

### SBOM-BusyBox-1.19.2

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The BusyBox version 1.19.2 found in the 'bin/sh' file contains multiple high-risk vulnerabilities. The version information is derived from the string table within the binary file, serving as a reliable version identifier. The discovered vulnerability information is sourced from the public CVE database and applies to BusyBox 1.19.2 or earlier versions. It is recommended to upgrade to the latest version of BusyBox to address these vulnerabilities.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, bin/sh, udhcpc, OPTION_6RD, TELNET, authentication, wget, buffer overflow, telnet, getspnam, command injection, REDACTED_PASSWORD_PLACEHOLDER access, default credentials, hush applet, pointer free, ash.c, stack overflow
- **Notes:** The version information is sourced from the string table within the binary file, serving as a reliable version identifier. The discovered vulnerability details originate from the public CVE database and are applicable to BusyBox 1.19.2 or earlier versions. Although some vulnerabilities target specific devices, they may also apply to similar configurations of BusyBox 1.19.2.

---
### CVE-2016-2148

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox before 1.25.0 allows remote attackers to have unspecified impact via vectors involving OPTION_6RD parsing.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, udhcpc, OPTION_6RD
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2016-5791

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** An Improper Authentication issue was discovered in JanTek JTC-200, all versions. The improper authentication could provide an undocumented BusyBox Linux shell accessible over the TELNET service without any authentication.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, TELNET, authentication
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2017-8415

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** BusyBox wget versions before commit REDACTED_PASSWORD_PLACEHOLDER contain a buffer overflow vulnerability in the BusyBox wget component that may lead to heap buffer overflow. This vulnerability appears exploitable through network connectivity.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, wget, buffer overflow
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2018-1000517

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** An issue was discovered on D-Link DCS-1100 and DCS-1130 devices. The device has a custom telnet daemon as a part of the busybox and retrieves the REDACTED_PASSWORD_PLACEHOLDER from the shadow file using the function getspnam.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, telnet, getspnam
- **Notes:** Affecting BusyBox 1.19.2 and earlier versions

---
### CVE-2018-14494

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Vivotek FD8136 devices are vulnerable to remote command injection, which is associated with BusyBox and wget.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, wget, command injection
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2019-13473

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** TELESTAR Bobs Rock Radio and other devices have an undisclosed TELNET service in the BusyBox subsystem, which can lead to obtaining REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, TELNET, REDACTED_PASSWORD_PLACEHOLDER access
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2021-37555

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The TX9 automatic feeder device allows shell access via telnet as REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER, using default credentials and the pre-installed BusyBox toolset.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, telnet, default credentials
- **Notes:** Affects BusyBox 1.19.2 and earlier versions

---
### CVE-2021-42377

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** An attacker-controlled pointer free in Busybox's hush applet leads to denial of service and possible code execution when processing a crafted shell command, due to the shell mishandling the &&& string.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, hush applet, pointer free
- **Notes:** Affecting BusyBox 1.19.2 and earlier versions

---
### CVE-2022-48174

- **File/Directory Path:** `bin/sh`
- **Location:** `bin/sh`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** command_execution
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-03-25 11:42:55 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2, ash.c, stack overflow
- **Notes:** Affects BusyBox versions 1.19.2 and earlier

---
### SBOM-uClibc-Unknown

- **File/Directory Path:** `sbin/hotplug`
- **Location:** `Linked library reference (libc.so.0)`
- **Risk Score:** 9.5
- **Confidence:** 8.0
- **Description:** The version of the uClibc library is unknown and contains multiple high-risk vulnerabilities (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523).
- **Code Snippet:**
  ```
  N/A (dynamic linking reference)
  ```
- **Keywords:** uClibc, libc, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** Evidence source: hotplug (dynamic linking references). Multiple high-risk CVEs exist, requiring further determination of the exact version.

---
### vulnerability-CVE-2020-8597

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `usr/sbin/pppd (strings output)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** rhosname buffer overflow in pppd version 2.4.5
- **Code Snippet:**
  ```
  pppd version 2.4.5
  ```
- **Keywords:** pppd, pppd version 2.4.5, CVE-2020-8597
- **Notes:** Although CVE does not explicitly list version 2.4.5, it may still be applicable given the version proximity (2.4.2-2.4.8).

---
### SBOM-GCC-4.6.3

- **File/Directory Path:** `usr/sbin/ripd`
- **Location:** `usr/sbin/ripd (strings output)`
- **Risk Score:** 8.0
- **Confidence:** 5.0
- **Description:** Compiler version identified as GCC 4.6.3 (Buildroot 2012.11.1). This version is outdated and may have multiple CVEs.
- **Code Snippet:**
  ```
  GCC: (Buildroot 2012.11.1) 4.6.3
  ```
- **Keywords:** GCC: (Buildroot 2012.11.1) 4.6.3
- **Notes:** GCC 4.6.3 is outdated and may have multiple CVEs

---
### thirdparty-component-upnp-sdk-1.6.19

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.soHIDDEN`
- **Risk Score:** 7.6
- **Confidence:** 7.5
- **Description:** Portable SDK for UPnP devices version 1.6.19 component information. This version fixes multiple stack overflow vulnerabilities (CVE-2012-5958 to CVE-2012-5965) present in versions prior to 1.6.18, but it may still be vulnerable to DNS rebinding attacks (CVE-2021-29462). The DNS rebinding attack vulnerability exists in the server component because it does not validate the Host header value. It is recommended to upgrade to version 1.14.6 or later to fully address the DNS rebinding vulnerability. For version 1.6.19, the risk can be mitigated by using a DNS resolver that blocks DNS rebinding attacks.
- **Code Snippet:**
  ```
  %s/%s, UPnP/1.0, Portable SDK for UPnP devices/1.6.19
  ```
- **Keywords:** libupnp.so, Portable SDK for UPnP devices/1.6.19, unique_service_name, ssdp/ssdp_server.c, Host header
- **Notes:** Component Name: Portable SDK for UPnP devices  
Version: 1.6.19  
Known Vulnerabilities:  
- CVE-2012-5958 to CVE-2012-5965: Multiple stack overflow vulnerabilities (fixed)  
- CVE-2021-29462: DNS rebinding attack vulnerability (unfixed)  
Evidence Source: Version string in the lib/libupnp.so file

---
### component-pppd-version

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `usr/sbin/pppd (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The version information 2.4.5 of the pppd component was found in the file 'usr/sbin/pppd', and related potential vulnerabilities were identified. It is recommended to further verify whether these vulnerabilities indeed affect version 2.4.5 and consider upgrading to a newer version to fix potential vulnerabilities.
- **Code Snippet:**
  ```
  pppd version 2.4.5
  ```
- **Keywords:** pppd, pppd version 2.4.5, CVE-2020-8597, CVE-2004-1002
- **Notes:** Although CVE does not explicitly list version 2.4.5, it may still be applicable given the version proximity (2.4.2-2.4.8).

---
### vulnerability-CVE-2004-1002

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `usr/sbin/pppd (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** CBCP integer underflow in pppd version 2.4.5
- **Code Snippet:**
  ```
  pppd version 2.4.5
  ```
- **Keywords:** pppd, pppd version 2.4.5, CVE-2004-1002
- **Notes:** Although CVE does not explicitly list version 2.4.5, it may still be applicable given the version proximity (2.4.2-2.4.8).

---
### SBOM-libpthread-Unknown

- **File/Directory Path:** `sbin/hotplug`
- **Location:** `Linked library reference (libpthread.so.0)`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The version of the libpthread library is unknown and is part of the uClibc implementation. The version needs to be determined for accurate evaluation.
- **Code Snippet:**
  ```
  N/A (dynamic linking reference)
  ```
- **Keywords:** libpthread, uClibc
- **Notes:** Evidence source: hotplug (dynamic linking references). Version-specific CVE cannot be determined.

---
