# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (8 alerts)

---

### sbom-uClibc-0.9.33.2

- **File/Directory Path:** `usr/bin/app_data_center`
- **Location:** `usr/bin/app_data_center`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The file usr/bin/app_data_center was found to contain uClibc version 0.9.33.2, with the evidence string '/lib/ld-uClibc.so.0'. Special attention is required for CVE-2022-29503 (CVSS 9.8), which affects uClibC version 0.9.33.2.
- **Code Snippet:**
  ```
  HIDDEN '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** uClibc, CVE-2022-29503, libc
- **Notes:** Further verification is required to assess the actual impact of the CVE-2022-29503 vulnerability.

---
### sbom-FastCGI

- **File/Directory Path:** `usr/bin/app_data_center`
- **Location:** `usr/bin/app_data_center`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** A FastCGI component with unknown version was detected in the file usr/bin/app_data_center, evidenced by the string 'FCGI_ROLE=RESPONDER'. Related high-risk CVEs include CVE-2018-5347 (CVSS 9.8, unauthenticated command injection vulnerability) and CVE-2025-23016 (CVSS 9.3, integer overflow and heap buffer overflow vulnerability).
- **Code Snippet:**
  ```
  HIDDEN 'FCGI_ROLE=RESPONDER'
  ```
- **Keywords:** FastCGI, CVE-2018-5347, web
- **Notes:** Since the FastCGI version is unknown, it is recommended to further analyze the firmware to determine the specific implementation and version number.

---
### sbom-libpthread

- **File/Directory Path:** `usr/bin/app_data_center`
- **Location:** `usr/bin/app_data_center`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** The libpthread component was detected in the file usr/bin/app_data_center with an unknown version, evidenced by the string 'libpthread.so.0'. Potentially related CVEs include CVE-2022-29503 (CVSS 9.8, uClibC memory corruption vulnerability), requiring version information to determine the exact applicability of the vulnerability.
- **Code Snippet:**
  ```
  HIDDEN 'libpthread.so.0'
  ```
- **Keywords:** libpthread, CVE-2022-29503, thread
- **Notes:** Version information is required to determine the exact applicability of the vulnerability, with CVE-2022-29503 being particularly critical (CVSS 9.8).

---
### component-libnvram.so

- **File/Directory Path:** `usr/bin/eapd`
- **Location:** `usr/bin/eapd`
- **Risk Score:** 8.8
- **Confidence:** 5.0
- **Description:** The libnvram.so component was found in the file 'usr/bin/eapd', with an unknown version. Associated potentially high-risk vulnerabilities include: CVE-2022-26780 (CVSS 8.8), CVE-2022-26781 (CVSS 8.8), CVE-2022-26782 (CVSS 8.8). These vulnerabilities target specific vendors and versions of libnvram implementations.
- **Code Snippet:**
  ```
  libnvram.so
  ```
- **Keywords:** libnvram.so
- **Notes:** Since the libnvram.so file was not found in the current firmware, it is not possible to confirm whether these vulnerabilities apply to the analyzed firmware. It is recommended to verify the location of the libnvram.so file for more accurate version and vulnerability analysis.

---
### thirdparty-zlib-dependency

- **File/Directory Path:** `usr/bin/nginx`
- **Location:** `usr/bin/nginx:0 (dynamic dependencies)`
- **Risk Score:** 8.0
- **Confidence:** 5.5
- **Description:** The zlib dependency information found in the nginx binary. The dynamic dependency is libz.so.1, but the exact version is unknown. Potential high-risk vulnerabilities include CVE-2002-0059, CVE-2016-9841, and CVE-2016-9843. Further verification is required to determine the exact version.
- **Code Snippet:**
  ```
  Dynamic dependency: libz.so.1
  ```
- **Keywords:** libz.so.1
- **Notes:** Search for the libz.so.1 file in the firmware to verify the exact version.

---
### thirdparty-udhcpc-CVEREDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.bound`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.bound`
- **Risk Score:** 7.8
- **Confidence:** 7.0
- **Description:** The file 'REDACTED_PASSWORD_PLACEHOLDER.bound' is a udhcpc renewal script used to configure network interfaces, routing, and DNS settings. While it does not directly contain version information, it mentions 'tenda add' and 'CONFIG_NEW_NETCTRL', suggesting a possible association with Tenda routers. A related CVE vulnerability, CVE-2021-34591, was identified, involving local privilege escalation where attackers could gain REDACTED_PASSWORD_PLACEHOLDER privileges through suid applications, including udhcpc.
- **Keywords:** udhcpc, tenda add, CONFIG_NEW_NETCTRL, CVE-2021-34591
- **Notes:** It is recommended to further analyze other files to confirm the specific version of udhcpc and whether other related vulnerabilities exist.

---
### thirdparty-udhcpc-CVE-2021-34591

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.renew`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.renew`
- **Risk Score:** 7.8
- **Confidence:** 6.0
- **Description:** The file 'REDACTED_PASSWORD_PLACEHOLDER.renew' is an example script bound to udhcpc, used for configuring network interfaces, routing, and DNS. The script mentions 'udhcpc' but does not directly provide the software name or version number. Research reveals that 'udhcpc' has a known CVE-2021-34591, involving a local privilege escalation vulnerability. Further analysis of other files or binaries is required to obtain specific version information for 'udhcpc'.
- **Keywords:** udhcpc, CVE-2021-34591
- **Notes:** Further analysis of other files or binaries is required to obtain the specific version information of 'udhcpc'.

---
### SBOM-iptables-1.4.12.2

- **File/Directory Path:** `usr/sbin/xtables-multi`
- **Location:** `Multiple locations in strings output`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The file 'usr/sbin/xtables-multi' has been analyzed and confirmed as an iptables component with version number 1.4.12.2. The version string is present in multiple locations within the binary file, particularly in help/usage messages and version output strings. Although no direct CVEs were found for this exact version, multiple high-risk vulnerabilities exist in iptables implementations, including command injection (CVE-2017-6079, CVE-2020-36178, CVE-2023-33376) and access control bypass (CVE-2021-20149).
- **Code Snippet:**
  ```
  # Generated by iptables-save v1.4.12.2 on %s
  ```
- **Keywords:** 1.4.12.2, iptables-save, ip6tables-save, xtables-multi, iptables-restore, ip6tables-restore
- **Notes:** While no direct CVEs were found for version 1.4.12.2, general iptables vulnerabilities should be considered as they may affect this version. It is recommended to further verify whether these vulnerabilities apply to this specific version.

---
