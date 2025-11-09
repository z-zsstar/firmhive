# _DWR-118_V1.01b01.bin.extracted (4 alerts)

---

### uClibc-unknown

- **File/Directory Path:** `lib/libc.so.0`
- **Location:** `lib/libc.so.0`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** uClibc library linked by multiple components. Version could not be determined from binary analysis alone but is likely around 0.9.33.2 based on Buildroot GCC version strings.
- **Code Snippet:**
  ```
  N/A (library binary)
  ```
- **Keywords:** uClibc, libc.so.0, GCC: (Buildroot 2011.05) 4.3.5
- **Notes:** library

---
### mini_httpd-1.19

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** network_service
- **Code Snippet:**
  ```
  Version string: 'mini_httpd/1.19 19dec2003'
  ```
- **Keywords:** mini_httpd, mini_httpd/1.19 19dec2003
- **Notes:** Very old version (from 2003). CVE search results not provided in findings but likely has known vulnerabilities given its age.

---
### Net-SNMP-4.1.2

- **File/Directory Path:** `usr/bin/snmpd-action (related to usr/sbin/snmpd)`
- **Location:** `usr/sbin/snmpd`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** Net-SNMP (formerly UCD-SNMP) version 4.1.2 identified through version strings in snmpd binary. No direct CVEs found for this specific version but later versions have significant vulnerabilities.
- **Code Snippet:**
  ```
  N/A (version strings in binary)
  ```
- **Keywords:** Net-SNMP, UCD-SNMP, snmpd, EXTEND-MIB
- **Notes:** While no CVEs were found for version 4.1.2, later versions have critical vulnerabilities. Vendor-specific advisories should be checked.

---
### ntpclient-unknown

- **File/Directory Path:** `usr/bin/ntpclient`
- **Location:** `usr/bin/ntpclient`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** executable
- **Code Snippet:**
  ```
  N/A (stripped binary)
  ```
- **Keywords:** ntpclient, uClibc, MIPS32
- **Notes:** executable file

---
