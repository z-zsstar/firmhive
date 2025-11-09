# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (2 alerts)

---

### SBOM-BusyBox-updated

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox (strings output)`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-04-22 19:07:41 HKT)
  ```
- **Keywords:** BusyBox v1.19.2, Buildroot 2012.02, DHCP client
- **Notes:** BusyBox version 1.19.2 is known to have multiple vulnerabilities and should be upgraded

---
### SBOM-BusyBox-wget

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox .rodataHIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-04-22 19:07:41 HKT)
  ```
- **Keywords:** wget, BusyBox v1.19.2, CVE-2018-1000517, bin/busybox
- **Notes:** It is recommended to upgrade BusyBox to the latest version to fix known vulnerabilities. While some CVEs may not directly affect the wget functionality, the shared BusyBox codebase means vulnerabilities in other components could potentially be exploited to compromise system security.

---
