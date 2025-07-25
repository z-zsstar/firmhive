# _AC1450-V1.0.0.36_10.0.17.chk.extracted (2 alerts)

---

### thirdparty-pupnp-libupnp

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libupnp.so`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Portable UPnP SDK (pupnp) implementation. Based on the Buildroot 2012.02 compilation environment and code characteristics (Server string format), it is inferred to be the pupnp 1.6.x series version. Two high-risk CVE vulnerabilities were found affecting this component. Version evidence source: format string 'Server: POSIX, UPnP/1.0 %s/%s' in usr/lib/libupnp.so.
- **Code Snippet:**
  ```
  HTTP/1.1 200 OK\r\nServer: POSIX, UPnP/1.0 %s/%s\r\n
  ```
- **Keywords:** Server: POSIX UPnP/1.0, UPnP Stack, pupnp, libupnp.so
- **Notes:** Estimated version range: pupnp 1.6.x. Related CVE vulnerabilities: CVE-2021-29462 (DNS rebinding attack, CVSS 7.6, affects versions <1.14.6), CVE-2021-28302 (stack overflow DoS, CVSS 7.5, affects versions <1.14.5). Recommended upgrade to 1.14.6+. Version evidence: Server string format in usr/lib/libupnp.so.

---
### thirdparty-iptables-libnetconf

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnetconf.so`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** A 32-bit ARM architecture dynamic link library, related to iptables network configuration. Based on the compilation environment and library context, it likely belongs to the iptables 1.4.x series. A high-risk vulnerability CVE-2012-2663 affecting this component has been identified.
- **Code Snippet:**
  ```
  libiptc v%s. %u bytes.
  ```
- **Keywords:** libnetconf.so, libiptc, iptables, GCC: (Buildroot 2012.02) 4.5.3
- **Notes:** Version inference basis: 1) GCC 4.5.3 (Buildroot 2012.02) compilation environment 2) libiptc-related string formats 3) Historical version release dates. It is recommended to confirm the exact version through dependency analysis or documentation.

---
