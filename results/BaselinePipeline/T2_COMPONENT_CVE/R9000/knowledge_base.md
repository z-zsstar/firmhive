# R9000 (6 alerts)

---

### OpenSSL-0.9.8p

- **File/Directory Path:** `usr/bin/openssl`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** OpenSSL version 0.9.8p (from 2010) was found. This version is affected by multiple high-severity vulnerabilities including certificate forgery (CVE-2005-2946), predictable random number generation (CVE-2008-0166), and SSL/TLS protocol version rollback (CVE-2005-2969).
- **Code Snippet:**
  ```
  N/A (version info from strings output)
  ```
- **Keywords:** openssl, libssl.so.0.9.8, libcrypto.so.0.9.8
- **Notes:** While no CVEs explicitly mention version 0.9.8p, all listed vulnerabilities affect the 0.9.8 branch and should be considered relevant unless specifically fixed in the 'p' sub-release.

---
### Avahi-0.6.10

- **File/Directory Path:** `etc/avahi/avahi-daemon.conf`
- **Location:** `etc/avahi/avahi-daemon.conf`
- **Risk Score:** 9.3
- **Confidence:** 8.0
- **Description:** sbom_component
- **Code Snippet:**
  ```
  N/A (version estimation from file contents)
  ```
- **Keywords:** avahi-daemon.conf, enable-wide-area
- **Notes:** Version estimation based on file date and content patterns

---
### ubus-unknown

- **File/Directory Path:** `lib/libubus.so`
- **Location:** `lib/libubus.so`
- **Risk Score:** 8.8
- **Confidence:** 7.0
- **Description:** sbom_component
- **Code Snippet:**
  ```
  N/A (stripped binary)
  ```
- **Keywords:** ubus_connect, ubus_invoke, ubus_register_event_handler
- **Notes:** sbom_component

---
### Transmission-2.76

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Transmission BitTorrent client version 2.76 was found. This version is known to have multiple vulnerabilities including potential remote code execution and privilege escalation issues.
- **Code Snippet:**
  ```
  N/A (version string in binary)
  ```
- **Keywords:** transmission-daemon, TR2760
- **Notes:** Version found in strings: 'Transmission 2.76 (13786) http://www.transmissionbt.com/'

---
### aMule-2.3.1

- **File/Directory Path:** `etc/aMule/amule.conf`
- **Location:** `etc/aMule/amule.conf`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** aMule version 2.3.1 was found in configuration files. This version is vulnerable to buffer overflow (CVE-2013-4475) and directory traversal (CVE-2012-5614) attacks.
- **Code Snippet:**
  ```
  N/A (version in config file)
  ```
- **Keywords:** amule.conf, AppVersion
- **Notes:** sbom_component

---
### libevent-2.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Risk Score:** 7.2
- **Confidence:** 7.0
- **Description:** sbom_component
- **Code Snippet:**
  ```
  N/A (library linkage)
  ```
- **Keywords:** libevent-2.0.so.5, evbuffer_
- **Notes:** Discovered as a dynamic library dependency of transmission-daemon

---
