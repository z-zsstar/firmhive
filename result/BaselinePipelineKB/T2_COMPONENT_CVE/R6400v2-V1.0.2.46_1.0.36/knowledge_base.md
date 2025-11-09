# R6400v2-V1.0.2.46_1.0.36 (5 alerts)

---

### thirdparty-avahi-0.6-updated

- **File/Directory Path:** `N/A`
- **Location:** `lib/libavahi-client.so (HIDDEN)`
- **Risk Score:** 9.1
- **Confidence:** 4.75
- **Description:** Avahi version 0.6 was identified in the firmware. This version contains multiple known security vulnerabilities, including CVE-2017-6519 (CVSS 9.1) and CVE-2021-3468.
- **Code Snippet:**
  ```
  Found version string 'avahi 0.6' in binary file
  Also found build information: 'GCC: (Buildroot 2012.02) 4.5.3'
  ```
- **Keywords:** avahi 0.6, libavahi-client.so, avahi_client_get_version_string, avahi-daemon, mDNS, DNS-SD
- **Notes:** It is recommended to upgrade to the latest Avahi version (0.8 or newer) to address multiple vulnerabilities. If not required, the Avahi service can be disabled.

---
### thirdparty-openssl-1.0.2h

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0 (HIDDENstringsHIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The firmware contains OpenSSL version 1.0.2h. This version has multiple known critical vulnerabilities, including CVE-2016-2177 (CVSS 9.8) and CVE-2016-2176.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  TLSv1 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, SSLv3, TLSv1, DTLSv1
- **Notes:** This version contains multiple high-risk vulnerabilities. It is recommended to upgrade to a secure version as soon as possible.

---
### thirdparty-openssl-1.0.0

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 3.75
- **Description:** Third-party component OpenSSL 1.0.0 series (libssl.so.1.0.0 and libcrypto.so.1.0.0) detected, which contains multiple known vulnerabilities.
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0, CRYPTO_
- **Notes:** OpenSSL 1.0.0 series contains multiple critical vulnerabilities. It is necessary to confirm the exact version and check the relevant CVEs.

---
### thirdparty-dbus-1.6.8

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/dbus-daemon`
- **Risk Score:** 7.5
- **Confidence:** 4.0
- **Description:** The firmware contains dbus-daemon version 1.6.8. While no CVEs directly associated with this specific version were found, multiple security vulnerabilities related to DBus have been identified, some of which may potentially affect system security.
- **Code Snippet:**
  ```
  libdbus 1.6.8
  ```
- **Keywords:** libdbus 1.6.8, dbus-daemon, D-Bus
- **Notes:** thirdparty_component

---
### thirdparty-avahi-0.6.25

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/avahi-browse (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The firmware contains Avahi version 0.6.25. This version has a known denial-of-service vulnerability CVE-2010-2244, which may allow remote attackers to cause service denial by sending specially crafted DNS packets.
- **Code Snippet:**
  ```
  avahi-browse 0.6.25
  ```
- **Keywords:** avahi-browse, avahi_service_browser_new, avahi_client_get_version_string, avahi-daemon
- **Notes:** The discovered CVE-2010-2244 vulnerability may allow remote attackers to cause a denial of service by sending specially crafted DNS packets. It is recommended to upgrade to a higher version of Avahi. Version evidence source: version string in the usr/bin/avahi-browse file.

---
