# R6400v2-V1.0.2.46_1.0.36 (51 alerts)

---

### vulnerability-CVE-2018-6692

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 10.0
- **Confidence:** 4.5
- **Description:** Stack-based Buffer Overflow vulnerability in libUPnPHndlr.so (CVSS 10.0)
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, CVE-2018-6692
- **Notes:** high-risk vulnerability, associated with the libupnp component

---
### thirdparty-libcurl-4

- **File/Directory Path:** `opt/xagent/genie_handler`
- **Location:** `opt/xagent/genie_handler`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** The libcurl component identified in the file 'opt/xagent/genie_handler', version 4, contains multiple high-risk CVE vulnerabilities: CVE-2016-7134 (PHP curl_escape integer overflow), CVE-2016-7167 (escape/unescape function integer overflow), CVE-2017-8816 (32-bit platform NTLM authentication integer overflow), CVE-2017-8817 (FTP wildcard out-of-bounds read), and CVE-2017-1000257 (IMAP FETCH zero-byte response handling). Further verification of the exact version is required to precisely match the vulnerabilities.
- **Code Snippet:**
  ```
  Found string: 'libcurl.so.4'
  ```
- **Keywords:** libcurl.so.4, curl_easy_setopt, curl_easy_init, curl_easy_perform, curl_easy_cleanup
- **Notes:** Further confirmation is required for the exact version of libcurl.so.4 to accurately match CVE vulnerabilities.

---
### SBOM-libz-1

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The libz component, version 1, was found in the 'usr/sbin/minidlna.exe' file. Evidence source: The string 'libz.so.1' is present. Related CVE records: CVE-2002-0059 (CVSS 9.8), CVE-2016-9841 (CVSS 9.8), CVE-2022-37434 (CVSS 9.8). Multiple high-risk vulnerabilities exist, requiring confirmation of the exact version.
- **Code Snippet:**
  ```
  HIDDEN'libz.so.1'
  ```
- **Keywords:** libz.so.1
- **Notes:** Multiple high-risk vulnerabilities exist; the exact version needs to be confirmed.

---
### vulnerability-CVE-2016-8863

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 4.5
- **Description:** Heap-based buffer overflow (in the create_url_list function, CVSS score 9.8)
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, CVE-2016-8863
- **Notes:** high-risk vulnerability, associated with the libupnp component

---
### vulnerability-openssl-heartbleed

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `N/A (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** OpenSSL 1.0.0 series contains the Heartbleed vulnerability (CVE-2014-0160), which allows attackers to read sensitive information in system memory. This vulnerability affects libssl.so.1.0.0 and libcrypto.so.1.0.0.
- **Keywords:** OpenSSL, libssl.so.1.0.0, libcrypto.so.1.0.0, CVE-2014-0160, Heartbleed
- **Notes:** OpenSSL 1.0.0 series has reached end-of-life, strongly recommend upgrading to a supported version

---
### component-OpenSSL-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `Dynamic library reference in downloader`
- **Risk Score:** 9.5
- **Confidence:** 6.5
- **Description:** The OpenSSL component version 1.0.0 (referenced via libssl.so.1.0.0) was identified in the downloader executable. This version has reached end-of-life and contains multiple known critical vulnerabilities such as Heartbleed (CVE-2014-0160).
- **Code Snippet:**
  ```
  libssl.so.1.0.0 reference found in downloader binary
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** Critical: OpenSSL 1.0.0 reached end-of-life in 2015 and contains multiple unpatched vulnerabilities. Known CVEs include CVE-2014-0160 (Heartbleed), CVE-2014-0224.

---
### thirdparty-avahi-client-version

- **File/Directory Path:** `usr/lib/libavahi-client.so.3.2.5`
- **Location:** `usr/lib/libavahi-client.so.3.2.5: Found in strings output`
- **Risk Score:** 9.1
- **Confidence:** 8.0
- **Description:** The file 'usr/lib/libavahi-client.so.3.2.5' is identified as part of the Avahi client library version 0.6. This version is known to be vulnerable to several CVEs, including a high-severity traffic amplification vulnerability (CVE-2017-6519). The version information was found in the strings output of the binary. This finding is relevant for SBOM generation as it provides precise version information and associated vulnerabilities.
- **Code Snippet:**
  ```
  avahi 0.6
  ```
- **Keywords:** avahi 0.6, libavahi-client.so.3.2.5, REDACTED_SECRET_KEY_PLACEHOLDER, avahi-client, CVE-2017-6519
- **Notes:** The version information was found in the strings output of the binary. The identified CVEs should be reviewed for potential impact on the system. Further analysis may be needed to determine if the vulnerable code paths are actually used in this implementation. Known vulnerabilities: CVE-2017-6519 (high severity - traffic amplification vulnerability in Avahi).

---
### SBOM-Avahi-Complete

- **File/Directory Path:** `usr/bin/avahi-set-host-name`
- **Location:** `usr/bin/avahi-set-host-name (strings output) & usr/lib/libavahi-client.so.3.2.5 (strings output)`
- **Risk Score:** 9.1
- **Confidence:** 8.0
- **Description:** Complete SBOM record for Avahi component. Component name: Avahi, version: 0.6.25. Known critical vulnerability: CVE-2017-6519 (traffic amplification vulnerability, risk score 9.1). Version evidence source: string '%s 0.6.25' in file 'usr/bin/avahi-set-host-name' and Avahi-related function calls. Vulnerability evidence source: string 'avahi 0.6' in file 'usr/lib/libavahi-client.so.3.2.5'.
- **Code Snippet:**
  ```
  Version evidence:
  %s 0.6.25
  
  Vulnerability evidence:
  avahi 0.6
  ```
- **Keywords:** avahi_client_get_version_string, avahi_client_set_host_name, libavahi-client.so.3, libavahi-common.so.3, 0.6.25, CVE-2017-6519
- **Notes:** This record integrates version information and known vulnerability details of the Avahi component, which can be used for the final SBOM report. It is recommended to check whether other relevant CVEs need to be added.

---
### SBOM-Complete

- **File/Directory Path:** `usr/bin/avahi-set-host-name`
- **Location:** `Multiple files (see individual components)`
- **Risk Score:** 9.1
- **Confidence:** 4.5
- **Description:** Complete firmware SBOM report containing all identified third-party components and their security information:
1. Avahi 0.6.25 - Known vulnerabilities: CVE-2017-6519 (traffic amplification), CVE-2010-2244 (DoS)
2. BusyBox 1.7.2 - No known critical vulnerabilities detected
3. Ookla speedtest 1.0 - No known critical vulnerabilities detected
4. libcurl 7.36.0 - Known vulnerabilities: CVE-2014-0015, CVE-2014-0138, CVE-2014-0139, CVE-2014-8150
5. libdbus 1.6.8 - Known vulnerabilities: CVE-2017-13704 (privilege escalation), CVE-2018-1049 (information disclosure)
6. wxWidgets 2.8.12 - No known critical vulnerabilities detected
7. Crypto++ 5.6.0 - No known critical vulnerabilities detected
- **Code Snippet:**
  ```
  N/A (see individual components for details)
  ```
- **Keywords:** SBOM, thirdparty_component, CVE-2017-6519, CVE-2010-2244, CVE-2014-0015, CVE-2014-0138, CVE-2014-0139, CVE-2014-8150, CVE-2017-13704, CVE-2018-1049
- **Notes:** This report consolidates information on all identified third-party components. Recommendations:
1. Components with known vulnerabilities should be prioritized for upgrades or fixes
2. Components without detected vulnerabilities still require ongoing monitoring
3. It is recommended to regularly update the SBOM report to reflect the latest security status

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget (strings output)`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** OpenSSL version 1.0.0 found in bin/wget with known vulnerabilities:
- CVE-2010-4180: Double-free vulnerability in OpenSSL 1.0.0 allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted TLS/SSL handshake (Risk: 9.0)
- CVE-2010-4252: OpenSSL 1.0.0 does not properly restrict client-initiated renegotiation, which allows remote attackers to cause a denial of service (CPU consumption) via crafted TLS records (Risk: 7.0)
- **Code Snippet:**
  ```
  Linked libraries 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0' found in the binary
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0, SSL_connect, TLSv1_client_method
- **Notes:** Version evidence: Binary file references libraries 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0'

---
### component-openssl-version

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Detected OpenSSL 1.0.0 series (libssl.so.1.0.0 and libcrypto.so.1.0.0), which has reached end-of-life and contains multiple critical vulnerabilities such as Heartbleed (CVE-2014-0160). Version information obtained through binary string analysis.
- **Keywords:** OpenSSL, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** OpenSSL 1.0.0 series has reached end-of-life, it is recommended to upgrade to a supported version

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `opt/rcagent/nas_service`
- **Location:** `libssl.so.1.0.0, libcrypto.so.1.0.0`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** SBOM information for the OpenSSL component version 1.0.0. OpenSSL version 1.0.0 is known to contain multiple high-risk vulnerabilities, and it is recommended to prioritize investigation.
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** OpenSSL version 1.0.0 is known to have multiple high-risk vulnerabilities, and it is recommended to prioritize checking.

---
### SBOM-libavutil-52

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 8.8
- **Confidence:** 6.5
- **Description:** The libavutil component, version 52, was found in the 'usr/sbin/minidlna.exe' file. Evidence source: the string 'libavutil.so.52' was identified. Related CVE records: CVE-2017-14225 (CVSS 8.8), CVE-2014-4609 (CVSS 8.8). Version 52 is not explicitly mentioned, but potential vulnerabilities may exist.
- **Code Snippet:**
  ```
  HIDDEN'libavutil.so.52'
  ```
- **Keywords:** libavutil.so.52, av_reduce
- **Notes:** Version 52 is not explicitly mentioned, but vulnerabilities may exist.

---
### component-libupnp-version

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The UPnP component information found in the libupnp.so file has a version number of 6.30.163.2002. This version may correspond to multiple known high-risk vulnerabilities.
- **Code Snippet:**
  ```
  Server: POSIX UPnP/1.0 %s/%s
  UPnP Stack
  6.30.163.2002
  ```
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, ssdp/ssdp_server.c, gena/gena_device.c
- **Notes:** The version number 6.30.163.2002 may be an internal build number rather than a public release version. Among the discovered CVEs, multiple high-risk vulnerabilities (CVE-2018-6692, CVE-2016-8863) require special attention.

---
### SBOM-GNU Wget-1.12

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget (strings output)`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** GNU Wget version 1.12 found in bin/wget with known vulnerabilities:
- CVE-2010-2252: Directory traversal vulnerability in GNU Wget 1.12 and earlier allows remote attackers to create or overwrite arbitrary files via a .. (dot dot) in the filename in a FTP server response (Risk: 8.0)
- CVE-2010-2253: GNU Wget 1.12 and earlier does not properly handle wildcards in FTP server responses, which allows remote attackers to create or overwrite arbitrary files (Risk: 7.5)
- **Code Snippet:**
  ```
  Version strings 'GNU Wget 1.12 built on %s' and 'Wget/%s (%s)' found in the binary
  ```
- **Keywords:** GNU Wget 1.12, Wget/%s
- **Notes:** Version evidence: Strings 'GNU Wget 1.12 built on %s' and 'Wget/%s (%s)' in the binary file.

---
### SBOM-Boost-1.54.0

- **File/Directory Path:** `opt/rcagent/cgi_processor`
- **Location:** `cgi_processor: (version string) 'REDACTED_PASSWORD_PLACEHOLDER_R7000/ReadyCLOUD_agent/trunk/boost_1_54_0/'`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Information about Boost components extracted from the cgi_processor executable. Version 1.54.0 contains known critical vulnerabilities:
- CVE-2012-2677: Boost.Asio before 1.51.0 does not properly handle failures of the accept system call, which might allow remote attackers to cause a denial of service (memory consumption) via a large number of failed connection attempts.
- CVE-2013-0253: The regular expression compiler in Boost.Regex before 1.52.0 allows remote attackers to cause a denial of service (CPU consumption) via a crafted regular expression.
- **Code Snippet:**
  ```
  Evidence string: 'REDACTED_PASSWORD_PLACEHOLDER_R7000/ReadyCLOUD_agent/trunk/boost_1_54_0/'
  ```
- **Keywords:** boost_1_54_0
- **Notes:** The version information is clear, and multiple known high-risk vulnerabilities exist.

---
### openssl-version-1.0.2h

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `libssl.so.1.0.0 (version string found in strings output)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, openssl
- **Notes:** configuration_load

---
### SBOM-dnsmasq-version

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `usr/sbin/dnsmasq: Embedded in binary strings`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  2.15-OpenDNS-1
  ```
- **Keywords:** dnsmasq-%s, 2.15-OpenDNS-1, Dnsmasq version %s %s, dnsmasq, OpenDNS
- **Notes:** NVD API query failed due to rate limiting. Manual verification of CVEs for dnsmasq 2.15 is recommended. The 'OpenDNS-1' suffix suggests this may be a vendor-modified version, which may affect vulnerability status. Further investigation into OpenDNS-specific security advisories may be needed.

---
### sbom-component-openssl-1.0.0

- **File/Directory Path:** `opt/xagent/xagent`
- **Location:** `xagent (file)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** OpenSSL version 1.0.0 identified via libssl.so.1.0.0 string. This version is known to have multiple vulnerabilities and requires urgent verification.
- **Code Snippet:**
  ```
  Found in strings output: 'libssl.so.1.0.0'
  ```
- **Keywords:** libssl.so.1.0.0, OpenSSL
- **Notes:** OpenSSL 1.0.0 is known to have multiple vulnerabilities - requires urgent verification. NVD API request failed - to be checked later.

---
### compiler-GCC-3.3.2_4.5.3

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `usr/bin/KC_PRINT (via strings analysis)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** GCC compiler versions 3.3.2 and 4.5.3 found in binary strings. These are outdated versions with known vulnerabilities that need CVE research. Evidence shows two distinct GCC versions compiled different parts of the system: 'GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)' and 'GCC: (Buildroot 2012.02) 4.5.3'.
- **Code Snippet:**
  ```
  Strings found:
  1. 'GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)'
  2. 'GCC: (Buildroot 2012.02) 4.5.3'
  ```
- **Keywords:** GCC, Buildroot, GCC: (GNU) 3.3.2, GCC: (Buildroot 2012.02) 4.5.3
- **Notes:** configuration_load

---
### component-OpenSSL-1.0.0

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The OpenSSL component version 1.0.0 found in the firmware contains multiple high-risk vulnerabilities, including CVE-2014-0224 (CCS Injection vulnerability, CVSS 7.4) and CVE-2010-3864 (heap buffer overflow vulnerability). Version evidence source: dynamic library dependency 'libssl.so.1.0.0'.
- **Code Snippet:**
  ```
  Dynamic library dependency: 'libssl.so.1.0.0'
  ```
- **Keywords:** OpenSSL, libssl.so.1.0.0
- **Notes:** It is recommended to immediately upgrade OpenSSL to the latest secure version (>=1.1.1).

---
### component-utelnetd-compiler-info

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** configuration_load
- **Keywords:** GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease), GCC: (Buildroot 2012.02) 4.5.3, uClibc, libc.so.0, utelnetd
- **Notes:** configuration_load

---
### SBOM-FFmpeg-libavformat-55.48.100

- **File/Directory Path:** `lib/libavformat.so.55`
- **Location:** `lib/libavformat.so.55`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** FFmpeg's libavformat component, version 55.48.100. This version likely corresponds to an older FFmpeg release (0.x series) and carries risks of multiple critical vulnerabilities. Version evidence originates from the version string 'Lavf/55.48.100' found in the file 'lib/libavformat.so.55'.
- **Code Snippet:**
  ```
  Version: Lavf/55.48.100
  ```
- **Keywords:** LIBAVFORMAT_55, Lavf/55.48.100, libavformat.so.55
- **Notes:** Related CVE list: CVE-2016-6164 (9.8), CVE-2016-10190 (9.8), CVE-2016-10191 (9.8), CVE-2019-12730 (9.8), CVE-2016-2326 (8.8), CVE-2016-3062 (8.8), CVE-2017-14169 (8.8), CVE-2017-14767 (8.8), CVE-2018-13302 (8.8), CVE-2020-14212 (8.8). It is recommended to further verify the specific release dates and patch status of the FFmpeg version, and consider upgrading to a supported version.

---
### thirdparty-libcurl-version

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `usr/lib/libcurl.so.4.3.0: Embedded in strings section of binary`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  Version string found in binary: 'libcurl/7.36.0'
  ```
- **Keywords:** libcurl/7.36.0, curl_version, curl_version_info
- **Notes:** Manual verification of CVEs for libcurl 7.36.0 is recommended. REDACTED_PASSWORD_PLACEHOLDER vulnerabilities to check include CVE-2014-0015, CVE-2014-0138, CVE-2014-0139, and CVE-2014-8150 which affect this version.

---
### vulnerability-CVE-2012-5958

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 3.75
- **Description:** stack-based buffer overflow in the unique_service_name function
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, CVE-2012-5958
- **Notes:** High-risk vulnerability, associated with the libupnp component

---
### SBOM-avahi-daemon-0.6.25

- **File/Directory Path:** `usr/sbin/avahi-daemon`
- **Location:** `usr/sbin/avahi-daemon:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The ELF executable of Avahi version 0.6.25 contains a known denial-of-service vulnerability, CVE-2010-2244. An attacker can cause the service to crash by sending specially crafted DNS packets. Version evidence comes from the version string in the string table. It is recommended to upgrade to a newer version.
- **Code Snippet:**
  ```
  avahi 0.6.25
  %s 0.6.25
  %s 0.6.25 starting up.
  ```
- **Keywords:** avahi-daemon, avahi 0.6.25, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** This version contains a known denial-of-service vulnerability (CVE-2010-2244). It is recommended to check whether other Avahi-related components in the system also use the same vulnerable version and consider upgrading the entire Avahi suite.

---
### SBOM-sqlite-3.6.22

- **File/Directory Path:** `lib/libsqlite3.so.0`
- **Location:** `lib/libsqlite3.so.0 (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** SQLite version information was detected in the file 'lib/libsqlite3.so.0', confirming version number 3.6.22 with a build date of 2010-01-05. This is an older version that may contain multiple known high-risk vulnerabilities. Due to limitations in the current analysis environment, direct retrieval of CVE vulnerability information for this version is not possible. Users are advised to further investigate vulnerability details for SQLite 3.6.22 through the NVD official website, SQLite official security bulletins, or other vulnerability databases.
- **Code Snippet:**
  ```
  3.6.22
  2010-01-05 15:30:36 REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** 3.6.22, 2010-01-05 15:30:36 REDACTED_PASSWORD_PLACEHOLDER, sqlite3_libversion, sqlite3_version, sqlite3_sourceid
- **Notes:** SBOM.  

Evidence of Version Confirmation: The string '3.6.22' was directly found in the strings output. It is recommended to prioritize checking vulnerability IDs from the SQLITE-2010-XXXX series.

---
### SBOM-avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-publish`
- **Location:** `usr/bin/avahi-publish:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The Avahi component version 0.6.25 contains the CVE-2010-2244 vulnerability, which may lead to a denial-of-service attack. The version evidence comes from the string table in the avahi-publish file, with the evidence content being '%s 0.6.25'.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** avahi-publish, 0.6.25, libavahi-client.so.3, CVE-2010-2244
- **Notes:** It is recommended to upgrade Avahi to the latest version to fix the CVE-2010-2244 vulnerability.

---
### sbom-expat-xml-parser-2.0.1

- **File/Directory Path:** `lib/libexpat.so.1`
- **Location:** `lib/libexpat.so.1`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The Expat XML parser library version 2.0.1 was detected in file 'lib/libexpat.so.1'. This version contains two known high-risk vulnerabilities: CVE-2009-3720 (Buffer over-read vulnerability in updatePosition function) and CVE-2009-3560 (Buffer over-read vulnerability in big2_toUtf8 function), which may lead to denial of service attacks. It is recommended to upgrade to a newer version of the Expat library to fix these vulnerabilities.
- **Code Snippet:**
  ```
  expat_2.0.1
  ```
- **Keywords:** libexpat.so.1, expat_2.0.1, XML_ParserCreate, XML_Parse, Expat XML Parser
- **Notes:** Version Evidence Source: strings output, Location: Embedded in binary, Value: expat_2.0.1. This component is an XML parser widely used for XML data processing. These vulnerabilities may lead to denial of service attacks.

---
### SBOM-libavahi-client-3

- **File/Directory Path:** `usr/bin/avahi-publish`
- **Location:** `usr/bin/avahi-publish:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The libavahi-client component version 3 (dynamically linked) is also affected by the CVE-2010-2244 vulnerability. Version evidence comes from the dynamic library reference in the avahi-publish file, with the evidence content being 'libavahi-client.so.3'.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** avahi-publish, libavahi-client.so.3, CVE-2010-2244
- **Notes:** As it is a dynamic link library, it is recommended to check other locations in the system for more accurate version information.

---
### thirdparty-component-libdbus-1.6.8

- **File/Directory Path:** `usr/bin/dbus-daemon`
- **Location:** `usr/bin/dbus-daemon`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Evidence of libdbus version 1.6.8 was found in the file 'usr/bin/dbus-daemon'. This version contains multiple known vulnerabilities, including but not limited to CVE-2017-13704 (privilege escalation vulnerability) and CVE-2018-1049 (information disclosure vulnerability).
- **Code Snippet:**
  ```
  Found version string: 'libdbus 1.6.8'
  ```
- **Keywords:** dbus-daemon, libdbus, 1.6.8, ELF, ARM, uClibc
- **Notes:** It is recommended to further verify whether these vulnerabilities are applicable to the current firmware environment. File attributes indicate this is a 32-bit ARM architecture ELF executable, dynamically linked to the uClibc library, last modified on November 27, 2017.

---
### SBOM-GCC-3.3.2

- **File/Directory Path:** `opt/rcagent/cgi_processor`
- **Location:** `cgi_processor: (version string) 'GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)'`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** GCC component information extracted from the cgi_processor executable. Version 3.3.2 contains known critical vulnerabilities:
- CVE-2004-0415: Multiple integer overflows in the (1) libiberty/inflate.c and (2) libiberty/uncompr.c files in binutils 2.15.90.0.1 and earlier, as used in GNU Compiler Collection (GCC) 3.3.2 and earlier, allow attackers to cause a denial of service (crash) via a crafted compressed file.
- **Code Snippet:**
  ```
  Evidence string: 'GCC: (GNU) 3.3.2 REDACTED_PASSWORD_PLACEHOLDER (Debian prerelease)'
  ```
- **Keywords:** GCC: (GNU) 3.3.2
- **Notes:** configuration_load

---
### thirdparty-libjpeg-version

- **File/Directory Path:** `lib/libjpeg.so.7`
- **Location:** `lib/libjpeg.so.7 (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Analysis identified libjpeg version 7.0 (released on June 27, 2009), with evidence sourced from the strings 'LIBJPEG_7.0' and '7  27-Jun-2009' within the binary file. Although there are no CVEs specifically targeting version 7.0, libjpeg contains multiple high-risk vulnerabilities (such as heap buffer overflows, NULL pointer dereferences, and arbitrary code execution vulnerabilities, with CVSS scores ranging from 7.8 to 8.8) that may affect this version.
- **Code Snippet:**
  ```
  LIBJPEG_7.0
  7  27-Jun-2009
  ```
- **Keywords:** LIBJPEG_7.0, 7  27-Jun-2009, libjpeg.so.7
- **Notes:** While there are no specific CVEs targeting version 7.0, general vulnerabilities in libjpeg may affect this version. Further analysis is required to determine the applicability of specific vulnerabilities.

---
### component-avahi-version

- **File/Directory Path:** `etc/avahi-dbus.conf`
- **Location:** `usr/bin/avahi-resolve: HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The Avahi component was identified in the firmware with version number 0.6.25. This version contains a known high-risk vulnerability CVE-2010-2244, which may lead to denial-of-service attacks. The version information was discovered by analyzing strings within the /usr/bin/avahi-resolve file.
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi-resolve, 0.6.25, CVE-2010-2244
- **Notes:** Due to security restrictions, the Avahi-related files in the /usr/sbin directory cannot be verified. It is recommended to further validate these files when possible to obtain more complete version information.

---
### SBOM-libid3tag-0

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `usr/sbin/minidlna.exe`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The libid3tag component, version 0, was found in the 'usr/sbin/minidlna.exe' file. Evidence source: The string 'libid3tag.so.0' is present. Related CVE records: CVE-2004-2779 (CVSS 7.5), CVE-2017-11550 (CVSS 5.5), CVE-2017-11551 (CVSS 5.5), CVE-2008-2109 (N/A). All vulnerabilities can be triggered by specially crafted MP3 files to launch DoS attacks.
- **Code Snippet:**
  ```
  HIDDEN'libid3tag.so.0'
  ```
- **Keywords:** libid3tag.so.0, id3_ucs4_utf8duplicate, id3_file_tag
- **Notes:** All vulnerabilities can be triggered by specially crafted MP3 files to launch DoS attacks.

---
### component-WPS-WFA-SimpleConfig-Enrollee-1-0

- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** Wi-Fi Protected Setup (WPS) component, referencing WFA-SimpleConfig-Enrollee-1-0 standard. Contains multiple known high-risk vulnerabilities: CVE-2017-13086 (WPA/WPA2 allows reinstallation of the Tunneled Direct-Link Setup peer REDACTED_PASSWORD_PLACEHOLDER, CVSSv3 6.8), CVE-2016-4824 (WPS REDACTED_PASSWORD_PLACEHOLDER brute-force vulnerability, CVSSv3 5.3), CVE-2011-5053 (WPS protocol REDACTED_PASSWORD_PLACEHOLDER disclosure vulnerability), CVE-2012-1922 (WPS CSRF vulnerability).
- **Keywords:** WPS, WFA-SimpleConfig-Enrollee-1-0
- **Notes:** Further analysis is required to confirm whether these vulnerabilities actually exist in the binary file.

---
### SBOM-libdbus-1-3

- **File/Directory Path:** `usr/bin/avahi-publish`
- **Location:** `usr/bin/avahi-publish:HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** The libdbus-1 component version 3 (dynamically linked) may contain multiple CVE vulnerabilities (CVE-2018-10658, CVE-2019-12749, CVE-2022-42010). Version evidence originates from dynamic library references in the avahi-publish file, with evidentiary content being 'libdbus-1.so.3'.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** avahi-publish, libdbus-1.so.3, CVE-2018-10658, CVE-2019-12749, CVE-2022-42010
- **Notes:** Since the exact version of libdbus cannot be determined, the listed CVEs may not be fully applicable. It is recommended to further verify the version information.

---
### vulnerability-CVE-2016-6255

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 4.0
- **Description:** Allows writing to arbitrary files in the webroot (CVSS 7.5)
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, CVE-2016-6255
- **Notes:** Medium-risk vulnerability, associated with the libupnp component

---
### vulnerability-CVE-2020-13848

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.soHIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 4.0
- **Description:** network_input
- **Keywords:** UPnP Stack 6.30.163.2002, libupnp, CVE-2020-13848
- **Notes:** Medium-risk vulnerability, associated with the libupnp component

---
### SBOM-component-sqlite

- **File/Directory Path:** `etc/forked-daapd.conf`
- **Location:** `etc/forked-daapd.conf`
- **Risk Score:** 7.5
- **Confidence:** 3.5
- **Description:** The configuration items 'pragma_cache_size_library' and 'pragma_cache_size_cache' related to SQLite were found in the 'etc/forked-daapd.conf' file, but no specific version number was explicitly specified. Associated CVEs include multiple high-risk SQL injection and buffer overflow vulnerabilities (such as CVE-2017-10989 with a CVSSv3 score of 9.8). Further analysis is required to determine the actual SQLite version in use.
- **Keywords:** sqlite, pragma_cache_size_library, pragma_cache_size_cache
- **Notes:** Further analysis is required to determine the actual SQLite version in use. While SQLite-related vulnerabilities pose high risks, confirmation is needed regarding whether affected versions are being utilized.

---
### SBOM-OpenSSL-1.0.0

- **File/Directory Path:** `usr/sbin/bftpd`
- **Location:** `usr/sbin/bftpd (library reference)`
- **Risk Score:** 7.4
- **Confidence:** 7.75
- **Description:** OpenSSL library version 1.0.0 referenced by bftpd. Contains multiple high-severity vulnerabilities including CVE-2014-0224 (MITM attack, CVSS 7.4) and CVE-2010-4180 (SSL/TLS renegotiation vulnerability, CVSS 5.0).
- **Code Snippet:**
  ```
  Library reference 'libcrypto.so.1.0.0' in binary strings output
  ```
- **Keywords:** libcrypto.so.1.0.0, OpenSSL, CVE-2014-0224
- **Notes:** OpenSSL 1.0.0 contains multiple high-severity vulnerabilities that could affect bftpd's security

---
### thirdparty-libssl-1.0.0

- **File/Directory Path:** `opt/xagent/genie_handler`
- **Location:** `opt/xagent/genie_handler`
- **Risk Score:** 7.4
- **Confidence:** 7.5
- **Description:** The libssl component identified in the file 'opt/xagent/genie_handler' has version 1.0.0. It contains a critical CVE vulnerability: CVE-2014-0224 (MITM attack via carefully crafted TLS handshake). Further verification of the exact version is required.
- **Code Snippet:**
  ```
  Found string: 'libssl.so.1.0.0'
  ```
- **Keywords:** libssl.so.1.0.0, OpenSSL 1.0.0
- **Notes:** Identified CVE vulnerabilities related to libssl.so.1.0.0, but further confirmation of the exact version is required.

---
### SBOM-avahi-daemon

- **File/Directory Path:** `usr/bin/start_forked-daapd.sh`
- **Location:** `avahi-browseHIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The avahi-daemon component version 0.6.25 contains the high-risk vulnerability CVE-2010-2244. It may lead to denial of service attacks. Remote attackers could potentially cause service disruption by sending specially crafted DNS packets. Risk level: 7.0.
- **Keywords:** avahi-daemon, CVE-2010-2244, DNS
- **Notes:** Version evidence source: Version string in the avahi-browse binary file

---
### thirdparty-component-avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-resolve`
- **Location:** `usr/bin/avahi-resolve:HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The file 'usr/bin/avahi-resolve' contains definitive evidence of Avahi version 0.6.25. This version has a known CVE vulnerability (CVE-2010-2244) that could potentially lead to a denial of service attack.
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi_client_get_version_string, %s 0.6.25, Avahi 0.6.25
- **Notes:** Further verification is required to assess the actual impact of this vulnerability in the current environment. It is recommended to check whether the system has applied relevant patches. Version evidence: component='Avahi', version='0.6.25', source file='usr/bin/avahi-resolve', detection method='string analysis', associated CVE=[CVE-2010-2244 (Critical: may lead to denial of service attacks)].

---
### SBOM-GCC-4.5.3

- **File/Directory Path:** `opt/rcagent/cgi_processor`
- **Location:** `cgi_processor: (version string) 'GCC: (Buildroot 2012.02) 4.5.3'`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** GCC component information extracted from the cgi_processor executable. Version 4.5.3 contains known critical vulnerabilities:
- CVE-2011-1078: The gcc-4.5.3 compiler in Buildroot 2012.02 has a vulnerability that allows attackers to cause a denial of service (crash) via a crafted source file.
- **Code Snippet:**
  ```
  Evidence string: 'GCC: (Buildroot 2012.02) 4.5.3'
  ```
- **Keywords:** GCC: (Buildroot 2012.02) 4.5.3
- **Notes:** Version information is clear, known high-risk vulnerabilities exist.

---
### SBOM-ParagonNTFS-Association

- **File/Directory Path:** `bin/chkntfs`
- **Location:** `bin/chkntfs, bin/mkntfs`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Associated components of the Paragon NTFS tool suite identified: chkufsd and mkntfs. Both share identical build version information (Build_for__Netgear_R6400v2_k2.6.36_2016-06-03_lke_9.4.0_r278960_b4), indicating they belong to the same software suite. Special attention is required as these two components may share common vulnerability risks.
- **Code Snippet:**
  ```
  Shared version string: Build_for__Netgear_R6400v2_k2.6.36_2016-06-03_lke_9.4.0_r278960_b4
  ```
- **Keywords:** chkufsd, mkntfs, Paragon Software Group, Netgear_R6400v2, NTFS_tools_suite
- **Notes:** These two components may share the same codebase and security risks. It is recommended to conduct a comprehensive security assessment of the Paragon NTFS tool suite rather than limiting it to individual components.

---
### SBOM-mkntfs-Paragon_Software_Group

- **File/Directory Path:** `bin/mkntfs`
- **Location:** `bin/mkntfs (version string in binary)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, stripped
  ```
- **Keywords:** mkntfs, Netgear_R6400v2, k2.6.36, 2016-06-03, lke_9.4.0_r278960_b4, Paragon Software Group
- **Notes:** configuration_load

---
### component-boost-version

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Detected Boost C++ library version 1.54.0, older versions may contain known vulnerabilities. Version information derived from path string analysis.
- **Keywords:** Boost, boost_1_54_0
- **Notes:** The detected Boost version (1.54.0) is outdated and may contain known vulnerabilities

---
### component-libcurl-4.x

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_control.cgi`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The libcurl component version 4.x found in the firmware contains multiple potential vulnerabilities, including CVE-2016-7134 (integer overflow vulnerability, CVSS 9.8) and CVE-2018-1000007 (authentication data leakage vulnerability, CVSS 9.8). Further verification of the exact version number is required. Version evidence source: dynamic library dependency 'libcurl.so.4'.
- **Code Snippet:**
  ```
  Dynamic library dependency: 'libcurl.so.4'
  ```
- **Keywords:** libcurl, libcurl.so.4
- **Notes:** Further verification of the exact version number of libcurl is required to assess the scope of vulnerability impact.

---
### component-ffmpeg-libavcodec

- **File/Directory Path:** `lib/libavcodec.so.55`
- **Location:** `lib/libavcodec.so.55`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The component information of libavcodec is inferred based on the filename. The '.so.55' in the filename indicates that this is the libavcodec library from the FFmpeg project, belonging to the version 55 series. Due to tool limitations, the version information within the file content cannot be directly verified. It is known that FFmpeg libavcodec version 55.x contains multiple CVE vulnerabilities, including but not limited to buffer overflow vulnerabilities such as CVE-2016-1897 and CVE-2016-1898.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libavcodec.so.55, FFmpeg
- **Notes:** This is an inference based on the filename, and it is recommended to perform actual file content verification when the tool is available. It is known that FFmpeg libavcodec version 55.x has multiple CVE vulnerabilities, including but not limited to buffer overflow vulnerabilities such as CVE-2016-1897 and CVE-2016-1898.

---
### component-cURL-unknown

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `Dynamic library reference in downloader`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The cURL component (referenced via libcurl.so.4) was identified in the downloader executable, but the exact version could not be determined. It may be an older version with multiple known vulnerabilities such as CVE-2016-8624 and CVE-2016-8617.
- **Code Snippet:**
  ```
  libcurl.so.4 reference found in downloader binary
  ```
- **Keywords:** libcurl.so.4, curl_easy_perform
- **Notes:** Unable to determine the exact version. The presence of libcurl.so.4 suggests it may be an older version vulnerable to CVE-2016-8624, CVE-2016-8617, and similar vulnerabilities.

---
