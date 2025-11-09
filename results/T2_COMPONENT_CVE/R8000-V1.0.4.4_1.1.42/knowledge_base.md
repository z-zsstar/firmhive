# R8000-V1.0.4.4_1.1.42 (35 alerts)

---

### component-libcurl-version

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'libcurl/7.36.0'`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  version string 'libcurl/7.36.0'
  ```
- **Keywords:** libcurl, 7.36.0, ntlm.c, Curl_auth_create_ntlm_type3_message, ntlm_decode_type2_target
- **Notes:** Version evidence: File 'sbin/curl', location: version string 'libcurl/7.36.0'. Vulnerabilities: CVE-2019-3822, CVE-2018-16890, CVE-2014-0138, CVE-2014-0139.

---
### vulnerability-CVE-2019-3822

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'libcurl/7.36.0'`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** Stack-based buffer overflow in NTLM type-3 header creation in libcurl.
- **Code Snippet:**
  ```
  version string 'libcurl/7.36.0'
  ```
- **Keywords:** ntlm.c, Curl_auth_create_ntlm_type3_message
- **Notes:** CVE-2019-3822 affects libcurl 7.36.0.

---
### thirdparty-libcurl-7.36.0

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `libcurl.so.4.3.0 (version string)`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** The file 'usr/lib/libcurl.so.4.3.0' is version 7.36.0 of the libcurl library. This version contains multiple known high-risk vulnerabilities, including a critical stack-based buffer overflow vulnerability (CVE-2019-3822) and a heap buffer out-of-bounds read vulnerability (CVE-2018-16890). The version information was extracted from the binary file's string output.
- **Code Snippet:**
  ```
  libcurl/7.36.0
  ```
- **Keywords:** libcurl/7.36.0, Curl_auth_create_ntlm_type3_message, ntlm_decode_type2_target
- **Notes:** The identified vulnerabilities affect versions from 7.36.0 to before 7.64.0. It is recommended to upgrade to a newer version of libcurl to mitigate these security issues.

---
### sbom-libz-1.2.8

- **File/Directory Path:** `lib/libavformat.so.55`
- **Location:** `libz.so.1`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The zlib component version 1.2.8, with evidence from the string 'deflate 1.2.8'. Associated high-risk CVEs include: CVE-2016-9841 (pointer arithmetic issue, CVSS 9.8), CVE-2016-9843 (CRC calculation issue, CVSS 9.8). It is recommended to immediately upgrade to zlib 1.2.11 or later.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** deflate 1.2.8
- **Notes:** These are high-risk vulnerabilities, it is recommended to upgrade the zlib version

---
### vulnerability-CUPS-CVE-2010-2941

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT (HIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** Potential vulnerabilities in CUPS 1.4.5: ipp.c in cupsd in CUPS 1.4.4 and earlier versions fails to properly allocate memory for attribute values containing invalid string data types. This flaw could allow remote attackers to trigger a denial of service (resulting in use-after-free conditions and application crashes) or potentially execute arbitrary code through a specially crafted IPP request.
- **Keywords:** ipp.c, cupsd, IPP request
- **Notes:** Although the vulnerability explicitly states that it affects 'version 1.4.4 and earlier,' version 1.4.5, as a subsequent release, may still not have addressed these vulnerabilities. It is recommended to review the CUPS 1.4.5 changelog or patch records to confirm whether these vulnerabilities have been fixed.

---
### thirdparty-CUPS-version

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT (HIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 5.0
- **Description:** Version information of the third-party software CUPS found in the KC_PRINT binary file.
- **Code Snippet:**
  ```
  CUPS/1.4
  cups-version 1.4.5
  ```
- **Keywords:** CUPS, cups-version
- **Notes:** Multiple high-risk vulnerabilities detected: CVE-2010-2941 (CVSS 9.8), CVE-2010-0302 (CVSS 7.5), CVE-2010-0540

---
### component-avahi-libavahi-client

- **File/Directory Path:** `usr/lib/libavahi-client.so.3.2.5`
- **Location:** `usr/lib/libavahi-client.so.3.2.5`
- **Risk Score:** 9.1
- **Confidence:** 9.0
- **Description:** The version information of the Avahi client library was found to be 0.6 in the file 'usr/lib/libavahi-client.so.3.2.5'. This version contains multiple known high-risk vulnerabilities. Source of version evidence: the string 'avahi 0.6' was identified within the binary file.
- **Code Snippet:**
  ```
  String 'avahi 0.6' found in binary
  ```
- **Keywords:** avahi 0.6, libavahi-client.so.3.2.5, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** configuration_load

---
### vulnerability-CVE-2017-6519

- **File/Directory Path:** `usr/lib/libavahi-client.so.3.2.5`
- **Location:** `usr/lib/libavahi-client.so.3.2.5`
- **Risk Score:** 9.1
- **Confidence:** 9.0
- **Description:** avahi-daemon responds to IPv6 unicast query source addresses from non-local links, potentially leading to traffic amplification and information disclosure risks.
- **Keywords:** avahi 0.6, CVE-2017-6519
- **Notes:** CVSS Score: 9.1, Severity: High

---
### openssl-component-1.0.2h

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `lib/libcrypto.so.1.0.0:0xREDACTED_PASSWORD_PLACEHOLDER (.rodata section)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** OpenSSL cryptographic library version 1.0.2h identified in lib/libcrypto.so.1.0.0. This version contains multiple known critical vulnerabilities including heap memory corruption (CVE-2016-2177), information disclosure (CVE-2016-2176) and padding oracle vulnerability (CVE-2016-2105).
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libcrypto.so.1.0.0, .rodata
- **Notes:** Component details:  
- Name: OpenSSL  
- Version: 1.0.2h  
- Release date: 3 May 2016  
Known vulnerabilities:  
- CVE-2016-2177: Heap memory corruption vulnerability (Critical, CVSS 9.8)  
- CVE-2016-2176: Information disclosure vulnerability (High)  
- CVE-2016-2105: Padding oracle vulnerability (High)  
Evidence location: Multiple locations in .rodata section (e.g., 0xREDACTED_PASSWORD_PLACEHOLDER)

---
### openssl-version-1.0.2h

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `libssl.so.1.0.0HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Clear evidence of OpenSSL version 1.0.2h was found in the 'lib/libssl.so.1.0.0' file. This version contains multiple known critical vulnerabilities, including flaws that could lead to remote code execution, information disclosure, and denial of service.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, s3_srvr.c, ssl_sess.c, t1_lib.c, EVP_EncodeUpdate, EVP_EncryptUpdate, asn1_d2i_read_bio, TS_OBJ_print_bio, dsa_sign_setup
- **Notes:** It is recommended to upgrade to the latest secure version of OpenSSL as soon as possible, especially to address critical vulnerabilities such as CVE-2016-2177.

---
### sbom-libavutil-52.x.x

- **File/Directory Path:** `lib/libavformat.so.55`
- **Location:** `libavutil.so.52`
- **Risk Score:** 8.8
- **Confidence:** 6.0
- **Description:** FFmpeg libavutil component API version 52.x.x, evidenced by the string 'LIBAVUTIL_52' and SONAME. Associated CVEs include: CVE-2017-14225 (null pointer dereference vulnerability, CVSS 8.8), CVE-2014-4610 (LZO decompression integer overflow vulnerability, CVSS 8.8), CVE-2020-21688 (use-after-free memory vulnerability, CVSS 8.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** LIBAVUTIL_52
- **Notes:** Further confirmation is required regarding the exact FFmpeg version.

---
### avahi-dbus-configuration

- **File/Directory Path:** `etc/avahi-dbus.conf`
- **Location:** `etc/avahi-dbus.conf`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The file 'etc/avahi-dbus.conf' is a D-Bus configuration file used to define access control policies for the Avahi service. While the file does not directly contain version information for Avahi, analysis of associated CVE vulnerabilities reveals that the Avahi service has multiple high-risk security issues, including denial of service, information disclosure, and privilege escalation vulnerabilities. These vulnerabilities have CVSS scores ranging from 5.5 to 9.1, indicating their high severity.
- **Keywords:** org.freedesktop.Avahi, SetHostName, REDACTED_PASSWORD_PLACEHOLDER, avahi-daemon
- **Notes:** Since the file 'etc/avahi-dbus.conf' does not directly contain version information for Avahi, it is recommended to further analyze other files (such as binary files or log files) to obtain the exact version number. Additionally, attention should be paid to security policies related to D-Bus configuration to prevent potential privilege escalation attacks.

---
### avahi-dbus-configuration

- **File/Directory Path:** `usr/bin/avahi-publish`
- **Location:** `etc/avahi-dbus.conf`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The file 'etc/avahi-dbus.conf' is a D-Bus configuration file used to define access control policies for the Avahi service. Although the file does not directly contain version information for Avahi, analysis of associated CVE vulnerabilities reveals that the Avahi service has multiple high-risk security issues, including denial of service, information disclosure, and privilege escalation vulnerabilities. These vulnerabilities have CVSS scores ranging from 5.5 to 9.1, indicating their high severity.
- **Keywords:** org.freedesktop.Avahi, SetHostName, REDACTED_PASSWORD_PLACEHOLDER, avahi-daemon, avahi, 0.6.25
- **Notes:** This configuration file is associated with the Avahi 0.6.25 version found in usr/bin/avahi-publish. It is recommended to verify whether the avahi-daemon version running on the system is also 0.6.25, as CVE-2010-2244 affects the avahi-daemon component.

---
### SBOM-ReadyDLNA-1.1.5

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `Embedded version string in minidlna.exe`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Version 1.1.5
  ```
- **Keywords:** ReadyDLNA/1.1.5, Version 1.1.5
- **Notes:** configuration_load

---
### thirdparty-avahi-libavahi-core

- **File/Directory Path:** `usr/lib/libavahi-core.so.6.0.1`
- **Location:** `usr/lib/libavahi-core.so.6.0.1`
- **Risk Score:** 8.5
- **Confidence:** 4.0
- **Description:** The file 'usr/lib/libavahi-core.so.6.0.1' is version 6.0.1 of the Avahi core library. This version contains multiple known critical vulnerabilities, including CVE-2017-6519 (CVSS 9.1), CVE-2021-26720 (CVSS 7.8), and CVE-2021-3502 (CVSS 5.5). These vulnerabilities may lead to denial of service, information leakage, and local symlink attacks.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libavahi-core.so.6.0.1, Avahi, CVE-2017-6519, CVE-2021-26720, CVE-2021-3502
- **Notes:** It is recommended to update to the latest version of the Avahi core library to fix these vulnerabilities. Further verification can be done by checking the package metadata to confirm the exact version information.

---
### component-curl-version

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s'`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Analysis of 'sbin/curl' binary revealed version information and associated vulnerabilities. Component: curl, Version: 7.36.0. Vulnerabilities include connection reuse issues and TLS certificate validation flaws.
- **Code Snippet:**
  ```
  version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s'
  ```
- **Keywords:** curl, 7.36.0, SCP, SFTP, POP3, IMAP, SMTP, LDAP, OpenSSL, axtls, qsossl, gskit, TLS
- **Notes:** Version evidence: file 'sbin/curl', location: version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s'. Vulnerabilities: CVE-2014-0138, CVE-2014-0139.

---
### vulnerability-CVE-2014-0138

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s' and 'libcurl/7.36.0'`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** network_input
- **Code Snippet:**
  ```
  version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s' and 'libcurl/7.36.0'
  ```
- **Keywords:** SCP, SFTP, POP3, IMAP, SMTP, LDAP
- **Notes:** CVE-2014-0138 affects both curl and libcurl 7.36.0.

---
### thirdparty-component-expat-2.0.1

- **File/Directory Path:** `lib/libexpat.so`
- **Location:** `lib/libexpat.so`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The Expat XML Parser component was found in the file 'lib/libexpat.so' with version number 2.0.1. This version contains two known high-risk vulnerabilities: CVE-2009-3720 and CVE-2009-3560, both of which may lead to denial-of-service attacks. The version information is derived from the internal string 'expat_2.0.1' in the file.
- **Code Snippet:**
  ```
  Found in strings output as 'expat_2.0.1'
  ```
- **Keywords:** expat_2.0.1, updatePosition, big2_toUtf8, xmltok_impl.c, xmltok.c, UTF-8, buffer over-read
- **Notes:** It is recommended to upgrade to a higher version of the Expat XML Parser to fix these vulnerabilities. If upgrading is not feasible, strict XML input validation should be implemented to mitigate the risks.

---
### thirdparty-Avahi-0.6.25

- **File/Directory Path:** `usr/bin/start_forked-daapd.sh`
- **Location:** `usr/bin/start_forked-daapd.sh`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The Avahi component found in the file 'usr/bin/start_forked-daapd.sh', version 0.6.25. Evidence includes: 'avahi-browse 0.6.25' in avahi-browse, '%s 0.6.25' in avahi-publish, '%s 0.6.25' in avahi-resolve, and '%s 0.6.25' in avahi-set-host-name. Known vulnerabilities include: CVE-2010-2244 (a vulnerability in the AvahiDnsPacket function that can lead to denial of service), CVE-2017-6519 (an infinite loop vulnerability in the mDNS responder), CVE-2011-1002 (an integer overflow vulnerability in the set_host_name function).
- **Code Snippet:**
  ```
  avahi-browse 0.6.25
  %s 0.6.25
  ```
- **Keywords:** avahi-browse, avahi-publish, avahi-resolve, avahi-set-host-name, 0.6.25, AvahiDnsPacket
- **Notes:** Avahi 0.6.25 contains multiple critical vulnerabilities, priority handling is recommended.

---
### thirdparty-dnsmasq-version

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `usr/sbin/dnsmasq: Embedded in binary strings`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The binary file contains dnsmasq version information '2.15-OpenDNS-1'. While no directly associated CVEs were found for this specific version, multiple critical vulnerabilities (CVSSv3 score 9.8) exist in dnsmasq that require consideration. The version string is located in the string table of the binary file.
- **Code Snippet:**
  ```
  2.15-OpenDNS-1
  ```
- **Keywords:** dnsmasq-%s, 2.15-OpenDNS-1, Dnsmasq version %s
- **Notes:** Although the discovered CVEs do not explicitly list version 2.15 as vulnerable, they represent critical vulnerabilities in the dnsmasq codebase that may affect this version. It is recommended to further investigate whether these vulnerabilities apply to this specific build.

---
### SBOM-uClibc-Unknown

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `strings output of utelnetd`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** uClibc library, version unknown (referenced as ld-uClibc.so.0 and libc.so.0). Multiple critical CVE vulnerabilities identified, including CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), etc. Since the exact version cannot be determined, some vulnerabilities may not be applicable.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0, libc.so.0
  ```
- **Keywords:** ld-uClibc.so.0, libc.so.0, utelnetd
- **Notes:** The exact version of uClibc could not be determined from the strings output. Some vulnerabilities may not apply depending on the actual version.

---
### thirdparty-libip6tc-version-analysis

- **File/Directory Path:** `usr/lib/libip6tc.so.0.0.0`
- **Location:** `usr/lib/libip6tc.so.0.0.0`
- **Risk Score:** 7.8
- **Confidence:** 6.75
- **Description:** Analysis of 'usr/lib/libip6tc.so.0.0.0' reveals:
1. Version Information: Built with GCC 4.5.3 (Buildroot 2012.02), indicating it dates back to approximately 2012. The SONAME 'libip6tc.so.0' signifies a major version number of 0.
2. Known Vulnerabilities: Two critical CVE vulnerabilities identified:
   - CVE-2020-28046: Local privilege escalation via xtables-multi binary (CVSSv3 score 7.8)
   - CVE-2024-50257: Use-after-free vulnerability in netfilter's get_info() function (CVSSv3 score 7.8)
3. Evidence Source: Version strings were discovered within the binary file, specifically the compiler version and build date.
- **Code Snippet:**
  ```
  Not applicable for binary analysis
  ```
- **Keywords:** libip6tc.so.0, GCC: (Buildroot 2012.02) 4.5.3, ip6tables, libiptc, xtables-multi, get_info, netfilter
- **Notes:** The exact version of the library cannot be determined based on the available evidence. Further examination of package metadata or cross-validation with the ip6tables release timeline is required for confirmation. The identified CVE vulnerabilities pertain to the core functionality of ip6tables that interacts with this library, thus maintaining relevance despite version uncertainty.

---
### vulnerability-CVE-2014-0139

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s' and 'libcurl/7.36.0'`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** network_input
- **Code Snippet:**
  ```
  version string 'curl 7.36.0 (arm-unknown-linux-gnu) %s' and 'libcurl/7.36.0'
  ```
- **Keywords:** OpenSSL, axtls, qsossl, gskit, TLS
- **Notes:** CVE-2014-0139 impacts both curl and libcurl version 7.36.0.

---
### vulnerability-CVE-2018-16890

- **File/Directory Path:** `sbin/curl`
- **Location:** `sbin/curl: version string 'libcurl/7.36.0'`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** Heap-based buffer over-read (NTLM type-2 message processing vulnerability in libcurl)
- **Code Snippet:**
  ```
  version string 'libcurl/7.36.0'
  ```
- **Keywords:** ntlm.c, ntlm_decode_type2_target
- **Notes:** CVE-2018-16890 impacts libcurl version 7.36.0.

---
### vulnerability-CVE-2006-2289

- **File/Directory Path:** `usr/lib/libavahi-client.so.3.2.5`
- **Location:** `usr/lib/libavahi-client.so.3.2.5`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** A buffer overflow vulnerability in avahi-core allows for arbitrary code execution.
- **Keywords:** avahi 0.6, CVE-2006-2289
- **Notes:** Severity: Unknown (Potentially High Risk)

---
### SBOM-Avahi-0.6.25

- **File/Directory Path:** `usr/sbin/avahi-daemon`
- **Location:** `usr/sbin/avahi-daemon`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The Avahi component version 0.6.25 found in the file 'usr/sbin/avahi-daemon' contains a known vulnerability CVE-2010-2244. This vulnerability resides in the AvahiDnsPacket function, where a remote attacker can cause a denial of service (assertion failure and daemon termination) by sending specially crafted DNS packets.
- **Code Snippet:**
  ```
  HIDDENstringsHIDDEN: '%s 0.6.25' HIDDEN 'avahi 0.6.25'
  ```
- **Keywords:** avahi-daemon, 0.6.25, AvahiDnsPacket, CVE-2010-2244, ELF, ARM
- **Notes:** File type: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV); Size: 110086 bytes; Permissions: 777; Last modified: 2017-11-13. It is recommended to check whether there are other versions of the Avahi component in the system and verify if the service is exposed to the network.

---
### vulnerability-CUPS-CVE-2010-0302

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** CUPS 1.4.5 potential vulnerability: A use-after-free vulnerability exists in the abstract file-descriptor handling interface within the cupsdDoSelect function in scheduler/select.c of the CUPS scheduler (cupsd) prior to version 1.4.4. When utilizing kqueue or epoll, this flaw allows remote attackers to trigger a denial of service (resulting in daemon crash or hang) by disconnecting a client during the listing of a large number of print jobs.
- **Keywords:** cupsdDoSelect, scheduler/select.c, kqueue, epoll
- **Notes:** Although the vulnerability is clearly marked as affecting 'version 1.4.4 and earlier,' version 1.4.5, as a subsequent release, may still not have addressed these vulnerabilities.

---
### SBOM-FFmpeg-libavformat-55

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `Dynamic library dependency libavformat.so.55`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** FFmpeg libavformat version 55 component with known vulnerabilities. Evidence from dynamic library reference libavformat.so.55. Known vulnerabilities: CVE-2013-7010 (Heap-based buffer overflow), CVE-2013-3672 (Null pointer dereference).
- **Code Snippet:**
  ```
  libavformat.so.55
  ```
- **Keywords:** libavformat.so.55, avformat_find_stream_info
- **Notes:** Part of FFmpeg suite, shares vulnerabilities with libavformat

---
### SBOM-libexif-12

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `Dynamic library dependency libexif.so.12`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** libexif version 12 component with known vulnerabilities. Evidence from dynamic library reference libexif.so.12. Known vulnerabilities: CVE-2012-2836 (EXIF parsing vulnerability), CVE-2012-2845 (Buffer overflow).
- **Code Snippet:**
  ```
  libexif.so.12
  ```
- **Keywords:** libexif.so.12, exif_loader_new
- **Notes:** configuration_load

---
### third-party-pppd-2.4.4

- **File/Directory Path:** `sbin/pppd`
- **Location:** `sbin/pppd: HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Version information 'pppd version 2.4.4' was found in the file 'sbin/pppd'. This version contains a known vulnerability CVE-2006-2194, where the winbind plugin fails to check the return code of setuid function calls, potentially allowing local users to gain privileges by causing setuid to fail.
- **Code Snippet:**
  ```
  pppd version 2.4.4
  ```
- **Keywords:** pppd, 2.4.4, winbind, setuid
- **Notes:** It is recommended to check whether the system uses the winbind plugin for NTLM authentication. If this feature is not utilized, the risk may be relatively low.

---
### component-avahi-version

- **File/Directory Path:** `usr/bin/avahi-browse`
- **Location:** `usr/bin/avahi-browse`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** In the file 'usr/bin/avahi-browse', version information 'avahi 0.6.25' of the Avahi component was detected. This version contains a known critical vulnerability CVE-2010-2244, which may lead to denial of service attacks.
- **Code Snippet:**
  ```
  avahi-browse 0.6.25
  ```
- **Keywords:** avahi-browse, avahi 0.6.25, CVE-2010-2244
- **Notes:** It is recommended to further check other files to confirm if other versions of the Avahi component exist.

---
### thirdparty-avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-publish`
- **Location:** `usr/bin/avahi-publish (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The Avahi component version 0.6.25 was detected in the file 'usr/bin/avahi-publish'. This version contains a known CVE vulnerability (CVE-2010-2244) that may lead to denial of service attacks. The version information is derived from the string '%s 0.6.25' within the file.
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi, 0.6.25, avahi-publish
- **Notes:** It is recommended to further check whether the avahi-daemon service exists in the system, as CVE-2010-2244 affects the avahi-daemon component.

---
### thirdparty-avahi-0.6.25

- **File/Directory Path:** `usr/bin/avahi-resolve`
- **Location:** `usr/bin/avahi-resolve`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The file '/usr/bin/avahi-resolve' is part of the Avahi software, version 0.6.25. This version contains a known critical vulnerability CVE-2010-2244, which may lead to denial of service attacks.
- **Code Snippet:**
  ```
  %s 0.6.25
  ```
- **Keywords:** avahi-resolve, Avahi, 0.6.25, CVE-2010-2244
- **Notes:** It is recommended to further inspect other components of Avahi for the same vulnerability and consider upgrading to the patched version. Version information evidence source: version string in usr/bin/avahi-resolve.

---
### SBOM-libjpeg-7.0

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `Dynamic library dependency libjpeg.so.7`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** libjpeg version 7.0 component with known vulnerabilities. Evidence from dynamic library reference libjpeg.so.7. Known vulnerabilities: CVE-2013-6629 (JPEGMarker vulnerability), CVE-2012-2806 (Buffer overflow).
- **Code Snippet:**
  ```
  libjpeg.so.7
  ```
- **Keywords:** LIBJPEG_7.0, libjpeg.so.7, jpeg_read_scanlines
- **Notes:** configuration_load

---
### SBOM-FFmpeg-libavutil-52

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `Dynamic library dependency libavutil.so.52`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  libavutil.so.52
  ```
- **Keywords:** libavutil.so.52, av_strerror
- **Notes:** Part of FFmpeg suite, shares vulnerabilities with libavformat

---
