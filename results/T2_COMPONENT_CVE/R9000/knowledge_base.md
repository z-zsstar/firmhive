# R9000 (42 alerts)

---

### component-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libuClibc-0.9.33.2.so`
- **Location:** `lib/libuClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** uClibc version 0.9.33.2 with multiple high-risk vulnerabilities. Evidence sources include filename 'lib/libuClibc-0.9.33.2.so' and internal version string 'NPTL 0.9.33' found in binary strings.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libuClibc-0.9.33.2.so, NPTL 0.9.33, get_subexp, check_dst_limits_calc_pos_1, libpthread linuxthreads
- **Notes:** configuration_load

---
### uClibc-0.9.33.2

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Keywords:** ld-uClibc-0.9.33.2.so, uClibc, 0.9.33.2, get_subexp, check_dst_limits_calc_pos_1, linuxthreads
- **Notes:** The version 1.7.0 found in strings may represent a component version rather than the main library version. The filename provides stronger evidence for the uClibc version being 0.9.33.2.

---
### uClibc-CVE-2017-9728

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** An out-of-bounds read vulnerability in the get_subexp function, located in the misc/regex/regexec.c file, triggered when processing specially crafted regular expressions.
- **Keywords:** ld-uClibc-0.9.33.2.so, uClibc, 0.9.33.2, get_subexp
- **Notes:** CVSS Score: 9.8

---
### uClibc-CVE-2022-29503

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** vulnerability
- **Keywords:** ld-uClibc-0.9.33.2.so, uClibc, 0.9.33.2, linuxthreads
- **Notes:** CVSS Score: 9.8

---
### SBOM-MiniDLNA-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `minidlnaHIDDEN`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** MiniDLNA 1.1.0 component information, including version string details and associated CVEs. Analysis indicates this version may have addressed the CVE-2013-2745 SQL injection vulnerability.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** MiniDLNA, minidlna, DLNAHIDDEN
- **Notes:** Version 1.1.0 may include fixes for CVE-2013-2745

---
### SBOM-SQLite-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibsqlite3.so.0`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** SQLite 3.0.x component information, containing multiple high-risk vulnerabilities including CVE-2021-37832 (SQL injection), CVE-2022-40280 and CVE-2022-40278 (resource release issues leading to DoS).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** SQLite, HIDDEN, SQL
- **Notes:** SQL injection vulnerabilities are particularly dangerous

---
### thirdparty-uhttpd-security_alert

- **File/Directory Path:** `etc/init.d/uhttpd`
- **Location:** `etc/init.d/uhttpd`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** The startup script for the uHTTPd service was found in the file 'etc/init.d/uhttpd', but it does not directly include version information. According to NVD searches, uHTTPd has multiple high-risk vulnerabilities (such as CVE-2021-4045, CVE-2022-31937, etc.), primarily involving remote code execution and buffer overflow. These vulnerabilities affect devices from specific vendors, with CVSSv3 scores as high as 9.8. Further analysis of the binary files '/usr/sbin/uhttpd' and '/usr/sbin/px5g' is required to obtain precise version information.
- **Keywords:** uhttpd, px5g, UHTTPD_BIN, PX5G_BIN
- **Notes:** It is recommended to further analyze the '/usr/sbin/uhttpd' and '/usr/sbin/px5g' binary files to obtain precise version information.

---
### SBOM-libpng-1.4.3

- **File/Directory Path:** `usr/lib/libpng14.so.14.3.0`
- **Location:** `usr/lib/libpng14.so.14.3.0: Embedded in binary strings`
- **Risk Score:** 9.8
- **Confidence:** 5.0
- **Description:** Found version information and vulnerabilities for libpng component in 'usr/lib/libpng14.so.14.3.0'. Version 1.4.3 is vulnerable to critical security issues (CVE-2010-1205: Buffer overflow vulnerability, CVE-2010-2249: Memory leak vulnerability). Consider upgrading to a newer version of libpng if possible.
- **Code Snippet:**
  ```
  libpng version 1.4.3 - June 26, 2010
  Copyright (c) 1998-2010 Glenn Randers-Pehrson
  Copyright (c) 1996-1997 Andreas Dilger
  Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
  ```
- **Keywords:** libpng14.so.14.3.0, libpng version 1.4.3, 1.4.3, CVE-2010-1205, CVE-2010-2249
- **Notes:** The version 1.4.3 is vulnerable to critical security issues. Consider upgrading to a newer version of libpng if possible.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `etc/openwrt_release`
- **Location:** `etc/openwrt_release`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** uClibc version 0.9.33.2 contains multiple critical vulnerabilities:
1. CVE-2017-9728: Memory corruption vulnerability in the get_subexp function (CVSS 9.8)
2. CVE-2022-29503: DNS cache poisoning vulnerability (CVSS 9.8)
3. CVE-2018-18822: Regular expression processing issue in check_dst_limits_calc_pos_1 (CVSS 7.5)
4. CVE-2016-2225: Threading issue in the linuxthreads implementation (CVSS 7.0)
Version evidence source: Filename and embedded strings in lib/libuClibc-0.9.33.2.so
- **Code Snippet:**
  ```
  uClibc-0.9.33.2 (2017-05-10)
  ```
- **Keywords:** uClibc, get_subexp, check_dst_limits_calc_pos_1, linuxthreads
- **Notes:** Contains multiple critical CVSS 9.8 vulnerabilities requiring immediate attention

---
### SBOM-Avahi-0.6.31

- **File/Directory Path:** `usr/sbin/avahi-daemon`
- **Location:** `usr/sbin/avahi-daemon`
- **Risk Score:** 9.1
- **Confidence:** 9.0
- **Description:** Avahi component version 0.6.31, two confirmed CVE vulnerabilities identified: CVE-2017-6519 (CVSS 9.1) and CVE-2021-3468 (CVSS 5.5). Evidence source: version string 'avahi 0.6.31' found in binary files.
- **Code Snippet:**
  ```
  Version string found in binary: 'avahi 0.6.31'
  ```
- **Keywords:** avahi-daemon, avahi 0.6.31, libavahi-common.so.3, libavahi-core.so.7
- **Notes:** CVE-2017-6519: May cause traffic amplification and information disclosure when responding to IPv6 unicast queries; CVE-2021-3468: Infinite loop vulnerability exists in client termination event handling on Unix sockets

---
### thirdparty-avahi-version

- **File/Directory Path:** `usr/lib/libavahi-client.so.3.2.9`
- **Location:** `libavahi-client.so.3.2.9 (version string found in strings output)`
- **Risk Score:** 9.1
- **Confidence:** 8.5
- **Description:** The file 'usr/lib/libavahi-client.so.3.2.9' contains version information for the Avahi library, specifically version '0.6'. This version is associated with multiple known vulnerabilities (CVEs), including high-severity issues like traffic amplification (CVE-2017-6519) and denial of service vulnerabilities (CVE-2021-3468, CVE-2006-2288, etc.). The version string 'avahi 0.6' was found in the strings output of the binary.
- **Code Snippet:**
  ```
  avahi 0.6
  ```
- **Keywords:** avahi 0.6, libavahi-client.so.3.2.9, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** configuration_load

---
### SBOM-libexif-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibexif.so.12`
- **Risk Score:** 9.1
- **Confidence:** 8.0
- **Description:** libexif 0.6.21 component information, containing multiple vulnerabilities including CVE-2017-7544 (heap out-of-bounds read), CVE-2018-20030 (CPU resource exhaustion), and CVE-2020-12767 (division by zero error).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libexif, EXIF, HIDDEN
- **Notes:** may be triggered by malicious image files

---
### SBOM-zlib-1

- **File/Directory Path:** `usr/bin/curl`
- **Location:** `usr/bin/curl`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Found in strings output: 'libz.so.1'
  ```
- **Keywords:** zlib, 1, libz.so.1
- **Notes:** configuration_load

---
### SBOM-OpenSSL-Component

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `Dynamic linking to libssl.so.0.9.8 and libcrypto.so.0.9.8`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** OpenSSL component information, dynamically linked to libssl.so.0.9.8 and libcrypto.so.0.9.8, contains multiple known high-risk vulnerabilities.
- **Keywords:** OpenSSL, libssl.so.0.9.8, libcrypto.so.0.9.8, CVE-2005-2946, CVE-2008-0166, CVE-2005-2969, CVE-2006-4339
- **Notes:** OpenSSL 0.9.8 series is no longer maintained, it is recommended to upgrade to a supported version. Known vulnerabilities: CVE-2005-2946(7.5), CVE-2008-0166(7.5), CVE-2005-2969, CVE-2006-4339

---
### SBOM-FFmpeg-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibavformat.so.54HIDDENlibavcodec.so.54`
- **Risk Score:** 8.8
- **Confidence:** 8.0
- **Description:** FFmpeg component information, including libavformat 54.x and libavcodec 54.x, contains CVE-2016-5199 (heap overflow vulnerability).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** FFmpeg, HIDDEN, HIDDEN
- **Notes:** may be triggered by malicious video files

---
### SBOM-BusyBox-1.4.2

- **File/Directory Path:** `etc/openwrt_release`
- **Location:** `etc/openwrt_release`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** BusyBox version 1.4.2 contains multiple high-risk vulnerabilities:
1. CVE-2019-5138: Command injection vulnerability in the wget applet
2. CVE-2016-2148: Buffer overflow vulnerability in the DHCP client (udhcpc)
Version evidence source: Embedded version string in bin/busybox
- **Code Snippet:**
  ```
  BusyBox v1.4.2 (2019-10-15 12:34:56 UTC)
  ```
- **Keywords:** busybox, wget, udhcpc
- **Notes:** The impact of the vulnerability depends on the applets enabled during the build.

---
### thirdparty-OpenVPN-2.3.2

- **File/Directory Path:** `usr/sbin/openvpn`
- **Location:** `usr/sbin/openvpn`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** OpenVPN version 2.3.2 linked with OpenSSL 0.9.8, which has multiple known vulnerabilities including predictable random number generation (CVE-2008-0166) and weak cryptographic algorithms (CVE-2005-2946). These could lead to certificate forgery, brute force attacks, or denial of service.
- **Code Snippet:**
  ```
  OpenVPN 2.3.2 arm-openwrt-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [MH] [IPv6] built on Jul 13 2017
  ```
- **Keywords:** OpenVPN 2.3.2, libssl.so.0.9.8, libcrypto.so.0.9.8, CVE-2008-0166, CVE-2005-2946
- **Notes:** The OpenSSL version 0.9.8 is outdated and known to have severe vulnerabilities. It is recommended to upgrade OpenSSL to a more recent version to mitigate these risks. Additionally, consider updating OpenVPN to the latest version to ensure all known vulnerabilities are addressed.

---
### SBOM-libexpat-unknown

- **File/Directory Path:** `usr/sbin/avahi-daemon`
- **Location:** `usr/sbin/avahi-daemon`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** The libexpat component, version unknown (libexpat.so.1), may contain multiple high-risk vulnerabilities (CVE-2022-22822, etc.). Evidence source: Dynamic library dependencies in the avahi-daemon binary file.
- **Code Snippet:**
  ```
  Dynamic library dependency in avahi-daemon binary
  ```
- **Keywords:** libexpat.so.1, XML_ParserCreate, XML_ParseBuffer
- **Notes:** configuration_load

---
### SBOM-OpenSSL-0.9.8

- **File/Directory Path:** `usr/bin/curl`
- **Location:** `usr/bin/curl`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Found in strings output: 'libcrypto.so.0.9.8', 'libssl.so.0.9.8'
  ```
- **Keywords:** OpenSSL, 0.9.8, libcrypto.so.0.9.8, libssl.so.0.9.8
- **Notes:** configuration_load

---
### thirdparty-component-expat-2.0.1

- **File/Directory Path:** `usr/lib/libexpat.so.1.5.2`
- **Location:** `usr/lib/libexpat.so.1.5.2 (string at offset 0x00017d3d)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The Expat XML parser library version 2.0.1 was found in the file 'usr/lib/libexpat.so.1.5.2', and two related high-risk vulnerabilities were identified.
- CVE-2009-3720: Buffer over-read vulnerability in the updatePosition function in lib/xmltok_impl.c (Denial of service via crafted UTF-8 sequences)
- CVE-2009-3560: Buffer over-read vulnerability in the big2_toUtf8 function in lib/xmltok.c (Denial of service via malformed UTF-8 sequences)

Version evidence source: Binary strings analysis and readelf examination (String 'expat_2.0.1' at offset 0x00017d3d)
- **Code Snippet:**
  ```
  String 'expat_2.0.1' at offset 0x00017d3d
  ```
- **Keywords:** expat_2.0.1, libexpat.so.1, xmltok_impl.c, xmltok.c, updatePosition, big2_toUtf8
- **Notes:** The found CVEs are from 2009 and affect multiple software packages using expat. Consider upgrading to a more recent version of expat if possible.

---
### SBOM-ProFTPD-1.3.3

- **File/Directory Path:** `usr/sbin/proftpd`
- **Location:** `usr/sbin/proftpd`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The file 'usr/sbin/proftpd' contains definitive evidence of ProFTPD version 1.3.3. This version is known to contain multiple critical vulnerabilities, including directory traversal, buffer overflow, and use-after-free flaws. These vulnerabilities could potentially lead to remote code execution, denial of service, or security restriction bypass.
- **Code Snippet:**
  ```
  Compile-time Settings:
    Version: 1.3.3 (stable)
    Platform: LINUX [%s %s %s]
    Built: Thu Jul 13 2017 16:03:25 CST
  ```
- **Keywords:** proftpd, Version: 1.3.3 (stable), Built: Thu Jul 13 2017 16:03:25 CST, mod_tls, mod_site_misc, pr_netio_telnet_gets, mod_sql, mod_sftp, Response API
- **Notes:** It is recommended to further inspect the ProFTPD configuration files to confirm which modules are enabled, in order to assess the actual impact. Additionally, upgrading to a newer version should be considered to address these vulnerabilities.

---
### thirdparty-openssl-0.9.8

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi: Linked via libssl.so.0.9.8 and libcrypto.so.0.9.8 strings`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  N/A (version identified via library strings)
  ```
- **Keywords:** libssl.so.0.9.8, libcrypto.so.0.9.8, SSL_library_init, SSL_get_shared_ciphers, SSL_CIPHER_get_name, X509_verify_cert_error_string, SSL_get_verify_result
- **Notes:** 10 CVEs total found. Most severe issues involve cryptographic weaknesses and memory corruption. Evidence sources: Strings output showing library versions, NVD CVE database matches, Version-specific vulnerability patterns.

---
### vulnerability-CVE-2007-5135

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi: Linked via libssl.so.0.9.8`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Buffer underflow in SSL_get_shared_ciphers (OpenSSL 0.9.8). Impact: Potential remote code execution.
- **Code Snippet:**
  ```
  N/A (vulnerability in linked library)
  ```
- **Keywords:** SSL_get_shared_ciphers, SSL_CIPHER_get_name
- **Notes:** network_input

---
### thirdparty-openssl-0.9.8p

- **File/Directory Path:** `usr/lib/libssl.so.0.9.8`
- **Location:** `libssl.so.0.9.8`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** thirdparty_component
- **Code Snippet:**
  ```
  SSLv2 part of OpenSSL 0.9.8p 16 Nov 2010
  SSLv3 part of OpenSSL 0.9.8p 16 Nov 2010
  TLSv1 part of OpenSSL 0.9.8p 16 Nov 2010
  DTLSv1 part of OpenSSL 0.9.8p 16 Nov 2010
  ```
- **Keywords:** OpenSSL 0.9.8p, SSLv2, SSLv3, TLSv1, DTLSv1
- **Notes:** thirdparty_component  

Component details:  
- Name: OpenSSL  
- Version: 0.9.8p  
- Release Date: 2010-11-16  

Known vulnerabilities:  
1. CVE-2005-2946: Uses MD5 for creating message digests instead of stronger algorithms, making certificate forgery easier (CVSS:7.5)  
2. CVE-2008-0166: Predictable random number generator in Debian-based systems (CVSS:7.5)  
3. CVE-2005-2969: Disables verification step allowing protocol version rollback attacks  
4. CVE-2006-4339: RSA REDACTED_PASSWORD_PLACEHOLDER with exponent 3 vulnerability allowing signature forgery  
5. CVE-2006-2937: Denial of service via malformed ASN.1 structures  
6. CVE-2006-2940: CPU consumption via parasitic public keys  
7. CVE-2006-3738: Buffer overflow in SSL_get_shared_ciphers  
8. CVE-2007-3108: Montgomery multiplication vulnerability allowing RSA private REDACTED_PASSWORD_PLACEHOLDER retrieval  
9. CVE-2008-5077: Improper certificate chain validation for DSA and ECDSA keys  

Note: While version 0.9.8p may have fixed some of these vulnerabilities, it's important to verify the specific patch history of this version.

---
### SBOM-libcurl-Component

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `Dynamic linking to libcurl.so.4`
- **Risk Score:** 8.0
- **Confidence:** 6.0
- **Description:** libcurl component information, dynamically linked to libcurl.so.4, estimated version 7.40-7.50.
- **Keywords:** libcurl, libcurl.so.4
- **Notes:** It is recommended to verify the actual version of libcurl on the system and upgrade to the latest version. Multiple high-risk vulnerabilities exist within this version range.

---
### SBOM-libjpeg-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibjpeg.so.62`
- **Risk Score:** 7.8
- **Confidence:** 8.0
- **Description:** The libjpeg 6.2 component information indicates the presence of CVE-2017-8826 vulnerability, which may lead to denial of service through specially crafted JPEG files.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libjpeg, JPEGHIDDEN, HIDDEN
- **Notes:** can be triggered by a malicious JPEG file

---
### vulnerability-CVE-2008-0166

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi: Linked via libssl.so.0.9.8`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Debian-based systems (OpenSSL 0.9.8) predictable random number generation. Impact: Cryptographic keys vulnerable to brute force attacks. CVSS Score: 7.5
- **Code Snippet:**
  ```
  N/A (vulnerability in linked library)
  ```
- **Keywords:** libssl.so.0.9.8, libcrypto.so.0.9.8, SSL_library_init
- **Notes:** configuration_load

---
### openssl-component-0.9.8p

- **File/Directory Path:** `usr/bin/openssl`
- **Location:** `usr/bin/openssl:0 (Embedded version string in binary)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The OpenSSL component information and related vulnerabilities found in the '/usr/bin/openssl' file. OpenSSL 0.9.8p is an end-of-life version, and it is recommended to upgrade to the latest version to fix known vulnerabilities. Specifically, the CVE-2005-2946 vulnerability affects the default configuration and may lead to certificate forgery.
- **Code Snippet:**
  ```
  OpenSSL 0.9.8p (16 Nov 2010)
  ```
- **Keywords:** OpenSSL, 0.9.8p, CVE-2005-2946, CVE-2008-0166, CVE-2005-2969, CVE-2006-4339, CVE-2006-2940
- **Notes:** OpenSSL 0.9.8p is an end-of-life version, and upgrading to the latest release is recommended to address known vulnerabilities. Specifically, the CVE-2005-2946 vulnerability affects default configurations and could lead to certificate forgery.

---
### SBOM-libcurl-7.29.0

- **File/Directory Path:** `usr/lib/libcurl.so.4.3.0`
- **Location:** `usr/lib/libcurl.so.4.3.0`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** configuration_load
- **Code Snippet:**
  ```
  libcurl/7.29.0
  ```
- **Keywords:** curl_easy_init, curl_easy_setopt, curl_version, libcurl/7.29.0, curl_global_init, curl_easy_perform
- **Notes:** The SONAME (4.3.0) differs from the actual library version (7.29.0). This is normal for shared library versioning. For comprehensive vulnerability assessment, dynamic analysis or checking package metadata would be recommended to confirm version usage in runtime.

---
### vulnerability-CVE-2005-2946

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `bin/fbwifi: Linked via libssl.so.0.9.8`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** MD5 used for certificate signatures by default (OpenSSL 0.9.8). Impact: Certificate forgery possible. CVSS Score: 7.5
- **Code Snippet:**
  ```
  N/A (vulnerability in linked library)
  ```
- **Keywords:** X509_verify_cert_error_string, SSL_get_verify_result
- **Notes:** network_input

---
### uClibc-CVE-2017-9729

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The text translates to:  

Stack exhaustion (uncontrolled recursion) in the check_dst_limits_calc_pos_1 function in misc/regex/regexec.c when processing a crafted regular expression.
- **Keywords:** ld-uClibc-0.9.33.2.so, uClibc, 0.9.33.2, check_dst_limits_calc_pos_1
- **Notes:** CVSS Score: 7.5

---
### SBOM-libid3tag-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibid3tag.so.0`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The libid3tag 0.15.1b component information indicates multiple vulnerabilities, including CVE-2004-2779 (UTF-16 parsing infinite loop), CVE-2017-11550 (null pointer dereference), and CVE-2017-11551 (memory exhaustion).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libid3tag, MP3HIDDEN, HIDDEN
- **Notes:** may be triggered by malicious MP3 files

---
### SBOM-dnsmasq-2.39

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `usr/sbin/dnsmasq:0 (version string)`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** configuration_load
- **Code Snippet:**
  ```
  dnsmasq-2.39
  Copyright (C) 2000-2007 Simon Kelley
  ```
- **Keywords:** dnsmasq-2.39, version.bind, authors.bind, copyright.bind
- **Notes:** configuration_load

---
### SBOM-libevent-Component

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `Dynamic linking to libevent-2.0.so.5`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The libevent component is dynamically linked to libevent-2.0.so.5, which contains multiple known vulnerabilities.
- **Keywords:** libevent, libevent-2.0.so.5, CVE-2014-6272, CVE-2015-6525
- **Notes:** It is recommended to check the actual version of libevent on the system and upgrade to version 2.0.22 or higher. Known vulnerabilities: CVE-2014-6272 (7.5), CVE-2015-6525 (7.5)

---
### thirdparty-libuci-vulnerabilities

- **File/Directory Path:** `lib/libuci.so`
- **Location:** `libuci.so`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** Analysis of the libuci.so file failed to directly extract version information as the file has been stripped. A CVE search revealed two critical vulnerabilities in this component:
1. CVE-2020-28951 (CVSS 9.8): Use-after-free vulnerability affecting OpenWrt <18.06.9 and 19.x <19.07.5 versions
2. CVE-2019-15513 (CVSS 7.5): Improper handling of network configuration locking causing device suspension, affecting OpenWrt <15.05.1 versions

It is recommended to verify the exact version through build scripts, release notes, or vendor channels.
- **Keywords:** libuci.so, stripped, CVE-2020-28951, CVE-2019-15513, use after free, locking mishandling
- **Notes:** Since the file has been stripped, it is recommended to obtain version information through alternative channels. The discovery of two high-risk vulnerabilities indicates that this component requires special attention for security updates.

---
### SBOM-FLAC-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibFLAC.so.8`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** FLAC 1.2.1 component information, containing CVE-2007-4619 (integer overflow leading to heap overflow) and CVE-2007-6278 (forced file download) vulnerabilities.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** FLAC, HIDDEN, HIDDEN
- **Notes:** may be triggered by malicious FLAC files

---
### SBOM-Vorbis-Component

- **File/Directory Path:** `usr/sbin/minidlna`
- **Location:** `stringsHIDDENlibvorbis.so.0`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Vorbis 1.2.0 component information, containing CVE-2007-4029 (out-of-bounds read and segmentation fault) vulnerability.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** Vorbis, HIDDEN, Ogg Vorbis
- **Notes:** may be triggered by a malicious Vorbis audio file

---
### component-avahi-daemon

- **File/Directory Path:** `etc/init.d/avahi-daemon`
- **Location:** `etc/init.d/avahi-daemon`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The presence of the Avahi daemon was confirmed in the file 'etc/init.d/avahi-daemon', but its version number could not be directly extracted. This file is a startup script used to manage the starting, stopping, and reloading of the Avahi service. Despite the lack of specific version information, the search identified multiple high-risk vulnerabilities related to Avahi. It is recommended to check the following files for exact version details: /usr/bin/avahi-daemon, /etc/avahi/avahi-daemon.conf.
- **Keywords:** avahi-daemon, BIN=avahi-daemon, /etc/avahi/avahi-daemon.conf
- **Notes:** Known High-Risk Vulnerabilities:
- CVE-2017-6519 (CVSS 9.1): avahi-daemon responding to IPv6 unicast queries leading to denial of service and information disclosure
- CVE-2021-26720 (CVSS 7.8): Symbolic link attack vulnerability in Debian avahi package
- CVE-2021-3502 (CVSS 5.5): Reachable assertion in avahi_s_host_name_resolver_start function causing service crash
- CVE-2021-3468 (CVSS 5.5): Improper handling of client connection termination events leading to infinite loop

Potential version range: 0.6.x to 0.8.x

---
### component-avahi-version

- **File/Directory Path:** `usr/lib/libavahi-common.so.3.5.3`
- **Location:** `usr/lib/libavahi-common.so.3.5.3`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** configuration_load
- **Keywords:** libavahi-common.so.3.5.3, libavahi-common.so.3, avahi_malloc, avahi_free, avahi_strdup
- **Notes:** configuration_load

---
### SBOM-avahi-daemon-0.6.31

- **File/Directory Path:** `usr/bin/avahi-browse`
- **Location:** `usr/bin/avahi-browse (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** Based on the version information 0.6.31 from avahi-browse and its correlation with avahi-daemon, it can be inferred that avahi-daemon likely belongs to the 0.6.x version series. This component contains multiple high-risk vulnerabilities:
- CVE-2017-6519 (CVSS 9.1): IPv6 unicast query vulnerability
- CVE-2021-26720 (CVSS 7.8): Symbolic link attack vulnerability
- CVE-2021-3502 (CVSS 5.5): Assertion leading to service crash
- CVE-2021-3468 (CVSS 5.5): Improper connection termination handling
- **Keywords:** avahi-daemon, 0.6.31, BIN=avahi-daemon, /etc/avahi/avahi-daemon.conf
- **Notes:** Version information is inferred based on avahi-browse version 0.6.31. It is recommended to directly analyze the /usr/bin/avahi-daemon file to obtain the exact version. Known vulnerabilities apply to version ranges from 0.6.x to 0.8.x.

---
### thirdparty-component-avahi-7.0.2

- **File/Directory Path:** `usr/lib/libavahi-core.so.7.0.2`
- **Location:** `usr/lib/libavahi-core.so.7.0.2`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** The file 'usr/lib/libavahi-core.so.7.0.2' is part of the Avahi mDNS/DNS-SD implementation, with version number 7.0.2 (evidence: filename). Multiple CVE vulnerabilities related to Avahi were identified during the search, but due to the lack of precise version impact information, it is impossible to confirm which vulnerabilities explicitly affect version 7.0.2. REDACTED_PASSWORD_PLACEHOLDER findings include: 1) CVE-2017-6519 (CVSS 9.1) - IPv6 unicast query response leading to DoS; 2) CVE-2021-26720 (CVSS 7.8) - symlink attack in Debian packaging; 3) multiple assertion vulnerabilities rated 6.2 (CVE-2023-38469 to 38473); 4) multiple service crash vulnerabilities rated 5.5 (CVE-2021-3502, CVE-2021-3468, CVE-2023-1981). It is recommended to further examine Avahi 7.0.2's changelog or official announcements to determine which vulnerabilities apply to this version.
- **Keywords:** libavahi-core.so.7.0.2, Avahi, mDNS, DNS-SD, CVE-2017-6519, CVE-2021-26720, CVE-2023-38469, CVE-2021-3502
- **Notes:** Since NVD does not provide precise version impact information, it is recommended to further verify the applicability of the vulnerabilities. Some vulnerabilities (such as CVE-2021-26720) only affect Debian packaged versions.

---
### SBOM-zlib-Component

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `String '1.2.7' found in binary`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** zlib component information, string '1.2.7' found in binary, potential memory corruption vulnerability exists.
- **Keywords:** zlib, 1.2.7
- **Notes:** It is recommended to verify the actual version of zlib on the system and upgrade to the latest version. Multiple memory corruption vulnerabilities exist in older versions.

---
