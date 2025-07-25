# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (23 alerts)

---

### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `usr/sbin/dhcp6c`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The uClibc component version 0.9.33.2 was identified in the file 'REDACTED_PASSWORD_PLACEHOLDER', extracted from the string '/lib/ld-uClibc.so.0'. Associated known high-risk vulnerabilities include: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2017-9729 (CVSS 7.5), CVE-2022-30295 (CVSS 6.5), CVE-2015-8777 (risk unknown).
- **Code Snippet:**
  ```
  String '/lib/ld-uClibc.so.0' found in binary
  ```
- **Keywords:** uClibc, 0.9.33.2, ld-uClibc.so.0, REDACTED_SECRET_KEY_PLACEHOLDER, get_subexp, check_dst_limits_calc_pos_1, libpthread, linuxthreads
- **Notes:** All vulnerabilities affect the uClibc version 0.9.33.2 in the firmware. The most critical vulnerability (CVSS 9.8) may lead to memory corruption and potential remote code execution. It is recommended to upgrade to the latest version or apply relevant patches.

---
### sbom-SQLite-version

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna`
- **Risk Score:** 9.8
- **Confidence:** 8.0
- **Description:** SQLite component version 3.5.1 or higher contains multiple high-risk CVE vulnerabilities. Version evidence source: The string 'SQLite library is old. Please use version 3.5.1 or newer.' appears in the text.
- **Code Snippet:**
  ```
  SQLite library is old. Please use version 3.5.1 or newer.
  ```
- **Keywords:** sqlite3_libversion, sqlite3_libversion_number
- **Notes:** High-risk CVE list: CVE-2017-10989(9.8), CVE-2019-8457(9.8), CVE-2020-11656(9.8), CVE-2018-20346(8.1), CVE-2018-20506(8.1), CVE-2019-5018(8.1)

---
### thirdparty-component-openssl-1.0.2h

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `libssl.so.1.0.0 (HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The file 'lib/libssl.so.1.0.0' contains explicit information indicating OpenSSL version 1.0.2h. This version has multiple known critical vulnerabilities, including heap buffer boundary check errors (CVE-2016-2177), information disclosure (CVE-2016-2176), memory corruption (CVE-2016-2105, CVE-2016-2106), among others. These vulnerabilities may lead to security risks such as denial of service, information disclosure, or remote code execution.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, SSLv3 part of OpenSSL 1.0.2h, TLSv1 part of OpenSSL 1.0.2h, DTLSv1 part of OpenSSL 1.0.2h
- **Notes:** It is recommended to upgrade OpenSSL to a higher version to fix these vulnerabilities. In particular, CVE-2016-2177 has the highest CVSSv3 score of 9.8 and should be addressed immediately.

---
### thirdparty-component-openssl-1.0.2h

- **File/Directory Path:** `etc/openssl.cnf`
- **Location:** `libssl.so.1.0.0 (HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The file 'lib/libssl.so.1.0.0' contains explicit information indicating OpenSSL version 1.0.2h. This version has multiple known critical vulnerabilities, including heap buffer boundary check errors (CVE-2016-2177), information disclosure (CVE-2016-2176), memory corruption (CVE-2016-2105, CVE-2016-2106), etc. These vulnerabilities may lead to security risks such as denial of service, information disclosure, or remote code execution.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, SSLv3 part of OpenSSL 1.0.2h, TLSv1 part of OpenSSL 1.0.2h, DTLSv1 part of OpenSSL 1.0.2h
- **Notes:** It is recommended to upgrade OpenSSL to a higher version to fix these vulnerabilities. In particular, CVE-2016-2177 has the highest CVSSv3 score of 9.8 and should be addressed immediately.

---
### sbom-FFmpeg-libavutil-version

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna`
- **Risk Score:** 8.8
- **Confidence:** 7.0
- **Description:** FFmpeg (libavutil) component version 51 may contain multiple high-risk CVE vulnerabilities. Version evidence source: the string 'libavutil.so.51' appears in the text.
- **Code Snippet:**
  ```
  libavutil.so.51
  ```
- **Keywords:** libavutil.so.51, av_reduce
- **Notes:** Potential CVE list: CVE-2017-14225(8.8), CVE-2014-4609(8.8), CVE-2014-4610(8.8), verification required whether libavutil 51 is affected

---
### sbom-pppd-2.4.2b3

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `usr/sbin/pppd`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The presence of the pppd component was confirmed in the file 'usr/sbin/pppd', with version number 2.4.2b3. This version contains multiple high-risk vulnerabilities, including risks such as privilege escalation, buffer overflow, and denial-of-service attacks.
- **Code Snippet:**
  ```
  pppd version %s
  2.4.2b3
  ```
- **Keywords:** pppd, 2.4.2b3
- **Notes:** It is recommended to prioritize fixing CVE-2020-8597 and CVE-2018-11574 vulnerabilities as they have the highest CVSS scores (9.8) and involve remote code execution risks.

---
### libexif-12.3.2-SBOM

- **File/Directory Path:** `lib/libexif.so.12.3.2`
- **Location:** `lib/libexif.so.12.3.2`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Filename: lib/libexif.so.12.3.2
  ```
- **Keywords:** libexif.so.12.3.2, exif_data_save_data, exif_content_fix, exif_mnote_data_load, exif_entry_get_value
- **Notes:** configuration_load

---
### sbom-libjpeg-version

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna`
- **Risk Score:** 8.1
- **Confidence:** 8.0
- **Description:** The libjpeg component version 8 contains multiple high-risk CVE vulnerabilities. Version evidence source: the string 'libjpeg.so.8' appears in the text.
- **Code Snippet:**
  ```
  libjpeg.so.8
  ```
- **Keywords:** libjpeg.so.8, jpeg_read_scanlines
- **Notes:** High-risk CVE list: CVE-2020-14153(7.1), CVE-2018-14498(6.5), CVE-2022-35166(5.5), CVE-2018-5252(5.3)

---
### component-ntfs-3g-version

- **File/Directory Path:** `sbin/ntfs-3g`
- **Location:** `sbin/ntfs-3g`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The file 'sbin/ntfs-3g' contains version information '2010.10.2', which is an older version likely vulnerable to multiple CVEs, including heap buffer overflows, memory disclosures, and privilege escalation vulnerabilities.
- **Code Snippet:**
  ```
  ntfs-3g
  2010.10.2
  ```
- **Keywords:** ntfs-3g, 2010.10.2, ntfs_get_attribute_value, ntfs_inode_real_open, ntfs_attr_setup_flag, ntfs_attr_pread_i, ntfs_extent_inode_open
- **Notes:** configuration_load

---
### openssl-version-1.0.2h

- **File/Directory Path:** `usr/sbin/openssl`
- **Location:** `usr/sbin/openssl (strings and ELF metadata)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, libcrypto.so.1.0.0, 3 May 2016
- **Notes:** configuration_load

---
### openssl-version-1.0.2h

- **File/Directory Path:** `etc/openssl.cnf`
- **Location:** `usr/sbin/openssl (strings and ELF metadata)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, libcrypto.so.1.0.0, 3 May 2016
- **Notes:** configuration_load

---
### SBOM-mDNSResponder-Unknown

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_SECRET_KEY_PLACEHOLDER binary`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Analysis results of mDNSResponder component SBOM (version unknown). Known vulnerabilities: CVE-2020-3837, CVE-2020-3838, etc. (Multiple vulnerabilities in mDNSResponder). Evidence source: The string 'REDACTED_SECRET_KEY_PLACEHOLDER' was identified in the REDACTED_SECRET_KEY_PLACEHOLDER binary file.
- **Code Snippet:**
  ```
  String 'REDACTED_SECRET_KEY_PLACEHOLDER' found in binary
  ```
- **Keywords:** mDNSResponder, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** Various memory corruption and DNS spoofing vulnerabilities. Exact version could not be determined from strings output

---
### thirdparty-stunnel-version

- **File/Directory Path:** `usr/sbin/stunnel`
- **Location:** `usr/sbin/stunnel`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** Analysis of 'usr/sbin/stunnel' revealed it is a 32-bit ARM executable linked against OpenSSL 1.0.0. The build environment suggests it is an older version (GCC 4.5.3, Buildroot 2012.02). While the exact stunnel version couldn't be determined from the binary, several critical vulnerabilities were identified, including CVE-2021-20230 (certificate validation bypass) in stunnel and CVE-2014-0224 (CCS Injection) in OpenSSL.
- **Keywords:** stunnel, OpenSSL 1.0.0, libssl.so.1.0.0, libcrypto.so.1.0.0, GCC: (Buildroot 2012.02) 4.5.3, CVE-2021-20230, CVE-2014-0224, CVE-2022-46174
- **Notes:** configuration_load

---
### sbom-FLAC-version

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna`
- **Risk Score:** 7.8
- **Confidence:** 7.5
- **Description:** The FLAC component version 8 contains a high-risk CVE vulnerability. Version evidence source: the string 'libFLAC.so.8' appears.
- **Code Snippet:**
  ```
  libFLAC.so.8
  ```
- **Keywords:** libFLAC.so.8, FLAC__metadata_simple_iterator_next
- **Notes:** CVE-2018-11285(7.8): Parsing corrupted FLAC file image blocks may lead to buffer read out-of-bounds

---
### thirdparty-component-mathopd-httpd

- **File/Directory Path:** `sbin/httpd`
- **Location:** `sbin/httpd (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The version information 'Mathopd/1.6b9' of the Mathopd HTTP server software was detected in the file 'sbin/httpd'. This version has 3 potentially relevant CVE vulnerabilities: a local file overwrite vulnerability (CVE-2005-0824), a buffer overflow vulnerability (CVE-2003-1228), and a directory traversal vulnerability (CVE-2012-1050). The version evidence originates from the string 'Mathopd/1.6b9' within the file.
- **Code Snippet:**
  ```
  Mathopd/1.6b9
  ```
- **Keywords:** Mathopd/1.6b9, internal_dump, prepare_reply, request.c
- **Notes:** Although the discovered CVEs are not directly targeting version 1.6b9, these vulnerabilities may still be applicable. It is recommended to further verify whether these vulnerabilities affect the current version.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_SECRET_KEY_PLACEHOLDER binary`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Analysis results of the uClibc 0.9.33.2 component SBOM. Known vulnerability: CVE-2015-8777 (Integer overflow in glob implementation). Evidence source: The string '/lib/ld-uClibc.so.0' was detected in the REDACTED_SECRET_KEY_PLACEHOLDER binary file.
- **Code Snippet:**
  ```
  String '/lib/ld-uClibc.so.0' found in binary
  ```
- **Keywords:** uClibc, ld-uClibc.so.0
- **Notes:** CVE-2015-8777 could lead to denial of service or potential code execution

---
### SBOM-FLAC-1.2.1

- **File/Directory Path:** `lib/libFLAC.so.8.2.0`
- **Location:** `lib/libFLAC.so.8.2.0 (strings output)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The FLAC library version 1.2.1 contains two known high-risk vulnerabilities: CVE-2007-4619 (integer overflow leading to arbitrary code execution) and CVE-2007-6278 (forced file download). The version information is confirmed by the strings '1.2.1' and 'reference libFLAC 1.2.1 REDACTED_PASSWORD_PLACEHOLDER' within the library.
- **Code Snippet:**
  ```
  1.2.1
  reference libFLAC 1.2.1 REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** libFLAC.so.8.2.0, 1.2.1, reference libFLAC 1.2.1 REDACTED_PASSWORD_PLACEHOLDER, FLAC__VERSION_STRING
- **Notes:** Recommended to upgrade the FLAC library to fix known vulnerabilities.

---
### sbom-libid3tag-version

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The libid3tag component version 0 has multiple CVE vulnerabilities. Version evidence source: the string 'libid3tag.so.0' appears in the text.
- **Code Snippet:**
  ```
  libid3tag.so.0
  ```
- **Keywords:** libid3tag.so.0, id3_file_tag
- **Notes:** CVE List: CVE-2004-2779 (7.5), CVE-2017-11550 (5.5), CVE-2017-11551 (5.5), CVE-2008-2109

---
### stunnel-configuration-analysis

- **File/Directory Path:** `etc/stunnel.conf`
- **Location:** `etc/stunnel.conf`
- **Risk Score:** 7.5
- **Confidence:** 5.5
- **Description:** After analyzing the 'etc/stunnel.conf' file, it was determined that this file serves as the configuration file for stunnel, containing certificate paths, log settings, and port forwarding configurations. Although the file does not directly include version information for stunnel, a CVE search revealed multiple known vulnerabilities associated with stunnel, including CVE-2021-20230 (CVSSv3 score: 7.5) and CVE-2022-46174 (CVSSv3 score: 4.2). Since direct access to log files or binary files is unavailable, the specific version of the current stunnel cannot be determined.
- **Keywords:** stunnel.conf, stunnel_cert.pem, stunnel.REDACTED_PASSWORD_PLACEHOLDER, stunnel.log
- **Notes:** It is recommended to further analyze the stunnel binary file or related log files to obtain precise version information, thereby enabling a more accurate assessment of the vulnerability impact.

---
### SBOM-util-linux-libuuid

- **File/Directory Path:** `lib/libuuid.so.1.2`
- **Location:** `libuuid.so.1.2`
- **Risk Score:** 7.5
- **Confidence:** 4.0
- **Description:** SBOM analysis results for the file libuuid.so.1.2. The software name is the libuuid component of util-linux, with an estimated version of 1.2 (based on the filename). Related high-risk CVEs include: CVE-2015-5224 (CVSS 9.8), CVE-2016-2779 (CVSS 7.8), CVE-2014-9114 (CVSS 7.8). Version evidence sources: filename libuuid.so.1.2, soname libuuid.so.1, compiler information GCC: (Buildroot 2012.02) 4.5.3. It is recommended to confirm the exact version number through the package management system.
- **Code Snippet:**
  ```
  N/A (SBOMHIDDEN)
  ```
- **Keywords:** libuuid.so.1.2, util-linux, GCC: (Buildroot 2012.02) 4.5.3, CVE-2015-5224, CVE-2016-2779, CVE-2014-9114
- **Notes:** All CVEs related to the util-linux package should be considered potential risks. It is recommended to verify the exact version number through the package management system for more precise vulnerability matching.

---
### SBOM-Compiler-GCC-4.5.3

- **File/Directory Path:** `usr/sbin/dhcp6s`
- **Location:** `usr/sbin/dhcp6s:Compiler metadata section`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** Compiler toolchain information found in the dhcp6s binary. GCC version 4.5.3 was built through Buildroot 2012.02, which is a relatively old version and may contain unpatched security vulnerabilities.
- **Code Snippet:**
  ```
  Embedded compiler strings in binary
  ```
- **Keywords:** dhcp6s, GCC, Buildroot, uClibc
- **Notes:** The version information of Buildroot 2012.02 indicates that this is an older implementation. It is recommended to check for known vulnerabilities in GCC 4.5.3 and Buildroot 2012.02.

---
### sbom-libavcodec-ffmpeg-53

- **File/Directory Path:** `lib/libavcodec.so.53`
- **Location:** `HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 3.5
- **Description:** The FFmpeg libavcodec component was found in the file lib/libavcodec.so.53, with version number 53. Due to the lack of a detailed FFmpeg version string, the specific FFmpeg version cannot be determined. The build information indicates compilation with GCC 3.3.2 and 4.5.3, and the configuration parameters suggest this is a streamlined version customized for embedded systems.
- **Keywords:** libavcodec.so.53, LIBAVCODEC_53, GCC: (GNU) 3.3.2, GCC: (Buildroot 2012.02) 4.5.3
- **Notes:** It is recommended to manually verify the correspondence between the FFmpeg version and libavcodec 53, and check related CVEs. Due to API limitations, CVE information could not be automatically retrieved. Component information: {'component_name': 'libavcodec (FFmpeg)', 'version': '53', 'evidence': 'filename libavcodec.so.53 and string LIBAVCODEC_53', 'known_vulnerabilities': 'requires manual verification', 'build_info': 'GCC 3.3.2 and 4.5.3, Buildroot 2012.02', 'license': 'GPL version 2 or later'}

---
### SBOM-GCC-4.5.3

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_SECRET_KEY_PLACEHOLDER binary`
- **Risk Score:** 6.8
- **Confidence:** 7.0
- **Description:** GCC 4.5.3 component SBOM analysis results. Known vulnerability: CVE-2016-2226 (Stack protection bypass vulnerability). Evidence source: 'GCC: (Buildroot 2012.02) 4.5.3' string was detected in the REDACTED_SECRET_KEY_PLACEHOLDER binary file.
- **Code Snippet:**
  ```
  String 'GCC: (Buildroot 2012.02) 4.5.3' found in binary
  ```
- **Keywords:** GCC, 4.5.3
- **Notes:** configuration_load

---
