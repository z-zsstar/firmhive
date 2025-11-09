# Archer_C2_V1_170228 (28 alerts)

---

### thirdparty-Buildroot-libcmm.so

- **File/Directory Path:** `lib/libcmm.so`
- **Location:** `lib/libcmm.so (HIDDENstringsHIDDEN)`
- **Risk Score:** 9.9
- **Confidence:** 7.5
- **Description:** The Buildroot component was identified in the lib/libcmm.so file, with version 2012.11.1. This version contains multiple critical vulnerabilities:
1. CVE-2017-14804 (CVSS 9.9): Directory name checking vulnerability allows untrusted builds to write outside the target system
2. CVE-2023-43608 (CVSS 8.1): Data integrity vulnerability in BR_NO_CHECK_HASH_FOR feature allows MITM attacks
3. CVE-2023-45838 (CVSS 8.1): Package hash checking vulnerability in aufs package allows MITM attacks
Version evidence source: String extraction from libcmm.so
- **Keywords:** Buildroot, libcmm.so, CVE-2017-14804, CVE-2023-43608, CVE-2023-45838
- **Notes:** The version information is extracted from strings in libcmm.so. The readelf tool analysis failed, and it is recommended to further verify the applicability of these vulnerabilities in specific environments.

---
### component-libpthread-0.9.33.2

- **File/Directory Path:** `lib/libpthread-0.9.33.2.so`
- **Location:** `lib/libpthread-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** LinuxThreads (pthread implementation) version 0.9.33.2 identified in lib/libpthread-0.9.33.2.so. This version contains a critical memory corruption vulnerability (CVE-2022-29503) with CVSSv3 score of 9.8. The version information was derived from the filename.
- **Keywords:** libpthread-0.9.33.2.so, LinuxThreads, uClibC, pthread_create, CVE-2022-29503
- **Notes:** configuration_load

---
### vulnerability-CVE-2022-29503

- **File/Directory Path:** `lib/libpthread-0.9.33.2.so`
- **Location:** `lib/libpthread-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** uClibC 0.9.33.2 and uClibC-ng 1.0.40 versions contain a memory corruption vulnerability in thread allocation. CVSSv3 score: 9.8.
- **Keywords:** CVE-2022-29503, libpthread-0.9.33.2.so, LinuxThreads, memory_corruption
- **Notes:** Affected versions: uClibC 0.9.33.2 and uClibC-ng 1.0.40. Source: NVD.

---
### component-uClibc-0.9.33.2

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** The uClibc version 0.9.33.2 component was found in the file 'lib/ld-uClibc-0.9.33.2.so'. Version evidence comes from the filename and NVD API confirmation.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** uClibc, 0.9.33.2, get_subexp, misc/regex/regexec.c, libpthread, linuxthreads, check_dst_limits_calc_pos_1, regexec.c, DNS transaction IDs
- **Notes:** Associated CVE vulnerabilities: CVE-2017-9728 (out-of-bounds read issue in get_subexp function), CVE-2022-29503 (memory corruption issue in libpthread linuxthreads), CVE-2017-9729 (stack exhaustion issue in check_dst_limits_calc_pos_1 function), CVE-2022-30295 (DNS cache poisoning vulnerability)

---
### VULN-CVE-2017-9728

- **File/Directory Path:** `lib/libutil-0.9.33.2.so`
- **Location:** `libutil-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** vulnerability
- **Keywords:** libutil-0.9.33.2.so, uClibc, CVE-2017-9728

---
### VULN-CVE-2022-29503

- **File/Directory Path:** `lib/libutil-0.9.33.2.so`
- **Location:** `libutil-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** vulnerability
- **Keywords:** libutil-0.9.33.2.so, uClibc, CVE-2022-29503

---
### component-librt-0.9.33.2

- **File/Directory Path:** `lib/librt-0.9.33.2.so`
- **Location:** `lib/librt-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Keywords:** librt-0.9.33.2.so, uClibc, libc.so.0, librt.so.0
- **Notes:** Extract version evidence from the file name. The listed vulnerability targets the parent project uClibc that includes this library.

---
### vulnerability-CVE-2017-9728

- **File/Directory Path:** `lib/librt-0.9.33.2.so`
- **Location:** `lib/librt-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** configuration_load
- **Keywords:** librt-0.9.33.2.so, uClibc, regexec.c
- **Notes:** Affects uClibc 0.9.33.2

---
### vulnerability-CVE-2022-29503

- **File/Directory Path:** `lib/librt-0.9.33.2.so`
- **Location:** `lib/librt-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Memory corruption vulnerability in the libpthread linuxthreads functionality (CVSS 9.8)
- **Keywords:** librt-0.9.33.2.so, uClibc, libpthread
- **Notes:** Affects uClibc 0.9.33.2

---
### library-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libdl-0.9.33.2.so`
- **Location:** `lib/libdl-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** The file 'lib/libdl-0.9.33.2.so' has been confirmed as part of uClibc version 0.9.33.2. This version contains multiple known critical vulnerabilities, including memory corruption, stack exhaustion, and DNS cache poisoning issues. The version information is derived from the filename and the string 'ld-uClibc.so.0' identified during string analysis.
- **Keywords:** libdl-0.9.33.2.so, uClibc, 0.9.33.2, ld-uClibc.so.0, libc.so.0
- **Notes:** These vulnerabilities affect the entire uClibc 0.9.33.2 package, not just this specific library file. It is recommended to further analyze the usage of uClibc in the firmware to assess the actual risk.

---
### thirdparty-GCC-libcmm.so

- **File/Directory Path:** `lib/libcmm.so`
- **Location:** `lib/libcmm.so (HIDDENstringsHIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The GCC component was identified in the lib/libcmm.so file with version 3.3.2/4.6.3. This version contains multiple high-risk vulnerabilities:
1. CVE-2023-29404 (CVSS 9.8): The go command may execute arbitrary code during builds when using cgo
2. CVE-2023-29405 (CVSS 9.8): The go command may execute arbitrary code during builds when processing flags containing embedded spaces
3. CVE-2014-9799 (CVSS 7.8): Missing the -fno-strict-overflow option may lead to privilege escalation
Version evidence source: String extraction from libcmm.so
- **Keywords:** GCC, libcmm.so, CVE-2023-29404, CVE-2023-29405, CVE-2014-9799
- **Notes:** The version information is extracted from strings within libcmm.so, and the readelf tool failed in the analysis. It is recommended to further verify the applicability of these vulnerabilities in the specific environment.

---
### thirdparty-libupnp-version

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.so`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The version of the Portable SDK for UPnP devices used in the lib/libupnp.so file is confirmed to be 1.6.19. This version falls between 1.6.18 and 1.14.6 and may be affected by multiple high-risk vulnerabilities. The version evidence comes from the HTTP server identification string.
- **Keywords:** libupnp, Portable SDK for UPnP devices, 1.6.19, HTTP server identification string
- **Notes:** It is recommended to upgrade to version 1.14.6 or later to fix the vulnerability.

---
### vulnerability-CVE-2012-5958

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.so`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Stack buffer overflow vulnerability in the unique_service_name function of the SSDP parser. Affects versions <1.6.18.
- **Keywords:** libupnp, Portable SDK for UPnP devices, 1.6.19, CVE-2012-5958
- **Notes:** Version 1.6.19 may have fixed this vulnerability

---
### vulnerability-CVE-2012-5959

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.so`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Stack buffer overflow vulnerability in the unique_service_name function of the SSDP parser. Affects versions <1.6.18.
- **Keywords:** libupnp, Portable SDK for UPnP devices, 1.6.19, CVE-2012-5959
- **Notes:** Version 1.6.19 may have fixed this vulnerability

---
### vulnerability-CVE-2012-5960

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.so`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Stack buffer overflow vulnerability in the unique_service_name function of the SSDP parser. Affects versions <1.6.18.
- **Keywords:** libupnp, Portable SDK for UPnP devices, 1.6.19, CVE-2012-5960
- **Notes:** Version 1.6.19 may have fixed this vulnerability

---
### sbom-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libuClibc-0.9.33.2.so`
- **Location:** `lib/libuClibc-0.9.33.2.so`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The uClibc component found in the file 'lib/libuClibc-0.9.33.2.so' has version number 0.9.33.2. This version contains multiple high-risk vulnerabilities, including CVE-2017-9728 (memory corruption vulnerability) and CVE-2022-29503 (DNS prediction issue). It is recommended to upgrade to a newer version to fix these vulnerabilities.
- **Code Snippet:**
  ```
  Filename: lib/libuClibc-0.9.33.2.so
  ```
- **Keywords:** libuClibc-0.9.33.2.so, uClibc, 0.9.33.2, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295
- **Notes:** It is recommended to upgrade to a newer version of uClibc to fix these vulnerabilities. In particular, the high-risk vulnerabilities CVE-2022-29503 and CVE-2017-9728 should be prioritized.

---
### thirdparty-samba-3.0.14a

- **File/Directory Path:** `lib/libbigballofmud.so`
- **Location:** `libbigballofmud.so (general strings output)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** Clear evidence was found in libbigballofmud.so indicating this is a Samba library, version 3.0.14a. This version is known to contain multiple critical vulnerabilities, including but not limited to CVE-2007-2446 and CVE-2007-2447.
- **Code Snippet:**
  ```
  Found version string: 'Samba 3.0.14a'
  ```
- **Keywords:** Samba, 3.0.14a, ELF32, MIPS R3000
- **Notes:** Samba 3.0.14a is an older version known to have multiple remote code execution vulnerabilities. It is recommended to check whether other Samba components exist in the firmware and consider upgrading to a secure version.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libutil-0.9.33.2.so`
- **Location:** `libutil-0.9.33.2.so`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Filename: libutil-0.9.33.2.so
  Strings output showing reference to '/lib/ld-uClibc.so.0'
  Dynamic section dependency on libc.so.0
  ```
- **Keywords:** libutil-0.9.33.2.so, uClibc, libc.so.0, ld-uClibc.so.0
- **Notes:** It is recommended to upgrade uClibc to a new version that has fixed these vulnerabilities. The version number is derived from the filename but conforms to uClibc's version numbering convention.

---
### thirdparty-uClibc-0.9.33.2

- **File/Directory Path:** `lib/libdl.so.0`
- **Location:** `lib/libcrypt-0.9.33.2.so (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** By analyzing the filename libcrypt-0.9.33.2.so, the uClibc version was identified as 0.9.33.2. This version contains multiple known critical vulnerabilities, including security issues such as memory corruption, denial of service, and remote code execution.
- **Keywords:** ld-uClibc.so.0, uClibc, libdl.so.0, libcrypt-0.9.33.2.so
- **Notes:** Verify uClibc version is 0.9.33.2. Known vulnerabilities include: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6). Recommend upgrading to a vulnerability-free version.

---
### SBOM-Buildroot-2012.11.1

- **File/Directory Path:** `sbin/usbp`
- **Location:** `usbpHIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** The Buildroot 2012.11.1 version information was found in the usbp file, with the evidence being the string 'GCC: (Buildroot 2012.11.1) 4.6.3'. Related CVE vulnerabilities: CVE-2017-14804 (CVSS 9.9), CVE-2023-43608 (CVSS 8.1).
- **Code Snippet:**
  ```
  GCC: (Buildroot 2012.11.1) 4.6.3
  ```
- **Keywords:** Buildroot 2012.11.1, usbp, SBOM
- **Notes:** Although no CVEs directly matching Buildroot 2012.11.1 were found, general vulnerabilities related to Buildroot are listed.

---
### thirdparty-uClibc-unknown_version

- **File/Directory Path:** `lib/libdl.so.0`
- **Location:** `lib/libdl.so.0`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The file 'lib/libdl.so.0' is dynamically linked to the uClibc library, but the exact version number was not extracted. Multiple known high-risk vulnerabilities related to uClibc have been identified, including security issues such as memory corruption, denial of service, and remote code execution. It is recommended to further analyze other files in the firmware to determine the exact version of uClibc.
- **Code Snippet:**
  ```
  ELF 32-bit LSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
  ```
- **Keywords:** ld-uClibc.so.0, uClibc, libdl.so.0
- **Notes:** It is recommended to further analyze other files in the firmware to determine the exact version of uClibc. Additionally, consideration should be given to patching or replacing the affected uClibc version to mitigate known vulnerabilities. Known vulnerabilities include: CVE-2017-9728 (CVSS 9.8), CVE-2022-29503 (CVSS 9.8), CVE-2021-43523 (CVSS 9.6).

---
### component-ld.so-1.7.0

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 7.8
- **Confidence:** 7.5
- **Description:** The ld.so version found in the file 'lib/ld-uClibc-0.9.33.2.so' is 1.7.0. The version is derived from the string output ('ld.so-1.7.0').
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** ld.so, 1.7.0, GLIBC_TUNABLES
- **Notes:** configuration_load

---
### vulnerability-CVE-2021-29462

- **File/Directory Path:** `lib/libupnp.so`
- **Location:** `lib/libupnp.so`
- **Risk Score:** 7.6
- **Confidence:** 8.0
- **Description:** DNS rebinding attack vulnerability due to unchecked Host header value. CVSS score 7.6, affecting versions <1.14.6.
- **Keywords:** libupnp, Portable SDK for UPnP devices, 1.6.19, CVE-2021-29462
- **Notes:** The affected version range includes 1.6.19.

---
### VULN-CVE-2017-9729

- **File/Directory Path:** `lib/libutil-0.9.33.2.so`
- **Location:** `libutil-0.9.33.2.so`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The check_dst_limits_calc_pos_1 function contains a stack exhaustion vulnerability when processing specially crafted regular expressions. Affects uClibc version 0.9.33.2.
- **Keywords:** libutil-0.9.33.2.so, uClibc, CVE-2017-9729

---
### vulnerability-CVE-2017-9729

- **File/Directory Path:** `lib/librt-0.9.33.2.so`
- **Location:** `lib/librt-0.9.33.2.so`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Keywords:** librt-0.9.33.2.so, uClibc, regexec.c
- **Notes:** Affects uClibc 0.9.33.2

---
### library-uClibc-version

- **File/Directory Path:** `lib/libutil.so.0`
- **Location:** `lib/libutil.so.0`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The file 'lib/libutil.so.0' is part of uClibc version 0.9.33.2, as evidenced by the directory listing showing the filename 'libutil-0.9.33.2.so'. This version of uClibc contains multiple critical vulnerabilities. The file has been stripped of its symbol table, and no other explicit third-party component information was found.
- **Keywords:** libutil.so.0, libutil-0.9.33.2.so, uClibc
- **Notes:** It is recommended to further analyze the dependency library 'libc.so.0' for more information and check for known vulnerabilities in uClibc version 0.9.33.2.

---
### thirdparty-uClibc-unknown

- **File/Directory Path:** `lib/libm.so.0`
- **Location:** `lib/libm.so.0`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** Suspected third-party component uClibc (version unknown), evidence source: file dependencies 'libc.so.0' and 'ld-uClibc.so.0'. Multiple high-risk vulnerabilities (CVEs) related to uClibc were identified, including CVE-2017-9728, CVE-2022-29503, CVE-2021-43523, etc.
- **Code Snippet:**
  ```
  HIDDEN：libc.so.0, ld-uClibc.so.0
  ```
- **Keywords:** uClibc, libc.so.0, ld-uClibc.so.0
- **Notes:** Further confirmation of the specific version of uClibc is required to determine whether it is affected by the aforementioned vulnerabilities.

---
### SBOM-libcmm.so

- **File/Directory Path:** `sbin/usbp`
- **Location:** `usbpHIDDEN`
- **Risk Score:** 6.8
- **Confidence:** 7.75
- **Description:** The reference to the libcmm.so dynamic link library found in the usbp file. Related CVE vulnerabilities: CVE-2023-44448 (CVSS 6.8), CVE-2023-50225 (CVSS 6.8).
- **Keywords:** libcmm.so, dm_fillObjByStr, usbp, SBOM
- **Notes:** The two vulnerabilities in libcmm.so require authentication to exploit, and the attacker must be in a network-adjacent position.

---
