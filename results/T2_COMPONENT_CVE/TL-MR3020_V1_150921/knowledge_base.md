# TL-MR3020_V1_150921 (9 alerts)

---

### component-uClibc-handle_card

- **File/Directory Path:** `usr/sbin/handle_card`
- **Location:** `usr/sbin/handle_card (HIDDEN)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The uClibc component found in the 'usr/sbin/handle_card' file is version 0.9.30.1. Multiple critical vulnerabilities exist: CVE-2017-9728 (Out-of-bounds read in get_subexp function when processing crafted regular expression, CVSS 9.8), CVE-2022-29503 (Memory corruption in libpthread linuxthreads functionality, CVSS 9.8), CVE-2021-43523 (Incorrect handling of special characters in domain names, CVSS 9.6). Although these vulnerabilities are not specific to version 0.9.30.1, it is recommended to verify whether the actual uClibc version used in the firmware is affected by these vulnerabilities.
- **Code Snippet:**
  ```
  HIDDEN '/lib/ld-uClibc.so.0' HIDDEN '__uClibc_main'
  ```
- **Keywords:** uClibc, CVE-2017-9728, CVE-2022-29503, CVE-2021-43523
- **Notes:** Although these vulnerabilities are not specific to version 0.9.30.1, it is recommended to verify whether the actual uClibc version used in the firmware is affected by these vulnerabilities.

---
### thirdparty-component-uClibc

- **File/Directory Path:** `usr/sbin/modem_scan`
- **Location:** `usr/sbin/modem_scan`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The uClibc component found in the modem_scan file, version unknown. Contains multiple high-risk CVE vulnerabilities: CVE-2017-9728 (CVSS 9.8, out-of-bounds read), CVE-2022-29503 (CVSS 9.8, memory corruption), CVE-2021-43523 (CVSS 9.6, DNS resolution vulnerability). Evidence sources: '/lib/ld-uClibc.so.0' and 'libc.so.0' strings.
- **Code Snippet:**
  ```
  Found in strings: '/lib/ld-uClibc.so.0' and 'libc.so.0'
  ```
- **Keywords:** /lib/ld-uClibc.so.0, libc.so.0, uClibc
- **Notes:** Analyze /lib/libc.so.0 to determine the exact version

---
### component-chat-1.30

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `usr/sbin/chat (HIDDENstringsHIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The chat utility version 1.30 (released in 2004) was found in the 'usr/sbin/chat' file. This outdated version may contain known security vulnerabilities.
- **Code Snippet:**
  ```
  $Id: chat.c,v 1.30 2004/01/17 05:47:55 carlsonj Exp $
  ```
- **Keywords:** chat.c,v 1.30, GCC 3.3.2, GCC 4.3.3, ld-uClibc.so.0
- **Notes:** It is recommended to further investigate the known vulnerabilities of chat version 1.30. Version evidence source: string: $Id: chat.c,v 1.30 2004/01/17 05:47:55 carlsonj Exp $

---
### component-GCC-3.3.2

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `usr/sbin/chat (HIDDENstringsHIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The GCC compiler version 3.3.2 was found in the 'usr/sbin/chat' file. This outdated version may contain known security vulnerabilities, such as CVE-2004-1011, CVE-2005-1689, etc.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** chat.c,v 1.30, GCC 3.3.2, GCC 4.3.3, ld-uClibc.so.0
- **Notes:** Known vulnerabilities include CVE-2004-1011, CVE-2005-1689, etc. Version evidence source: string: GCC: (GNU) 3.3.2

---
### component-GCC-4.3.3

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `usr/sbin/chat (HIDDENstringsHIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The GCC compiler version 4.3.3 was found in the 'usr/sbin/chat' file. This outdated version may contain known security vulnerabilities.
- **Code Snippet:**
  ```
  GCC: (GNU) 4.3.3
  ```
- **Keywords:** chat.c,v 1.30, GCC 3.3.2, GCC 4.3.3, ld-uClibc.so.0
- **Notes:** It is recommended to further investigate known vulnerabilities in GCC version 4.3.3. Version evidence source: string: GCC: (GNU) 4.3.3

---
### SBOM-Kernel-2.6.15

- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `rc.modules:3-5`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The Linux kernel version 2.6.15 contains multiple critical vulnerabilities:
- CVE-2006-7229 (CVSSv3:7.5): skge driver issue may lead to denial of service
- CVE-2005-3784: Automatic child process reaping issue may result in local privilege escalation
- CVE-2005-3807: Memory leak in VFS file lease handling
- CVE-2005-3857: Log consumption issue in time_out_leases function
- CVE-2005-3358: set_mempolicy call may cause kernel panic
- **Code Snippet:**
  ```
  N/A (HIDDENrc.modulesHIDDEN)
  ```
- **Keywords:** Linux Kernel 2.6.15
- **Notes:** Version evidence source: lines 3-5 of the rc.modules file

---
### thirdparty-component-GCC-4.3.3

- **File/Directory Path:** `usr/sbin/modem_scan`
- **Location:** `usr/sbin/modem_scan strings output`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The GCC compiler version 4.3.3 was found in the modem_scan string output. Existing CVE vulnerabilities: CVE-2008-1367 (missing CLD instruction generation), CVE-2008-1685 (pointer arithmetic optimization issue). Evidence source: multiple GCC version strings in the binary.
- **Code Snippet:**
  ```
  Multiple GCC version strings in binary
  ```
- **Keywords:** GCC, 4.3.3
- **Notes:** The vulnerability may apply to the 4.3.x series.

---
### component-uClibc-unknown

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `usr/sbin/chat (HIDDENstringsHIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The uClibc library found in the 'usr/sbin/chat' file has an unknown specific version. This library may have potential security issues.
- **Code Snippet:**
  ```
  /lib/ld-uClibc.so.0
  ```
- **Keywords:** chat.c,v 1.30, GCC 3.3.2, GCC 4.3.3, ld-uClibc.so.0
- **Notes:** Determine the specific version of uClibc to investigate related vulnerabilities. Source of version evidence: Dynamic library reference: /lib/ld-uClibc.so.0

---
### thirdparty-net-tools-version

- **File/Directory Path:** `usr/arp`
- **Location:** `usr/arp`
- **Risk Score:** 6.6
- **Confidence:** 6.0
- **Description:** The file 'usr/arp' is part of the net-tools package. Compilation information indicates the use of GCC 3.3.2 and 4.3.3. However, no explicit net-tools version information was found in the file. Based on the GCC versions and compilation timestamps, this net-tools version is likely outdated and may contain known vulnerabilities. It is recommended to check other files in the firmware or system logs to obtain the exact version information.
- **Keywords:** net-tools, GCC: (GNU) 3.3.2, GCC: (GNU) 4.3.3, arp
- **Notes:** Since the exact version cannot be determined, it is recommended to further analyze other files in the firmware for additional information. Older versions of net-tools may contain vulnerabilities, such as CVE-2025-46836 and CVE-1999-0748, but the exact version number is required for confirmation.

---
