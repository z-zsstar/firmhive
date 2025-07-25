# Archer_D2_V1_150921 (2 alerts)

---

### thirdparty-component-dropbear-ssh-server

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER: .rodata section (0xREDACTED_PASSWORD_PLACEHOLDER, 0x0002765c, 0x000295cc)`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The Dropbear SSH server version 2012.55 contains multiple high-risk common vulnerabilities (CVE-2016-7406, CVE-2016-7407, etc.). Version evidence comes from the strings 'SSH-2.0-dropbear_2012.55' and 'Dropbear sshd v%s' in the .rodata section. It is recommended to upgrade to the latest version to fix potential vulnerabilities.
- **Code Snippet:**
  ```
  Dropbear multi-purpose version %s
  Make a symlink pointing at this binary with one of the following names:
  'dropbear' - the Dropbear server
  'dropbearkey' - the REDACTED_PASSWORD_PLACEHOLDER generator
  'scp' - secure copy
  ```
- **Keywords:** dropbearmulti, SSH-2.0-dropbear_2012.55, Dropbear sshd v%s
- **Notes:** Related CVE list: CVE-2016-7406 (9.8), CVE-2016-7407 (9.8), CVE-2020-15833 (9.8), CVE-2018-5399 (9.4), CVE-2016-7408 (8.8)

---
### thirdparty-component-BusyBox

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** BusyBox version 1.19.2, identified by the version string 'BusyBox v1.19.2 (2015-07-03 11:30:00 HKT)' found in the bin/busybox file using the strings command. While no direct CVEs were found specifically for version 1.19.2, multiple high-risk vulnerabilities (CVE-2019-5138, CVE-2016-2148, CVE-2021-42377) may affect this version.
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-07-03 11:30:00 HKT)
  ```
- **Keywords:** BusyBox, 1.19.2
- **Notes:** It is recommended to upgrade to the latest version (1.35 or higher) to fix potential vulnerabilities.

---
