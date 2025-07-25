# TL-WR1043ND_V3_150514 (2 alerts)

---

### dropbear-ssh-2012.55

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER: Strings extraction with 'dropbear' keyword`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Dropbear SSH version 2012.55 has been confirmed to contain multiple high-risk vulnerabilities (CVE-2016-7406, CVE-2016-7407, etc.), which affect versions prior to 2016.74.
- **Code Snippet:**
  ```
  Dropbear multi-purpose version %s
  2012.55
  ```
- **Keywords:** Dropbear multi-purpose version %s
2012.55, CVE-2016-7406, CVE-2016-7407
- **Notes:** It is recommended to upgrade to a version later than 2016.74, or implement network-level protection and restrict SSH access.

---
### wpa_supplicant-2.0-devel

- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `sbin/wpa_supplicant: .rodata section (0x00478c1c)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** third_party_application
- **Code Snippet:**
  ```
  wpa_supplicant v2.0-devel
  ```
- **Keywords:** wpa_supplicant v2.0-devel, CVE-2018-14526, CVE-2015-0210
- **Notes:** The version string indicates this is a development build, which may contain additional unmatched vulnerabilities.

---
