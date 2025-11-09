# R6400v2-V1.0.2.46_1.0.36 (4 alerts)

---

### nvram-getall-leak

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:0x899c`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The discovery of the NVRAM batch operation function nvram_getall being called may lead to the leakage of all NVRAM variable values. The return value is directly output to standard output, posing an information disclosure risk.
- **Keywords:** nvram_getall, puts
- **Notes:** nvram_get

---
### httpd-getenv-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x35af0`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The function `fcn.REDACTED_PASSWORD_PLACEHOLDER` calls `getenv` to retrieve environment variable values and uses them to construct system commands. This may pose a command injection risk if the environment variable values are maliciously controlled.
- **Keywords:** getenv, system, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further verification is needed to confirm the trustworthiness of the environment variable value source.

---
### nvram-set-overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/nvram:0x8904`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** Detected NVRAM variable setting operation implemented through strncpy and nvram_set combination. Potential buffer overflow risk exists (fixed 0x20000 buffer size).
- **Keywords:** strncpy, nvram_set, 0x20000
- **Notes:** nvram_set

---
### fbwifi-proxy-env-vars

- **File/Directory Path:** `N/A`
- **Location:** `bin/fbwifi:0x39c38-0x39c44`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The text identifies multiple HTTP proxy-related environment variable read operations, including http_proxy, https_proxy, etc. These values may be used to construct network requests, posing a command injection risk.
- **Keywords:** http_proxy, https_proxy, all_proxy, no_proxy
- **Notes:** Pay special attention to the parsing and processing logic of proxy URLs

---
