# _XR500-V2.1.0.4.img.extracted (4 alerts)

---

### SBOM-kernel

- **File/Directory Path:** `usr/lib/opkg/status`
- **Location:** `Lines 2449-2453 in status file`
- **Risk Score:** 10.0
- **Confidence:** 9.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Package: kernel
  Version: 3.4.103-1-REDACTED_PASSWORD_PLACEHOLDER
  Description: Linux kernel
  Status: hold
  ```
- **Keywords:** kernel, 3.4.103-1-REDACTED_PASSWORD_PLACEHOLDER, Package, Version, status, opkg, hold
- **Notes:** configuration_load

---
### SBOM-libc

- **File/Directory Path:** `usr/lib/opkg/status`
- **Location:** `Lines 61-68 in status file`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Package: libc
  Version: 0.9.33.2-1
  Description: C library
  Status: essential
  ```
- **Keywords:** libc, 0.9.33.2-1, Package, Version, status, opkg, essential
- **Notes:** configuration_load

---
### SBOM-openssl-util

- **File/Directory Path:** `usr/lib/opkg/status`
- **Location:** `Lines 249-254 in status file`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** OpenSSL utility version 1.0.2h-1 extracted from opkg status file. Security critical component that should be checked for known vulnerabilities.
- **Code Snippet:**
  ```
  Package: openssl-util
  Version: 1.0.2h-1
  Description: OpenSSL utility
  ```
- **Keywords:** openssl-util, 1.0.2h-1, Package, Version, status, opkg
- **Notes:** configuration_load

---
### SBOM-kmod-usb-storage

- **File/Directory Path:** `usr/lib/opkg/status`
- **Location:** `Lines 9-15 in status file`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Package: kmod-usb-storage
  Version: 3.4.103-1
  Description: Kernel module for USB storage support
  ```
- **Keywords:** kmod-usb-storage, 3.4.103-1, Package, Version, status, opkg
- **Notes:** configuration_load

---
