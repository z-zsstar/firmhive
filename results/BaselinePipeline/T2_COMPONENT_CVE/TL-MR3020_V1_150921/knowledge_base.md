# TL-MR3020_V1_150921 (2 alerts)

---

### Linux-Kernel-2.6.31

- **File/Directory Path:** `lib/modules/2.6.31`
- **Location:** `lib/modules/2.6.31`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** kernel
- **Code Snippet:**
  ```
  Directory path evidence: lib/modules/2.6.31
  ```
- **Keywords:** 2.6.31
- **Notes:** kernel

---
### uClibc-0.9.30

- **File/Directory Path:** `lib/libuClibc-0.9.30.so`
- **Location:** `lib/libuClibc-0.9.30.so`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The uClibc C library version 0.9.30 was identified in the firmware. This is a critical system component that provides standard C library functionality for embedded systems. The version was confirmed through the library filename.
- **Code Snippet:**
  ```
  Filename evidence: libuClibc-0.9.30.so
  ```
- **Keywords:** libuClibc-0.9.30.so, ld-uClibc-0.9.30.so
- **Notes:** uClibc 0.9.30 is known to have several vulnerabilities. Recommend checking CVE databases for this specific version. The component is fundamental to system operation.

---
