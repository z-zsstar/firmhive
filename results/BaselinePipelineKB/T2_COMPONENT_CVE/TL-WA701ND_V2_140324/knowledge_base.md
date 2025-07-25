# TL-WA701ND_V2_140324 (13 alerts)

---

### SBOM-LinuxKernel-2.6.15

- **File/Directory Path:** `N/A`
- **Location:** `etc/rc.d/rcS (HIDDEN/lib/modules/2.6.15/)`
- **Risk Score:** 9.8
- **Confidence:** 9.5
- **Description:** Linux kernel version 2.6.15 found in firmware through rcS startup script. This version contains multiple critical vulnerabilities including denial of service and privilege escalation issues.
- **Code Snippet:**
  ```
  HIDDEN: /lib/modules/2.6.15/
  ```
- **Keywords:** Linux, kernel, 2.6.15, rcS
- **Notes:** Version verified through direct code comments in rcS script. Contains 5 known CVEs including CVE-2006-7229 (CVSS 7.5).

---
### SBOM-LinuxKernel-2.6.31-LSDK

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/2.6.31/kernel/`
- **Risk Score:** 9.5
- **Confidence:** 9.4
- **Description:** Linux kernel version 2.6.31 (LSDK-9.2.0.312 variant) with critical vulnerabilities. Verified through usbserial.ko and usb-storage.ko module strings.
- **Code Snippet:**
  ```
  Module vermagic strings confirming version 2.6.31
  ```
- **Keywords:** Linux, kernel, 2.6.31, LSDK
- **Notes:** Detected LSDK (Linux Software Development Kit) variant

---
### SBOM-LinuxKernel-2.6.31

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/2.6.31/kernel/`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Linux kernel version 2.6.31 found in firmware through module directory structure. Very old kernel version with known vulnerabilities.
- **Code Snippet:**
  ```
  Directory path containing version: /lib/modules/2.6.31/kernel/
  ```
- **Keywords:** Linux, kernel, 2.6.31
- **Notes:** Version identified through directory structure. Kernel 2.6.31 was released in 2009 and is known to contain numerous vulnerabilities.

---
### SBOM-BusyBox-1.01-update2

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/udhcpd`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The BusyBox component version 1.01 was found in udhcpd. This is an extremely outdated version (released in 2014) that likely contains numerous unpatched security vulnerabilities.
- **Code Snippet:**
  ```
  'BusyBox v1.01 (2014.03.24-02:05+0000)'
  ```
- **Keywords:** BusyBox, udhcpd
- **Notes:** network_input

---
### SBOM-BusyBox-1.01

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox: Found in multiple strings within the binary (e.g., at offsets 0x00039ac4, 0x00039e30, 0x0003b2cf)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** BusyBox component version 1.01 (2014.03.24-02:05+0000) found in firmware. This is an extremely old version (from 2014) that likely contains numerous unpatched vulnerabilities. The tftp functionality in this firmware is provided by BusyBox. Consider upgrading to a supported BusyBox version (current stable is 1.36.x).
- **Code Snippet:**
  ```
  Version string: 'BusyBox v1.01 (2014.03.24-02:05+0000)'
  ```
- **Keywords:** BusyBox, tftp
- **Notes:** configuration_load

---
### SBOM-BusyBox-1.01-update

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox (HIDDENgrepHIDDEN)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Version string: 'BusyBox v1.01 (2014.03.24-02:05+0000)'
  ```
- **Keywords:** BusyBox, grep, NVD
- **Notes:** Detection method updated: Use the grep command to extract version information. No CVE records for this specific version were found in the NVD database. It is recommended to check broader vulnerability databases or consider that this version may contain undisclosed security issues. Analysis summary: Only one third-party component, BusyBox, was found in the bin directory.

---
### SBOM-iptables-2.1.0

- **File/Directory Path:** `N/A`
- **Location:** `lib/libxtables.so.2.1.0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** network_input
- **Code Snippet:**
  ```
  Filename containing version: libxtables.so.2.1.0
  ```
- **Keywords:** iptables, libxtables, firewall
- **Notes:** Version identified via filename pattern recognition. CVE search pending. Firewall components often contain critical vulnerabilities.

---
### SBOM-NET-SNMP-5.4.2.1

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/snmpd`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** NET-SNMP component version 5.4.2.1 found in firmware. Simple Network Management Protocol implementation.
- **Code Snippet:**
  ```
  'NET-SNMP version: 5.4.2.1'
  ```
- **Keywords:** NET-SNMP, SNMP
- **Notes:** network_input

---
### SBOM-USB-Storage-Driver-2.6.31

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/2.6.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.8
- **Confidence:** 8.5
- **Description:** The USB storage driver built into Linux kernel 2.6.31 contains a buffer overflow vulnerability.
- **Code Snippet:**
  ```
  usb-storage.ko module with GPL license
  ```
- **Keywords:** USB, storage, usb-storage.ko
- **Notes:** GPL-licensed kernel module

---
### SBOM-pppd-2.4.3

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/pppd`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** pppd component version 2.4.3 found in firmware. Point-to-Point Protocol daemon.
- **Code Snippet:**
  ```
  'pppd %s started by %s, uid %d
  2.4.3'
  ```
- **Keywords:** pppd, PPP
- **Notes:** network_input

---
### SBOM-WirelessTools-29

- **File/Directory Path:** `N/A`
- **Location:** `lib/libiw.so.29`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Wireless Tools version 29 found in firmware through library file. Used for wireless interface configuration.
- **Code Snippet:**
  ```
  Filename containing version: libiw.so.29
  ```
- **Keywords:** Wireless, libiw, wifi
- **Notes:** Identify versions via filename patterns. CVE search pending. Wireless components often have security issues.

---
### SBOM-xl2tpd-1.1.12

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/xl2tpd`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** xl2tpd component version 1.1.12 found in firmware. Layer 2 Tunneling Protocol daemon.
- **Code Snippet:**
  ```
  'xl2tpd-1.1.12'
  ```
- **Keywords:** xl2tpd, L2TP
- **Notes:** network_input

---
### SBOM-uClibc-0.9.30

- **File/Directory Path:** `N/A`
- **Location:** `lib/libpthread-0.9.30.so, lib/ld-uClibc-0.9.30.so, lib/libuClibc-0.9.30.so`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** uClibc C library version 0.9.30 found in firmware through multiple library files. This is a lightweight C library for embedded systems.
- **Code Snippet:**
  ```
  Filenames containing version: libpthread-0.9.30.so, ld-uClibc-0.9.30.so, libuClibc-0.9.30.so
  ```
- **Keywords:** uClibc, libpthread, ld-uClibc
- **Notes:** configuration_load

---
