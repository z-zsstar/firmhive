# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (10 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-md5

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was discovered, encrypted using MD5 (identified by the $1$ marker). This hash could potentially be brute-forced to gain REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1
- **Notes:** The hash encrypted with DES can be brute-forced in a short time on modern hardware.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-des

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash of the REDACTED_PASSWORD_PLACEHOLDER user was discovered, using traditional DES encryption (13 characters). This hash may be brute-forced to gain administrator privileges.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, 6HgsSsJIEOc2U
- **Notes:** The hash encrypted with DES can be brute-forced in a short time on modern hardware.

---
### default-wep-keys

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A hardcoded WEP REDACTED_PASSWORD_PLACEHOLDER '12345' was detected, which may allow wireless networks using WEP encryption to be easily compromised.
- **Code Snippet:**
  ```
  wl2g.ssid0.wep_key1=12345
  wl2g.ssid0.wep_key2=12345
  wl2g.ssid0.wep_key3=12345
  wl2g.ssid0.wep_key4=12345
  ```
- **Keywords:** wl2g.ssid0.wep_key1, wl2g.ssid0.wep_key2, wl2g.ssid0.wep_key3, wl2g.ssid0.wep_key4
- **Notes:** WEP encryption is inherently insecure; it is recommended to use more secure encryption methods such as WPA2 or WPA3.

---
### REDACTED_PASSWORD_PLACEHOLDER-support-REDACTED_PASSWORD_PLACEHOLDER-des

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:3`
- **Risk Score:** 8.5
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash of the support user was discovered, encrypted using traditional DES. A compromised technical support account could lead to system information leakage.
- **Code Snippet:**
  ```
  support:Ead09Ca6IhzZY:0:0:support:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** support, Ead09Ca6IhzZY
- **Notes:** The hash encrypted with DES can be brute-forced in a short time on modern hardware.

---
### REDACTED_PASSWORD_PLACEHOLDER-wps-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/nvram_default.cfg`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** A hardcoded WPS device REDACTED_PASSWORD_PLACEHOLDER has been detected. This REDACTED_PASSWORD_PLACEHOLDER is used for the Wi-Fi Protected Setup functionality and could potentially be exploited for unauthorized network access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to change this REDACTED_PASSWORD_PLACEHOLDER immediately and disable the WPS function (if not needed).

---
### default-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** Hardcoded default administrator credentials detected. Both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER are set to 'user', which may lead to unauthorized access.
- **Code Snippet:**
  ```
  sys.baseREDACTED_PASSWORD_PLACEHOLDER=user
  sys.baseuserpass=user
  ```
- **Keywords:** sys.baseREDACTED_PASSWORD_PLACEHOLDER, sys.baseuserpass
- **Notes:** These are the default credentials for the device and should be changed upon first use.

---
### REDACTED_PASSWORD_PLACEHOLDER-user-REDACTED_PASSWORD_PLACEHOLDER-des

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:4`
- **Risk Score:** 7.5
- **Confidence:** 10.0
- **Description:** Discovered REDACTED_PASSWORD_PLACEHOLDER hashes for regular user accounts using traditional DES encryption. Compromised regular user accounts could serve as entry points for lateral movement.
- **Code Snippet:**
  ```
  user:tGqcT.qjxbEik:0:0:user:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** user, tGqcT.qjxbEik
- **Notes:** DES-encrypted hashes can be brute-forced in a short time on modern hardware

---
### default-wifi-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 9.0
- **Description:** A hardcoded WPA2-PSK wireless network REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' was detected, which may lead to unauthorized access to the wireless network.
- **Code Snippet:**
  ```
  wl2g.ssid0.wpapsk_psk=REDACTED_PASSWORD_PLACEHOLDER
  wl5g.ssid0.wpapsk_psk=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** wl2g.ssid0.wpapsk_psk, wl5g.ssid0.wpapsk_psk
- **Notes:** These are default wireless passwords and should be changed during device setup.

---
### default-ftp-credentials

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Hardcoded FTP service credentials detected, with both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER set to 'REDACTED_PASSWORD_PLACEHOLDER', which may lead to unauthorized access to the FTP service.
- **Code Snippet:**
  ```
  usb.ftp.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.ftp.pwd=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** usb.ftp.user, usb.ftp.pwd
- **Notes:** These are the default credentials for the FTP service. If the FTP service is enabled, these credentials should be changed.

---
### default-samba-credentials

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Hardcoded Samba service credentials detected with both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER set as 'REDACTED_PASSWORD_PLACEHOLDER', which may lead to unauthorized access to file sharing services.
- **Code Snippet:**
  ```
  usb.samba.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.samba.pwd=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** usb.samba.user, usb.samba.pwd
- **Notes:** These are the default credentials for the Samba service. If the Samba service is enabled, these credentials should be changed.

---
