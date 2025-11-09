# TL-MR3020_V1_150921 (2 alerts)

---

### env-MODULE_PATH-rc.wlan

- **File/Directory Path:** `etc/rc.d/rc.wlan`
- **Location:** `./etc/rc.d/rc.wlan:80-91`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** env_get

Control module loading path. Malicious values may lead to arbitrary code execution. The variable is used to construct kernel module loading parameters (insmod command). Although the script checks for null values, there is no explicit input sanitization before using the values for module parameters.
- **Code Snippet:**
  ```
  MODULE_PATHHIDDENinsmodHIDDEN
  ```
- **Keywords:** insmod, MODULE_PATH
- **Notes:** Further verification is required to determine whether these environment variables are set through NVRAM or other configuration systems.

---
### env-ATH_countrycode-rc.wlan

- **File/Directory Path:** `etc/rc.d/rc.wlan`
- **Location:** `./etc/rc.d/rc.wlan:60-61`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** env_get

Regulations govern radio frequency control. Invalid values may violate these regulations. Variables are used to construct kernel module loading parameters (insmod command). While the script checks for null values, there is no explicit input sanitization before using the values as module parameters.
- **Code Snippet:**
  ```
  ATH_countrycodeHIDDENPCI_ARGSHIDDENath_pci.koHIDDEN
  ```
- **Keywords:** PCI_ARGS, ath_pci.ko
- **Notes:** Further verification is required to determine whether these environment variables are set via NVRAM or other configuration systems.

---
