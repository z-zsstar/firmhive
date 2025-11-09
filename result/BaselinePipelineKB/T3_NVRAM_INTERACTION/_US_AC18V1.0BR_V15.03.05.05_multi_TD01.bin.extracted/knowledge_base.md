# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (10 alerts)

---

### wireless_repeat_config

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xa2af4 sym.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The function sym.REDACTED_PASSWORD_PLACEHOLDER extensively uses bcm_nvram_set/bcm_nvram_get to manipulate wireless relay configurations, including parameters such as 'wl0.1_ssid'. These operations lack integrity checks and could potentially be exploited for man-in-the-middle attacks.
- **Keywords:** bcm_nvram_set, bcm_nvram_get, wl0.1_ssid, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Verify the security boundaries of wireless configuration

---
### bcm_nvram_get-fcn.0003ca5c

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x3cbf4 fcn.0003ca5c`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function fcn.0003ca5c calls bcm_nvram_get to retrieve NVRAM variables, where the variable names are constructed through formatted strings, posing a potential formatted string vulnerability risk. The retrieved values are subsequently used for system command execution, which may lead to command injection.
- **Keywords:** bcm_nvram_get, doSystemCmd, sprintf
- **Notes:** Verify whether the formatted string is user-controlled

---
### envram_get_value-fcn.00067a0c

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x67a30 fcn.00067a0c`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** The function fcn.00067a0c retrieves environment variable values using envram_get_value but fails to verify the return value length, potentially leading to buffer overflow.
- **Keywords:** envram_get_value, fcn.00067a0c
- **Notes:** env_get

---
### envram_set_value-fcn.00067ae8

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x67b24 fcn.00067ae8`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** The function fcn.00067ae8 uses envram_set_value to set environment variables, but first logs the operation via printf, introducing a potential format string vulnerability.
- **Keywords:** envram_set_value, printf, fcn.00067ae8
- **Notes:** Need to verify if the parameters of printf are user-controlled

---
### bcm_nvram_get-wifi_power

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x69bc0 sym.REDACTED_SECRET_KEY_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In the function sym.REDACTED_SECRET_KEY_PLACEHOLDER, WiFi power settings such as 'wl0_country' are obtained through bcm_nvram_get and used for critical configurations. The lack of input validation may lead to illegal power settings.
- **Keywords:** bcm_nvram_get, wl0_country, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** Verify the power value range check

---
### libnvram-core-functions

- **File/Directory Path:** `N/A`
- **Location:** `lib/libnvram.so`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The core NVRAM operation functions, including nvram_get, nvram_set, nvram_unset, and nvram_commit, were discovered in libnvram.so. These functions operate through the /dev/nvram device.
- **Keywords:** nvram_get, nvram_set, nvram_unset, nvram_commit, /dev/nvram
- **Notes:** These are basic NVRAM operation functions, and the upper-level code calling these functions needs to be checked.

---
### nvram-set-0x87c8

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x87c8 fcn.000086fc`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The nvram_set function is called at address 0x87c8 to set NVRAM variables. This operation involves string copying (strncpy) and separation (strsep) operations, potentially used for configuring multiple parameters. The lack of strict input validation may lead to command injection or buffer overflow vulnerabilities.
- **Keywords:** nvram_set, 0x87c8, strncpy, strsep
- **Notes:** nvram_set

---
### bcm_nvram_set-pptp_client

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xb977c sym.REDACTED_SECRET_KEY_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The function sym.REDACTED_SECRET_KEY_PLACEHOLDER configures PPTP client settings via bcm_nvram_set, including parameters such as 'pptp_client_enable'. These configurations could potentially be used to establish unauthorized VPN connections.
- **Keywords:** bcm_nvram_set, pptp_client_enable, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** Check the authentication mechanism of the VPN connection

---
### bcm_nvram_set-wifi_config

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x67078 sym.form_fast_setting_wifi_set`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The function sym.form_fast_setting_wifi_set makes multiple calls to bcm_nvram_set to configure WiFi-related settings, including sensitive parameters such as 'wl0_country_code'. These values are written directly to NVRAM without validation, potentially allowing configurations to be tampered with.
- **Keywords:** bcm_nvram_set, wl0_country_code, form_fast_setting_wifi_set
- **Notes:** Check if there is sufficient permission control

---
### bcm_nvram_set-pptpd

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xb6f3c sym.REDACTED_SECRET_KEY_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The function sym.REDACTED_SECRET_KEY_PLACEHOLDER configures PPTP server settings, including parameters such as 'pptpd_enable', via bcm_nvram_set. These configurations could potentially be used to enable unauthorized VPN services.
- **Keywords:** bcm_nvram_set, pptpd_enable, REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** Check if there is an authentication mechanism protecting these settings.

---
