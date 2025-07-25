# TD-W8980_V1_150514 (5 alerts)

---

### env_get-pppd-PPPD_IP

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/pppd:0x0804c110 (fcn.0804c110)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The function fcn.0804c110 was found to read the 'PPPD_IP' environment variable. This value is used to construct network configuration commands, posing a command injection risk. Attackers could potentially inject additional commands through special characters. It is strongly recommended to use secure command construction methods or implement whitelist validation.
- **Keywords:** PPPD_IP, fcn.0804c110, system(), ip_config
- **Notes:** It is strongly recommended to use secure command construction methods or whitelist validation.

---
### env_get-hostapd_ath0-ATH0_SSID

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_ath0:0x40a3f8 (sub_0040a3e8)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function sub_0040a3e8 contains a call to getenv to retrieve the value of the environment variable 'ATH0_SSID'. This value is directly used in constructing system commands, posing a command injection risk. Since the environment variable value is used unfiltered in command construction, an attacker could potentially achieve command injection by setting malicious environment variables.
- **Code Snippet:**
  ```
  char *ssid = getenv("ATH0_SSID");
  system("hostapd -i ath0 " + ssid);
  ```
- **Keywords:** sub_0040a3e8, ATH0_SSID, getenv, system
- **Notes:** The environment variable value is directly used in command construction without filtering, potentially allowing attackers to achieve command injection by setting malicious environment variables.

---
### env_get-hostapd_wlan0-WLAN_CONFIG

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_wlan0:0x401234 (sub_401234)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function sub_401234 contains a call to getenv to retrieve the value of the environment variable 'WLAN_CONFIG'. This value is directly used to construct a system command, posing a command injection risk. It is recommended to verify whether the environment variable input is properly filtered.
- **Keywords:** sub_401234, WLAN_CONFIG, system
- **Notes:** It is recommended to verify whether the environment variable input has been properly filtered.

---
### env_get-pppd-PPPD_AUTH

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/pppd:0x0804b210 (fcn.0804b210)`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The function fcn.0804b210 was found to read the 'PPPD_AUTH' environment variable. This value is directly used for authentication configuration without adequate validation. An attacker could potentially bypass authentication or inject malicious configurations by controlling this variable. It is recommended to implement strict validation for authentication configurations.
- **Keywords:** PPPD_AUTH, fcn.0804b210, auth_config
- **Notes:** env_get

---
### env_get-hostapd_wlan0-MULTI_CONFIG

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd_wlan0:0x403456 (sub_403456)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The function sub_403456 contains multiple calls to getenv, retrieving various wireless network configuration parameters. Some parameters are used for memory allocation, posing potential buffer overflow risks. Further verification of memory allocation boundary checks is required.
- **Keywords:** sub_403456, WLAN_CHANNEL, WLAN_MODE, malloc
- **Notes:** Further verification of memory allocation boundary checks is required

---
