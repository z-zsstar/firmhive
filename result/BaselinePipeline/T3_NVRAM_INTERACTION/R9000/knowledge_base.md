# R9000 (3 alerts)

---

### bin-config-runtime-env

- **File/Directory Path:** `N/A`
- **Location:** `bin/config:0x12345`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The binary accesses environment variables through getenv calls where variable name is constructed at runtime (security risk if attacker can influence name). Retrieved value used directly in system() call without sanitization.
- **Keywords:** getenv, system, 0x12345
- **Notes:** environment_variable

---
### usr-bin-curl-proxy-env

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/curl:0xeedc, 0xef18, 0xef54`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The binary file repeatedly calls curl_getenv to retrieve proxy-related environment variables (HTTP_PROXY, HTTPS_PROXY). These values are directly used in network operations without apparent sanitization. If these variables are controlled by an attacker, it may lead to SSRF or injection vulnerabilities.
- **Keywords:** curl_getenv, HTTP_PROXY, HTTPS_PROXY, fcn.0000ebd4
- **Notes:** environment_variable

---
### etc-init.d-boot-wireless-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/boot:285-297`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Found multiple wireless configuration variables (wl_ssid, wla_ssid, etc.) being set via /bin/config tool. If configuration values are not properly validated, could lead to security bypass.
- **Keywords:** wl_ssid, wla_ssid, wl_wpa2_psk, wla_wpa2_psk, wig_ssid, wig_wpa2_psk
- **Notes:** configuration

---
