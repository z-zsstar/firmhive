# R9000 (9 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-uhttpd-rsa-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was found in the etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER file. This private REDACTED_PASSWORD_PLACEHOLDER is used for SSL/TLS encrypted communication by the uHTTPd web server. If this private REDACTED_PASSWORD_PLACEHOLDER is compromised, attackers could perform man-in-the-middle attacks or decrypt encrypted communications. It is recommended to immediately replace this private REDACTED_PASSWORD_PLACEHOLDER and regenerate the certificate. Check whether other services are using the same REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  ...
  ```
- **Keywords:** uhttpd.REDACTED_PASSWORD_PLACEHOLDER, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: RSA private REDACTED_PASSWORD_PLACEHOLDER. It is recommended to further inspect other configuration files in the etc directory, such as dhcp6cctlkey, uhttpd.crt, etc.

---
### hardcoded-crypto-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `lib/wifi/hostapd.sh`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Detected a hardcoded cryptographic REDACTED_PASSWORD_PLACEHOLDER parameter kh_key_hex with default value 'REDACTED_PASSWORD_PLACEHOLDER'. Such hardcoded keys compromise system security.
- **Keywords:** kh_key_hex, REDACTED_PASSWORD_PLACEHOLDER, r0kh, r1kh
- **Notes:** It is recommended to check all instances where kh_key_hex is used and replace them with randomly generated values.

---
### wifi-auth-config

- **File/Directory Path:** `N/A`
- **Location:** `lib/wifi/wpa_supplicant.sh`
- **Risk Score:** 8.5
- **Confidence:** 7.9
- **Description:** The configuration of multiple authentication methods includes WEP, WPA-PSK, and WPA-EAP. It handles private REDACTED_PASSWORD_PLACEHOLDER passwords and EAP authentication passwords, which may be hardcoded in the configuration.
- **Keywords:** priv_key_pwd, REDACTED_PASSWORD_PLACEHOLDER, key_mgmt, wep_key0, wep_tx_keyidx, auth_alg
- **Notes:** Pay special attention to the sources of the private_key_REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER variables

---
### wifi-psk-config

- **File/Directory Path:** `N/A`
- **Location:** `lib/wifi/hostapd.sh`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Wi-Fi Protected Access (WPA/WPA2) pre-shared REDACTED_PASSWORD_PLACEHOLDER (PSK) configuration obtains the Wi-Fi REDACTED_PASSWORD_PLACEHOLDER through config_get and uses it for WPA authentication. The REDACTED_PASSWORD_PLACEHOLDER processing logic includes WEP REDACTED_PASSWORD_PLACEHOLDER index and length configuration.
- **Keywords:** psk, REDACTED_PASSWORD_PLACEHOLDER, wpa_key_mgmt, auth_secret, wep_key_len_broadcast, wep_key_len_unicast
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER may come from the configuration file, and the configuration source needs to be checked.

---
### analysis-limitation-usr-bin

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** Due to security restrictions, a comprehensive scan for hardcoded credentials in the /usr/bin directory cannot be performed in the current environment. Recommended alternatives: 1) Re-analyze in an unrestricted environment 2) Manually inspect critical binaries 3) Perform offline analysis using static analysis tools.
- **Keywords:** usr/bin, hardcoded credentials, sensitive information
- **Notes:** Critical binary files such as transmission-daemon and openssl are common locations for storing sensitive information and should be prioritized for inspection.

---
### wifi-psk-update

- **File/Directory Path:** `N/A`
- **Location:** `lib/wifi/wps-hostapd-update-uci`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Directly manipulating UCI configuration to set WiFi PSK keys indicates that the system may modify wireless network keys under certain circumstances.
- **Keywords:** uci set wireless, REDACTED_PASSWORD_PLACEHOLDER, psk, wpa_key_mgmt
- **Notes:** Verify the source and generation method of the psk variable.

---
### REDACTED_PASSWORD_PLACEHOLDER-encoded-dhcp6-control-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/dhcp6cctlkey`
- **Risk Score:** 7.5
- **Confidence:** 4.0
- **Description:** A Base64-encoded string was found in the dhcp6 control REDACTED_PASSWORD_PLACEHOLDER file, suspected to be a hardcoded REDACTED_PASSWORD_PLACEHOLDER or encryption REDACTED_PASSWORD_PLACEHOLDER. This may be a control REDACTED_PASSWORD_PLACEHOLDER used for DHCPv6 configuration. Manual decoding of the Base64 value is required to determine its actual content and purpose. The presence of hardcoded credentials in configuration files poses a security risk.
- **Keywords:** dhcp6cctlkey, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Base64 encoded value: 'REDACTED_PASSWORD_PLACEHOLDER'. Manual decoding is required to determine the actual content. REDACTED_PASSWORD_PLACEHOLDER type: DHCPv6 control REDACTED_PASSWORD_PLACEHOLDER.

---
### pppoe-REDACTED_PASSWORD_PLACEHOLDER-handling

- **File/Directory Path:** `N/A`
- **Location:** `lib/network/ppp.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The PPPoE REDACTED_PASSWORD_PLACEHOLDER configuration logic retrieves the WAN port PPPoE REDACTED_PASSWORD_PLACEHOLDER from the configuration and writes it to the /etc/ppp/ipv4-secrets file. The REDACTED_PASSWORD_PLACEHOLDER undergoes escaping before being written, but the configuration retrieval method may pose a hardcoding risk.
- **Keywords:** wan_pppoe_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, IPV4_PPPS, /etc/ppp/ipv4-secrets
- **Notes:** The specific implementation of $CONFIG needs to be verified to evaluate REDACTED_PASSWORD_PLACEHOLDER storage security

---
### REDACTED_PASSWORD_PLACEHOLDER-encoded-dhcp6s-control-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/dhcp6sctlkey:1`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A Base64-encoded string was found in the dhcp6sctlkey file, suspected to be a hardcoded REDACTED_PASSWORD_PLACEHOLDER or REDACTED_PASSWORD_PLACEHOLDER. The string is 24 characters long and may be a DHCPv6 control REDACTED_PASSWORD_PLACEHOLDER or other authentication REDACTED_PASSWORD_PLACEHOLDER. Due to environmental restrictions, direct decoding is not possible. Further analysis in a secure environment is recommended.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** dhcp6sctlkey, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Verification required: 1) REDACTED_PASSWORD_PLACEHOLDER usage 2) Environment consistency 3) Decoding feasibility. REDACTED_PASSWORD_PLACEHOLDER type: Suspected DHCPv6 service control REDACTED_PASSWORD_PLACEHOLDER.

---
