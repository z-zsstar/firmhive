# _DWR-118_V1.01b01.bin.extracted (10 alerts)

---

### hardcoded-ui-passwords

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/pwd_chk.sh`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Hardcoded references to default and current UI passwords were found in the pwd_chk.sh file. The file contains DEF_PASS and UI_PASS variables, potentially exposing system administration passwords.
- **Keywords:** DEF_PASS, UI_PASS, pwd_chk.sh
- **Notes:** Hardcoded passwords in the management interface may lead to complete loss of system control.

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The encrypted REDACTED_PASSWORD_PLACEHOLDER hash of the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER file, using the DES encryption algorithm. This may lead to privilege escalation risks if the hash is cracked.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_PASSWORD_PLACEHOLDER:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/ash
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$
- **Notes:** The DES encryption algorithm is weak; it is recommended to enforce a change of the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER and use a stronger encryption algorithm.

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-zebra-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.conf`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER was found in the zebra.conf configuration file. This REDACTED_PASSWORD_PLACEHOLDER is used for Zebra routing daemon authentication and is stored in plaintext within the configuration file. Any user with access to this file can obtain the REDACTED_PASSWORD_PLACEHOLDER, potentially leading to unauthorized access to routing configurations.
- **Code Snippet:**
  ```
  hostname ZEBRA
  REDACTED_PASSWORD_PLACEHOLDER zebra
  log file /var/zebra.log
  ```
- **Keywords:** zebra.conf, REDACTED_PASSWORD_PLACEHOLDER zebra
- **Notes:** It is recommended to immediately change this REDACTED_PASSWORD_PLACEHOLDER and ensure proper configuration file permissions. Consider replacing plaintext REDACTED_PASSWORD_PLACEHOLDER storage with more secure authentication mechanisms.

---
### hardcoded-zebra-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER.conf:2`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER for the routing daemon was found in the Zebra configuration file, stored in plaintext within the configuration file. Any user with access to this file can obtain the REDACTED_PASSWORD_PLACEHOLDER, potentially leading to unauthorized access to routing configurations.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER zebra
  ```
- **Keywords:** zebra.conf, REDACTED_PASSWORD_PLACEHOLDER zebra
- **Notes:** It is recommended to modify it to encrypted storage or use a more secure authentication mechanism. This REDACTED_PASSWORD_PLACEHOLDER may be used for routing protocol authentication, and leakage could lead to tampering with network configurations.

---
### hardcoded-3g-ppp-credentials

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/3g-ppp-action`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** Hardcoded 3G PPP authentication credentials were found in the 3g-ppp-action file. The file contains the use of CSID_C_3G_REDACTED_PASSWORD_PLACEHOLDER and CSID_C_3G_PASSWORD variables, which may include user authentication information.
- **Keywords:** CSID_C_3G_REDACTED_PASSWORD_PLACEHOLDER, CSID_C_3G_PASSWORD, 3g-ppp-action
- **Notes:** hardcoded_credentials

---
### hardcoded-pptp-vpn-credentials

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/pptp-connect`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Hardcoded credentials for PPTP VPN connection were found in the pptp-connect file. The file directly uses ACCOUNT and REDACTED_PASSWORD_PLACEHOLDER variables for PPTP authentication.
- **Keywords:** ACCOUNT, REDACTED_PASSWORD_PLACEHOLDER, pptp-connect
- **Notes:** Hardcoded credentials may lead to network perimeter breaches

---
### REDACTED_PASSWORD_PLACEHOLDER-PPPoE-rdcsman-read

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/pppoe-action: REDACTED_SECRET_KEY_PLACEHOLDERHIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The script retrieves the PPPoE REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER from the system configuration using the rdcsman command. The REDACTED_PASSWORD_PLACEHOLDER is read from address 0xREDACTED_PASSWORD_PLACEHOLDER, and the REDACTED_PASSWORD_PLACEHOLDER is read from 0xREDACTED_PASSWORD_PLACEHOLDER. These credentials may be stored in the device configuration. Although not directly hardcoded credentials, this demonstrates the REDACTED_PASSWORD_PLACEHOLDER handling logic.
- **Keywords:** rdcsman, 0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER, CSID_C_PPPOE_USER, CSID_C_PPPOE_PASSWORD
- **Notes:** The implementation of the rdcsman command needs to be examined to verify the REDACTED_PASSWORD_PLACEHOLDER storage method. These credentials may be stored in the device's non-volatile memory.

---
### hardcoded-wifi-keys

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/qrwifi`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** Hardcoded storage of Wi-Fi network keys was found in the qrwifi file. The file contains references and operations involving multiple WEP/WPA keys.
- **Keywords:** RF1_WLANAP_KEY0, RF1_WLANAP_KEY1, RF2_WLANAP_KEY0, qrwifi
- **Notes:** hardcoded_wifi_keys

---
### wifi-authentication-config

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/wifi-action`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The wireless authentication mode and REDACTED_PASSWORD_PLACEHOLDER configuration were found in the wifi-action file. The file contains operations for WLAN authentication modes and encryption keys.
- **Keywords:** CSID_C_WLANAPCLI_ApCliAuthMode, CSID_C_WLANAPCLI_WEPKEY0, wifi-action
- **Notes:** wireless_configuration

---
### ui-REDACTED_PASSWORD_PLACEHOLDER-retrieval-mechanism

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/pwd_chk.sh:4-5`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The script retrieves the current UI REDACTED_PASSWORD_PLACEHOLDER and default UI REDACTED_PASSWORD_PLACEHOLDER from system configuration using the rdcsman command with specific parameters (0xREDACTED_PASSWORD_PLACEHOLDER and 0x0001003e). Although the passwords are not directly hardcoded, this parameterized retrieval method could potentially be exploited through reverse engineering.
- **Code Snippet:**
  ```
  UI_PASS=\`rdcsman 0xREDACTED_PASSWORD_PLACEHOLDER str\`
  DEF_PASS=\`rdcsman 0x0001003e str\`
  ```
- **Keywords:** UI_PASS, DEF_PASS, rdcsman, 0xREDACTED_PASSWORD_PLACEHOLDER, 0x0001003e
- **Notes:** Analyze the implementation and parameter meanings of the rdcsman command, and check whether other parts of the system use the same parameters to store sensitive information.

---
