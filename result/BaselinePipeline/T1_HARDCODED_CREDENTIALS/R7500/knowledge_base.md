# R7500 (7 alerts)

---

### hardcoded-rsa-REDACTED_PASSWORD_PLACEHOLDER-client_key.pem

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_key.pem`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_key.pem`
- **Risk Score:** 10.0
- **Confidence:** 9.0
- **Description:** In the file REDACTED_PASSWORD_PLACEHOLDER_key.pem, a hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was discovered, which constitutes highly sensitive information that could lead to unauthorized system access or man-in-the-middle attacks. The private REDACTED_PASSWORD_PLACEHOLDER is stored unencrypted, allowing any user with access to the file to utilize it.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----...
  ```
- **Keywords:** client_key.pem, BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to immediately revoke and replace this private REDACTED_PASSWORD_PLACEHOLDER, and restrict access to the directory containing the private REDACTED_PASSWORD_PLACEHOLDER file.

---
### hardcoded-rsa-REDACTED_PASSWORD_PLACEHOLDER-uhttpd.REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** A hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was found in the etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER file, which constitutes a critical security vulnerability. This private REDACTED_PASSWORD_PLACEHOLDER may be used for SSL/TLS encrypted communication by the uhttpd web server. If attackers obtain this private REDACTED_PASSWORD_PLACEHOLDER, they could perform man-in-the-middle attacks or decrypt encrypted traffic.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  -----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  ```
- **Keywords:** uhttpd.REDACTED_PASSWORD_PLACEHOLDER, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to immediately replace this private REDACTED_PASSWORD_PLACEHOLDER and ensure that newly generated private keys are not hardcoded in the firmware. Consider using a REDACTED_PASSWORD_PLACEHOLDER management system or generating a unique REDACTED_PASSWORD_PLACEHOLDER during the device's first boot.

---
### smtp-credentials-email_log

- **File/Directory Path:** `etc/email/email_log`
- **Location:** `etc/email/email_log`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** SMTP authentication credentials were found in the /etc/email/email_log script, which retrieves email_REDACTED_PASSWORD_PLACEHOLDER and email_password from nvram for email sending authentication.
- **Keywords:** email_REDACTED_PASSWORD_PLACEHOLDER, email_password, AuthPass, smtp
- **Notes:** need to verify if these credentials are hardcoded in NVRAM

---
### pppoe-credentials-6pppoe

- **File/Directory Path:** `.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER:180-192`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** In the etc/net6conf/6pppoe script, PPPoE REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER configurations were found, obtaining ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER and ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER from the system configuration.
- **Code Snippet:**
  ```
  local user=\`$CONFIG get ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER\`
  local REDACTED_PASSWORD_PLACEHOLDER=\`$CONFIG get ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER\`
  ...
  echo "${user} * \"${REDACTED_PASSWORD_PLACEHOLDER}\"" > $IPV6_PPPS
  ```
- **Keywords:** ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER, ipv6_pppoe_REDACTED_PASSWORD_PLACEHOLDER, PPP_SCT, IPV6_PPPS, $CONFIG get
- **Notes:** It is recommended to check the configuration file pointed to by $CONFIG to confirm whether hardcoded credentials exist. It is also advisable to examine the contents of the IPV6_PPPS file.

---
### encrypted-keys-wopr.yaml

- **File/Directory Path:** `etc/appflow/wopr.yaml`
- **Location:** `etc/appflow/wopr.yaml`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** Multiple suspected encryption REDACTED_PASSWORD_PLACEHOLDER strings were found in the etc/appflow/wopr.yaml file, which may be used for network communication encryption. The file contains numerous REDACTED_PASSWORD_PLACEHOLDER fields in hexadecimal format, potentially containing sensitive information.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, wopr.yaml, REDACTED_PASSWORD_REDACTED_SECRET_KEY_PLACEHOLDER, b05624cf
- **Notes:** Further analysis is required to determine the specific purposes and decoding methods of these keys.

---
### private-REDACTED_PASSWORD_PLACEHOLDER-config-openssl

- **File/Directory Path:** `etc/easy-rsa/openssl-1.0.0.cnf`
- **Location:** `etc/easy-rsa/openssl-1.0.0.cnf`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Sensitive information including private REDACTED_PASSWORD_PLACEHOLDER paths and REDACTED_PASSWORD_PLACEHOLDER comments was found in etc/easy-rsa/openssl-1.0.0.cnf.
- **Keywords:** private_key, cakey.pem, input_password, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Need to check the actual private REDACTED_PASSWORD_PLACEHOLDER file content

---
### openvpn-REDACTED_PASSWORD_PLACEHOLDER-references

- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `etc/init.d/openvpn`
- **Risk Score:** 7.0
- **Confidence:** 5.5
- **Description:** References to /tmp/openvpn/server.REDACTED_PASSWORD_PLACEHOLDER and /tmp/openvpn/client.REDACTED_PASSWORD_PLACEHOLDER were found in the etc/init.d/openvpn script, but the existence of these files could not be directly verified.
- **Keywords:** server.REDACTED_PASSWORD_PLACEHOLDER, client.REDACTED_PASSWORD_PLACEHOLDER, OPENVPN_CONF_DIR
- **Notes:** Further verification is required to determine whether these REDACTED_PASSWORD_PLACEHOLDER files are generated during runtime or extracted from elsewhere.

---
