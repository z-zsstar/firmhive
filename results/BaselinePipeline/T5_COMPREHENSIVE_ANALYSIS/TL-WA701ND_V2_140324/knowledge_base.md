# TL-WA701ND_V2_140324 (7 alerts)

---

### authentication-weak-hashes-default-creds

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1-13`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** Multiple accounts with REDACTED_PASSWORD_PLACEHOLDER-equivalent privileges (REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER) utilized the same weak MD5 REDACTED_PASSWORD_PLACEHOLDER hash (prefixed with $1$), making them vulnerable to rainbow table attacks. Additionally, service accounts such as 'ap71' were configured without REDACTED_PASSWORD_PLACEHOLDER protection yet possessed REDACTED_PASSWORD_PLACEHOLDER privileges, creating a direct path for privilege escalation. The combination of weak hashing algorithms and default credentials significantly lowered the barrier for unauthorized access.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, ap71, $1$, ::
- **Notes:** authentication

---
### init-scripts-insecure-permissions

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The text is "configuration".
- **Keywords:** rcS, rc.modules, /usr/bin/httpd
- **Notes:** configuration

---
### lld2d-protocol-vulnerabilities

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/lld2d`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** The lld2d binary exhibits multiple protocol handling vulnerabilities, including insufficient input validation, sequence number verification flaws, and broadcast packet filtering weaknesses. These could lead to denial of service, replay attacks, or potential code execution via crafted network packets.
- **Keywords:** packetio_recv_handler, g_opcode, jumptable
- **Notes:** network

---
### network-hostapd-wps-radius-vulns

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The hostapd binary contains multiple vulnerabilities in its WPS and RADIUS implementations. WPS functionality is susceptible to brute-force attacks, while RADIUS message parsing lacks proper input validation, potentially leading to buffer overflows. The UPnP integration also exposes network configuration functionality to untrusted networks.
- **Keywords:** wps_config_create_beacon_ie, radius_msg_parse, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Disabling WPS and UPnP if not needed, and implementing strict input validation for RADIUS messages, would mitigate these risks.

---
### wifi-config-insecure-settings

- **File/Directory Path:** `N/A`
- **Location:** `etc/ath/wsc_config.txt`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** configuration
- **Keywords:** KEY_MGMT, NW_KEY, UUID
- **Notes:** configuration

---
### web-interface-csrf-info-leak

- **File/Directory Path:** `N/A`
- **Location:** `web/userRpm/*.htm`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The web management interface contains multiple HTML and JavaScript files that may be vulnerable to CSRF, XSS, and information leakage. Forms using GET methods expose sensitive data in URLs, and client-side validation can be bypassed. The interface also lacks CSRF protection, making it susceptible to cross-site request forgery attacks.
- **Keywords:** SnmpRpm.htm, get_community, doSubmit
- **Notes:** web

---
### model-conf-decryption-vulns

- **File/Directory Path:** `N/A`
- **Location:** `web/oem/model.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The model.conf file processing involves decryption routines with potential cryptographic weaknesses (file_md5_des) and creates world-readable temporary files. The configuration parsing uses vulnerable sscanf patterns that could lead to buffer overflows.
- **Keywords:** file_md5_des, _tmp_dec_model.conf, sscanf
- **Notes:** Improving encryption implementation and input validation will address these issues.

---
