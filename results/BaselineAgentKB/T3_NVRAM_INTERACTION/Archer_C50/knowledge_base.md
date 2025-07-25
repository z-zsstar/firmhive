# Archer_C50 (2 alerts)

---

### cwmp-nvram_access-1

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cwmp:0xREDACTED_PASSWORD_PLACEHOLDER (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The TR-069 client accesses device management credentials (REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER) via nvram_get, and these values are directly used for authenticated communication with the ACS server. If these credentials are tampered with, it may result in the device being illegally controlled.
- **Code Snippet:**
  ```
  char *REDACTED_PASSWORD_PLACEHOLDER = nvram_get("acs_REDACTED_PASSWORD_PLACEHOLDER");
  char *REDACTED_PASSWORD_PLACEHOLDER = nvram_get("acs_password");
  build_auth_header(REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER);
  ```
- **Keywords:** acs_REDACTED_PASSWORD_PLACEHOLDER, acs_password, nvram_get, tr069_auth
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER authentication information should be stored encrypted

---
### upnpd-nvram_access-1

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/upnpd:0x0040a210 (fcn.0040a210)`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** The UPnP service accesses port mapping configurations via nvram_get, and these values are directly used to set UPnP port forwarding rules. If these configurations are tampered with, it may result in unauthorized port openings.
- **Code Snippet:**
  ```
  char *port = nvram_get("upnp_port");
  char *enabled = nvram_get("upnp_enable");
  setup_port_mapping(port, enabled);
  ```
- **Keywords:** upnp_port, upnp_enable, nvram_get, port_mapping
- **Notes:** Potential risk of port abuse

---
