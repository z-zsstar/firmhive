# _DWR-118_V1.01b01.bin.extracted (4 alerts)

---

### wifi-action-WPAPSK

- **File/Directory Path:** `usr/bin/wifi-action`
- **Location:** `usr/bin/wifi-action:HIDDEN(HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Read WPA PSK (CSID_C_WLANAPCLI_WPAPSK) and use it directly to set iwpriv parameters. The PSK is stored and transmitted in plaintext, posing a risk of leakage.
- **Keywords:** rdcsman, CSID_C_WLANAPCLI_WPAPSK, DWPAPSK, IWPRIV
- **Notes:** WPA PSK is processed in plaintext, posing a serious security risk

---
### pppoe-action-MULTIWAN

- **File/Directory Path:** `usr/bin/pppoe-action`
- **Location:** `usr/bin/pppoe-action: multiple locations`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The environment variable $MULTIWAN is widely used for multi-WAN configuration control. This variable is directly utilized in command construction (such as pppoe-stop, pppoe-start, etc.), posing a risk of command injection.
- **Keywords:** MULTIWAN, pppoe-stop, pppoe-start
- **Notes:** The variable is passed directly to multiple commands, and it is necessary to verify whether it has been properly filtered.

---
### wifi-action-WEPKEY

- **File/Directory Path:** `usr/bin/wifi-action`
- **Location:** `usr/bin/wifi-action:HIDDEN(HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Reading WEP keys (CSID_C_WLANAPCLI_WEPKEY[0-3]) and directly using them to configure iwpriv parameters. The keys are stored and transmitted in plaintext, posing a risk of leakage.
- **Keywords:** rdcsman, CSID_C_WLANAPCLI_WEPKEY0, CSID_C_WLANAPCLI_WEPKEY1, CSID_C_WLANAPCLI_WEPKEY2, CSID_C_WLANAPCLI_WEPKEY3, REDACTED_PASSWORD_PLACEHOLDER, IWPRIV
- **Notes:** WEP keys are processed in plaintext, posing a security risk

---
### udhcpc-action-HOSTNAME

- **File/Directory Path:** `usr/bin/udhcpc-action`
- **Location:** `usr/bin/udhcpc-action: multiple locations`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The HOSTNAME variable is directly used to construct the --hostname parameter for udhcpc, posing a potential shell injection risk.
- **Keywords:** HOSTNAME, --hostname, $HOSTNAME
- **Notes:** The HOSTNAME comes from the rdcsman call, and its input filtering needs to be verified.

---
