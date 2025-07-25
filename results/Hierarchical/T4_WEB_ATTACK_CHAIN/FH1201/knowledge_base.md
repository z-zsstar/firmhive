# FH1201 (2 alerts)

---

### httpd-QuickIndex-REDACTED_SECRET_KEY_PLACEHOLDER

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd:0x0044f270 sym.formQuickIndex`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the httpd program, a function sym.formQuickIndex (0x0044f270) was discovered that handles the 'goform/QuickIndex' request. This function processes multiple sensitive parameters, including the PPPOE REDACTED_PASSWORD_PLACEHOLDER (str.PPPOEName), REDACTED_PASSWORD_PLACEHOLDER (str.PPPOEPassword), and wireless REDACTED_PASSWORD_PLACEHOLDER (str.mit_wrlpwd). The main findings are as follows:
1. The PPPOE REDACTED_PASSWORD_PLACEHOLDER is stored in a 256-byte stack buffer (auStack_10c), posing a potential buffer overflow risk.
2. The wireless REDACTED_PASSWORD_PLACEHOLDER is directly used for configuring wireless security settings without apparent security measures.
3. The security of the REDACTED_PASSWORD_PLACEHOLDER handling function (address iVar7 + -0x7cd0) is unknown.

Although no direct calls to dangerous functions like system() were found, the handling methods of these sensitive parameters present security risks.
- **Code Snippet:**
  ```
  (**(iVar7 + -0x7cd0))(uVar2,auStack_10c);
  (**(iVar7 + -0x7e14))(*(iVar7 + -0x7fd8) + -0x3db8,auStack_10c);
  ```
- **Keywords:** sym.formQuickIndex, str.PPPOEName, str.PPPOEPassword, str.mit_wrlpwd, auStack_10c, 0x0044f270
- **Notes:** It is recommended to further analyze:
1. The specific implementation of the PPPoE REDACTED_PASSWORD_PLACEHOLDER processing function (address iVar7 + -0x7cd0)
2. The verification mechanism for the source of wireless passwords
3. The boundary checks for the usage of stack buffer auStack_10c

---
### httpd-QuickIndex-REDACTED_SECRET_KEY_PLACEHOLDER

- **File/Directory Path:** `bin/ses`
- **Location:** `httpd:0x0044f270 sym.formQuickIndex`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the httpd program, a function sym.formQuickIndex (0x0044f270) was discovered that handles the 'goform/QuickIndex' request. This function processes multiple sensitive parameters, including the PPPOE REDACTED_PASSWORD_PLACEHOLDER (str.PPPOEName), REDACTED_PASSWORD_PLACEHOLDER (str.PPPOEPassword), and wireless REDACTED_PASSWORD_PLACEHOLDER (str.mit_wrlpwd). The main findings are as follows:
1. The PPPOE REDACTED_PASSWORD_PLACEHOLDER is stored in a 256-byte stack buffer (auStack_10c), posing a potential buffer overflow risk.
2. The wireless REDACTED_PASSWORD_PLACEHOLDER is directly used for configuring wireless security settings without apparent security measures.
3. The security of the REDACTED_PASSWORD_PLACEHOLDER processing function (address iVar7 + -0x7cd0) is unknown.

Although no direct calls to dangerous functions like system() were found, the handling methods of these sensitive parameters present security risks.
- **Code Snippet:**
  ```
  (**(iVar7 + -0x7cd0))(uVar2,auStack_10c);
  (**(iVar7 + -0x7e14))(*(iVar7 + -0x7fd8) + -0x3db8,auStack_10c);
  ```
- **Keywords:** sym.formQuickIndex, str.PPPOEName, str.PPPOEPassword, str.mit_wrlpwd, auStack_10c, 0x0044f270
- **Notes:** It is recommended to further analyze:
1. The specific implementation of the PPPOE REDACTED_PASSWORD_PLACEHOLDER processing function (address iVar7 + -0x7cd0)
2. The verification mechanism for the source of wireless passwords
3. The boundary checks for the usage of stack buffer auStack_10c

---
