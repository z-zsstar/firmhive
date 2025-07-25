# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (5 alerts)

---

### httpd-system-cmd-injection

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x000927c4 (sym.REDACTED_SECRET_KEY_PLACEHOLDER)`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** In the REDACTED_SECRET_KEY_PLACEHOLDER function, the system command is executed via doSystemCmd, with part of the command parameters originating from user input. Insufficient filtering may lead to command injection vulnerabilities. Attackers could craft special parameters to inject malicious commands.
- **Code Snippet:**
  ```
  sym.imp.doSystemCmd(iVar5 + *0x9214c,3,uVar1);
  sym.imp.doSystemCmd(iVar5 + *0x92150,7);
  ```
- **Keywords:** doSystemCmd, REDACTED_SECRET_KEY_PLACEHOLDER, system, command_injection
- **Notes:** Analyze the implementation of the doSystemCmd function to confirm the filtering status.

---
### httpd-wifi-config-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER (sym.REDACTED_SECRET_KEY_PLACEHOLDER)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** In the REDACTED_SECRET_KEY_PLACEHOLDER function, the use of strcpy to directly copy user-provided WiFi configuration parameters (SSID/REDACTED_PASSWORD_PLACEHOLDER) into a stack buffer without length checking may lead to buffer overflow. An attacker could trigger a stack overflow by sending an excessively long SSID or REDACTED_PASSWORD_PLACEHOLDER, potentially enabling remote code execution.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar6 + iVar3 + -0x274,*(puVar6 + -0x24));
  sym.imp.strcpy(puVar6 + iVar3 + -0x174,*(puVar6 + -0x14));
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, strcpy, wifi_ssid, wifi_password
- **Notes:** need to verify the relationship between buffer size and actual copy length

---
### httpd-reboot-timer-sprintf

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x000b1054 (sym.REDACTED_SECRET_KEY_PLACEHOLDER)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In the REDACTED_SECRET_KEY_PLACEHOLDER function, the sprintf function is used to format user-provided time parameters without checking the output buffer size, which may lead to buffer overflow. Attackers can exploit this vulnerability by crafting specially designed time parameters.
- **Code Snippet:**
  ```
  sym.imp.sprintf(puVar6 + iVar3 + -0x40,iVar5 + *0xb1054,
                  ((0x6667 | 0xREDACTED_PASSWORD_PLACEHOLDER) * iVar2 >> 0x22) - (iVar2 >> 0x1f),
                  iVar4 + (((0x6667 | 0xREDACTED_PASSWORD_PLACEHOLDER) * iVar4 >> 0x22) - (iVar4 >> 0x1f)) * -10);
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, sprintf, reboot_timer, buffer_overflow
- **Notes:** need to confirm whether the formatted string is user-controllable

---
### httpd-sprintf-format-string

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER (sym.REDACTED_SECRET_KEY_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** In the function REDACTED_SECRET_KEY_PLACEHOLDER, sprintf is used to format a string at the end without checking the output buffer size, which may lead to buffer overflow or format string vulnerabilities.
- **Code Snippet:**
  ```
  sym.imp.sprintf(puVar6 + 8 + -0x974,iVar5 + *0x92164,*(puVar6 + -8));
  ```
- **Keywords:** sprintf, REDACTED_SECRET_KEY_PLACEHOLDER, format_string
- **Notes:** need to confirm whether the format string is user-controllable

---
### httpd-reboot-timer-int-overflow

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x000b104c (sym.REDACTED_SECRET_KEY_PLACEHOLDER)`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** In the REDACTED_SECRET_KEY_PLACEHOLDER function, there exists a potential integer overflow risk in the time parameter calculation. Attackers could trigger unexpected behaviors by providing specially crafted time values.
- **Code Snippet:**
  ```
  *(puVar6 + -0x2c) = *(puVar6 + -0x2c) + 2;
  iVar2 = *(puVar6 + -0x2c);
  *(puVar6 + -0x2c) = iVar2 + (((0xaaab | 0x2aaa0000) * iVar2 >> 0x22) - (iVar2 >> 0x1f)) * -0x18;
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, integer_overflow, time_calculation
- **Notes:** Need to verify the calculation logic

---
