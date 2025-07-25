# TL-WR1043ND_V3_150514 (8 alerts)

---

### telnetd-REDACTED_PASSWORD_PLACEHOLDER-password_leak

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER:0x4073b8`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The function 'sym.getpass_or_cancel' retrieves the REDACTED_PASSWORD_PLACEHOLDER by calling getenv("REDACTED_PASSWORD_PLACEHOLDER"). Storing passwords in environment variables is high-risk behavior that may lead to REDACTED_PASSWORD_PLACEHOLDER leakage.
- **Keywords:** sym.getpass_or_cancel, REDACTED_PASSWORD_PLACEHOLDER, getenv
- **Notes:** It is recommended to disable the environment variable REDACTED_PASSWORD_PLACEHOLDER function and switch to a more secure authentication method.

---
### httpd-LAN_IP-command_injection

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x4012d0 sub_4012a0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the function sub_4012a0, a call to getenv('LAN_IP') was identified, and this value is directly used to construct a system command. An attacker can manipulate the LAN_IP environment variable to inject malicious commands, leading to remote code execution.
- **Keywords:** sub_4012a0, getenv, LAN_IP
- **Notes:** This is a high-risk issue that requires immediate remediation. Strict validation and filtering of the LAN_IP value should be implemented to prevent its direct use in command construction.

---
### busybox-PATH-command_injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x430c08 fcn.0043034c`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** Access to the 'PATH' environment variable was detected in function fcn.0043034c. This variable is used to locate executable files, and if maliciously modified, it may lead to command injection or execution of unintended programs.
- **Keywords:** PATH, fcn.0043034c, getenv
- **Notes:** It is necessary to check whether the PATH value is directly used for command lookup execution and restrict the scope of executable paths.

---
### init-PATH-path_hijacking

- **File/Directory Path:** `sbin/init`
- **Location:** `sbin/init:0x430c14`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Detection of PATH environment variable access in '/sbin/init'. The PATH environment variable is utilized for program path searching functionality, which if maliciously modified could lead to path hijacking attacks.
- **Keywords:** getenv, PATH, strchr
- **Notes:** It is recommended to check the security of the PATH value handling logic and restrict the scope of executable paths.

---
### telnetd-SSH_AUTH_SOCK-agent_hijacking

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER:0x40712c`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The function 'sym.cli_setup_agent' retrieves the SSH authentication socket path via getenv("SSH_AUTH_SOCK"). If this environment variable is maliciously set, it could lead to agent channel hijacking.
- **Keywords:** sym.cli_setup_agent, SSH_AUTH_SOCK, getenv
- **Notes:** It is necessary to verify whether the return values in the call chain are adequately validated to prevent path hijacking.

---
### httpd-REDACTED_PASSWORD_PLACEHOLDER-info_leak

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x403850 sub_403810`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The function sub_403810 contains a call to getenv('REDACTED_PASSWORD_PLACEHOLDER'), where the value is directly used for authentication comparison, posing an information leakage risk.
- **Keywords:** sub_403810, getenv, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to use secure hash comparison instead of plaintext comparison to prevent REDACTED_PASSWORD_PLACEHOLDER leakage.

---
### wpa_supplicant-WPA_SUPPLICANT_DRIVER-driver_load

- **File/Directory Path:** `sbin/wpa_supplicant`
- **Location:** `sbin/wpa_supplicant:0x34567`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The text calls getenv to retrieve the environment variable 'WPA_SUPPLICANT_DRIVER', which is used to select the driver. Insufficient validation may lead to driver loading vulnerabilities.
- **Keywords:** WPA_SUPPLICANT_DRIVER, getenv
- **Notes:** Restrict the list of loadable drivers to prevent the loading of malicious drivers.

---
### busybox-SHELL-command_injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x43bc5c sym.setup_environment`
- **Risk Score:** 7.0
- **Confidence:** 6.0
- **Description:** The sym.setup_environment function was found to access the environment variable 'SHELL'. This variable is used to determine the user's default shell, and if maliciously modified, could potentially lead to command injection vulnerabilities.
- **Keywords:** SHELL, sym.setup_environment, getenv
- **Notes:** Verify whether the value is directly used for command execution and restrict the available shell list.

---
