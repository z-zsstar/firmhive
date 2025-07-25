# Archer_C2_V1_170228 (27 alerts)

---

### firmware_update-httpd-memory_management

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00407c4c sym.http_rpm_update`
- **Risk Score:** 9.5
- **Confidence:** 7.25
- **Description:** The firmware update functionality has memory management issues. The function `sym.http_rpm_update` fails to properly validate input size during firmware updates, which may lead to buffer overflow or memory corruption. Specifically, when handling large files, the boundary check for `param_1[6]` is insufficient.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** sym.http_rpm_update, *0x4376d0, *0x4376d4, sym.http_parser_illMultiObj
- **Notes:** Further information is required to confirm the specific triggering conditions and scope of impact.

---
### network_service-rcS-telnetd_enabled

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:54`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The telnet service (telnetd) is enabled without apparent authentication protection. This provides attackers with direct remote access, potentially leading to unauthorized access.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** telnetd
- **Notes:** It is recommended to check whether there are additional authentication mechanisms or network access controls protecting the telnet service.

---
### REDACTED_PASSWORD_PLACEHOLDER-exposure-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The `etc/REDACTED_PASSWORD_PLACEHOLDER.bak` file was found to contain the REDACTED_PASSWORD_PLACEHOLDER hash ($1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/) for the REDACTED_PASSWORD_PLACEHOLDER user. This is an MD5 hash stored in a globally readable file, posing a severe security risk. Attackers could obtain this hash and perform offline cracking. Without the protection of a shadow file, the REDACTED_PASSWORD_PLACEHOLDER hash is directly exposed.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to check if the system stores REDACTED_PASSWORD_PLACEHOLDER hashes elsewhere. This MD5 hash can be quickly cracked by modern GPUs, especially if the REDACTED_PASSWORD_PLACEHOLDER strength is insufficient.

---
### authentication-httpd-hardcoded_credentials

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER sym.http_auth_doAuth`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Hardcoded authentication credentials were detected. The function `sym.http_auth_doAuth` utilizes authentication data from a fixed memory address (0x437560), which may lead to authentication bypass. Attackers could potentially obtain these credentials through reverse engineering or directly circumvent the authentication check.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** sym.http_auth_doAuth, 0x437560, *(param_2 + 0x34)
- **Notes:** It is necessary to confirm whether this memory area contains sensitive authentication information.

---
### upnp-unauthorized_control

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/wscd:0x004098d0-0x0040a628`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The program was found to have registered multiple UPnP actions (REDACTED_PASSWORD_PLACEHOLDER, etc.) and exposed device control interfaces. These interfaces lack sufficient authentication mechanisms and could potentially be exploited for unauthorized device control.
- **Keywords:** GetAPSettings, SetAPSettings, RebootAP, ResetAP, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** These interfaces may be used to initiate denial-of-service attacks or tamper with device configurations.

---
### network_input-httpd-path_traversal

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00404d40 sym.http_parser_main`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The HTTP request parser contains a path traversal vulnerability. The function `sym.http_parser_main` only checks for simple `../` patterns when processing HTTP request paths, but fails to filter encoded path traversal characters (such as `%2e%2e%2f`). Attackers may potentially access sensitive system files by constructing specially crafted paths.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** sym.http_parser_main, str._._, sym.http_tool_stripLine, sym.http_stream_fgets
- **Notes:** Further verification is needed to determine if there are other encoding forms of path traversal that can be exploited.

---
### network_input-rtinicapd-buffer_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/rtinicapd:0x0040224c Handle_read`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A buffer overflow risk was identified in the `Handle_read` function during network packet processing. The recv call receives up to 3000 bytes of data, but subsequent processing lacks strict length validation. Attackers could exploit this by sending specially crafted large packets to trigger buffer overflow.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** Handle_read, recv, 3000
- **Notes:** Further verification is needed to determine whether all data copy operations have boundary checks.

---
### upnp-unsafe_string_ops

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/wscd`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** Multiple dangerous string operation function calls were detected, including strcpy, strcat, sprintf, etc., lacking boundary checks. Particularly when handling HTTP requests and UPnP messages, these operations may lead to buffer overflows.
- **Keywords:** strcpy, strcat, sprintf, http_ReadHttpGet, UpnpMakeAction
- **Notes:** Dynamic analysis is required to verify whether these functions can be triggered by malicious input.

---
### wireless_config-insecure_defaults

- **File/Directory Path:** `N/A`
- **Location:** `etc/RT2860AP.dat`
- **Risk Score:** 8.0
- **Confidence:** 10.0
- **Description:** The default authentication and encryption settings are insecure. AuthMode is set to OPEN and EncrypType is set to NONE, meaning the wireless network has no authentication or encryption enabled by default.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** AuthMode=OPEN, EncrypType=NONE
- **Notes:** This makes the network vulnerable to man-in-the-middle attacks and data eavesdropping.

---
### wireless_config-hardcoded_wpa_key

- **File/Directory Path:** `N/A`
- **Location:** `etc/RT2860AP5G.dat`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The file contains a hardcoded WPA pre-shared REDACTED_PASSWORD_PLACEHOLDER (WPAPSK1), stored in plaintext. If an attacker gains access to this file, they could extract and use this REDACTED_PASSWORD_PLACEHOLDER to obtain unauthorized access to the wireless network. The REDACTED_PASSWORD_PLACEHOLDER is stored as a hexadecimal string, making it easily extractable.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** WPAPSK1, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** If an attacker can read this file (e.g., through a directory traversal vulnerability or incorrect file permissions), they could extract the WPA REDACTED_PASSWORD_PLACEHOLDER and connect to the network.

---
### ftp-config-risks

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The vsftpd configuration has enabled write permissions for local users (write_enable=YES) and ASCII mode transfer, which may allow attackers to upload malicious files or perform newline injection attacks.
- **Keywords:** write_enable=YES, ascii_upload_enable=YES, ascii_download_enable=YES
- **Notes:** Disable ASCII mode transfer and restrict write permissions

---
### kernel_module-rcS-module_loading

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:32-50`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Multiple kernel modules (such as rt_rdm.ko, usbcore.ko, etc.) were loaded without verifying their integrity or origin. Malicious modules could lead to complete system compromise.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** insmod REDACTED_PASSWORD_PLACEHOLDER_rdm/rt_rdm.ko, usbcore.ko, ehci-hcd.ko
- **Notes:** The signature verification mechanism and storage location security of these kernel modules need to be inspected.

---
### configuration-firewall-iptables_disable

- **File/Directory Path:** `N/A`
- **Location:** `etc/iptables-stop`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** The iptables-stop script completely disables all firewall rules by flushing all chains and setting the default policy to ACCEPT. This may be triggered during system shutdown, leaving a brief unprotected time window for the system.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** iptables-stop, iptables -F, iptables -P INPUT ACCEPT
- **Notes:** If this state persists or attackers can trigger script execution, it is extremely dangerous.

---
### upnp-memory_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/wscd:0x0041974c`
- **Risk Score:** 8.0
- **Confidence:** 6.25
- **Description:** In the REDACTED_PASSWORD_PLACEHOLDER function, a memory allocation operation was found to lack boundary checking. The function uses malloc to allocate a fixed size (0x1d4) of memory but fails to verify whether subsequent operations might exceed the bounds. Specifically, when handling the device and serviceList tags, it could potentially lead to heap overflow.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, malloc, device, serviceList, ixmlDocument_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Need to verify with specific XML input whether overflow can be triggered

---
### file_permission-rcS-world_writable_dirs

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:5-20`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The file created multiple directories with permissions set to 0777, including /var/lock, /var/log, /var/run, etc. Such lax permission settings may allow attackers to write malicious files or tamper with system logs. In particular, the REDACTED_PASSWORD_PLACEHOLDER directory may contain wireless configuration information, and insecure permissions could lead to unauthorized modification of these configurations.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** /bin/mkdir -m 0777, REDACTED_PASSWORD_PLACEHOLDER, /var/lock, /var/log
- **Notes:** Attackers may exploit these loosely permissioned directories to implant malicious files or modify system files.

---
### protocol_validation-rtinicapd-eap_validation

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/rtinicapd:0x0040ae08 ieee802_1x_receive`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** In the `ieee802_1x_receive` function, insufficient validation of EAP packet length was discovered. When processing EAP response packets, the function only checks the minimum length (4 bytes) without verifying whether the actual data length matches the declared length, which may lead to memory out-of-bounds read.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** ieee802_1x_receive, EAP, length
- **Notes:** Triggered by sending malformed EAP packets

---
### wireless_config-plaintext_credentials

- **File/Directory Path:** `N/A`
- **Location:** `etc/RT2860AP.dat`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The configuration file stores sensitive information in plaintext. It contains wireless network configuration parameters such as SSID, encryption type, RADIUS server details, etc., but lacks evident encryption protection. If an attacker gains access to this file, they could obtain network configuration information, including potential RADIUS keys ('ralink').
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** SSID1, SSID2, SSID3, SSID4, AuthMode, EncrypType, RADIUS_Key, WPAPSK1, WPAPSK2, WPAPSK3, WPAPSK4
- **Notes:** If an attacker gains physical access to the device or obtains filesystem access through other vulnerabilities, this information could be compromised.

---
### upnp-path_injection

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/wscd:0x004098d0`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** In the WscUPnPDevStart function, a potential injection risk was identified in the XML file path concatenation operation. The function uses sprintf to concatenate user-provided parameters param_4 and param_3 to form a file path without sufficient validation. Attackers could potentially exploit these parameters to achieve directory traversal or XML injection attacks.
- **Keywords:** WscUPnPDevStart, sprintf, param_3, param_4, WFADeviceDesc.xml
- **Notes:** Verify whether the sources of the param_3 and param_4 parameters are controllable.

---
### network_input-busybox-ifconfig-buffer_overflow

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x00409d5c`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The function fcn.00409d5c handles network interface information with multiple unvalidated buffer operations. It uses a fixed-size stack buffer (auStack_40[16]) to store interface names and retrieves interface information through multiple system calls (ioctl). When the interface name exceeds 16 bytes, a buffer overflow may occur. Attackers could exploit this vulnerability by crafting specially designed interface names.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** fcn.00409d5c, auStack_40, fcn.004056c8, ioctl, 0x8913, 0x8927
- **Notes:** It is necessary to verify whether this vulnerability can be triggered by network interface configuration. It is recommended to check the maximum allowed length of interface names in the system.

---
### configuration-ftp-vsftpd_privilege_escalation

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The vsftpd configuration has enabled write permissions for local users (write_enable=YES) while using chroot (chroot_local_user=YES). If a local user account is compromised, it may lead to privilege escalation, allowing users to upload malicious files but confined within their home directories. The FTP banner also exposes server information (TP-LINK FTP server).
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** vsftpd.conf, write_enable, chroot_local_user, ftpd_banner
- **Notes:** The risk depends on whether anonymous access is truly disabled and the strength of the local REDACTED_PASSWORD_PLACEHOLDER.

---
### privilege-groups-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/group`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The system has multiple privileged group configurations, including REDACTED_PASSWORD_PLACEHOLDER, wheel, adm, and other privileged groups, with the REDACTED_PASSWORD_PLACEHOLDER user belonging to multiple privileged groups. This may lead to privilege escalation risks, especially when non-privileged users are mistakenly added to these groups.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:x:0, wheel:x:10:REDACTED_PASSWORD_PLACEHOLDER, adm:x:4:REDACTED_PASSWORD_PLACEHOLDER,adm,daemon
- **Notes:** Review all user accounts belonging to privileged groups

---
### service_management-rcS-cos_service

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS:60`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The 'cos' service was started without providing a path or authentication mechanism. If an attacker can control the PATH environment variable or replace the cos binary file, it may lead to arbitrary code execution.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** cos &
- **Notes:** Need to determine the specific location and permission settings of the COS service.

---
### driver_communication-rtinicapd-ioctl_vulnerability

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/rtinicapd:0x00402adc RT_ioctl`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The program communicates with the driver using ioctl (command 0x8be1) but fails to adequately validate the input. An attacker could potentially cause denial of service or memory corruption by forging ioctl calls.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** RT_ioctl, 0x8be1
- **Notes:** Analyze the processing logic on the driver side

---
### wireless_config-radius_weakness

- **File/Directory Path:** `N/A`
- **Location:** `etc/RT2860AP.dat`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The RADIUS server configuration uses default ports and a simple REDACTED_PASSWORD_PLACEHOLDER. RADIUS_Port=1812 (default), RADIUS_Key=ralink (simple REDACTED_PASSWORD_PLACEHOLDER), which may make RADIUS authentication vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** RADIUS_Server, RADIUS_Port, RADIUS_Key
- **Notes:** If RADIUS authentication is used, it is recommended to use a more complex shared REDACTED_PASSWORD_PLACEHOLDER.

---
### wireless_config-hardcoded_radius_key

- **File/Directory Path:** `N/A`
- **Location:** `etc/RT2860AP5G.dat`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The RADIUS server configuration contains a hardcoded RADIUS REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER ('ralink'). This REDACTED_PASSWORD_PLACEHOLDER is used for authentication between the access point and the RADIUS server. If compromised, an attacker could impersonate either the access point or the RADIUS server.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** RADIUS_Key, ralink
- **Notes:** The RADIUS REDACTED_PASSWORD_PLACEHOLDER is stored in plaintext, which may be exposed if the file is accessed by unauthorized users.

---
### session_management-httpd-session_fixation

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00404d40 sym.http_parser_main`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The session management has vulnerabilities. Multiple functions (such as `sym.http_parser_main`) utilize global variables (e.g., `0x436ed0`) to store session states, and the timeout checks are not stringent, potentially leading to session fixation or session hijacking attacks.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** *0x436ed0, *(puVar15 + 0xc), puVar15[8]
- **Notes:** Analyze the implementation details of actual session management

---
### authentication-rtinicapd-state_machine_flaw

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/rtinicapd:0xREDACTED_PASSWORD_PLACEHOLDER eapol_sm_step`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The program has a logical flaw in handling the 802.1X authentication state machine. Certain state transitions fail to properly verify preconditions, potentially leading to authentication bypass.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** eapol_sm_step, sm_AUTH_PAE_FORCE_AUTH_Enter, sm_AUTH_PAE_FORCE_UNAUTH_Enter
- **Notes:** authentication

---
