# Archer_C50 (34 alerts)

---

### unauthenticated_telnetd-rcS

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS: line containing 'telnetd'`
- **Risk Score:** 9.5
- **Confidence:** 9.25
- **Description:** The script initiates the telnetd service without an apparent authentication mechanism. This could lead to unauthenticated remote access, posing a severe security risk. Additionally, the telnet protocol itself is unencrypted, exposing credentials and session data.
- **Keywords:** telnetd
- **Notes:** It is recommended to disable telnetd or at least configure strong authentication. A better practice is to use SSH instead of telnet.

---
### insecure_firmware_upload-softup

- **File/Directory Path:** `N/A`
- **Location:** `web/main/softup.htm:4-20`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Insecure File Upload Handling - The form directly submits to /cgi/softup without client-side file type validation. Attackers may upload malicious firmware files. Trigger Condition: User submits any file. Security Impact: May lead to device firmware being replaced with malicious versions, resulting in complete device control.
- **Code Snippet:**
  ```
  formObj.action = "/cgi/softup";
  formObj.submit();
  ```
- **Keywords:** doSubmit, /cgi/softup, filename, formObj
- **Notes:** Further analysis of the /cgi/softup implementation is required to confirm the server-side validation status.

---
### httpd_buffer_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.7
- **Confidence:** 7.85
- **Description:** Memory corruption was found in the httpd binary due to insufficient validation of HTTP header parameters, which may lead to buffer overflow. The issue stems from the use of unsafe string manipulation functions (strcpy, sprintf) and a lack of rigorous boundary checks.
- **Code Snippet:**
  ```
  HIDDEN：
  strcpyHIDDEN：0x00408e74
  sprintfHIDDEN：0xREDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** http_cgi_main, http_parser_main, strcpy, sprintf
- **Notes:** Dynamic analysis is required to confirm exploitability of the vulnerability, with a focus on the network input processing flow.

---
### firmware_update_vulnerability-httpd

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The firmware was found to contain two critical endpoints related to firmware updates: `/cgi/softup` and `/cgi/softburn`, which handle firmware upload requests and upgrade errors, respectively. These endpoints exhibit insufficient filename validation, buffer allocation issues, and lack adequate authentication and authorization checks.
- **Keywords:** http_rpm_update, http_rpm_softerr, softup.htm, /cgi/softup, /cgi/softburn, cmem_REDACTED_SECRET_KEY_PLACEHOLDER, cmem_REDACTED_PASSWORD_PLACEHOLDER, rdp_updateFirmware
- **Notes:** Further verification is required for the specific implementation of buffer handling logic and file validation mechanisms. It is recommended to inspect memory management and boundary checks during the firmware update process.

---
### init_config_injection-busybox-fcn.0042a698

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x0042a698`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Keywords:** /etc/inittab, /etc/init.d/rcS, fcn.0042a698, fcn.0042a33c, str.reboot, str.umount__a__r, str.__bin_sh
- **Notes:** configuration_load

---
### unsafe_string_operations-cos

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos:HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The program extensively uses unsafe string manipulation functions (such as strcpy, strcat) without apparent boundary checks, potentially posing buffer overflow risks.
- **Keywords:** strcpy, strcat, strncpy
- **Notes:** Further analysis of the calling context of these functions is required to determine whether the inputs can be controlled.

---
### httpd_header_overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:sym.http_parser_main`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** Buffer overflow risk exists in HTTP header processing. When handling long HTTP headers, although 'header line len overflow' is detected, the absence of explicit length restrictions and truncation handling may lead to buffer overflow.
- **Keywords:** str.Msg:_header_line_len_overflow_n, http_stream_fgets, acStack_859
- **Notes:** need to confirm the size and actual usage of the acStack_859 buffer

---
### unprotected_cgi_endpoints-tplink

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm, web/main/softup.htm, REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.5
- **Confidence:** 6.5
- **Description:** Multiple unprotected CGI endpoints (/cgi/conf.bin, /cgi/confup, /cgi/softup, /cgi/usb3gup) were discovered for configuration upload and firmware updates, which lack apparent authentication mechanisms. Attackers could potentially exploit these interfaces to upload malicious configurations or firmware.
- **Keywords:** /cgi/conf.bin, /cgi/confup, /cgi/softup, /cgi/usb3gup
- **Notes:** Further verification is needed to confirm the actual existence of these endpoints and their access control mechanisms.

---
### unverified_file_upload-cgi

- **File/Directory Path:** `N/A`
- **Location:** `web/`
- **Risk Score:** 8.5
- **Confidence:** 3.5
- **Description:** Multiple unauthenticated file upload interfaces (/cgi/confup, /cgi/softup, /cgi/usb3gup) were discovered, which may allow attackers to upload malicious files. The forms use multipart/form-data encoding, but no apparent file type verification mechanism was identified.
- **Keywords:** /cgi/confup, /cgi/softup, /cgi/usb3gup, multipart/form-data
- **Notes:** Further confirmation is required regarding the actual location and implementation of these CGI programs to verify the existence of file upload vulnerabilities.

---
### file_upload_vulnerabilities-tplink

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm, web/main/softup.htm, REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple file upload functionalities were discovered (configuration backup and restore, firmware upgrade, 3G modem configuration), which could potentially be exploited to upload malicious files and achieve code execution.
- **Keywords:** enctype="multipart/form-data", method="post"
- **Notes:** Need to verify file type checking and upload processing logic

---
### kernel_module_loading-rcS

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS: multiple insmod lines`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The script loads multiple kernel modules (.ko files), including network and USB-related modules. If an attacker can replace these module files, it may lead to kernel-level code execution.
- **Keywords:** insmod, rt_rdm.ko, raeth.ko, usbcore.ko, ehci-hcd.ko, ohci-hcd.ko
- **Notes:** Kernel modules should be stored in secure locations with integrity checking mechanisms to prevent tampering.

---
### httpd_path_traversal

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:sym.http_parser_main`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Directory traversal vulnerability exists in HTTP request parsing. The code checks for '../' but may not be comprehensive enough, potentially allowing attackers to bypass checks through encoding or specially crafted paths. When processing HTTP request paths, URL-encoded paths are not sufficiently decoded and validated.
- **Keywords:** http_parser_main, http_tool_stripLine, str._._, pcStack_890
- **Notes:** Further testing is required to determine if path checks can be bypassed through double encoding or other specially crafted constructions.

---
### httpd_input_validation

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.0
- **Confidence:** 7.4
- **Description:** The HTTP stream processing function (http_stream_fgets) lacks strict boundary checking for user input, which may lead to various injection attacks.
- **Keywords:** http_stream_fgets
- **Notes:** Analyze all code paths that utilize this function.

---
### potential_command_injection-softburn

- **File/Directory Path:** `N/A`
- **Location:** `web/main/softup.htm:15-17`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Potential Firmware Burning Command Injection - Direct invocation of /cgi/softburn via $.cgi without visible parameter validation. Trigger condition: Automatically triggered after firmware upload. Security impact: May lead to arbitrary command execution.
- **Code Snippet:**
  ```
  $.cgi("/cgi/softburn", null, function(ret){
  	if (ret && ret != ERR_NETWORK && ret != ERR_EXIT && ret != ERR_NONE_FILE) $.errBack(ret, "softup.htm");
  }, false, true);
  ```
- **Keywords:** $.cgi, /cgi/softburn, softburn
- **Notes:** Need to confirm whether the /cgi/softburn implementation has a command injection vulnerability

---
### buffer_overflow-http_stream

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x004060cc`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The `http_stream_fgets` function has potential buffer overflow risks. This function reads data from a socket into a fixed-size buffer but does not strictly verify the relationship between input length and buffer size. Reading long lines may cause buffer overflow.
- **Keywords:** sym.http_stream_fgets, param_3, param_4
- **Notes:** buffer_overflow

---
### insecure_directory_permissions-rcS

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS: multiple lines`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The script creates multiple directories with permissions set to 0777, including /var/lock, /var/log, /var/run, and others. Such permissive permission settings may allow attackers to write or modify files within these directories, potentially leading to privilege escalation or persistence attacks. In particular, the /var/tmp/dropbear directory is used for the dropbear SSH service, where lax permissions could compromise SSH security.
- **Keywords:** /bin/mkdir -m 0777, /var/tmp/dropbear, /var/lock, /var/log, /var/run
- **Notes:** Attackers can exploit these directories with overly permissive permissions to inject or modify files, especially security-related directories such as dropbear. It is recommended to set stricter permission modes for these directories.

---
### path_traversal-http_parser

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00404d40`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A potential directory traversal vulnerability was discovered in the `http_parser_main` function. While the function checks for the `../` string when processing HTTP request paths, it fails to adequately filter URL-encoded path traversal sequences. Attackers could bypass the check using encoded `%2e%2e%2f` sequences.
- **Keywords:** sym.http_parser_main, sym.http_tool_stripLine, str._._, str.http:__
- **Notes:** Further validation of the URL decoding logic is required

---
### missing_csrf_protection-softup

- **File/Directory Path:** `N/A`
- **Location:** `web/main/softup.htm:28-30`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Lack of CSRF protection - The form does not include a CSRF REDACTED_PASSWORD_PLACEHOLDER. Trigger condition: When luring users to visit a malicious page. Security impact: May cause users to unknowingly trigger firmware updates.
- **Code Snippet:**
  ```
  <form action="/cgi/softup" enctype="multipart/form-data" method="post">
  ```
- **Keywords:** form, action, /cgi/softup
- **Notes:** Verify whether the server-side has CSRF protection measures in place.

---
### parameter_injection-cos-main

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/cos:0xREDACTED_PASSWORD_PLACEHOLDER (main)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A potential parameter injection vulnerability has been identified in the main function. When the 'krf' parameter is passed, the program executes the fcn.REDACTED_PASSWORD_PLACEHOLDER() function, which subsequently invokes a series of dangerous operations (including kill operations). This parameter lacks sufficient validation and could potentially be exploited by attackers to perform unauthorized operations.
- **Code Snippet:**
  ```
  if (iVar2 == 0x6b) {
      bVar1 = true;
  }
  ...
  if (bVar1) {
      fcn.REDACTED_PASSWORD_PLACEHOLDER();
      (**(loc._gp + -0x7fac))();
      (**(loc._gp + -0x7f24))(0);
      (**(loc._gp + -0x7e60))();
  }
  ```
- **Keywords:** main, krf, kill, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further analysis of the specific functionality of the fcn.REDACTED_PASSWORD_PLACEHOLDER() function is required to determine the exact attack impact.

---
### ftp_file_upload-vsftpd

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In FTP service configuration, `write_enable=YES` allows local users to upload files, which combined with `chroot_local_user=YES` may lead to privilege escalation risks. Attackers could execute code within the restricted directory by uploading malicious files.
- **Keywords:** write_enable, chroot_local_user
- **Notes:** Verify the strength of local user accounts and the possibility of anonymous access.

---
### httpd_hardcoded_paths

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Hardcoded sensitive information paths ('/cgi/conf.bin', '/cgi/softup') and critical operations (ACT_REBOOT) were detected, which could potentially be exploited for information disclosure or system control.
- **Keywords:** g_http_file_pTypeDefault, /cgi/conf.bin, /cgi/softup, ACT_REBOOT
- **Notes:** Verify the access controls and practical uses of these paths.

---
### httpd_session_weakness

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:sym.http_parser_main`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Session management is at risk. The logic in the code for handling session timeout (600 seconds) and session identifiers is not robust enough, potentially making it vulnerable to session fixation attacks.
- **Keywords:** 0x436ed0, puVar15, 600
- **Notes:** session_management

---
### command_injection-busybox-fcn.00412b00

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x412b00`
- **Risk Score:** 7.2
- **Confidence:** 7.15
- **Description:** A potential command injection vulnerability was discovered in `bin/busybox`. The function `fcn.00412b00` processes the `/proc/self/exe` path and may execute shell commands (`ash`). When handling input parameters containing specific characters (such as `/`), it could bypass path checks and execute arbitrary commands. Attackers could trigger this vulnerability through carefully crafted environment variables or command-line arguments.
- **Code Snippet:**
  ```
  fcn.00412b00(param_1,param_2,param_3);
  ...
  *ppcVar1 = "ash";
  ppcVar1[1] = param_1;
  ```
- **Keywords:** fcn.00412b00, /proc/self/exe, ash, execve, fcn.00419dc0
- **Notes:** Further verification is required to determine whether input parameters are fully controllable. It is recommended to inspect all code paths that call `fcn.00419dc0`, particularly sections handling environment variables and command-line arguments.

---
### httpd_auth_weakness

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:sym.http_parser_main`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The authentication mechanism has potential issues. Basic authentication processing lacks sufficient input validation and protective measures, potentially making it vulnerable to brute force attacks. The code handling the Authorization header shows no apparent rate limiting or failure lockout mechanisms.
- **Keywords:** str.Authorization, http_author_hasAuthor, http_filter_checkClientType
- **Notes:** It is recommended to check if there are authentication protection measures in other areas.

---
### unsafe_string_ops-http_parser

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x004041d0`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The use of unsafe string manipulation functions (such as strcpy, strcat) in HTTP header parsing may lead to buffer overflow. This risk is particularly high when processing long or malformed HTTP headers.
- **Keywords:** sym.http_parser_argStrToList, strcpy, strcat, strncpy
- **Notes:** memory_corruption

---
### rcS_script_vulnerability-inittab

- **File/Directory Path:** `N/A`
- **Location:** `etc/inittab:1`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The `/etc/init.d/rcS` script executed during system startup may pose security risks. This script typically contains multiple commands and service startup instructions during the system initialization process. If the script can be modified or includes improperly validated commands, attackers may achieve persistence or privilege escalation by altering this script.
- **Keywords:** ::sysinit, /etc/init.d/rcS
- **Notes:** Further analysis of the `/etc/init.d/rcS` script content is required to confirm specific risks.

---
### httpd_mac_bypass

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:sym.http_parser_main`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** There is a logical flaw in MAC address verification. The validation logic for client MAC addresses in the code can be bypassed because the request continues to be processed even when MAC retrieval fails (uVar12=0).
- **Keywords:** sym.http_filter_fillMac, str.Msg:_Can_not_get_MAC_n, uVar12, uVar13
- **Notes:** may lead to bypassing MAC-based access control

---
### internal_api_exposure-tplink

- **File/Directory Path:** `N/A`
- **Location:** `web/js/lib.js`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** A significant number of internal APIs (such as ACT_GET operations) called through the $.act() function have been discovered. These APIs can access device configurations, status information, and network settings. Some APIs may expose sensitive information or allow unauthorized modifications.
- **Keywords:** $.act, ACT_GET, IGD_DEV_INFO, ETH_SWITCH, SYS_MODE
- **Notes:** Reverse engineering is required to analyze the actual implementation and access control of these APIs.

---
### race_condition-firmware_update

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00407c4c, 0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The `http_rpm_update` and `http_rpm_restore` functions utilize shared memory buffers (0x4376d4/0x4376e4) for firmware updates without proper synchronization mechanisms, potentially leading to race conditions. Additionally, error handling is inadequate, which may result in sensitive information leakage upon failure.
- **Keywords:** sym.http_rpm_update, sym.http_rpm_restore, 0x4376d4, 0x4376e4, str.Attach_big_buffer_error_n, str.Detach_big_buffer_error_n
- **Notes:** analyze the calling context in a multithreaded environment

---
### buffer_overflow-busybox-fcn.0042a33c

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x0042a33c`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The command execution function at 0x0042a33c handles command strings without proper sanitization or validation. It copies command strings into buffers (size 0x100 and 0x20) without explicit length checks, potentially leading to buffer overflows if malicious configuration entries are processed.
- **Keywords:** fcn.0042a33c, strcmp, 0x100, 0x20
- **Notes:** command_execution

---
### unvalidated_cos_service-rcS

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/rcS: last line`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The script starts the 'cos' service (likely a custom service) but does not provide a path or validation mechanism. If an attacker can control the PATH environment variable or file system, malicious code execution may occur.
- **Keywords:** cos &
- **Notes:** It is recommended to start the service using the full path and verify the integrity of the service.

---
### system_operations_definition-libjs

- **File/Directory Path:** `N/A`
- **Location:** `web/js/lib.js:1-50`
- **Risk Score:** 7.0
- **Confidence:** 5.75
- **Description:** Critical system operation definitions and potential CGI call interfaces were discovered in web/js/lib.js. The file begins by defining various operation types (ACT_GET/ACT_SET, etc.) and system-level operations (such as reboot, factory reset, etc.). These operations may invoke backend CGI programs through ACT_CGI(8). Due to the lack of visibility into input validation code, further analysis is required regarding the invocation methods and security of these operations.
- **Keywords:** ACT_GET, ACT_SET, ACT_CGI, ACT_OP_REBOOT, ACT_OP_FACTORY_RESET, $.params
- **Notes:** Suggested follow-up analysis: 1) Complete content of the lib.js file 2) Locate code paths that call these REDACTED_PASSWORD_PLACEHOLDER operations 3) Check if executable CGI programs exist in the web directory 4) Analyze the content of the local.js parameter file

---
### xss_risk-innerHTML

- **File/Directory Path:** `N/A`
- **Location:** `web/js/lib.js`
- **Risk Score:** 7.0
- **Confidence:** 4.0
- **Description:** JavaScript code that directly manipulates innerHTML may lead to XSS vulnerabilities, especially when no obvious input filtering is observed during dynamic element content setting.
- **Keywords:** innerHTML, lib.js, elem.innerHTML
- **Notes:** It is necessary to check all contexts where innerHTML is used to verify whether they contain user-controllable input.

---
### dom_xss_risk-localjs

- **File/Directory Path:** `N/A`
- **Location:** `web/js/local.js`
- **Risk Score:** 7.0
- **Confidence:** 3.75
- **Description:** xss
- **Keywords:** $.find, query, container
- **Notes:** It is necessary to verify whether malicious code can be executed through crafted selectors.

---
