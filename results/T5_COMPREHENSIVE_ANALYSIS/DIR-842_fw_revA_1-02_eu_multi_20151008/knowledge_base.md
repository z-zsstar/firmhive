# DIR-842_fw_revA_1-02_eu_multi_20151008 (16 findings)

---

### command-injection-main

- **File/Directory Path:** `bin/iapp`
- **Location:** `iapp:0x004021ec and 0x00402220 (main function)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'iapp' program, allowing attackers to execute arbitrary commands through malicious interface names. The program uses system calls to execute routing commands (such as 'route delete' and 'route add'), where the interface name is directly obtained from command-line arguments and embedded into the command string via sprintf, without any input filtering or validation. Attackers can provide interface names containing shell metacharacters (such as semicolons or backticks) to inject and execute arbitrary commands. Since the program typically runs with root privileges (such as when creating /var/run/iapp.pid), successful exploitation could lead to complete system control. Trigger condition: When an attacker has valid login credentials and can execute the iapp command, providing a malicious interface name (e.g., 'wlan0; malicious_command'). The exploitation method is straightforward and direct, requiring no complex memory manipulation.
- **Code Snippet:**
  ```
  0x004021ec: 8f99805c lw t9, -sym.imp.sprintf(gp)
  0x004021f0: 00602821 move a1, v1 ; Command string 'route delete -net 224.0.0.0 netmask 240.0.0.0 dev %s'
  0x004021f4: afa30158 sw v1, (var_158h)
  0x004021f8: 02803021 move a2, s4 ; Interface name (from global variable)
  0x004021fc: 0320f809 jalr t9 ; Call sprintf to construct command
  0x00402200: 02602021 move a0, s3 ; Buffer address
  0x00402208: 8f9980dc lw t9, -sym.imp.system(gp)
  0x0040220c: 0320f809 jalr t9 ; Call system to execute command
  0x00402210: 02602021 move a0, s3 ; Command string buffer
  ```
- **Keywords:** Command-line argument (interface name), Global variable storing interface name, system command string
- **Notes:** This vulnerability requires the program to run with root privileges, which is common in network services. Attackers can directly control the input through command-line arguments, and the exploitation chain is complete and verifiable. It is recommended to strictly validate and filter interface names, or use secure functions like execve instead of system. Further analysis should check if similar issues exist in other input points (such as network packets and FIFO files).

---
### command-injection-upgrade_firmware

- **File/Directory Path:** `sbin/bulkagent`
- **Location:** `bulkagent:0x40379c upgrade_firmware`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'upgrade_firmware' function, where user-controlled input from network packets is unsafely incorporated into a 'system' call. Attackers can exploit this by sending crafted firmware upgrade commands containing shell metacharacters, leading to arbitrary command execution as the user running 'bulkagent'. The vulnerability is triggered when the command type 0x7eff or 0x7f00 is processed, calling 'upgrade_firmware' with attacker-controlled data. The function uses 'snprintf' to build a command string but does not validate or escape the input, allowing injection into the 'bulkUpgrade' command.
- **Code Snippet:**
  ```
  In upgrade_firmware (0x40379c):
  - Constructs command using snprintf: 'bulkUpgrade -f "%s%s" -force' with user-controlled strings
  - Calls system() with the constructed command
  Evidence from control_command (0x404118) shows command type 0x7eff/0x7f00 leads to upgrade_firmware call with network data.
  ```
- **Keywords:** ipaddr_server, /var/tmp/, bulkUpgrade
- **Notes:** The attack requires network access to the bulkagent service. As a non-root user, exploitation can lead to privilege escalation if bulkagent runs with elevated privileges. Recommend immediate input sanitization and avoiding system() with user input.

---
### buffer-overflow-main

- **File/Directory Path:** `sbin/get_set`
- **Location:** `get_set:0x00400d44 main (specifically at the ncc_socket_recv call around 0x00400e00 based on decompilation context)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack-based buffer overflow occurs in the main function when ncc_socket_recv is called. The function sets uStack_a48 to 0x100 (256 bytes) but provides auStack_a50, a stack buffer of only 4 bytes. This mismatch allows an attacker to send more than 4 bytes of data, overflowing the buffer and corrupting adjacent stack variables, including the return address. The vulnerability is triggered by sending crafted network data to the service. As the program may run with elevated privileges (e.g., via CGI or network service), successful exploitation could lead to arbitrary code execution. The attack chain is: network input → ncc_socket_recv with oversized data → buffer overflow → control of execution flow.
- **Code Snippet:**
  ```
  // From main function decompilation
  uStack_a48 = 0x100; // Size set to 256 bytes
  uStack_a44 = 0x310;
  uStack_a40 = 0;
  iStack_a3c = 0;
  pcStack_a38 = NULL;
  iStack_a3c = (**(loc._gp + -0x7fc4))(acStack_434); // strlen call
  pcStack_a38 = acStack_434;
  iVar3 = (**(loc._gp + -0x7f70))(uStack_a4c, &uStack_a48, auStack_a50); // ncc_socket_recv call
  // auStack_a50 is defined as uchar auStack_a50 [4]; (4-byte buffer)
  // But uStack_a48 is 0x100, allowing up to 256 bytes to be written
  ```
- **Keywords:** ncc_socket_recv, auStack_a50, uStack_a48
- **Notes:** The vulnerability is verified through decompilation evidence. Exploitation depends on the service's accessibility and privileges. Further analysis could involve testing the network protocol and identifying exact offset for overwriting the return address. No other exploitable issues were found in helper functions.

---
### Sensitive-Data-Exposure-key_file.pem

- **File/Directory Path:** `etc/key_file.pem`
- **Location:** `key_file.pem:1 (file content)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The file 'key_file.pem' contains an unencrypted RSA private key and certificate, exposing highly sensitive information. The issue manifests as the private key being readable by non-root users, triggered when an attacker has filesystem access and can read the file. Constraints include the file being located in an accessible directory and having improper permission settings. Potential attack methods include using the private key for identity impersonation (such as SSH login or TLS connection decryption), man-in-the-middle attacks, or privilege escalation. The relevant technical detail is that the private key is stored in plaintext, lacking encryption or access control.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIICXAIBAAKBgQDLLKEQqDuuLDhF7s8TqHGofvXWMJNopCgbHyGRGt9s3bB+2A7a
  rnNjzTlN5MOGwWE/ELXjm0fQDLIiIBgalke5StNqF5i3FHteMN16fdd83BaM2/L6
  U3kyYQ9K6m5GXeoOt6x3mP0xJf1ADovPc59reepPL3wi4eSMXQOpnl0gUwIDAQAB
  AoGAVA97+DNSteZPxgdfH8gCdm9I8TyZ0KKSgV4o+is/I4C5ZFGqG6ovzav8OJEc
  oKVjwb79MlVtqdOG4/2ZW26v72nh/V9OtIpNdHcaulkoJglMwq/w/xIgEwctS6c1
  se/UlM8DEH/WBYtMMJ6/nwJwDB6x8+WD7Hm+vjwVozuUOSkCQQDwBW4AD+FN97RP
  NwSBS64qyhFB7IstT7EPCarbnqPTbEGM39y/PKgPT5wUIS3Zkih09OizsZuroJpS
  XAXhlAXHAkEA2LM8NtdNibGWjzA5PhLCUf225UjTN0ccjSZLKqjW4N/G4hVy6jtL
  9noENq/zir85dTIaIxUpVy9fhjHuq7YhFQJBAJavUffIAHKqaBCzQajKknValqsE
  jfvMZCREtXdbiQ5akGyYvkVxFzFFkX8xtU86axvCBbWKc2i0Uy4Rh7+u5lECQBcl
  TdEtvgJvDX3N0M9ogYjwaJCk7qqA1fPdmzm7PvhV7pBHajbKjpqM/dY5hPHU6vYx
  m8kTgY7maHWU78E3euECQH1AJSESOXzLGcsPPkY0a0M2SWPU+W2SSoxhHnbmG1vG
  KuBYPVK1emsIxwVdGlE13EEaXn9qiK8OcQNKzbEqrww=
  -----END RSA PRIVATE KEY-----
  -----BEGIN CERTIFICATE-----
  MIICoTCCAgqgAwIBAgIJAMu7EW1f923hMA0GCSqGSIb3DQEBBQUAMEAxCzAJBgNV
  BAYTAlRXMQ8wDQYDVQQIEwZUQUlXQU4xDzANBgNVBAcTBlRBSVBFSTEPMA0GA1UE
  ChMGRC1MaW5rMB4XDTEzMTExMTAxMjMwNFoXDTIzMTEwOTAxMjMwNFowQDELMAkG
  A1UEBhMCVFcxDzANBgNVBAgTBlRBSVdBTjEPMA0GA1UEBxMGVEFJUEVJMQ8wDQYD
  VQQKEwZELUxpbmswgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMssoRCoO64s
  OEXuzxOocah+9dYwk2ikKBsfIZEa32zdsH7YDtquc2PNOU3kw4bBYT8QteObR9AM
  siIgGBqWR7lK02oXmLcUe14w3Xp913zcFozb8vpTeTJhD0rqbkZd6g63rHeY/TEl
  /UAOi89zn2t56k8vfCLh5IxdA6meXSBTAgMBAAGjgaIwgZ8wHQYDVR0OBBYEFIvH
  8ES2FWMrzwH0fIj2nJf1nIhGMHAGA1UdIwRpMGeAFIvH8ES2FWMrzwH0fIj2nJf1
  nIhGoUSkQjBAMQswCQYDVQQGEwJUVzEPMA0GA1UECBMGVEFJV0FOMQ8wDQYDVQQH
  EwZUQUlQRUkxDzANBgNVBAoTBkQtTGlua4IJAMu7EW1f923hMAwGA1UdEwQFMAMB
  Af8wDQYJKoZIhvcNAQEFBQADgYEAc3dlDo8BCZHN6iwUjAojGQKuEok8hNFgnTh+
  DI3HZDEGWajn8ytgqFMJvSqMq94mx4KsMUCyqsAfiNlyI22DgrAYGG8aAVOLEZIV
  AT1opv500zQA6gVA4UXecjVv6QjPe8uJRY7BljP1SLg5XRgyKrHsyzedzN5p9nuN
  KajGJc0=
  -----END CERTIFICATE-----
  ```
- **Keywords:** key_file.pem
- **Notes:** This finding is based on file content analysis; the exposed private key can be directly exploited. It is recommended to further verify file permissions (e.g., using 'ls -l key_file.pem') and how system components use this private key to confirm the completeness of the attack chain. Related files may include service configuration files that use this private key.

---
### Command-Injection-set_timeZone

- **File/Directory Path:** `lib/libapmib.so`
- **Location:** `libapmib.so:0x5990 (system call in set_timeZone)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The `set_timeZone` function in libapmib.so contains a command injection vulnerability due to improper sanitization of user-controlled input from the NTP_TIMEZONE MIB setting (ID 0x99). The function retrieves the timezone string via `apmib_get`, processes it with `gettoken` to extract the first token (using space as delimiter), and then uses this token in a `sprintf` format string (e.g., 'GMT%s:30%s' or 'GMT%s%s') that is incorporated into a shell command executed via `system`. The command constructed is 'echo %s >/var/TZ', where the first %s is the formatted string containing the user-controlled token. An attacker with valid login credentials can set the NTP_TIMEZONE value to a string containing shell metacharacters (e.g., '; malicious_command #') to break out of the intended command and execute arbitrary commands. The vulnerability is triggered when `set_timeZone` is called, which typically occurs during timezone configuration updates via MIB settings. The function includes multiple `strcmp` checks against hardcoded timezone strings, but if no match is found, it falls back to a default path where the user input is still used unsanitized. The lack of input validation allows command injection regardless of the strcmp outcomes.
- **Code Snippet:**
  ```
  Relevant code from set_timeZone disassembly:
  0x5990: lw t9, -sym.imp.system(gp)
  0x5994: jalr t9  # Executes the command string
  
  Preceding code constructs the command:
  0x5980: lw t9, -sym.imp.sprintf(gp)
  0x5984: jalr t9  # Formats 'echo %s >%s' with user input
  0x5988: addiu a1, a1, -0x6e38  # 'echo %s >%s' string
  0x598c: move a0, s0  # Command buffer
  0x5990: jalr t9  # Calls system
  
  The user input is derived from:
  0x5848: lw t9, -sym.gettoken(gp)
  0x584c: jalr t9  # Gets first token of timezone string
  0x5850: move a2, zero  # Delimiter space
  0x5854: move a0, s0  # Input buffer from apmib_get(0x99)
  ```
- **Keywords:** NTP_TIMEZONE (MIB ID 0x99), DAYLIGHT_SAVE (MIB ID 0x11a), apmib_set, apmib_get, set_timeZone, /var/TZ
- **Notes:** The vulnerability requires that set_timeZone is called by a process after the MIB value is set. This is likely triggered through configuration interfaces (e.g., web UI or CLI) accessible to authenticated users. The process executing set_timeZone may run with elevated privileges (e.g., root), leading to full system compromise. Further analysis should identify all callers of set_timeZone in the system to confirm exploitability in context. The use of strcpy and sprintf in this function also indicates potential for buffer overflows, but command injection is the immediately exploitable issue.

---
### PrivEsc-ShadowSample

- **File/Directory Path:** `etc/shadow.sample`
- **Location:** `shadow.sample:1`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The shadow.sample file contains the root user's password hash (MD5 format: $1$KEKJV2R0$TFJ4jy7waGKrjdNHwPGzV.), and the file permissions are set to 777 (-rwxrwxrwx), allowing any user (including non-root users) to read it. An attacker (a logged-in non-root user) can easily read the file, extract the hash value, and use offline cracking tools (such as John the Ripper or hashcat) to attempt to crack the password. If the password strength is weak, the attacker may obtain the root password, thereby escalating privileges to root. The trigger condition is that the attacker has file read permissions, with no additional conditions required. Exploitation methods include directly reading the file and using cracking tools for dictionary or brute-force attacks.
- **Code Snippet:**
  ```
  root:$1$KEKJV2R0$TFJ4jy7waGKrjdNHwPGzV.:14587:0:99999:7:::
  ```
- **Keywords:** shadow.sample
- **Notes:** Further verification of the password hash strength is needed to assess the cracking difficulty. It is recommended to check the permissions of other similar files in the system (such as /etc/shadow) to prevent similar information leaks. This finding is related to permission management issues and may affect overall system security.

---
### XSS-category_asp_file_list

- **File/Directory Path:** `wa_www/category.asp`
- **Location:** `category.asp: show_media_list function and show_media_list2 function (specific line numbers unknown, but based on content, located in the code segment that outputs filenames)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A stored XSS vulnerability exists in the file list display functionality. The filename (returned from the '/dws/api/ListCategory' API) is directly output into the HTML in the 'show_media_list' and 'show_media_list2' functions without HTML escaping. An attacker can upload a file with a filename containing a malicious script (e.g., `<script>alert('XSS')</script>.mp3`). When an authenticated user visits the 'category.asp' page, the malicious script will execute in their browser. Since session cookies ('id' and 'key') are accessible via JavaScript (no HttpOnly flag), an attacker could steal session tokens and hijack the user's session. Trigger condition: Attacker uploads a file with a malicious filename; User browses the file list. Exploitation method: Execute arbitrary JavaScript code via XSS, potentially leading to session theft, privilege escalation, or further attacks.
- **Code Snippet:**
  ```
  In the show_media_list function:
  str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  In the show_media_list2 function:
  bg_str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  The filename 'file_name' is directly concatenated into the HTML string without using an escape function.
  ```
- **Keywords:** media_info.files[i].name, session_id, session_tok, /dws/api/ListCategory, /dws/api/GetFile
- **Notes:** The vulnerability relies on the backend API allowing malicious filenames to be uploaded; it is recommended to verify if the backend filters filenames. Related files: Upload functionality might be in other scripts (e.g., 'webfile.js'). Future analysis direction: Check the file upload mechanism and backend API implementation to confirm filename controllability. This vulnerability is exploitable in an authenticated context, and the attack chain is complete.

---
### buffer-overflow-fcn.00401658

- **File/Directory Path:** `bin/iwpriv`
- **Location:** `iwpriv:0x00401658 fcn.00401658`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability was identified in the 'iwpriv' binary within the function fcn.00401658 when processing ioctl commands of type 0x6000. The vulnerability arises from the use of a strcpy-like function to copy user-controlled data from command-line arguments into a fixed-size stack buffer (auStack_10b4 of 127 bytes) without length validation. An attacker with valid login credentials (non-root user) can trigger this by providing a specially crafted long string as part of the command-line arguments for a specific ioctl command. This could lead to stack buffer overflow, allowing overwrite of adjacent stack data including return addresses, potentially resulting in arbitrary code execution or denial of service. The vulnerability is triggered when the command-line arguments activate the type 0x6000 handling path in the code.
- **Code Snippet:**
  ```
  // From decompilation of fcn.00401658
  if (uVar15 == 0x6000) {
      ppuVar16 = apuStack_1034;
      for (iVar2 = 0; iVar2 < uVar3; iVar2 = iVar2 + 1) {
          pcVar21 = loc._gp;
          if (iVar2 != 0) {
              uVar4 = (**(loc._gp + -0x7fb4))(param_5);
              (**(loc._gp + -0x7ef0))("           %.*s", uVar4, "                ");
          }
          iVar17 = ppuVar16 + 2;
          ppuVar16 = ppuVar16 + 4;
          (**(pcVar21 + -0x7f48))(iVar17, auStack_10b4);  // Vulnerable strcpy-like call
          (**(loc._gp + -0x7f1c))(auStack_10b4);
      }
      return 0;
  }
  ```
- **Keywords:** argv, ioctl commands, auStack_10b4
- **Notes:** The function at offset -0x7f48 from loc._gp is likely strcpy based on the two-argument call and the presence of strcpy in the import table. The buffer auStack_10b4 is only 127 bytes, and user input from command-line arguments can exceed this size. Further analysis is needed to confirm the exact exploitation scenario, including the availability of the binary to non-root users and the stack layout for successful code execution. Additional functions like fcn.00400f1c and fcn.00401154 should be examined for similar vulnerabilities.

---
### BufferOverflow-callback_ccp_hnap

- **File/Directory Path:** `sbin/ncc2`
- **Location:** `ncc2:0x0047b3b0 callback_ccp_hnap`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A potential buffer overflow vulnerability exists in the HNAP request handler (callback_ccp_hnap) where user-controlled input from network requests is copied into fixed-size stack buffers without proper bounds checking. Specifically, the function uses a string copy operation (likely strcpy) to copy data from the input parameter (param_2+0x41) into a 128-byte buffer (auStack_4b0) and a 1024-byte buffer (auStack_430). The lack of length validation before copying allows an attacker to overflow the buffer by sending a crafted HNAP request with excessive data. This could lead to arbitrary code execution if the stack is executable or via return-oriented programming (ROP) in the MIPS architecture. The vulnerability is triggered when processing HNAP requests, which are accessible to authenticated users via network interfaces.
- **Code Snippet:**
  ```
  // Decompiled code from callback_ccp_hnap
  uchar auStack_4b0 [128]; // 128-byte buffer on stack
  uchar auStack_430 [1024]; // 1024-byte buffer on stack
  // ...
  // Copy user input from param_2+0x41 into auStack_4b0 without bounds check
  (**(iVar10 + -0x7f18))(auStack_4b0, param_2 + 0x41); // Likely strcpy equivalent
  // Similar copies to auStack_430 and other buffers occur later in the function
  ```
- **Keywords:** HNAP protocol, SOAP action parameters, network interface
- **Notes:** The evidence is based on decompilation analysis showing unchecked copy operations. However, further validation is needed to confirm the exact function used (e.g., strcpy) and to test exploitability in a real environment. The binary is for MIPS architecture, and exploitation may require specific techniques due to platform constraints. Additional input points like CGI handlers should be investigated for similar issues.

---
### XSS-FileFolderDisplay

- **File/Directory Path:** `wa_www/folder_view.asp`
- **Location:** `folder_view.asp: function show_folder_content (approx. lines 300-400) and function get_sub_tree (approx. lines 350-400)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** A Cross-Site Scripting (XSS) vulnerability exists in the file list and folder tree display. File names and folder names (user-controlled input) are not HTML-escaped when displayed and are directly inserted into innerHTML and event handlers. An attacker can create or upload file names or folder names containing malicious scripts (for example: <script>alert('XSS')</script>). When other users view the file list or navigate the folder tree, the script will execute in their browser. This may lead to session theft, privilege escalation, or other malicious actions. Trigger condition: After the attacker uploads a file or creates a folder, the victim views the relevant page. Exploitation method: The attacker uses valid login credentials to upload a malicious file and tricks an administrator or other user into accessing the file management page.
- **Code Snippet:**
  ```
  // In the show_folder_content function
  cell_html = "<input type=\"checkbox\" id=\"" + sum + "\" name=\"" + file_name + "\" value=\"1\" class=\"chk\" onclick=\"shiftkey(event);\" />"
                  + "<a href=\"" + APIGetFileURL(path,volid,file_name) + "\" target=\"_blank\">"
                  + "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div></a>";
  // In the get_sub_tree function
  my_tree += "<li id=\"" + li_id + "\" class=\"tocollapse\">"
          + "<a href=\"#\" title=\"" + obj.name + "\" " 
          + "onClick=\"click_folder('" + li_id + "', '" + current_volid + "', '" + obj.mode + "')\">"
          + obj.name + "</a></li>"
          + "<li></li>"
          + "<li><span id=\"" + li_id + "-sub\"></span></li>";
  ```
- **Keywords:** file_name, folder_name, APIGetFileURL, show_folder_content, get_sub_tree, current_path, current_volid
- **Notes:** This is a stored XSS vulnerability. The attack chain is complete and verifiable from the front-end code. It is recommended to add input validation and output encoding on the backend. Related files: May affect all pages using the same display logic. Subsequent checks should examine the backend API implementation to ensure path traversal and file upload vulnerabilities are mitigated.

---
### FileUpload-API_UploadFile

- **File/Directory Path:** `wa_www/file_access.asp`
- **Location:** `file_access.asp:btn_upload function and dlg_upload_ok function (approximately lines 450-500)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The file upload function is processed via the '/dws/api/UploadFile' API, but the client-side code does not validate file types, relying solely on backend checks. An attacker could potentially upload malicious files (such as a webshell). If the backend does not strictly restrict file types or paths, it could lead to remote code execution. Trigger condition: An attacker uses the upload function to submit a malicious file and tricks a user or the system into accessing that file. The exploitation method depends on the backend configuration, but based on the client-side code, the lack of client-side validation increases the risk.
- **Code Snippet:**
  ```
  function btn_upload()
  {
      $('#wfa_file').val('');
      $('#wfa_tok').val('');
      $('#upload_form').show();
      upload_count = 0;
      clearInterval(polling_id);
      $('#dlg_upload').dialog('open');
  }
  
  function dlg_upload_ok(obj)
  {
      if ($('#wfa_file').val() == '') {
          alert('Select a file');
          return;
      }
      var rand = gen_rand_num(32);//generate 32 bytes random number
      var arg1 = '/dws/api/UploadFile?id='+session_id+rand;
      $('#wfa_id').val(session_id);
      $('#wfa_path').val(cur_path);
      $('#wfa_volid').val(cur_volId);
      $('#wfa_tok').val(rand+hex_hmac_md5(session_tok, arg1));
      document.getElementById('form1').action = '/dws/api/UploadFile';
      document.getElementById('form1').target = 'upload_target';
      $('#form1').submit();
      $(obj).dialog("close");
      setTimeout('delay_refresh_ctx()', 1000);
  }
  ```
- **Keywords:** /dws/api/UploadFile, wfa_file, form1
- **Notes:** The risk depends on the backend implementation. If the backend allows execution of uploaded files (such as PHP files), it could lead to a serious vulnerability. It is recommended to check the backend code to confirm file type validation and storage path security. The attack chain is complete, but it requires a corresponding backend vulnerability to be fully exploited.

---
### XSS-file_access_show_content_update_tree

- **File/Directory Path:** `wa_www/file_access.asp`
- **Location:** `file_access.asp:show_content function (approximately lines 350-400) and update_tree function (approximately lines 250-280)`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** In the 'file_access.asp' file, user-controlled folder and file names are not escaped when output to HTML, leading to a reflected cross-site scripting (XSS) vulnerability. Attackers can create malicious folders or files (for example, names containing JavaScript code). When other logged-in users browse the file manager, the malicious script will execute in their browsers. This may lead to session hijacking, unauthorized operations, or data theft. Trigger conditions include: users accessing the file management page and viewing folders or files containing malicious names. The vulnerability exists in multiple functions where user input is directly concatenated into HTML strings.
- **Code Snippet:**
  ```
  // In the show_content function:
  content_msg += '<tr class=listCtx onclick="ctxClick(\''+rPath+folders[i].name+'\', \''+ulId+'/'+folders[i].name+'\', \'1\')">';
  content_msg += "<td class=listName><img src="+extIcon+">&nbsp;"+files[i].name+"</td>";
  
  // In the update_tree function:
  branches += '<li><span class=folder>'+dispName+'</span>'+
      '<ul id="'+ulId+'/'+dispName+'"'+
      ' url="req_subfolder(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')"'+
      ' clr="req_ctx(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')">'+
      '</ul></li>';
  ```
- **Keywords:** folders[i].name, files[i].name, /dws/api/ListDir, /dws/api/ListFile, /dws/api/AddDir
- **Notes:** The vulnerability is highly exploitable because an attacker only needs to create a malicious folder or file (via the upload or create folder function) to trigger the XSS. User interaction is required (browsing the file manager), but as a logged-in user, the risk is significant. It is recommended to perform HTML escaping on user input. Subsequent verification can check if the backend API filters input.

---
### XSS-login_asp_json_ajax

- **File/Directory Path:** `wa_www/login.asp`
- **Location:** `login.asp: ~line 80-120 (check function), pandoraBox.js: ~line 600-650 (json_ajax function)`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** A reflected cross-site scripting (XSS) vulnerability exists in the login authentication mechanism of 'login.asp'. The vulnerability allows an attacker to inject and execute arbitrary JavaScript code via the username field, leading to session cookie theft and account hijacking. The attack triggers when a user submits a malicious username that causes the server to return an HTML error response containing the unsanitized username. The client-side 'json_ajax' function in 'pandoraBox.js' handles such errors by writing the raw response to the document using 'document.write', executing any embedded scripts. This requires the user to attempt login with the malicious username and fail, which can be achieved through social engineering. The stolen cookies ('uid', 'id', 'key') can then be used to impersonate the user and access their account.
- **Code Snippet:**
  ```
  From login.asp:
  \`\`\`javascript
  function check() {
      // ...
      var username = $("#username").val();
      var password = $("#password").val();
      // First AJAX call to get challenge
      var param = { url: 'dws/api/Login', arg: '' };
      var data = json_ajax(param);
      // Second AJAX call with username and hashed password
      param.arg = 'id=' + username + '&password=' + digs;
      var data = json_ajax(param);
      // ...
  }
  \`\`\`
  From pandoraBox.js:
  \`\`\`javascript
  function json_ajax(param) {
      // ...
      var ajax_param = {
          type: "POST",
          async: false,
          url: param.url,
          data: param.arg,
          dataType: "json",
          success: function(data) {
              if (data['status'] != 'fail') {
                  myData = data;
                  return;
              }
              alert('Error: ' + drws_err[data['errno']]);
              // ...
          },
          error: function(xhr, ajaxOptions, thrownError) {
              if (xhr.status == 200) {
                  try {
                      setTimeout(function() {
                          document.write(xhr.responseText);
                      }, 0);
                  } catch (e) {}
              } else {}
          }
      };
      // ...
  }
  \`\`\`
  ```
- **Keywords:** username input field in login.asp, dws/api/Login endpoint, json_ajax function in pandoraBox.js, document.cookie
- **Notes:** This vulnerability requires the server to reflect the username in error responses without proper sanitization, which is a common practice. The attack depends on user interaction (entering a malicious username) and a failed login attempt. While the user is a non-root user, session hijacking could lead to unauthorized access to the user's privileges. Further verification should include testing the 'dws/api/Login' endpoint with malicious input to confirm server-side reflection. Additional analysis of other pages may reveal more severe vulnerabilities, but this is the most exploitable issue found in 'login.asp'.

---
### PathTraversal-API_ListDir_GetFile

- **File/Directory Path:** `wa_www/file_access.asp`
- **Location:** `file_access.asp: req_subfolder function (approximately lines 150-180) and fileClick function (approximately lines 320-350)`
- **Risk Score:** 6.0
- **Confidence:** 6.5
- **Description:** Path parameters (such as 'path' and 'volid') are used directly in multiple API calls (such as '/dws/api/ListDir', '/dws/api/GetFile') without apparent client-side validation. If the backend does not properly sanitize the input, it may lead to path traversal attacks, allowing attackers to access sensitive system files. Trigger condition: An attacker manipulates the 'path' parameter (for example, using '../') to access restricted directories. Exploitation method: By modifying the 'path' value in AJAX requests, attempt to read or download system files.
- **Code Snippet:**
  ```
  function req_subfolder(path, ulId, volId) 
  {
      var param = {
          url: '/dws/api/ListDir',
          arg: 'id='+session_id+'&path='+urlencode(path)+'&volid='+volId
      };
      // ...
  }
  
  function fileClick(path, filename, volId)
  {
      var rand = gen_rand_num(32);//generate 32 bytes random number
      var arg1 = '/dws/api/GetFile?id='+session_id+rand;
      $('#get_wfa_id').val(session_id);
      $('#get_wfa_path').val(urlencode(path));
      $('#get_wfa_volid').val(volId);
      $('#get_wfa_file').val(urlencode(filename));
      $('#get_wfa_tok').val(rand+hex_hmac_md5(session_tok, arg1));
      document.getElementById('form2').target = 'upload_target';
      $('#form2').submit();
  }
  ```
- **Keywords:** path, volid, /dws/api/ListDir, /dws/api/GetFile, req_subfolder, fileClick
- **Notes:** Vulnerability exploitability depends on the backend not performing strict path validation. The urlencode function may not be sufficient to prevent path traversal. It is recommended to check the backend API implementation. The attack chain may be incomplete and requires backend vulnerability verification.

---
### NULL-Pointer-Dereference-pptp_inbound_pkt

- **File/Directory Path:** `lib/modules/2.6.30.9/kernel/net/ipv4/netfilter/nf_nat_pptp.ko`
- **Location:** `nf_nat_pptp.ko:Unknown line number sym.pptp_inbound_pkt function`
- **Risk Score:** 5.0
- **Confidence:** 7.0
- **Description:** A NULL pointer dereference vulnerability was discovered in the sym.pptp_inbound_pkt function. The code calls (*NULL)(), and when processing specific PPTP inbound packets, if the value of a field in the packet (uVar1, possibly corresponding to PPTP message type or other identifier) is 0xb (11) or 0xc to 0xf (12-15), it will cause a kernel crash (denial-of-service). An attacker, as a non-root user with valid login credentials, can trigger this vulnerability by sending malicious PPTP packets over the network (using TCP port 1723 or GRE). The vulnerability trigger condition depends on the packet content, lacking proper input validation and boundary checks. The potential exploitation method is only DoS; no privilege escalation or other more severe attack chains have been discovered.
- **Code Snippet:**
  ```
  uVar1 = *in_a3;
  if (uVar1 != 0xb) {
      if (uVar1 < 0xc) {
          if (uVar1 != 8) {
              return true;
          }
          halt_baddata();
      }
      if (2 < uVar1 - 0xd) {
          halt_baddata();
      }
  }
  iVar2 = (*NULL)();
  return iVar2 != 0;
  ```
- **Keywords:** PPTP packet field (uVar1), TCP port 1723, GRE protocol
- **Notes:** This vulnerability only leads to denial-of-service; no complete attack chains such as privilege escalation have been discovered. Further validation of the PPTP packet format is needed to confirm the specific meaning of uVar1. It is recommended to analyze other functions (such as sym.pptp_outbound_pkt) to look for similar issues. Since it is a kernel module, the vulnerability may affect system stability, but the exploitation conditions are limited.

---
### Client-JS-Injection-deviceinfo.js

- **File/Directory Path:** `www/config/deviceinfo.js`
- **Location:** `deviceinfo.js:1 DeviceInfo()`
- **Risk Score:** 3.0
- **Confidence:** 8.0
- **Description:** The 'deviceinfo.js' file is globally writable (permissions: rwxrwxrwx) and is dynamically loaded by 'features.js' using $.getScript in a client-side JavaScript context. An attacker with non-root login credentials can modify this file to inject malicious JavaScript code, which will execute in the browser of any user who accesses the web page that relies on 'features.js'. This could lead to client-side attacks such as session hijacking or configuration tampering within the web interface. However, the vulnerability is limited to client-side execution and does not provide a direct path to system-level privilege escalation or remote code execution on the device. The trigger condition is when the web page loading 'features.js' is accessed, and the exploitation requires the attacker to have write access to the file, which is already available due to the permissions.
- **Code Snippet:**
  ```
  // From deviceinfo.js
  function DeviceInfo()
  {
  	this.bridgeMode = true;
  	this.featureVPN = true;
  	// ... other properties
  }
  
  // From features.js
  $.getScript("/config/deviceinfo.js", function(){
  	DeviceInfo.prototype = new CommonDeviceInfo();
  	DeviceInfo.prototype.constructor = DeviceInfo;
  	var currentDevice = new DeviceInfo();
  	sessionStorage.setItem('currentDevice', JSON.stringify(currentDevice));
  });
  ```
- **Keywords:** /config/deviceinfo.js, /config/features.js
- **Notes:** This finding is based on direct evidence of file permissions and code usage. The risk is low because the exploitation is confined to the client-side and does not escalate privileges on the device. Further analysis could involve checking if the web server or other server-side components use these files, but based on the current code, it appears to be client-only. No additional input sources or cross-component interactions were identified in this analysis.

---
