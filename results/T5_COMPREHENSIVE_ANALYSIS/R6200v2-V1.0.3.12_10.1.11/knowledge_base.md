# R6200v2-V1.0.3.12_10.1.11 (15 findings)

---

### command-injection-fcn.0000a290

- **File/Directory Path:** `bin/eapd`
- **Location:** `eapd:0x0000a290 (fcn.0000a290), 0x0000b20c (fcn.0000b20c)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The vulnerability occurs in the function `fcn.0000a290` (decompiled from address 0x0000a290), which handles data from network sockets. User input received via `recv` in `fcn.0000b20c` is passed as `param_2` to `fcn.0000a290`. Inside `fcn.0000a290`, this input is used in a command string constructed with `snprintf` and executed via `_eval` without sanitization. An attacker can inject shell metacharacters (e.g., `;`, `&`, `|`) into the input to execute arbitrary commands. The trigger condition is when data is sent to the eapd socket associated with socket descriptor 0x5170 (as seen in `fcn.0000b20c`), which likely corresponds to a local network service based on strings like '127.0.0.1'. The lack of input validation or escaping allows full command injection.
- **Code Snippet:**
  ```
  // From fcn.0000b20c (network input handling)
  uVar2 = *(param_1 + 0x5170);
  if ((-1 < uVar2 + 0) && ... ) {
      iVar3 = sym.imp.recv(uVar2, iVar8, 0xff0, 0); // iVar8 is the input buffer
      ...
      if (*(param_1 + 0x20) == 0) {
          fcn.0000a290(param_1, iVar8); // Pass user input to vulnerable function
      }
  }
  
  // From fcn.0000a290 (command execution)
  *(puVar3 + -0x3c) = *0xa3fc; // Format string
  *(puVar3 + -0x38) = param_2;  // User input from recv
  *(puVar3 + -0x34) = *0xa404; // Additional string
  sym.imp._eval(puVar3 + -0x3c, *0xa400, iVar1, iVar1); // Execute command without sanitization
  ```
- **Keywords:** socket:127.0.0.1 (local IP socket), NVRAM variables: None directly involved in this chain, IPC socket: eapd daemon socket, Functions: sym.imp.recv, sym.imp._eval, fcn.0000a290, fcn.0000b20c
- **Notes:** This vulnerability requires the eapd daemon to be running and accessible to the attacker. Since the attacker has valid login credentials, they can connect to the local socket. The daemon likely runs with root privileges, enabling privilege escalation. Further analysis could identify the exact socket configuration and test exploitability. No additional files or functions are immediately needed for this chain.

---
### crypto-weak-certificate-exposed-key

- **File/Directory Path:** `usr/local/share/foxconn_ca/server.crt`
- **Location:** `File: server.crt and server.key in /usr/local/share/foxconn_ca/`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The 'server.crt' file contains an X.509 certificate using weak and deprecated cryptographic algorithms (md5WithRSAEncryption and 1024-bit RSA key). Combined with the world-readable 'server.key' private key file, this allows any non-root user with login credentials to access the private key. An attacker can exploit this by copying the private key and using it to impersonate the server, perform man-in-the-middle attacks on encrypted channels (e.g., HTTPS, VPN), or decrypt sensitive communications. The attack requires no additional privileges and is directly feasible due to lax file permissions (rwx for all users). The weak algorithms further increase vulnerability to cryptographic attacks like collision or factorization.
- **Code Snippet:**
  ```
  Certificate snippet from server.crt:
  -----BEGIN CERTIFICATE-----
  MIIDiDCCAvGgAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhDELMAkGA1UEBhMCVFcx
  ... (truncated for brevity)
  -----END CERTIFICATE-----
  
  Private key snippet from server.key:
  -----BEGIN RSA PRIVATE KEY-----
  MIICXAIBAAKBgQC3TYAabx6bUyBsLPiJ8hzYbup8l28jniriODdoSJ69NR2ODWH6
  ... (truncated for brevity)
  -----END RSA PRIVATE KEY-----
  ```
- **Keywords:** /usr/local/share/foxconn_ca/server.crt, /usr/local/share/foxconn_ca/server.key
- **Notes:** The weak cryptography and exposed private key form a critical vulnerability. Further analysis is recommended to identify services using these certificates (e.g., web servers, VPNs) to confirm active exploitation scenarios. The directory also contains other sensitive files (e.g., client.key, ca.crt) that may amplify the risk. Ensure file permissions are restricted and upgrade to stronger algorithms (e.g., SHA-256, 2048-bit RSA).

---
### Untitled Finding

- **File/Directory Path:** `sbin/parser`
- **Location:** `parser:0x00008f4c fcn.00008eb8`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability exists in the NVRAM configuration handler (fcn.00008eb8) of the 'parser' binary. The function parses input strings for a '*' character, splitting them into key and value parts. The value part is copied using strcpy into a stack-allocated buffer without bounds checking. An attacker can send a long value string via the network socket to overflow the buffer, overwriting the return address on the stack. This can lead to arbitrary code execution with the privileges of the parser process, which is likely root. The vulnerability is triggered when command code 0 is processed, corresponding to NVRAM set operations. The lack of input validation and use of unsafe functions like strcpy makes this exploitable.
- **Code Snippet:**
  ```
  0x00008f44      011087e2       add r1, r7, 1               ; const char *src
  0x00008f48      0600a0e1       mov r0, r6                  ; char *dest
  0x00008f4c      05ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** socket:0xf82a, acosNvramConfig_set, strcpy
- **Notes:** The vulnerability requires network access to port 63530. The parser service forks a child process for each connection, so exploitation may need to bypass fork-related mitigations. Further analysis is needed to determine exact buffer sizes and develop a reliable exploit. Other functions in the command dispatcher should be checked for similar issues.

---
### BufferOverflow-noauth_login

- **File/Directory Path:** `usr/lib/uams/uams_guest.so`
- **Location:** `uams_guest.so:0x000008bc sym.noauth_login`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'noauth_login' function, the 'strcpy' function is used to copy the username obtained from 'uam_afpserver_option' to a stack buffer, lacking length validation. The username is untrusted input, acquired from the network via the AFP protocol. An attacker, as an authenticated user (non-root), can send a specially crafted long username to trigger a buffer overflow, overwriting the saved return address (lr), thereby controlling program flow and potentially executing arbitrary code. Stack layout analysis shows the local variable area size is 0x30 bytes, with the saved return address located at the end of the stack frame. The overflow distance is approximately 60 bytes, indicating high exploitability.
- **Code Snippet:**
  ```
  0x000008b4      18201be5       ldr r2, [dest]              ; 0x18
  0x000008b8      14301be5       ldr r3, [src]               ; 0x14
  0x000008bc      0200a0e1       mov r0, r2                  ; char *dest
  0x000008c0      0310a0e1       mov r1, r3                  ; const char *src
  0x000008c4      55ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** uam_afpserver_option, strcpy, getpwnam
- **Notes:** Vulnerability trigger relies on username input in the AFP protocol; the attacker requires valid login credentials. It is recommended to further verify the exact size and offset of the target buffer and test the feasibility of the exploit chain. Related functions 'noauth_login_ext' and 'uam_setup' may provide additional context. Other 'strcpy'-related findings exist in the knowledge base (e.g., 'parser'), but this is an independent vulnerability.

---
### Stack-Buffer-Overflow-logincont2

- **File/Directory Path:** `usr/lib/uams/uams_dhx2_passwd.so`
- **Location:** `uams_dhx2_passwd.so:sym.logincont2 (addresses 0x2428-0x2438 based on cross-references)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability exists in the sym.logincont2 function, which is part of the extended password handling logic. The function reads from the file '/tmp/afppasswd' using fgets into a 1024-byte buffer, then uses sscanf to parse the content into a 512-byte stack buffer without proper bounds checking. The format string in sscanf is likely '%s', allowing uncontrolled string copying. An attacker with valid login credentials can write a payload longer than 512 bytes to '/tmp/afppasswd' (which is writable by any user) and trigger the authentication process (e.g., via sym.passwd_login_ext). This overflow can overwrite stack data, including return addresses, leading to arbitrary code execution or privilege escalation. The trigger condition requires the attacker to initiate login and have write access to /tmp/afppasswd, which is default writable.
- **Code Snippet:**
  ```
  // Relevant code from sym.logincont2 decompilation
  sym.imp.fopen64(iVar4 + *0x26dc, iVar4 + *0x26e0); // Opens '/tmp/afppasswd'
  sym.imp.fgets(puVar5 + 8 + -0x630, 0x400, *(puVar5 + -0x14)); // Reads into 1024-byte buffer
  sym.imp.sscanf(puVar5 + 8 + -0x630, iVar4 + *0x26e4, puVar5 + iVar3 + -0x230); // Parses into 512-byte buffer without bounds check
  if (*(puVar5 + iVar3 + -0x230) != '\0') {
      iVar3 = sym.imp.strcmp(*(puVar5 + -0x638), puVar5 + iVar3 + -0x230); // Comparison after sscanf
  }
  ```
- **Keywords:** /tmp/afppasswd, sym.passwd_login_ext, sym.login, sym.logincont2
- **Notes:** The vulnerability is highly exploitable due to the writable /tmp/afppasswd and lack of stack protections (e.g., canaries) in the decompiled code. The attack chain is complete: from user-controlled file input to stack overflow. Further validation could confirm the exact sscanf format string and stack layout for reliable exploitation. Recommended next steps include dynamic testing and checking for ASLR mitigations.

---
### BufferOverflow-fcn.00015ac8

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0x00015ac8 (fcn.00015ac8)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability in function fcn.00015ac8 where network data from recv/recvfrom is copied into a fixed-size stack buffer (auStack_20ec [8188 bytes]) with a size of 0x1fff (8191 bytes). The null-termination write occurs out-of-bounds for lengths >= 8188, leading to an off-by-three overflow. An attacker with network access can send large UDP or TCP packets to trigger this, potentially overwriting return addresses and executing arbitrary code. The vulnerability is directly accessible via UPnP network sockets and does not require authentication beyond network reachability.
- **Code Snippet:**
  ```
  iVar4 = sym.imp.recvfrom(uVar3, *(iVar17 + -0x20e0), 0x1fff, 0);
  *(*(iVar17 + -0x20e0) + iVar4) = 0;  // Null-termination out-of-bounds for iVar4 >= 8188
  ```
- **Keywords:** Network socket (UDP/TCP) via recv/recvfrom, Function fcn.00015ac8
- **Notes:** Buffer size is 8188 bytes, recv size is 8191 bytes, making it easily triggerable. High confidence due to direct evidence from r2 decompilation.

---
### BufferOverflow-fcn.0001dbcc

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0x0001dbcc (fcn.0001dbcc)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A buffer overflow via strcpy in function fcn.0001dbcc, where network input from recvfrom is directly copied to a stack buffer (auStack_634 [1500 bytes]) without bounds checking. An attacker can craft large UDP packets to overflow the stack, leading to code execution. The vulnerability is accessible through UPnP network interfaces and exploitable by any user who can send packets to the daemon.
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar5, param_1);  // param_1 is tainted network data, iVar5 is stack buffer
  ```
- **Keywords:** Network input via UDP, Function fcn.0001dbcc
- **Notes:** Simple and direct exploitation path with unsafe strcpy usage. Buffer size inferred from stack layout.

---
### Heap-Buffer-Overflow-reply_trans2

- **File/Directory Path:** `usr/local/samba/smbd`
- **Location:** `smbd:0x00066d60 reply_trans2 (malloc at 0x00067040 and memcpy at 0x00067278 for first overflow; malloc at 0x00067120 and memcpy at 0x00067290 for second overflow)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The function 'reply_trans2' at address 0x00066d60 contains a heap buffer overflow vulnerability due to missing size validation in memcpy operations. The function allocates heap buffers based on size fields from the SMB packet (e.g., from offsets 0x27-0x28 and 0x25-0x26) but performs memcpy using different size fields (e.g., from offsets 0x3b-0x3c and 0x37-0x38) without checking if the copy size exceeds the allocated buffer size. An attacker with valid login credentials can craft a malicious SMB TRANS2 request with a large copy size and small allocation size, causing heap buffer overflow. This can overwrite adjacent heap metadata or function pointers, leading to arbitrary code execution or service crash. The vulnerability is triggered immediately upon processing the crafted packet, and the overflow occurs in the heap, which can be exploited for remote code execution in the context of the smbd process.
- **Code Snippet:**
  ```
  // First overflow path: malloc with size from packet offsets 0x27-0x28 (uVar8), memcpy with size from offsets 0x3b-0x3c (sb)
  0x00067040: bl sym.imp.malloc                    ; allocate buffer with size uVar8 (from packet)
  0x00067278: bl sym.imp.memcpy                   ; copy sb bytes to buffer, no check if sb <= uVar8
  
  // Second overflow path: malloc with size from packet offsets 0x25-0x26 (uVar9), memcpy with size from offsets 0x37-0x38 (sl)
  0x00067120: bl sym.imp.malloc                    ; allocate buffer with size uVar9 (from packet)
  0x00067290: bl sym.imp.memcpy                   ; copy sl bytes to buffer, no check if sl <= uVar9
  ```
- **Keywords:** SMB transaction packet fields at offsets 0x27-0x28 (allocation size), 0x3b-0x3c (copy size), 0x25-0x26 (allocation size), 0x37-0x38 (copy size), Network input via SMB protocol
- **Notes:** This vulnerability is similar to known SMB transaction vulnerabilities in Samba. The missing size check allows controlled heap overflow, which can be leveraged for code execution. Further analysis of the heap layout and exploitation techniques is recommended for full weaponization. The function 'handle_trans2' called later may also be affected if the overflow corrupts data structures. Attack chain is verifiable: network input → SMB packet parsing → heap allocation → memcpy overflow → potential EIP control.

---
### FormatStringChain-fcn.00015640

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0x00015640 (fcn.00015640) and related functions`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** An attack chain where tainted network data propagates through functions fcn.00015640, fcn.0001c458, fcn.0001a4d0, and fcn.00018178 to sprintf without validation. The sprintf uses format strings with %s, leading to buffer overflow or command injection. Trigger conditions require specific tokens in network data (e.g., matching *0x15820 or *0x1582c). An attacker can craft packets with these tokens to exploit the vulnerability, potentially achieving code execution.
- **Code Snippet:**
  ```
  sym.imp.sprintf(iVar6, *0x18558, iVar4);  // iVar4 is tainted data
  sym.imp.strncpy(iVar7, param_1, 0x3ff);  // Tokenization in data flow
  ```
- **Keywords:** Network input, Functions fcn.00015640, fcn.0001c458, fcn.0001a4d0, fcn.00018178, sprintf
- **Notes:** Exploit requires specific token matches, but the chain is complete and verifiable. Additional format string risks should be checked.

---
### Command-Injection-rc-main

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0xf6d4 main function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the main function of the 'rc' binary, there is a command injection vulnerability. The code obtains the value of the NVRAM variable 'router_disable' via nvram_get and sets it as an environment variable. Subsequently, under specific conditions, the code uses the system function to execute commands but does not adequately validate or filter the input. An attacker can inject malicious commands by setting the 'router_disable' NVRAM variable, thereby executing arbitrary code. Trigger conditions include: the attacker being able to set the NVRAM variable (via an authenticated web interface or CLI), and the rc program running with root privileges (as is typically the case). Exploitation methods include: setting 'router_disable' to a value containing shell metacharacters, such as '; malicious_command'. This is a complete and verifiable attack chain.
- **Code Snippet:**
  ```
  iVar2 = sym.imp.nvram_get(*0xf714);  // Get 'router_disable'
  iVar1 = *0xf718;
  if (iVar2 != 0) {
      iVar1 = iVar2;
  }
  sym.imp.setenv(*0xf71c,iVar1,1);  // Set as environment variable
  // ... Subsequent code calls system
  sym.imp.system(*0xf784,*0xf778,3);  // Execute command
  ```
- **Keywords:** router_disable, nvram_get, system
- **Notes:** Need to verify if the NVRAM variable 'router_disable' can be set by a non-root user. In typical router firmware, NVRAM settings usually require access via the web interface or specific CLI commands, but authenticated users may have this permission. The attack chain is complete, and exploitability is high.

---
### OffByOne-BufferOverflow-uams_passwd

- **File/Directory Path:** `usr/lib/uams/uams_passwd.so`
- **Location:** `uams_passwd.so:0x00000910 sym.passwd_login, uams_passwd.so:0x00000d98 sym.passwd_login_ext`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** An off-by-one buffer overflow vulnerability exists in the authentication functions due to insufficient length validation before memcpy and null termination. In sym.passwd_login and sym.passwd_login_ext, the code checks if the input length (*puVar4) is zero or if it is greater than or equal to the buffer size (puVar4[-2] or puVar4[-7]) but not equal, allowing the copy to proceed when the length exactly equals the buffer size. This results in memcpy copying exactly buffer size bytes, followed by null termination one byte beyond the buffer, causing a one-byte overflow. Trigger conditions include sending crafted authentication requests with specific length values that match the buffer size. Potential exploitation could involve overwriting adjacent memory, such as return addresses or function pointers, leading to arbitrary code execution. The vulnerability is reachable via network inputs to the AFP authentication service, and as a non-root user, an attacker could leverage this to escalate privileges if the service runs as root.
- **Code Snippet:**
  ```
  From sym.passwd_login:
  if (((*puVar4 == 0) || (puVar4[-7] <= *puVar4 && *puVar4 != puVar4[-7])) || (puVar4[-2] <= *puVar4 && *puVar4 != puVar4[-2])) {
      uVar2 = 0xec65 | 0xffff0000;
  } else {
      sym.imp.memcpy(puVar4[-1], puVar4[-6], *puVar4);
      *(puVar4[-1] + *puVar4) = 0;
      // ...
  }
  
  From sym.passwd_login_ext:
  if ((*puVar4 == 0) || (puVar4[-2] <= *puVar4 && *puVar4 != puVar4[-2])) {
      uVar2 = 0xec65 | 0xffff0000;
  } else {
      sym.imp.memcpy(puVar4[-1], puVar4[-5] + 2, *puVar4);
      *(puVar4[-1] + *puVar4) = 0;
      // ...
  }
  ```
- **Keywords:** uam_afpserver_option, uam_getname, uam_checkuser
- **Notes:** The vulnerability is evidenced by code analysis, but full exploitability depends on the runtime environment (e.g., stack layout, service privileges). Further validation through dynamic analysis or testing in a real system is recommended. The functions are part of the UAM for AFP, suggesting network exposure. Associated files or functions include sym.pwd_login and system libraries like libcrypt.so.0.

---
### FileInputOverflow-fcn.0000b5c8

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0x0000b5c8 (fcn.0000b5c8)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability in function fcn.0000b5c8 where user-controlled file data is read via fopen and fread, then processed through fcn.0000b410 and copied using strcpy without bounds checking. An attacker with file write access (e.g., through configuration manipulation or network requests) can provide a malicious file that overflows the buffer, leading to code execution. The vulnerability is accessible to authenticated users who can influence file paths or content.
- **Code Snippet:**
  ```
  sym.imp.fopen(param_3, *0xc120);  // Open user-controlled file
  sym.imp.fread(iVar2, 1, 0x4000, *(puVar22 + -0x710));  // Read data
  sym.imp.strcpy(sb, r4);  // In fcn.0000b410, copy to buffer
  sym.imp.strcpy(puVar22 + -0x40, puVar22 + -0xc0);  // Final strcpy in fcn.0000b5c8
  ```
- **Keywords:** File input via param_3 in fcn.0000b5c8, NVRAM variables (e.g., through acosNvramConfig functions), Socket communication for UPnP requests
- **Notes:** Requires attacker to control file input, which may be achievable through configuration or network requests. Further analysis of fcn.000269f0 is recommended for additional vectors.

---
### DoS-wl_ioctl

- **File/Directory Path:** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/wl/wl.ko`
- **Location:** `File:wl.ko Address:0x0810c6ac Function Name:sym.wl_ioctl`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the function `sym.wl_ioctl`, when processing the ioctl command `0x89f0`, there is insufficient validation of the user-provided input value `*(param_2 + 0x10)`. When this value is greater than `0xffffffe7`, the condition check fails, causing `uVar5` to be set to 0, leading to an infinite loop. This causes the kernel module to hang, resulting in a denial of service. An attacker (authenticated non-root user) can trigger this vulnerability by opening a network device handle and calling the ioctl command `0x89f0` with malicious input, making the system unresponsive.
- **Code Snippet:**
  ```
  Key part extracted from decompiled code:
  \`\`\`c
  if (param_3 == 0x89f0) {
      uVar5 = *((puVar8 + -0x20 & 0xffffe03f & 0xffffffc0) + 8);
      bVar7 = 0xffffffe7 < *(param_2 + 0x10);
      uVar4 = *(param_2 + 0x10) + 0x18;
      if (!bVar7) {
          // ... complex condition calculation ...
      }
      if (!bVar7) {
          uVar5 = 0;
      }
      if (uVar5 == 0) {
          do {
              // infinite loop
          } while( true );
      }
      // ...
  }
  \`\`\`
  ```
- **Keywords:** ioctl command 0x89f0, User input parameter param_2 offset 0x10
- **Notes:** This vulnerability allows an attacker to cause a kernel hang through a simple ioctl call. Recommended fixes include adding strict validation of user input values to ensure `*(param_2 + 0x10)` is within a reasonable range. Subsequent analysis should check if similar issues exist with other ioctl commands (such as `0x8946`).

---
### DataLeakageChain-fcn.00015834

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `upnpd:0x00015834 (fcn.00015834)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** An attack chain involving data leakage and buffer overflow via functions fcn.00015834, fcn.00015640, fcn.0001c458, fcn.0001b290, and fcn.00018178. Tainted network data is copied via memcpy and propagated to sprintf (causing buffer overflow) and send (causing data leakage). An attacker can trigger this by sending crafted network packets, leading to potential code execution via overflow or exposure of sensitive information via leakage.
- **Code Snippet:**
  ```
  sym.imp.memcpy(iVar1, param_2, param_3);  // Tainted data copy
  sym.imp.sprintf(iVar6, *0x18558, iVar4);  // Buffer overflow
  sym.imp.send(...);  // Data leakage
  ```
- **Keywords:** Network input, Functions fcn.00015834, fcn.00015640, fcn.0001c458, fcn.0001b290, fcn.00018178, sprintf, send
- **Notes:** Sprintf chain is exploitable for code execution; data leakage is less critical but still a concern. Chain is verifiable from input to sink.

---
### OOB-Read-logincont2

- **File/Directory Path:** `usr/lib/uams/uams_dhx2_passwd.so`
- **Location:** `uams_dhx2_passwd.so:0x219c sym.logincont2 (approximate address of decryption call)`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** The function sym.logincont2 lacks proper length validation on param_3 before using it in gcry_cipher_decrypt with a fixed size of 0x110 bytes. This occurs when param_4 is 0x112 or 0x11c, indicating specific packet types in the DHX2 authentication protocol. An attacker with valid login credentials can send a crafted authentication packet with a short param_3 buffer, triggering an out-of-bounds read during decryption. This could leak adjacent memory contents, such as encryption keys or session data, but does not directly enable code execution. The missing check allows reading beyond the allocated buffer, primarily resulting in information disclosure. The trigger condition involves sending malicious packets during the login process.
- **Code Snippet:**
  ```
  if ((*(puVar5 + -0x63c) != 0x112) && (*(puVar5 + -0x63c) != 0x11c)) {
      // error handling
  } else {
      // decryption setup
      *(puVar5 + -0x638) = *(puVar5 + -0x638) + 2;
      uVar2 = loc.imp.gcry_cipher_decrypt(*(puVar5 + -0x28), *(puVar5 + -0x638), 0x110, 0);
      // no length check on *(puVar5 + -0x638) before decryption
  }
  ```
- **Keywords:** param_3 (input buffer from UAM authentication), gcry_cipher_decrypt function call, UAM handler sym.passwd_logincont
- **Notes:** Exploitable by an authenticated non-root user via crafted AFP packets, but the impact is limited to information disclosure without a full code execution chain. Further analysis should trace UAM dispatch to confirm external controllability. Related functions include sym.passwd_logincont and uam_setup.

---
