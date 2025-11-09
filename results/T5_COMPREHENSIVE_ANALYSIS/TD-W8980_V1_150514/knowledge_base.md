# TD-W8980_V1_150514 (4 findings)

---

### permission-etc-group

- **File/Directory Path:** `etc/group`
- **Location:** `etc/group`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The /etc/group file has world-writable permissions (rwxrwxrwx), allowing any non-root user with login credentials to modify group memberships. This vulnerability can be triggered by simply editing the file using standard text editors or commands. Attackers can add themselves to privileged groups (e.g., root, wheel) to gain elevated privileges. For example, adding to the 'wheel' group might allow sudo access if configured, or adding to the 'root' group could grant access to root-owned files. The exploitation requires the attacker to write to the file and may necessitate a re-login for group changes to take effect, but it is feasible and directly actionable.
- **Code Snippet:**
  ```
  File permissions: -rwxrwxrwx 1 user user 877 May 11 2015 group
  Relevant group entries (e.g., root group): root:x:0:root
  wheel group: wheel:x:10:root
  ```
- **Keywords:** /etc/group
- **Notes:** The risk is high due to the direct write capability, but full privilege escalation may depend on ancillary system configurations (e.g., /etc/sudoers). No additional files in the current directory were analyzed, as the task was focused solely on 'group'. Recommend verifying sudo configurations and monitoring for unauthorized group modifications.

---
### Untitled Finding

- **File/Directory Path:** `usr/bin/cwmp`
- **Location:** `bin/cwmp:0x00404974 In function parseSetParameterValues (fcn.00404974)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** When parsing a SOAP SetParameterValues request, the function uses strncpy to copy parameter values to a small buffer on the stack, but does not adequately validate the input length, leading to a stack buffer overflow. The specific issue occurs when processing string-type parameter values: the code uses strncpy(&uStack_c28, uStack_f30, iVar7), where &uStack_c28 may point to a small stack buffer (possibly only 1 byte), and iVar7 is a controllable length from the input. If iVar7 is sufficiently large, it will overwrite the return address or other critical data on the stack, allowing an attacker to execute arbitrary code. The trigger condition is sending a SetParameterValues SOAP request containing a long parameter value. Potential exploitation methods include overwriting the return address to control program flow, potentially achieving code execution on MIPS architecture through a carefully crafted payload. An attacker, as a logged-in non-root user, can exploit this vulnerability by sending a malicious request via the network or local interface.
- **Code Snippet:**
  ```
  // Relevant code snippet extracted from decompilation:
  sym.imp.strncpy(&uStack_c28, uStack_f30, iVar7);
  *(*0x74 + iVar7 + -0xc28) = 0;
  sym.imp.xml_unescapeString(&uStack_c28, iVar7 + 1, iVar2);
  // Where iVar7 is the length of the parameter value, from the input and controllable; &uStack_c28 is the stack buffer address.
  ```
- **Keywords:** SOAP SetParameterValues Request, ParameterValue Parameter, cwmp Service Network Interface
- **Notes:** This vulnerability requires further validation to confirm exploitability, such as through dynamic testing or building a complete attack payload. It is recommended to analyze other related functions (such as HTTP request processing) to determine how the input point reaches this code path. Additionally, check binary protection mechanisms (such as ASLR, stack protection) to assess the actual exploitation difficulty. Associated files may include configuration files or network service components. The attacker scenario is a logged-in non-root user, who may access the cwmp service via the local network.

---
### info-leak-passwd.bak

- **File/Directory Path:** `etc/passwd.bak`
- **Location:** `passwd.bak:1 (First line of file content)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The file 'passwd.bak' contains the password hash (MD5: $1$$iC.dUsGpxNNJGeOm1dFio/) for the admin user, and the file permissions are set to globally readable (-rwxrwxrwx), allowing any user to access it. An attacker (non-root user) can read this file, extract the hash, and use offline tools (such as John the Ripper or Hashcat) for dictionary or brute-force attacks. Once the hash is cracked, the attacker can obtain the admin password, thereby escalating privileges to root (because the admin user has UID 0). Trigger conditions include: the attacker having file read permissions, the hash being crackable (MD5 is weak), and the system potentially using this hash for authentication. The exploitation method involves simple file reading and subsequent offline attacks, requiring no additional system interaction.
- **Code Snippet:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** passwd.bak
- **Notes:** Evidence is based on file content and permission checks. It is recommended to further verify whether the system actually uses this 'passwd.bak' file for user authentication, or check if related processes (such as login services) reference this file. Associated files may include /etc/passwd or authentication modules. Subsequent analysis direction: check the system authentication mechanism and hash usage to confirm exploitability.

---
### Untitled Finding

- **File/Directory Path:** `usr/bin/smbd`
- **Location:** `smbd:0x0044b0bc sym.reply_sesssetup_and_X`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the function 'reply_sesssetup_and_X' when processing SMB session setup requests, there exists a stack buffer overflow vulnerability. Specific manifestation: When the first byte of the request data is not 'N', '`', or 0xa1, it enters the hexadecimal encoding path, using a fixed-size stack buffer (256 bytes). The input data length (iStack_788) comes from a user-controlled SMB request field (such as offset 0x33, 0x34 of param_2), and its size is not sufficiently validated. If the input data length is greater than 128 bytes, the hexadecimal encoding loop writes beyond the buffer boundary (for example, with a length of 129, it writes from index 0 to 257, while the buffer size is only 256 bytes), causing a stack overflow that may overwrite the return address or other critical data. Trigger condition: An attacker sends an SMB session setup request where the data part length is greater than 128 bytes and the first byte does not match the specific values. Constraints and boundary checks: The code lacks strict validation of the input data length, only checking via the loop condition, but the buffer size is fixed. Potential attacks and exploitation methods: An attacker can overwrite the return address with carefully crafted overflow data, control the program execution flow, and achieve arbitrary code execution. The probability of exploitation is high because the attacker only needs valid login credentials to send a malicious request.
- **Code Snippet:**
  ```
              sym.imp.memset(&uStack_45c,0,0x100);
              iVar15 = 0x80;
              if ((0xff < iStack_788 << 1) || (iVar15 = iStack_788, 0 < iStack_788)) {
                  pcVar11 = &uStack_45c + 1;
                  iVar6 = 0;
                  do {
                      if (pcStack_78c[iVar6] >> 4 < 10) {
                          cVar4 = '0';
                      }
                      else {
                          cVar4 = 'W';
                      }
                      pcVar11[-1] = cVar4 + (pcStack_78c[iVar6] >> 4);
                      cVar4 = 'W';
                      if ((pcStack_78c[iVar6] & 0xfU) < 10) {
                          cVar4 = '0';
                      }
                      *pcVar11 = cVar4 + (pcStack_78c[iVar6] & 0xf);
                      iVar6 = iVar6 + 1;
                      pcVar11 = pcVar11 + 2;
                  } while (iVar6 < iVar15);
              }
              uStack_35d = 0;
  ```
- **Keywords:** SMB request data field (such as the length field at offset 0x33, 0x34 of param_2), pcStack_78c (input data pointer), iStack_788 (input data length)
- **Notes:** The vulnerability exists in the core path of SMB session setup processing; the attack chain is complete: from network input (SMB request) to stack overflow. The attacker requires valid login credentials, but even a non-root user can exploit it. It is recommended to further verify the impact of the stack layout and mitigation measures (such as ASLR, stack protection), but embedded devices may lack protection, increasing exploitability. Other analyses (such as references to 'file_new', 'execl', and environment variables) did not reveal a complete attack chain, hence they are not included.

---
