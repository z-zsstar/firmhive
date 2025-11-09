# R7000 (6 alerts)

---

### remote-script-command-injection

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Critical security vulnerabilities found in the etc/init.d/remote.sh script: 1) Symbolic links created in /tmp/www/cgi-bin pointing to remote plugins may lead to path traversal 2) Numerous NVRAM operations lack input validation 3) Hardcoded external network service URLs vulnerable to man-in-the-middle attacks 4) Firewall settings controllable via NVRAM. Combined with the discovered system() function vulnerability in the REDACTED_PASSWORD_PLACEHOLDER program that executes system commands, this could form a complete remote command execution attack chain.
- **Keywords:** leafp2p_replication_url, leafp2p_firewall, RMT_invite.cgi, nvram set, system, popen
- **Notes:** Further analysis is required for the files in the REDACTED_PASSWORD_PLACEHOLDER directory.

---
### eapd-unsafe-string-operations

- **File/Directory Path:** `bin/eapd`
- **Location:** `Multiple locations in fcn.0000b7c0`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Multiple insecure string manipulation function calls (strcpy, strncpy) were identified in bin/eapd. These functions are used without proper boundary checks, potentially leading to buffer overflow vulnerabilities. These functions are frequently called, particularly when handling wireless network configurations and event messages. Combined with the discovered wireless control interfaces (wl_ioctl, wl_iovar_set, wl_iovar_getbuf), this could allow attackers to trigger buffer overflows through wireless interfaces.
- **Code Snippet:**
  ```
  strcpy(dest, src);
  ```
- **Keywords:** strcpy, strncpy, bcopy, memcpy, wl_ioctl, wl_iovar_set
- **Notes:** Further verification is required to determine whether these string operations handle externally controllable input data, and to analyze the access control of the wireless control interface.

---
### genie-cgi-ssrf

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x9f74`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In www/cgi-bin/genie.cgi, the QUERY_STRING environment variable is used to construct remote request URLs without sufficient validation. Attackers can control the request target by injecting malicious parameters, potentially leading to SSRF vulnerabilities. Combined with the lack of SSL certificate verification in curl request configurations, this could result in MITM attacks. Additionally, memory allocation using malloc was found without return value checks, potentially causing NULL pointer dereference.
- **Code Snippet:**
  ```
  snprintf(acStack144, 0x80, "%s%s", "http://", getenv("QUERY_STRING"));
  ```
- **Keywords:** QUERY_STRING, fcn.REDACTED_PASSWORD_PLACEHOLDER, snprintf, curl_easy_perform, curl_easy_setopt, CURLOPT_SSL_VERIFYPEER
- **Notes:** It is necessary to verify whether the QUERY_STRING parameter can be controlled via HTTP requests and assess the risks in the network environment.

---
### utelnetd-buffer-overflow

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd:0x95cc fcn.000090a4`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** An insecure strcpy call was found in bin/utelnetd, used to copy the pseudoterminal device path returned by ptsname. Due to the lack of length checking, this could lead to buffer overflow. Attackers could trigger this vulnerability by controlling the pseudoterminal name. Combined with the fixed-size buffer (4000 bytes) in network input processing and insufficient validation of read length, this could form a complete remote code execution attack chain.
- **Code Snippet:**
  ```
  strcpy(local_108, ptsname(__fd));
  ```
- **Keywords:** strcpy, ptsname, ppuVar3, uVar4, read, 4000
- **Notes:** It is necessary to verify whether the maximum length of the ptsname return value exceeds the target buffer size and analyze all network data reading paths.

---
### brcm-clm-file-permissions

- **File/Directory Path:** `etc/brcm/clm/`
- **Location:** `etc/brcm/clm/`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Multiple Broadcom calibration data files (.clm_blob) in the etc/brcm/clm/ directory were found with globally REDACTED_PASSWORD_PLACEHOLDER permissions (777). This could allow unprivileged users to modify or execute these critical hardware configuration files. Attackers might exploit this permission issue to inject malicious configurations or access sensitive calibration data. Combined with other vulnerabilities, this could form an attack chain for privilege escalation.
- **Keywords:** 43602a1_access.clm_blob, 4366_access.clm_blob, router.clm_blob, CLM DATA
- **Notes:** It is recommended to check which processes load these files and whether they accept external input to specify the file paths.

---
### httpd-shared-memory

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:main`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A potential shared memory vulnerability was identified in /usr/sbin/httpd. The main function utilizes shmget and shmat for shared memory operations but lacks proper access controls and boundary checks. Attackers could potentially exploit this by forging shared memory structures. When combined with the buffer overflow risk present in HTTP parameter processing, this could form a complex attack chain.
- **Keywords:** shmget, shmat, *(iVar7 + 0xa6c), *(iVar6 + 0xbd4), strcpy, puVar9 + -0x24
- **Notes:** Further verification is required for the specific implementation of shared memory operations and access control mechanisms.

---
