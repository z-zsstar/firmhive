# R8000-V1.0.4.4_1.1.42 (7 alerts)

---

### libssl-vulnerabilities

- **File/Directory Path:** `lib/libssl.so.1.0.0`
- **Location:** `lib/libssl.so.1.0.0:sym.SSL_get_verify_result`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** Multiple security vulnerabilities were found in lib/libssl.so.1.0.0: (1) The SSL_get_verify_result function directly accesses memory offsets without performing pointer validity checks; (2) An older version of OpenSSL (1.0.0) is used, which is known to contain several high-risk vulnerabilities such as Heartbleed.
- **Keywords:** SSL_get_verify_result, param_1, 0xec, OpenSSL 1.0.0
- **Notes:** It is recommended to use the cve_search_nvd tool to further verify specific vulnerabilities.

---
### httpsd-pem-private-REDACTED_PASSWORD_PLACEHOLDER-exposure

- **File/Directory Path:** `usr/sbin/httpsd.pem`
- **Location:** `usr/sbin/httpsd.pem`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Plaintext RSA private REDACTED_PASSWORD_PLACEHOLDER file found in usr/sbin/httpsd.pem may lead to man-in-the-middle attacks or server identity spoofing. Attackers could extract this private REDACTED_PASSWORD_PLACEHOLDER to decrypt HTTPS communications or carry out man-in-the-middle attacks.
- **Keywords:** httpsd.pem, PEM RSA private REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to immediately revoke all certificates associated with this private REDACTED_PASSWORD_PLACEHOLDER and generate a new REDACTED_PASSWORD_PLACEHOLDER pair

---
### bd-command-injection

- **File/Directory Path:** `sbin/bd`
- **Location:** `sbin/bd:0x9f78`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** The sbin/bd program was found to contain 72 instances of insufficiently validated system function calls that execute various system commands without proper parameter validation. Attackers could potentially achieve command injection by manipulating NVRAM variables or input parameters. The program also includes multiple functions for modifying critical firmware parameters, which lack adequate permission checks.
- **Code Snippet:**
  ```
  system(command);
  acosNvramConfig_set("eth_mac", mac);
  ```
- **Keywords:** system, fcn.00009f78, acosNvramConfig_set, acosNvramConfig_get, bd_write_eth_mac, bd_write_ssid
- **Notes:** Dynamic analysis is required to confirm which system call parameters can be controlled by external inputs.

---
### genie-cgi-command-injection

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x9f74`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A vulnerability was identified in www/cgi-bin/genie.cgi where unvalidated user input is directly obtained from the QUERY_STRING environment variable, potentially leading to command injection or cross-site scripting attacks. This input is passed to the processing function fcn.REDACTED_PASSWORD_PLACEHOLDER, posing a critical security risk.
- **Code Snippet:**
  ```
  char *query = getenv("QUERY_STRING");
  fcn.REDACTED_PASSWORD_PLACEHOLDER(query);
  ```
- **Keywords:** fcn.00009ef8, getenv, QUERY_STRING, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** The specific processing logic of fcn.REDACTED_PASSWORD_PLACEHOLDER needs to be analyzed to confirm the vulnerability type.

---
### utelnetd-telnet-buffer-overflow

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd: fcn.000090a4 (main function)`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Multiple high-risk vulnerabilities were discovered in bin/utelnetd: (1) The insecure strcpy operation is used to copy pseudoterminal names, which may lead to buffer overflow; (2) Network input is directly written to fixed-size buffers without length validation; (3) Privilege separation issue where child processes fail to properly drop privileges. Attackers can establish telnet connections, send malicious data to trigger buffer overflow or replace shell programs to gain REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Code Snippet:**
  ```
  strcpy(puVar8[5], ptsname);
  read(ppuVar17[4], puVar17[6], 4000);
  execv((*0x9af4)[2], ...);
  ```
- **Keywords:** strcpy, ptsname, accept, fork, execv, (*0x9af4)[2]
- **Notes:** Verify the buffer size and input control possibilities, especially whether (*0x9af4)[2] is user-controllable

---
### netatalk-weak-authentication

- **File/Directory Path:** `etc/netatalk/afpd.conf`
- **Location:** `etc/netatalk/afpd.conf:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Weak REDACTED_PASSWORD_PLACEHOLDER policy was identified in the Netatalk AFP service configuration at etc/netatalk/afpd.conf: empty passwords are permitted and potentially vulnerable authentication modules may be used. Attackers could exploit weak authentication mechanisms to gain unauthorized access.
- **Keywords:** afpd.conf, uams_guest.so, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_REDACTED_SECRET_KEY_PLACEHOLDER
- **Notes:** It is recommended to check if the version of the uams module has any known vulnerabilities and to strengthen the REDACTED_PASSWORD_PLACEHOLDER policy.

---
### remote-script-nvram-vulnerability

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The script etc/init.d/remote.sh was found to automatically configure multiple NVRAM variables related to leafp2p, including remote service URLs and debug levels. Attackers could potentially alter device behavior or enable debugging features by modifying these NVRAM values, particularly the leafp2p_firewall=0 setting which may disable firewall protection.
- **Code Snippet:**
  ```
  nvram set leafp2p_firewall=0
  nvram commit
  ```
- **Keywords:** leafp2p_sys_prefix, leafp2p_replication_url, leafp2p_remote_url, leafp2p_debug, leafp2p_firewall, nvram set, nvram commit
- **Notes:** Further verification is required for the modification permissions and impact scope of NVRAM values.

---
