# R8500 (8 alerts)

---

### web-cgi-command-injection

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_invite.cgi`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_invite.cgi:3, www/cgi-bin/proccgi: fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** command_injection
- **Code Snippet:**
  ```
  eval \`proccgi $*\`
  ```
- **Keywords:** eval, proccgi, QUERY_STRING, system, popen, /tmp/www/cgi-bin
- **Notes:** command_injection

---
### insecure-etc-permissions

- **File/Directory Path:** `./etc`
- **Location:** `./etc`
- **Risk Score:** 9.0
- **Confidence:** 9.25
- **Description:** The /etc directory has 777 permissions (drwxrwxrwx), allowing any user to modify system configurations. This could lead to authentication bypass (by modifying shadow/REDACTED_PASSWORD_PLACEHOLDER), service manipulation, or privilege escalation. Particularly dangerous given the broken symlink from REDACTED_PASSWORD_PLACEHOLDER to REDACTED_PASSWORD_PLACEHOLDER which doesn't exist.
- **Keywords:** etc, shadow, REDACTED_PASSWORD_PLACEHOLDER, group, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** privilege_escalation

---
### high-risk-service-ports

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:58-62`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The leafp2p_service_0 configuration opens multiple high-risk ports (135-139,445,548 TCP/UDP) associated with Windows file sharing. These could enable lateral movement if the services are vulnerable. The configuration is set by default with firewall disabled (leafp2p_firewall=0), significantly increasing attack surface.
- **Code Snippet:**
  ```
  leafp2p_service_0="RouterRemote:6:135,6:136,6:137,6:138,6:139,6:445,6:548,17:135,17:136,17:137,17:138,17:139,17:445,17:548"
  ```
- **Keywords:** leafp2p_service_0, 6:135, 6:445, 17:135, leafp2p_firewall
- **Notes:** network_exposure

---
### nvram-injection-chain

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:22-68, REDACTED_PASSWORD_PLACEHOLDER_invite.cgi:5`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_injection
- **Code Snippet:**
  ```
  nvram set leafp2p_replication_url="http://example.com"
  nvram commit
  ```
- **Keywords:** nvram set, leafp2p_sys_prefix, leafp2p_replication_url, leafp2p_remote_url, leafp2p_debug, SYS_PREFIX
- **Notes:** Requires initial foothold to modify NVRAM, but provides persistence and lateral movement capabilities.

---
### unsafe-symbolic-links

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:14-20`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** path_exposure
- **Code Snippet:**
  ```
  ln -s REDACTED_PASSWORD_PLACEHOLDER_invite.cgi /tmp/www/cgi-bin/RMT_invite.cgi
  ```
- **Keywords:** ln -s, /tmp/www/cgi-bin, RMT_invite.cgi, func.sh, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Combined with the command injection in RMT_invite.cgi, this creates a direct remote attack path.

---
### unsafe-curl-operations

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi: fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple components (genie.cgi, proccgi) do not enable SSL verification (CURLOPT_SSL_VERIFYPEER is disabled) when executing cURL requests. This allows man-in-the-middle attacks to intercept or tamper with communication data, posing an extremely high security risk—especially when combined with NVRAM configuration (leafp2p_replication_url) for remote URLs.
- **Keywords:** curl_easy_perform, leafp2p_replication_url, CURLOPT_SSL_VERIFYPEER, MITM
- **Notes:** network_security

---
### xss-template-injection

- **File/Directory Path:** `www/index.htm`
- **Location:** `www/index.htm: JavaScript function loadnext()`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** xss
- **Keywords:** <%425%>, <%429%>, top.location.replace, loadnext()
- **Notes:** xss

---
### buffer-overflow-risks

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:sym.REDACTED_PASSWORD_PLACEHOLDER_main, www/cgi-bin/genie.cgi:0x999c`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Several components contain unsafe string operations (strncpy, sprintf) without proper bounds checking. Most notably in genie.cgi (fcn.REDACTED_PASSWORD_PLACEHOLDER) and busybox's REDACTED_PASSWORD_PLACEHOLDER utility. While some may be theoretically unexploitable, the REDACTED_PASSWORD_PLACEHOLDER utility's getpass() usage is particularly concerning as it handles authentication.
- **Keywords:** strncpy, getpass, pw->pw_REDACTED_PASSWORD_PLACEHOLDER, snprintf, malloc
- **Notes:** memory_corruption

---
