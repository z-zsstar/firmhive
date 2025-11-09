# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (4 alerts)

---

### buffer_overflow-dhttpd-websJstWrite

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `fcn.0002958cHIDDENmemcpyHIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A critical buffer overflow vulnerability was identified in the HTTP response generation process of the sym.websJstWrite function. This function passes HTTP response data through multiple layers of function calls, ultimately delivering it to a memcpy operation with insufficient boundary checks. Attackers could exploit this by crafting malicious HTTP response data to trigger buffer overflow, potentially leading to arbitrary code execution.
- **Code Snippet:**
  ```
  memcpy(dest, src, length);
  ```
- **Keywords:** sym.websJstWrite, fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.0002958c, memcpy, piVar6[-3], uVar4, uVar2
- **Notes:** Further confirmation is needed to determine whether the source of the HTTP response data is fully controllable.

---
### httpd-command_injection-GetValue_doSystemCmd

- **File/Directory Path:** `bin/httpd`
- **Location:** `unknown`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** A potential command injection vulnerability has been identified where user input obtained via GetValue is passed to doSystemCmd without adequate validation. Although the call chain is incomplete, this constitutes a high-risk security issue.
- **Keywords:** GetValue, doSystemCmd
- **Notes:** Further confirmation of the call chain's integrity is required to assess the actual exploitability of the vulnerability.

---
### network_input-fastcgi-luci_forward

- **File/Directory Path:** `etc_ro/nginx/conf/nginx.conf`
- **Location:** `nginx.conf:25-28, fastcgi.conf:1-20`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the nginx.conf file, the path /cgi-bin/luci/ is configured to forward via FastCGI to 127.0.0.1:8188, with multiple HTTP parameters (QUERY_STRING, REQUEST_METHOD, REQUEST_URI, etc.) being passed to the backend program through the fastcgi.conf file. These parameters may be passed to dangerous functions, posing potential security risks.
- **Code Snippet:**
  ```
  location /cgi-bin/luci/ {
      fastcgi_pass 127.0.0.1:8188;
      fastcgi_index index.php;
      include fastcgi.conf;
  }
  ```
- **Keywords:** fastcgi_pass, fastcgi_param, QUERY_STRING, REQUEST_METHOD, REQUEST_URI, 127.0.0.1:8188, /cgi-bin/luci/
- **Notes:** It is recommended to proceed with analyzing the FastCGI program listening on port 8188 to verify whether these HTTP parameters are being passed to dangerous functions such as system, exec, or strcpy.

---
### buffer_overflow-dhttpd-websAccept

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `dhttpd: sym.websAccept (strncpyHIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A potential buffer overflow vulnerability was discovered in the sym.websAccept function. This function uses strncpy to copy HTTP request parameters into the target buffer. Although there is a protective measure limiting the length to 0x3f bytes, the actual size of the target buffer is unknown, and strncpy may not automatically append a null terminator. This could potentially be exploited by attackers to perform buffer overflow attacks.
- **Code Snippet:**
  ```
  strncpy(target_buffer, http_param, 0x3f);
  ```
- **Keywords:** sym.websAccept, strncpy, *(puVar7 + -0x9c), iVar1 + 0x84, 0x3f, 0x40
- **Notes:** Further verification is required for the actual size of the target buffer (iVar1 + 0x84). It is recommended to examine the higher-level function that calls sym.websAccept.

---
