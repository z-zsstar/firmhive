# _AC1450-V1.0.0.36_10.0.17.chk.extracted (4 alerts)

---

### command-injection-acos_service-system

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xb5b4`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** Multiple instances of 'system' function calls (100+) were found in the file 'sbin/acos_service', with some involving dynamic command construction, posing a risk of command injection. If the web interface allows setting related NVRAM parameters (such as DNS configuration), it may constitute an RCE risk. The dynamic command construction pattern, when combined with user input, could lead to command injection.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** system, sym.imp.system, wan_dns, wan2_dns, acosNvramConfig_get
- **Notes:** Suggested follow-up analysis: Examine the correlation between the web interface and NVRAM configuration; Trace input sources in dynamic command construction; Analyze interactions between other web components (such as CGI scripts) and these functions.

---
### buffer-overflow-acos_service-strcpy

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xca64`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** Multiple insecure 'strcpy' calls were identified in the file 'sbin/acos_service', including a stack buffer overflow risk (0xb5b4) in the main function and unvalidated copying of DNS parameters in the network configuration function (fcn.0000ca64). If the web interface permits setting these DNS parameters, it may lead to buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** strcpy, sym.imp.strcpy, wan_dns, wan2_dns, fcn.0000ca64
- **Notes:** Suggested follow-up analysis: Examine the correlation between the web interface and NVRAM configuration; Trace input sources in dynamic command construction; Analyze interactions between other web components (such as CGI scripts) and these functions.

---
### nvram-unsafe-copy-acos_service

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xd34c`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** Multiple instances of direct NVRAM configuration data copying (fcn.0000d34c) were found in the file 'sbin/acos_service'. If the web interface allows setting these NVRAM parameters, it may lead to insecure data copying.
- **Code Snippet:**
  ```
  Not provided
  ```
- **Keywords:** acosNvramConfig_get, fcn.0000d34c, wan_dns, wan2_dns
- **Notes:** Suggested follow-up analysis: Examine the correlation between the web interface and NVRAM configuration; Trace input sources in dynamic command construction; Analyze interactions between other web components (such as CGI scripts) and these functions.

---
### buffer_overflow-acos_service-strcpy

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service:fcn.0000a5bc:0xa82c, main:0xb5b4, fcn.0000ca64:0xcb48, fcn.0000ca64:0xcbe8, fcn.0000ca64:0xccc8, fcn.0000ca64:0xcce0`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Multiple buffer overflow vulnerabilities were discovered in '/sbin/acos_service', primarily due to unsafe strcpy() calls. These vulnerabilities occur in functions fcn.0000a5bc, main, and fcn.0000ca64 when copying data from configuration sources (obtained via acosNvramConfig_get()) to local buffers without proper size validation. If attackers can manipulate these configuration data, they could potentially exploit these vulnerabilities.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** strcpy, acosNvramConfig_get, fcn.0000a5bc, main, fcn.0000ca64
- **Notes:** Further analysis is required on the input validation mechanisms of the acosNvramConfig_get() and acosNvramConfig_set() functions to determine whether these configuration sources can be controlled via the web interface or other external inputs. It is recommended to examine other components that interact with these functions, particularly the web service components.

---
