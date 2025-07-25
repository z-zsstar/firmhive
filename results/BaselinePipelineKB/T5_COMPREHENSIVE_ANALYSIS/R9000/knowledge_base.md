# R9000 (35 alerts)

---

### etc-world-writable

- **File/Directory Path:** `N/A`
- **Location:** `etc/ directory`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** The entire /etc directory and most of its files have globally writable permissions (777), including sensitive configuration files. This excessive permission allows any user or process to modify system configurations, create backdoors, or manipulate authentication mechanisms.
- **Code Snippet:**
  ```
  ls -ld /etc
  drwxrwxrwx 10 REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 4096 Jan  1  2020 /etc
  ```
- **Keywords:** drwxrwxrwx, -rwxrwxrwx, permissions 777
- **Notes:** These permissions violate fundamental security principles. The impact is amplified due to symbolic links to /tmp, making exploitation easier. This suggests either a development configuration or a serious security oversight.

---
### proccgi-combined-exploit

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi`
- **Risk Score:** 9.5
- **Confidence:** 7.5
- **Description:** Multiple vulnerabilities can be chained together: 1) Triggering buffer overflow via unvalidated input; 2) Bypassing protection mechanisms through injection vulnerabilities; 3) Leaking memory information via environment variables. This forms a complete remote code execution attack chain.
- **Keywords:** proccgi, strcpy, getenv
- **Notes:** Verify the actual feasibility of combined vulnerability exploitation

---
### proccgi-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** In the proccgi CGI handler, the use of the insecure strcpy function was identified, which may lead to buffer overflow. Combined with insufficient validation of HTTP parameter lengths, attackers could potentially achieve remote code execution by crafting malicious HTTP requests.
- **Code Snippet:**
  ```
  HIDDEN：strcpy(buffer, getenv("QUERY_STRING"));
  ```
- **Keywords:** proccgi, strcpy, REQUEST_METHOD, QUERY_STRING
- **Notes:** Need to confirm the buffer size and copy operations in the specific code implementation

---
### RMT-invite-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The RMT_invite.cgi script directly executes the output of proccgi through eval, which may lead to command injection. Attackers could inject malicious commands by manipulating CGI parameters.
- **Code Snippet:**
  ```
  eval \`proccgi $*\`
  ```
- **Keywords:** RMT_invite.cgi, eval, proccgi, FORM_submit_flag
- **Notes:** The vulnerability in proccgi could potentially form a complete attack chain

---
### uhttpd-interpreter-injection

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/uhttpd: start_instance()HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 7.25
- **Description:** The CGI/Lua interpreter path is dynamically configured via the 'interpreter' parameter, with no observed path security validation. Arbitrary program execution may be possible through path injection.
- **Code Snippet:**
  ```
  config_get interpreter "$cfg" interpreter
  append UHTTPD_ARGS "-i $interpreter"
  ```
- **Keywords:** interpreter, append UHTTPD_ARGS "-i $path"
- **Notes:** The configuration interface needs to check the filtering of the interpreter parameter.

---
### nvram-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `bin/nvram:0x87c4 fcn.000087c4`
- **Risk Score:** 8.7
- **Confidence:** 8.0
- **Description:** The configuration settings functionality of the NVRAM binary file contains critical vulnerabilities. The function at address 0x87c4 uses strcpy to copy potentially user-controlled input, which is passed to config_set without boundary checks. This leads to a buffer overflow vulnerability, potentially allowing attackers to: 1) Overwrite adjacent memory 2) Manipulate NVRAM configurations 3) Potentially execute arbitrary code. This vulnerability is triggered when processing configuration values containing the '=' character (used to separate name/value pairs).
- **Code Snippet:**
  ```
  0x000087c4      95ffffeb       bl sym.imp.strcpy
  0x000087e8      b0ffffeb       bl sym.imp.config_set
  ```
- **Keywords:** strcpy, config_set, fcn.000087c4, 0x87c4, 0x87e8
- **Notes:** This vulnerability can be chained with other weaknesses to form a complete exploit chain. It is recommended to further analyze the config_set implementation in libconfig.so. The presence of strchr indicates some input parsing is performed, but it's insufficient to meet security requirements.

---
### auth-files-symlink-to-tmp

- **File/Directory Path:** `N/A`
- **Location:** `Multiple files in etc/`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Multiple critical authentication files (REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, /etc/gshadow) are symbolically linked to the /tmp/config location, creating a centralized single point of failure. All links were created simultaneously (timestamped 2019-11-26), indicating they were part of the system initialization process.
- **Code Snippet:**
  ```
  ls -l REDACTED_PASSWORD_PLACEHOLDER
  lrwxrwxrwx 1 REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 18 Nov 26  2019 REDACTED_PASSWORD_PLACEHOLDER -> /tmp/config/shadow
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, shadow, group, gshadow, /tmp/config
- **Notes:** This pattern suggests the system may employ a custom authentication scheme. Investigate the /tmp/config directory for: 1) ownership and permissions, 2) creation mechanism, 3) any monitoring or integrity checks

---
### proccgi-strcpy-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x000088a8`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In function fcn.000088a8, the use of strcpy for unsafe string copying operations may lead to buffer overflow. Attackers can inject malicious data by controlling environment variables. The function first retrieves an environment variable via getenv, then directly copies it into the allocated buffer using strcpy without performing length checks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER env = getenv("MALICIOUS_ENV");
  REDACTED_PASSWORD_PLACEHOLDER buf = malloc(100);
  strcpy(buf, env); // HIDDEN
  ```
- **Keywords:** fcn.000088a8, strcpy, getenv, malloc
- **Notes:** Verify the controllability of environment variables and the buffer size

---
### ldd-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `etc/profile:13`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The ldd command is redefined to set the LD_TRACE_LOADED_OBJECTS environment variable before executing the arguments, which may result in arbitrary command execution when users run ldd, posing a command injection risk.
- **Code Snippet:**
  ```
  [ -x /usr/bin/ldd ] || ldd() { LD_TRACE_LOADED_OBJECTS=1 $*; }
  ```
- **Keywords:** ldd, LD_TRACE_LOADED_OBJECTS
- **Notes:** This method of redefining ldd poses security risks and could potentially be exploited for command injection attacks.

---
### uci-import-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `lib/libuci.so:0x000040c0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the `uci_import` function, the use of the unsafe string operation function `strcpy` was identified, which may lead to a buffer overflow vulnerability. This function processes externally input configuration file data, and attackers could potentially trigger an overflow by crafting malicious configuration files.
- **Code Snippet:**
  ```
  strcpy(dest, src); // No length check
  ```
- **Keywords:** uci_import, strcpy, memcpy
- **Notes:** Further verification is needed to determine whether malicious configuration data can be transmitted through network interfaces or other input points.

---
### proccgi-input-validation

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Insufficient length validation in HTTP parameter processing and inadequate handling of special characters may lead to injection attacks. The use of unverified environment variables could be chained to escalate attack vectors.
- **Code Snippet:**
  ```
  HIDDEN：REDACTED_PASSWORD_PLACEHOLDER param = getenv("QUERY_STRING"); fprintf(output, param);
  ```
- **Keywords:** getenv, fprintf, CONTENT_LENGTH
- **Notes:** Analyze the network request processing flow to determine the complete attack path

---
### uhttpd-http-smuggling

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd:0x0000d10c sym.uh_http_sendhf`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The uhttpd service may be vulnerable to HTTP request smuggling attacks when processing HTTP requests. The `sym.uh_http_sendf` and `sym.uh_http_send` functions do not adequately validate the format of request headers.
- **Code Snippet:**
  ```
  fprintf(socket, "%s: %s\r\n", name, value); // No header validation
  ```
- **Keywords:** sym.uh_http_sendf, sym.uh_http_send, HTTP headers
- **Notes:** Test custom HTTP request headers

---
### uhttpd-cgi-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd:0x0000f204 sym.uh_cgi_request`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A potential buffer overflow vulnerability was discovered in the `sym.uh_cgi_request` function. When processing CGI requests, this function uses `memcpy` to copy data into a fixed-size buffer without adequately validating the input length. Attackers could exploit this by sending specially crafted oversized requests to trigger a buffer overflow.
- **Code Snippet:**
  ```
  memcpy(buffer, input, input_len); // No length check
  ```
- **Keywords:** sym.uh_cgi_request, memcpy, 0x1000
- **Notes:** Further verification is required regarding the relationship between buffer size and input length.

---
### proccgi-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x888c`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** An unsafe use of strcpy was identified in the proccgi binary, which may lead to buffer overflow. Attackers could exploit this vulnerability by crafting malicious HTTP request parameters to hijack the program's execution flow. The vulnerability resides in the fcn.REDACTED_PASSWORD_PLACEHOLDER function, which is called by multiple CGI parameter processing functions.
- **Code Snippet:**
  ```
  strcpy(dest, src); // No bounds checking
  ```
- **Keywords:** proccgi, strcpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.00008b38
- **Notes:** Further verification is required to determine whether this vulnerability can be triggered through the network interface.

---
### uhttpd-external-script-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/uhttpd: start()HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 5.5
- **Description:** During startup, an external script `/www/cgi-bin/uhttpd.sh` (currently inaccessible) is executed, posing potential uncontrolled operations. Comments indicate it launches inetd service and detplc command, potentially introducing additional attack surfaces.
- **Code Snippet:**
  ```
  start() {
      # Start inetd and detplc
      /www/cgi-bin/uhttpd.sh start
  }
  ```
- **Keywords:** /www/cgi-bin/uhttpd.sh, inetd, detplc
- **Notes:** Further analysis requires obtaining the content of uhttpd.sh.

---
### uhttpd-unsafe-string-ops

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Multiple instances of insecure string manipulation functions, such as `strcpy` and `strcat`, were identified throughout the uhttpd service without proper length checks. These functions may lead to buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  strcpy(dest, src);
  strcat(buffer, input);
  ```
- **Keywords:** strcpy, strcat, memcpy
- **Notes:** memory_corruption

---
### uhttpd-port-exposure

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/uhttpd: start_instance()HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The HTTP/HTTPS listening ports are dynamically specified through configuration files (listen_http/listen_https parameters), with no mandatory access control restrictions identified. This may expose management interfaces to unintended networks.
- **Code Snippet:**
  ```
  start_instance() {
      config_get listen_http "$cfg" listen_http
      config_get listen_https "$cfg" listen_https
      append UHTTPD_ARGS "-p $listen_http"
      append UHTTPD_ARGS "-s $listen_https"
  }
  ```
- **Keywords:** listen_http, listen_https, append UHTTPD_ARGS "-p $listen", append UHTTPD_ARGS "-s $listen"
- **Notes:** The actual exposure situation needs to be analyzed in conjunction with network configuration.

---
### REDACTED_PASSWORD_PLACEHOLDER-symlink-to-tmpfs

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER -> REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The symbolic link of the REDACTED_PASSWORD_PLACEHOLDER file points to REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER, storing sensitive user authentication data in volatile memory (tmpfs). This configuration presents multiple security risks: 1) Data loss upon reboot, 2) Potential race conditions during system startup, 3) Increased vulnerability to tampering by malicious processes due to tmpfs permission settings. The link was established during system initialization (as evidenced by the 2019 timestamp).
- **Code Snippet:**
  ```
  ls -l REDACTED_PASSWORD_PLACEHOLDER
  lrwxrwxrwx 1 REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 17 Nov 26  2019 REDACTED_PASSWORD_PLACEHOLDER -> REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER, symbolic link, tmpfs
- **Notes:** This indicates the system employs a non-persistent authentication model. Further investigation is required regarding: 1) How user accounts are created/maintained, 2) Which services rely on this configuration, 3) Whether backup mechanisms exist for the REDACTED_PASSWORD_PLACEHOLDER file.

---
### uhttpd-exposure-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc/config/uhttpd:5-9`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The uHTTPd server configuration has both HTTP and HTTPS services enabled, listening on all interfaces (0.0.0.0). Although rfc1918_filter is enabled, the management interface may still be exposed to external networks.
- **Code Snippet:**
  ```
  list listen_http '0.0.0.0:80'
  list listen_https '0.0.0.0:443'
  ```
- **Keywords:** list listen_http, list listen_https, option rfc1918_filter
- **Notes:** It is recommended to restrict the listening address or configure stricter authentication

---
### proccgi-env-variable-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x000088a8`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The program retrieves user input from the environment variables CGI_POST_TMPFILE and REQUEST_METHOD, but fails to adequately validate these inputs. Attackers may manipulate these environment variables to control the program's behavior. Specifically, when REQUEST_METHOD is POST, the program reads CONTENT_LENGTH and allocates memory without checking the reasonableness of CONTENT_LENGTH, potentially leading to memory exhaustion attacks.
- **Code Snippet:**
  ```
  ldr r0, [0x000089d0] ; "CGI_POST_TMPFILE"
  bl sym.imp.getenv
  ldr r0, str.REQUEST_METHOD ; "REQUEST_METHOD"
  bl sym.imp.getenv
  ldr r0, [0x000089e8] ; "CONTENT_LENGTH"
  bl sym.imp.getenv
  bl sym.imp.atoi
  bl sym.imp.malloc
  ```
- **Keywords:** CGI_POST_TMPFILE, REQUEST_METHOD, CONTENT_LENGTH, getenv, malloc
- **Notes:** It is recommended to add a maximum limit for CONTENT_LENGTH and implement input validation

---
### uci-fixed-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `lib/libuci.so`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Several functions (such as `uci_import`) utilize fixed-size buffers (e.g., `auStack_128[272]`) for processing input data without performing boundary checks, potentially leading to stack overflow.
- **Code Snippet:**
  ```
  char auStack_128[272];
  memcpy(auStack_128, input, input_len);
  ```
- **Keywords:** auStack_128, uci_import, memcpy
- **Notes:** memory_corruption

---
### uhttpd-auth-bypass

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd:0x0000dda0 sym.uh_auth_check`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A potential authentication bypass vulnerability was identified in the `sym.uh_auth_check` function. The function utilizes `strncasecmp` for string comparison, which may be susceptible to case confusion attacks. Additionally, the REDACTED_PASSWORD_PLACEHOLDER comparison logic may be vulnerable to timing attacks.
- **Code Snippet:**
  ```
  if(strncasecmp(input, REDACTED_PASSWORD_PLACEHOLDER, len) == 0)
  ```
- **Keywords:** sym.uh_auth_check, strncasecmp, crypt
- **Notes:** authentication_bypass

---
### firewall-input-policy-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc/config/firewall:3`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Setting the input policy to ACCEPT in the firewall configuration may allow unfiltered network traffic to enter the system. Attackers could exploit this permissive policy for network infiltration.
- **Code Snippet:**
  ```
  option input 'ACCEPT'
  ```
- **Keywords:** option input, ACCEPT
- **Notes:** It is recommended to set the input policy to REJECT or DROP and only open necessary ports.

---
### proccgi-unsafe-input-processing

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x000088d8-0x000089a0`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The program uses strcmp to compare the value of REQUEST_METHOD, but subsequently processes unvalidated user input data directly. When REQUEST_METHOD is GET, the program retrieves data from QUERY_STRING; when it's POST, it reads data from standard input or temporary files. All these data paths could potentially be controlled by attackers.
- **Code Snippet:**
  ```
  ldr r1, [0x000089dc] ; "GET"
  bl sym.imp.strcmp
  ldr r0, [0x000089e0] ; "QUERY_STRING"
  bl sym.imp.getenv
  ldr r3, obj.stdin
  ldr r3, [r3]
  bl sym.imp.fread
  ```
- **Keywords:** strcmp, QUERY_STRING, fread, stdin, CGI_POST_TMPFILE
- **Notes:** All user inputs should undergo rigorous validation and filtering.

---
### uhttpd-cert-generation-weakness

- **File/Directory Path:** `N/A`
- **Location:** `etc/init.d/uhttpd: generate_keys()HIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The uhttpd service utilizes a self-signed certificate generation feature (via the px5g tool), where certificate parameters such as country and organization can be dynamically obtained from the configuration file. If an attacker can tamper with the configuration, they could forge certificates to carry out man-in-the-middle attacks. By default, the certificates use a relatively weak 1024-bit RSA REDACTED_PASSWORD_PLACEHOLDER (modifiable via the bits parameter).
- **Code Snippet:**
  ```
  generate_keys() {
      local bits=${bits:-1024}
      px5g selfsigned -der \
          -keyout "$UHTTPD_KEY" \
          -out "$UHTTPD_CERT" \
          -subj "/C=${country:-US}/..." \
          -days ${days:-365} \
          -rsa ${bits}
  }
  ```
- **Keywords:** PX5G_BIN, generate_keys, selfsigned, rsa:${bits:-1024}, UHTTPD_CERT, UHTTPD_KEY
- **Notes:** Verify the write permissions of the configuration file and the source of configuration parameters.

---
### proccgi-env-variable-abuse

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x000088a8`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The program extensively uses getenv to retrieve environment variables but fails to adequately validate the obtained values. Attackers could potentially manipulate environment variables to control program flow or inject malicious data. Notably, in function fcn.000088a8, environment variable values are directly used for file operations and memory allocation.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER path = getenv("MALICIOUS_PATH");
  REDACTED_PASSWORD_PLACEHOLDER f = fopen(path, "r"); // HIDDEN
  ```
- **Keywords:** getenv, fopen, atoi, malloc
- **Notes:** Analyze which environment variables will be used by the CGI script

---
### ubus-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `bin/ubus:0x0000899c`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The ubus command-line tool contains insecure command handling logic. Analysis of the main function (fcn.0000899c) reveals that the program directly compares user-input command strings ("list", "call", etc.) using strcmp without performing input validation or normalization. Attackers could potentially influence program behavior through command injection or parameter pollution.
- **Code Snippet:**
  ```
  strcmp(user_input, "list") == 0
  ```
- **Keywords:** strcmp, fcn.0000899c, ubus_invoke, getopt
- **Notes:** Further verification is needed to determine whether the vulnerability can be triggered by carefully crafted command parameters.

---
### uhttpd-realm-injection

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/uhttpd.sh:3`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The script reads content from the '/module_name' file as the REALM variable without performing any input validation or filtering. An attacker could potentially inject malicious parameters into the uhttpd startup command by controlling the contents of the /module_name file.
- **Code Snippet:**
  ```
  REALM=\`/bin/cat /module_name | sed 's/\n//g'\`
  ```
- **Keywords:** REALM, /module_name, uhttpd_start
- **Notes:** Verify whether the /module_name file can be externally controlled for writing.

---
### uci-parse-argument-unsafe-jmp

- **File/Directory Path:** `N/A`
- **Location:** `lib/libuci.so:0x00003eb0`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The `uci_parse_argument` function employs `setjmp`/`longjmp` for error handling but lacks adequate input validation mechanisms, potentially leading to undefined behavior or memory corruption.
- **Code Snippet:**
  ```
  if (_setjmp(env) == 0) { ... }
  ```
- **Keywords:** uci_parse_argument, _setjmp, longjmp
- **Notes:** Check all code paths that call this function

---
### uhttpd-url-decode-issue

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd:0x0000d2e8 sym.uh_urldecode`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Potential issues were identified in the URL decoding implementation within the `sym.uh_urldecode` function. When processing percent-encoded sequences, the function fails to adequately validate input validity, which may lead to decoding errors or memory out-of-bounds access.
- **Code Snippet:**
  ```
  while(*src) {
    if(*src == '%') { /* no full validation */ }
  ```
- **Keywords:** sym.uh_urldecode, percent encoding, 0xd3bc
- **Notes:** test specially constructed URL-encoded input

---
### proccgi-format-string-vuln

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x00008b38`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** In function fcn.00008b38, there exists a potential format string vulnerability. This function may allow attackers to inject format string specifiers when processing input parameters, potentially leading to information disclosure or memory corruption. Particularly when handling inputs containing special characters (such as $, \, `, etc.), additional processing logic will be triggered.
- **Code Snippet:**
  ```
  fprintf(output, user_input); // HIDDEN
  ```
- **Keywords:** fcn.00008b38, fprintf, fputc, __fputc_unlocked
- **Notes:** memory_corruption

---
### profile-ldd-command-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc/profile:12`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Defines an alternative implementation of the ldd command that executes arbitrary commands using the LD_TRACE_LOADED_OBJECTS environment variable. If an attacker can control the $* parameter, it may lead to command injection.
- **Code Snippet:**
  ```
  ldd() { LD_TRACE_LOADED_OBJECTS=1 $*; }
  ```
- **Keywords:** ldd, LD_TRACE_LOADED_OBJECTS
- **Notes:** This custom implementation may bypass security restrictions, requiring inspection of the context in which ldd is called.

---
### mkshrc-loading-risk

- **File/Directory Path:** `N/A`
- **Location:** `etc/profile:10`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Dynamically loads the /etc/mkshrc file. If this file can be controlled or injected with malicious code by an attacker, it will be executed during shell initialization. Verification of the existence and permissions of the /etc/mkshrc file is required.
- **Code Snippet:**
  ```
  [ -z "$KSH_VERSION" -o \! -s /etc/mkshrc ] || . /etc/mkshrc
  ```
- **Keywords:** /etc/mkshrc, KSH_VERSION
- **Notes:** It is recommended to check whether the /etc/mkshrc file exists and review its contents.

---
### firewall-nvram-weakness

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/firewall.sh`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The firewall script stores and retrieves configurations via NVRAM without sufficient input validation. Attackers may manipulate configuration parameters to influence firewall rules.
- **Code Snippet:**
  ```
  nvram set forfirewall="$FORM_rules"
  ```
- **Keywords:** firewall.sh, nvram, net-wall, forfirewall
- **Notes:** Requires REDACTED_PASSWORD_PLACEHOLDER privileges to exploit, relatively low risk

---
### ubus-event-info-leak

- **File/Directory Path:** `N/A`
- **Location:** `bin/ubus:0x0000893c`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The ubus event handling mechanism may expose sensitive information. The program provides the functions ubus_send_event and ubus_register_event_handler, but lacks evident event filtering or permission verification mechanisms.
- **Keywords:** ubus_send_event, ubus_register_event_handler, fcn.0000899c
- **Notes:** Need to analyze the specific implementation of event handling

---
