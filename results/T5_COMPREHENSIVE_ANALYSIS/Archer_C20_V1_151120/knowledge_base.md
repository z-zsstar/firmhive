# Archer_C20_V1_151120 (10 findings)

---

### BufferOverflow-cwmp_processConnReq

- **File/Directory Path:** `usr/bin/cwmp`
- **Location:** `cwmp:0x0040b34c sym.cwmp_processConnReq`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Buffer overflow in HTTP Authorization header parsing in 'cwmp_processConnReq'. The function reads HTTP requests from a socket, parses the Authorization header, and uses strcpy to copy header values into fixed-size stack buffers without bounds checking. Attackers with valid login credentials can send crafted HTTP GET requests with long Authorization header values, overflowing the buffer and potentially overwriting return addresses or critical stack data. This can lead to arbitrary code execution or denial of service. The vulnerability triggers during connection request processing before full authentication, making it accessible to authenticated users. Code logic involves reading input via read() and cwmp_getLine(), then unsafe copying with strcpy.
- **Code Snippet:**
  ```
  Key code locations from disassembly and decompilation:
  - 0x0040ad78: read(socket_fd, stack_buffer, 0x400)  // Read untrusted HTTP request
  - 0x0040ade8: cwmp_getLine(buffer, 0x200, stack_buffer)  // Parse HTTP lines
  - 0x0040b150: strncpy(temp_buffer, field_value, length)  // Copy field value with limited check
  - 0x0040b34c: strcpy(dest_buffer, temp_buffer)  // Unsafe copy to fixed buffer causing overflow
  ```
- **Keywords:** socket_fd, HTTP_Authorization_header, cwmp_processConnReq, cwmp_getLine, auStack_e18, auStack_e7c
- **Notes:** Vulnerability verified through static analysis with evidence of unsafe strcpy use. The stack buffers (e.g., auStack_e18 and auStack_e7c) are fixed-size (100 bytes), and overflow is achievable with headers exceeding this size. Further dynamic testing could confirm exploitability, but the attack chain is complete from input to dangerous operation. Associated functions include cwmp_digestCalcHA1 and cwmp_digestCalcResponse for authentication handling.

---
### BufferOverflow-fcn.0040553c

- **File/Directory Path:** `usr/bin/cwmp`
- **Location:** `cwmp:0x0040553c fcn.0040553c`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Buffer overflow in SOAP SetParameterValues string parameter handling in subfunction fcn.0040553c. When processing SOAP requests to set parameter values, the function uses memcpy to copy string-type parameter values into a fixed-size stack buffer (auStack_c38, 3072 bytes) without checking the length. Attackers can send crafted SOAP SetParameterValues requests with string parameter values exceeding 3071 bytes, causing a stack buffer overflow that may overwrite return addresses and lead to arbitrary code execution. The vulnerability triggers during SOAP message parsing for parameter updates, and exploitation requires authenticated access. Code logic involves parsing ParameterValueStruct elements and directly copying values via memcpy.
- **Code Snippet:**
  ```
  Key code from decompilation:
  if (parameter_type == 'string') {
      memcpy(auStack_c38, parameter_value, value_length); // value_length not bounded to 3072
      auStack_c38[value_length] = 0; // Null-terminate, but if value_length >= 3072, overflow occurs
  }
  ```
- **Keywords:** ParameterList, ParameterValueStruct, Name, Value, string, fcn.0040553c, cwmp_processSetParameterValues
- **Notes:** Vulnerability identified in a subfunction called by cwmp_processSetParameterValues. The stack buffer auStack_c38 is 3072 bytes, and memcpy allows unbounded copying. Exploitability is high on MIPS architecture due to predictable stack layouts. Recommend verification through dynamic analysis to confirm EIP control. Associated functions include fcn.00405f2c for parameter validation.

---
### RCE-$.exe

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js: In the `$.exe` function's resolve function`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The function `$.exe` processes CGI responses and executes JavaScript code within them, which may lead to remote code execution. If an attacker can control the CGI response content (for example, through backend injection or malicious configuration), they can inject arbitrary code. During the resolution process of `$.exe`, if the response contains a 'cgi' stack, the script content is collected and executed via `$.script`. Trigger condition: The attacker can manipulate the output of CGI scripts, for example by modifying NVRAM variables or exploiting backend vulnerabilities. Exploitation method: The attacker sends a malicious request through an authenticated session, causing the backend to return malicious JavaScript, which is then executed on the frontend.
- **Code Snippet:**
  ```
  var resolve = function(ret, ds) {
      // ...
      if (stack == "cgi") {
          scripts += lines[i] + '\n';
      }
      // ...
      if (scripts != "") {
          $.script(scripts);
          if ($.ret) {
              ret = $.ret;
              $.err("cgi", ret, unerr);
              break;
          }
          scripts = "";
      }
      // ...
  };
  ```
- **Keywords:** $.exe, $.script, CGI Response, /cgi?
- **Notes:** This vulnerability relies on the behavior of backend CGI scripts. It is recommended to analyze backend CGI scripts to ensure input validation and output encoding. Associated files may include other CGI scripts or configuration files.

---
### stack-buffer-overflow-login

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `bpalogin:sym.login (Address range based on decompilation, specifically in the loop processing section)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** In the sym.login function, when processing a string extracted from the network, strcspn and strncpy are used to copy data into a fixed-size stack buffer auStack_d8[200]. If the input string is longer than 200 bytes and does not contain a ' ' or ',' character, strncpy will overflow the buffer. Subsequently, the code performs a write operation `(&stack0xfffff8e8)[iVar5 + 0x640] = 0`, where iVar5 is based on the input length, which may overwrite the return address or other critical data on the stack. The trigger condition is sending specific fields (field 0x16) in malicious data through the network authentication process, causing the string length to exceed 200 bytes without delimiters. Potential exploitation methods include overwriting the return address to control program flow and execute arbitrary code.
- **Code Snippet:**
  ```
  while (iVar5 = strcspn(iStack_6f0, " ,"), iVar5 != 0) {
      strncpy(auStack_d8, iStack_6f0, iVar5);
      (&stack0xfffff8e8)[iVar5 + 0x640] = 0;
      iStack_6f0 = iStack_6f0 + iVar5 + 1;
      ...
  }
  ```
- **Keywords:** auStack_d8, iStack_6f0, strcspn, strncpy, sym.extract_valuestring
- **Notes:** Further verification is needed for bpalogin's runtime permissions (whether it runs as root) and actual network interaction. It is recommended to test malicious data injection to confirm exploitability. Related functions include sym.receive_transaction and sym.extract_valuestring, used for tracking data flow.

---
### XSS-doAddUrl-initUrlTbl

- **File/Directory Path:** `web/main/parentCtrl.htm`
- **Location:** `parentCtrl.htm: doAddUrl() function and initUrlTbl() function (specific line numbers unavailable, but relevant sections are marked in the code snippet)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored XSS vulnerability exists in the URL addition functionality. Attackers can input malicious JavaScript code (e.g., <script>alert('XSS')</script>) into the 'urlInfo' input field. When a user adds a URL via the doAddUrl() function, the code is directly inserted into the table's innerHTML (without escaping). In the initUrlTbl() function, all URLs are again inserted into the DOM, causing the script to execute when the page loads or is viewed. Trigger condition: After logging in, the attacker accesses the parental control page, inputs a malicious URL, and adds it; when any user (including administrators) views the page, the script automatically executes. Exploitation methods: Steal session cookies, redirect pages, or perform unauthorized actions. The vulnerability is due to a lack of input escaping and output encoding.
- **Code Snippet:**
  ```
  // Vulnerable code in the doAddUrl() function
  cell.innerHTML = $.id("urlInfo").value; // Directly inserts user input into HTML
  // Vulnerable code in the initUrlTbl() function
  cell.innerHTML = allUrl[i]; // Again inserts unescaped data
  ```
- **Keywords:** urlInfo, doAddUrl, initUrlTbl, urltbl, allUrl
- **Notes:** Evidence is based on code snippets within the file content. The vulnerability can be exploited by authenticated users, forming a complete attack chain (input → storage → execution). It is recommended to further analyze backend CGI processing (e.g., /cgi/lanMac) to confirm data persistence impact. Related files: May involve other HTML or CGI files, but the current task is limited to this file.

---
### XSS-$.dhtml

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js: `$.dhtml` function definition`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In 'lib.js', the function `$.dhtml` uses `innerHTML` to parse strings and extract script elements for execution, which may lead to XSS vulnerabilities. If user-controlled input (such as via URL parameters or form data) is passed to `$.dhtml` or related functions (like `$.append`, `$.load`) without proper sanitization, an attacker can inject malicious scripts. These scripts will execute in the context of the user's session, potentially leading to session hijacking, data theft, or unauthorized actions. Trigger conditions include: user input being directly used to dynamically update page content, and the input containing malicious HTML or JavaScript code. Exploitation method: an attacker crafts malicious input and lures the victim into visiting a specific page or performing an action, thereby triggering script execution.
- **Code Snippet:**
  ```
  dhtml: function(str, hook, midhook) {
      $.div.innerHTML = "div" + str;
      var scripts = [];
      $.chgChd($.div.childNodes, function() {
          if (this.nodeName && this.nodeName.toLowerCase() === "script")
              scripts.push(this);
          else
              hook.call(this);
      });
      if (midhook) midhook();
      $.each(scripts, function() {$.script(this.text || this.textContent || this.innerHTML || "")});
      $.empty($.div);
  }
  ```
- **Keywords:** $.dhtml, $.append, $.load, innerHTML
- **Notes:** This vulnerability requires user input to be passed to `$.dhtml` or related functions. It is recommended to check the locations where these functions are called to ensure input sanitization. Subsequent analysis should trace the source of user input, such as HTTP request parameters or CGI responses.

---
### PathTraversal-reply_ntcreate_and_X

- **File/Directory Path:** `usr/bin/smbd`
- **Location:** `smbd:0x004354ec sym.reply_ntcreate_and_X`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A path traversal vulnerability exists in the 'reply_ntcreate_and_X' function (handling SMB NT_CREATE_ANDX requests). The function uses 'srvstr_get_path' to extract file paths from SMB packets but does not adequately sanitize paths containing '..' sequences. This allows an authenticated user to access files outside the intended share directory. The vulnerability is triggered when a malicious SMB request includes a path with traversal sequences, leading to arbitrary file read/write operations. The function 'check_path_syntax' is called but may not block all traversal attempts depending on configuration.
- **Code Snippet:**
  ```
  // From sym.reply_ntcreate_and_X decompilation
  sym.srvstr_get_path(param_2, acStack_911 + 1, param_2 + *(param_2 + 0x24) * 2 + 0x27, 0x400, 0, 1, &iStack_460, 0);
  // Then uses the path in file operations without sufficient traversal checks
  ```
- **Keywords:** SMB command: NT_CREATE_ANDX, Function: sym.reply_ntcreate_and_X, Function: sym.srvstr_get_path, Function: sym.check_path_syntax
- **Notes:** This vulnerability requires the attacker to have valid login credentials (non-root user). Exploitation depends on share configuration and permissions. Further validation is needed to confirm if 'check_path_syntax' always blocks traversals in practice. Associated functions: sym.open_file_shared, sym.file_set_dosmode.

---
### BufferOverflow-sym.cli_input_parse

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `0x00404664 sym.cli_input_parse`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the sym.cli_input_parse function, when processing CLI input, normal character input has boundary checks (limited to 512 bytes), but the history mechanism (recalling via arrow keys) uses a strcpy-like function to copy the history string to the input buffer param_1 without verifying the history string length. If the history string exceeds 512 bytes, it will cause a buffer overflow. Trigger condition: An attacker, as a logged-in user, first inputs an overly long command (e.g., via CLI interaction) to fill the history buffer, then uses the up/down arrow keys to recall that command. Potential attack: The overflow can overwrite stack memory, leading to arbitrary code execution or service crash. Exploitation method: The attacker carefully crafts a long command containing shellcode or manipulates the return address, triggering the overflow via history recall.
- **Code Snippet:**
  ```
  puVar9 = *(iVar11 * 4 + 0x4269f8);
  if (puVar9 != NULL) {
      puStack_2c = puVar9;
      (**(loc._gp + -0x7dcc))(param_1, puVar9);  // strcpy-like copy without bounds check
      puStack_30 = *0x426a24;
      pcVar13 = *(loc._gp + -0x7ec4);
      *0x426a24 = 0;
      *0x426a20 = 0;
      *0x426a28 = 0;
      uVar4 = (*pcVar13)(puStack_2c);
      puVar7 = puStack_30;
      *0x426a2c = uVar4;
      iVar11 = 0;
      goto code_r0x00404f60;
  }
  ```
- **Keywords:** param_1, *0x4269f8, function_ptr_gp_minus_0x7dcc, sym.cli_input_parse, g_cliMsgBuff
- **Notes:** This vulnerability requires the user to have CLI access and the history feature to be enabled. The history buffer *0x4269f8 may persist across sessions, increasing the attack surface. It is recommended to further analyze the sym.cli_parseTab function (handling tab completion) for potential similar vulnerabilities. Related files or functions: sym.start_cli (CLI initialization), msg_recv (IPC communication). Subsequent analysis direction: Check the history storage mechanism and the possibility of control flow hijacking after overflow.

---
### XSS-virtualServer-init

- **File/Directory Path:** `web/main/virtualServer.htm`
- **Location:** `virtualServer.htm: Table cell rendering section in the init function (multiple lines, e.g., within IP and PPP connection loops)`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** A stored cross-site scripting (XSS) vulnerability exists in the table display logic of the 'virtualServer.htm' file. When rendering the 'internalClient' field (IP address) of port mapping rules, the code directly uses the `innerHTML` property without escaping user input, allowing an attacker to inject arbitrary JavaScript code. Trigger condition: When an attacker, as a logged-in user, adds or edits a port mapping rule, they set the 'internalClient' to a malicious payload (e.g., `<script>alert('xss')</script>`). When other users (including potential administrators) view the page, the payload automatically executes. Exploitation method: Attackers can steal session cookies, perform unauthorized operations (such as modifying configurations), or attempt privilege escalation. The root cause of the vulnerability is the lack of input validation and output encoding, allowing user-controllable data to be directly inserted into the DOM.
- **Code Snippet:**
  ```
  // Example code snippet from the IP connection handling section
  cell = row.insertCell(-1);
  cell.width = "18%";
  cell.innerHTML = this.internalClient; // Directly using innerHTML without escaping
  
  // Similar code repeats in PPP, L2TP, PPTP connection handling
  ```
- **Keywords:** WAN_IP_CONN_PORTMAPPING, WAN_PPP_CONN_PORTMAPPING, WAN_L2TP_CONN_PORTMAPPING, WAN_PPTP_CONN_PORTMAPPING, internalClient
- **Notes:** This vulnerability requires the attacker to have permission to configure port mapping, but as a logged-in user, this might be allowed by default. The attack chain is complete: entry point (internalClient setting) → data flow (stored to NVRAM and retrieved) → trigger point (page rendering). It is recommended to subsequently verify if the backend filters internalClient input and check if other similar fields (such as name fields) also have XSS. Related file: vtlServEdit.htm (used for editing rules) may contain relevant input processing logic.

---
### XSS-$.cgi

- **File/Directory Path:** `web/js/lib.js`
- **Location:** `lib.js: `$.cgi` function definition`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** Function `$.cgi` uses `$.toStr` without encoding when constructing URLs and query parameters, potentially reflecting user input in the response. If the backend CGI script reflects these parameters without sanitization, it may lead to XSS or code execution. In `$.cgi`, `path` and `arg` are used to build the request, and the response may be executed as a script via `$.io`. Trigger condition: User input is passed as `arg` to `$.cgi`, and the backend reflects this input. Exploitation method: Attacker injects malicious scripts into parameters, which execute when the response is processed.
- **Code Snippet:**
  ```
  cgi: function(path, arg, hook, noquit, unerr) {
      if ($.local || $.sim) path = $.params;
      else path = (path ? path : $.curPage.replace(/\.htm$/, ".cgi")) + (arg ? "?" + $.toStr(arg, "=", "&") : "");
      // ...
      var ret =  $.io(path, true, func, null, noquit, unerr);
      // ...
  }
  ```
- **Keywords:** $.cgi, $.toStr, $.io, CGI parameters
- **Notes:** Requires the backend CGI script to actually reflect user input. It is recommended to verify the implementation of the specific CGI script. Subsequent analysis should focus on the CGI script files.

---
