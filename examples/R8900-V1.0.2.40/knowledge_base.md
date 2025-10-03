# R8900-V1.0.2.40 (20 alerts)

---

### CommandInjection-openvpn_update

- **File/Directory Path:** `bin/openvpn_update`
- **Location:** `The `date -s $MM$DD$HH$mm$YY` command in the script`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'openvpn_update' script due to improper quoting of variables in the `date -s` command. The attack chain is as follows: 1) An attacker gains write access to the /firmware_time file (e.g., through a separate vulnerability or misconfiguration). 2) The attacker crafts a malicious /firmware_time file where the sixth field (used for YY) contains a command injection payload (e.g., '; malicious_command'). 3) When the script runs, it reads YY from the file and executes `date -s $MM$DD$HH$mm$YY` without quoting, causing the shell to interpret metacharacters and execute arbitrary commands. The trigger condition is the execution of the script (e.g., via cron or system service) with a malicious /firmware_time file. This is exploitable because the lack of input sanitization and quoting allows command injection, leading to arbitrary code execution with root privileges.
- **Code Snippet:**
  ```
  YY=\`cat /firmware_time|cut -d " " -f 6\`
  
  date -s $MM$DD$HH$mm$YY
  ```
- **Keywords:** /firmware_time, YY
- **Notes:** The exploit requires that /firmware_time is writable by an attacker, which may depend on other system configurations. Further analysis of how /firmware_time is populated and accessed is recommended. The script likely runs with root privileges, amplifying the impact.

---
### buffer-overflow-nvram-set

- **File/Directory Path:** `bin/nvram`
- **Location:** `nvram_binary:0x87c4 [strcpy]`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A buffer overflow vulnerability exists in the 'set' command handling of the nvram binary. The attack chain is as follows: 1) Attacker controls the command-line argument for the 'set' command (e.g., './nvram set long_string...'). 2) The argument is passed to strcpy without any length validation (at address 0x87c4). 3) strcpy copies the input into a fixed-size stack buffer (at sp + 0x200), allowing overflow of stack data including the return address. The trigger condition is executing the nvram binary with the 'set' command and a sufficiently long argument. This is exploitable because the lack of bounds check enables overwriting critical stack structures, and the input is directly controllable from the command line.
- **Code Snippet:**
  ```
  0x000087b0      081095e5       ldr r1, [r5, 8]          ; Load argv[2] into r1
  0x000087b4      000051e3       cmp r1, 0                 ; Check if argv[2] is null
  0x000087b8      eaffff0a       beq 0x8768               ; Jump if null
  0x000087bc      024c8de2       add r4, sp, 0x200        ; Set r4 to stack buffer at sp+0x200
  0x000087c0      0400a0e1       mov r0, r4               ; Set dest to buffer
  0x000087c4      95ffffeb       bl sym.imp.strcpy        ; Call strcpy(dest, src) - buffer overflow here
  ```
- **Keywords:** command-line argument for 'set' command, argv[2]
- **Notes:** The stack buffer size is not explicitly checked, and the large stack frame (0x60200 bytes) may allow overwriting the return address. Further analysis could identify additional vulnerabilities involving other dangerous functions like sprintf, but this finding is independently exploitable. Recommend fuzzing the 'set' command with long inputs to confirm exploitability.

---
### Command-Injection-ntgr_sw_api_rule

- **File/Directory Path:** `etc/scripts/firewall/ntgr_sw_api.rule`
- **Location:** `ntgr_sw_api.rule, within the while loops for 'start' and 'stop' cases`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The script 'ntgr_sw_api.rule' contains a command injection vulnerability in the handling of configuration values retrieved via 'config get'. An attacker can set NVRAM variables (e.g., 'ntgr_api_firewall*') with malicious values containing shell metacharacters (e.g., semicolons) to execute arbitrary commands when the script is run with root privileges. The complete attack chain is: untrusted input (e.g., via network API or NVRAM setting) -> NVRAM variable set -> script reads variable via 'config get' -> uses 'set $value' to split into positional parameters -> incorporates parameters into 'iptables' command without validation or quoting -> shell interprets metacharacters, leading to command injection. The trigger condition is executing the script with 'start' or 'stop' argument while malicious config values are present. Exploitable due to lack of input sanitization and proper quoting, allowing bypass of firewall rules or arbitrary code execution.
- **Code Snippet:**
  ```
  #! /bin/sh
  
  # THIS IS A SCRIPT FOR NET-WALL EXTRA CALLING TO SET NETGEAR INTEGRATION SW API RULES.
  
  FIREWALL_NVCONF_PREFIX="ntgr_api_firewall"
  
  case $1 in
  	"start")
  		index=1
  		while true
  		do
  			value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
  			[ "x$value" = "x" ] && break || set $value
  			[ "x$3" = "xALL" ] && useport="" || useport="yes"
  			iptables -I INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
  			iptables -I OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
  			index=$((index + 1))
  		done;;
  	"stop")
  		index=1
  		while true
  		do
  			value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
  			[ "x$value" = "x" ] && break || set $value
  			[ "x$3" = "xALL" ] && useport="" || useport="yes"
  			iptables -D INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
  			iptables -D OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
  			index=$((index + 1))
  		done;;
  	*)
  		:;;
  esac
  ```
- **Keywords:** ntgr_api_firewall*
- **Notes:** Assumption: The 'config get' command retrieves NVRAM variables that can be set by untrusted sources (e.g., through web interfaces or APIs). The script is likely run with root privileges. Further analysis is recommended to verify how these variables are set and if the script is automatically triggered during system events. Mitigation: Implement input validation, sanitization, or use arrays instead of 'set $value' to handle config values safely.

---
### command-injection-fcn.000186ac

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `函数 fcn.000186ac 中的 system 调用点（基于反编译代码）`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在函数 fcn.000186ac 中发现命令注入漏洞。攻击链如下：- **输入点**：用户通过函数参数 `param_1` 和 `param_2` 提供可控输入。- **数据流传播**：输入通过 `fcn.00017b88` 影响条件检查（`iVar1 != iVar3`），然后通过字符串操作函数（`fcn.0000fb50` 和 `fcn.0000fb80`）构建到缓冲区 `puVar4 + -8`。`fcn.0007ae5c` 将 `puVar4 + -0x20` 设置为基于该缓冲区的值。- **危险操作**：当 `*(*(puVar4 + -0x20) + -0xc) != 0` 时，`sym.imp.system(*(puVar4 + -0x20))` 执行，其中 `*(puVar4 + -0x20)` 包含用户可控数据。- **触发条件**：必须满足 `iVar1 != iVar3`（受 `param_1` 和 `param_2` 影响）且 `*(*(puVar4 + -0x20) + -0xc) != 0`。攻击者可通过操纵输入使条件为真。- **可利用性分析**：缺少输入验证和过滤，允许注入恶意命令字符串（如 shell 元字符），导致任意命令执行。
- **Code Snippet:**
  ```
  关键代码片段（从反编译中提取）：
  if (*(*(puVar4 + -0x20) + -0xc) != 0) {
      sym.imp.printf(*0x18864);
      sym.imp.system(*(puVar4 + -0x20));
  }
  相关数据流：
  fcn.0007ae5c(puVar4 + -0x20, puVar4 + -8);
  ```
- **Keywords:** param_1, param_2, puVar4 + -0x20, puVar4 + -8
- **Notes:** 攻击链基于委托分析证据，确认用户输入可控。建议验证运行时条件触发概率，并检查调用上下文（如网络接口或 IPC）以确认输入源。

---
### command-injection-fcn.000177bc

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `函数 fcn.000177bc 中的 system 调用点（地址 0x00017820、0x0001787c、0x000178d8、0x000178e0）`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在函数 fcn.000177bc 中发现 NVRAM 相关命令注入漏洞。攻击链如下：- **输入点**：外部可控的 NVRAM 变量名或值通过函数参数（如 `r0`）传入。- **数据流传播**：参数用于构建命令字符串（通过 `fcn.0000fae4` 和 `fcn.0000fb50` 拼接），形成完整 shell 命令（如 'fbwifi_nvram set' 和 'fbwifi_nvram commit'）。- **危险操作**：构建的命令通过 system 函数执行（地址 0x00017820、0x0001787c、0x000178d8、0x000178e0）。- **触发条件**：攻击者控制输入参数（如设置恶意 NVRAM 变量），注入 shell 元字符（如分号或反引号）即可触发。- **可利用性分析**：缺少输入验证、过滤或转义，允许任意命令执行，导致系统妥协。
- **Code Snippet:**
  ```
  示例代码片段（从反汇编中提取）：
  0x000177ec: ldrb r1, [r4]          ; 加载输入参数
  0x000177f0: bl fcn.00017528        ; 处理字符
  0x00017800: bl fcn.0000fb80        ; 构建命令字符串
  0x00017820: bl sym.imp.system      ; 执行命令
  0x000178e0: bl sym.imp.system      ; 执行 'fbwifi_nvram commit'
  ```
- **Keywords:** fbwifi_nvram set, fbwifi_nvram commit
- **Notes:** 此漏洞通过 NVRAM 变量进行命令注入，影响系统安全。建议对输入进行严格验证和转义。测试实际固件环境以确认可利用性。

---
### Command-Injection-cmd_ddns

- **File/Directory Path:** `sbin/cmd_ddns`
- **Location:** `脚本中的函数：ddns_update，具体在 phddns 调用（约行 130）、noip2 调用（约行 132）和 ez-ipupdate 调用（约行 150）`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 'cmd_ddns' 脚本中发现命令注入漏洞，允许通过用户控制的 NVRAM 变量执行任意命令。攻击链如下：1) 攻击者通过 web 界面或 API 设置恶意的 NVRAM 变量（如 sysDNSUser、sysDNSPassword、sysDNSHost），值包含 shell 元字符（如 ';'、'&'）；2) 当脚本执行 DDNS 更新（通过 'start' 或 'ddns_update' 函数）时，这些变量被直接用于外部程序调用（phddns、noip2、ez-ipupdate）而未引号；3) 由于缺少输入过滤和引号，元字符被 shell 解释，导致命令注入。例如，设置 sysDNSHost 为 'example.com; malicious_command' 在 ez-ipupdate 调用中会执行 'malicious_command'。可利用性高，因为缺少清理和验证，且触发条件简单（DDNS 更新）。
- **Code Snippet:**
  ```
  # phddns 调用（未引号变量）
  /usr/sbin/phddns  $ORAY_SERVER $usr_name $usr_password $(get_wan_ifname)&
  
  # noip2 调用（未引号变量）
  /usr/sbin/noip2 -I $wan_ifname -o $host_name -u $usr_name -p $usr_password -U 10 -C -c $no_ip_conf
  
  # ez-ipupdate 调用（部分未引号变量）
  $prog -S $service_type -u "$usr_name":"$usr_password" -h $host_name -i $wan_ifname $DDNS_WILDCARD -M 86400 -p 30 -P 10 -r 7 -F $pid -d -e $DDNS_SCRIPT -b $DDNS_CACHE -c $DDNS_CONF
  ```
- **Keywords:** sysDNSUser, sysDNSPassword, sysDNSHost, wan_proto, endis_ddns, sysDNSProviderlist
- **Notes:** 漏洞在多个外部程序调用中存在，phddns 和 noip2 调用风险最高（所有参数未引号）。ez-ipupdate 调用中 host_name 和 wan_ifname 未引号。建议对所有用户输入变量使用引号并实施输入验证。后续可分析 ez-ipupdate、phddns、noip2 二进制文件以确认其参数处理行为。

---
### command-injection-RMT_invite.cgi

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `代码汇聚点位于：
- 输入处理：'proccgi' 二进制文件中的环境变量解析逻辑（通过 `getenv`）。
- 危险汇点：'RMT_invite.cgi' 脚本中的 `eval "`/www/cgi-bin/proccgi $*`"` 语句。`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** 一个完整的命令注入攻击链已被验证：
- **完整攻击链**：攻击者可通过 HTTP 请求（如 POST 或 GET）提供恶意参数（例如，在 QUERY_STRING 或表单字段中）。这些参数被 'proccgi' 二进制文件使用 `getenv` 检索，并通过不安全函数如 `strcpy` 复制到输出中，缺乏边界检查和过滤。输出随后在 'RMT_invite.cgi' 脚本中被 `eval` 语句执行，导致任意命令注入。例如，如果 'proccgi' 输出字符串包含 shell 元字符（如分号或反引号），它将在评估时作为命令执行。
- **触发条件**：当 'RMT_invite.cgi' 作为 CGI 脚本被调用时（例如，通过 HTTP 请求到相应端点），且用户输入未被 sanitized。具体案例包括表单提交（如 'register_user' 或 'unregister_user' 操作）时，参数 'FORM_TXT_remote_login' 和 'FORM_TXT_remote_passwd' 被直接用于构建 JSON 和设置 NVRAM，但更关键的是 'proccgi' 的输出评估。
- **可利用性分析**：这是高度可利用的，因为：1) 'proccgi' 使用 `strcpy` 等函数表明缺乏输入验证，允许任意数据注入输出；2) `eval` 在 shell 脚本中盲目执行输出，提供直接的命令执行路径；3) 证据显示格式字符串如 'FORM_%s="' 暗示用户数据被输出而未过滤， enabling injection。
- **Code Snippet:**
  ```
  从 'RMT_invite.cgi' 脚本：
  \`\`\`sh
  eval "\`/www/cgi-bin/proccgi $*\`"
  # 用户输入直接使用示例：
  case "$FORM_submit_flag" in
      register_user)
          echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"password\":\"$FORM_TXT_remote_passwd\"}"|...
  \`\`\`
  从 'proccgi' 分析（字符串输出）：
  - 嵌入式脚本片段：\`eval "\`/www/cgi-bin/proccgi $*\`"\`
  - 环境变量引用：'QUERY_STRING', 'REQUEST_METHOD', 'POST', 'CONTENT_LENGTH', 'PATH_INFO'
  - 不安全函数导入：'strcpy', 'getenv'
  - 格式字符串："FORM_%s=\"" 表示用户数据输出
  ```
- **Keywords:** QUERY_STRING, REQUEST_METHOD, POST, CONTENT_LENGTH, PATH_INFO, FORM_TXT_remote_login, FORM_TXT_remote_passwd, FORM_submit_flag, getenv, strcpy, /www/cgi-bin/proccgi, /www/cgi-bin/RMT_invite.cgi
- **Notes:** 分析受限于 'proccgi' 二进制的剥离性质和 Radare2 反编译困难，但字符串分析和脚本内容提供了足够证据。建议进行动态测试以确认可利用性。相关文件如 'readycloud_control.cgi' 可能包含额外攻击面，应进一步检查。关联发现 'integer-overflow-proccgi' 共享标识符，但此为独立攻击链。

---
### Untitled Finding

- **File/Directory Path:** `sbin/udhcpc`
- **Location:** `Function fcn.000090c0 (main) at address 0x9e60 (system call) and surrounding code involving sprintf at address 0x... (from decompilation).`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was identified in the 'udhcpc' DHCP client. The attack chain begins with untrusted input from DHCP response packets (network interface). The IP address from the DHCP packet is parsed and used in a sprintf call to construct a command string, which is then executed via system. The specific code path involves: 1) Receiving a DHCP packet (untrusted input), 2) Extracting the IP address using fcn.0000b728 (DHCP option parsing), 3) Using sprintf with format strings from memory to build a command (e.g., '/sbin/ipconflict <IP>'), 4) Executing the command with system. The trigger condition is when a DHCP response is processed, and the IP address is used in the command. Exploitable because the IP address is not sanitized for shell metacharacters, allowing command injection if an attacker controls the DHCP server.
- **Code Snippet:**
  ```
  // From decompiled code:
  puVar10 = fcn.0000b728(puVar22,1); // Extract IP address from DHCP packet
  if ((puVar10 != NULL) && (uVar21 = *(puVar2 + 0xb), uVar21 == 0)) {
      uVar11 = *(puVar26 + 0xfffffd98); // IP address
      // ... other assignments ...
      sym.imp.sprintf(puVar26 + 0xfffffd08, *0xa118, *0xa11c, uVar11); // Build command string
      iVar3 = sym.imp.system(puVar26 + 0xfffffd08); // Execute command
  }
  ```
- **Keywords:** DHCP response packets, IP address from option 0x36 (server identifier), system call, sprintf format strings
- **Notes:** The strings at *0xa118 and *0xa11c were verified to be '/sbin/ipconflict' and a space or similar, forming the command. The IP address is directly embedded without sanitization. This vulnerability is exploitable if the attacker can send crafted DHCP responses. Recommended to validate and sanitize all inputs from DHCP packets before use in system commands.

---
### buffer-overflow-readycloud-nvram-set

- **File/Directory Path:** `bin/readycloud_nvram`
- **Location:** `代码地址 0x000087c4（strcpy 调用）`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击链从不可信输入点（命令行参数）开始，具体是 'config set' 命令的第二个参数（值）。程序在地址 0x00008794 处使用 strncmp 检查第一个参数是否为 'set'，然后在地址 0x000087c4 调用 strcpy 将第二个参数复制到栈缓冲区（地址 r4 = SP0 - 0x60020）。由于 strcpy 不检查边界，如果第二个参数长度超过 0x6001c 字节（约 384 KB），它会覆盖栈上的返回地址（保存在地址 SP0 - 0x4）。触发条件：运行 './readycloud_nvram set <long_string>'，其中 <long_string> 长度超过 0x6001c 字节。可利用性分析：攻击者可以精心构造长字符串包含 shellcode 或覆盖返回地址以控制程序流，实现任意代码执行。
- **Code Snippet:**
  ```
  0x00008794      ac129fe5       ldr r1, [0x00008a48]        ; [0x8a48:4]=0x510
  0x00008798      0400a0e1       mov r0, r4
  0x0000879c      0320a0e3       mov r2, 3
  0x000087a0      01108fe0       add r1, pc, r1
  0x000087a4      b5ffffeb       bl sym.imp.strncmp          ; int strncmp(const char *s1, const char *s2, size_t n)
  0x000087a8      006050e2       subs r6, r0, 0
  0x000087ac      0f00001a       bne 0x87f0
  0x000087b0      081095e5       ldr r1, [r5, 8]           ; argv[2]
  0x000087b4      000051e3       cmp r1, 0
  0x000087b8      eaffff0a       beq 0x8768
  0x000087bc      024c8de2       add r4, sp, 0x200         ; r4 = sp + 0x200 (stack buffer)
  0x000087c0      0400a0e1       mov r0, r4
  0x000087c4      95ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src) ; VULNERABLE: buffer overflow
  ```
- **Keywords:** 命令行参数（argv[2] for 'set' command）, config set
- **Notes:** 缓冲区大小计算基于反汇编代码：从缓冲区起始地址 (SP0 - 0x60020) 到返回地址 (SP0 - 0x4) 的距离为 0x6001c 字节。实际可利用性可能受系统命令行长度限制，但通常足够长以触发溢出。建议进一步测试以验证溢出条件和利用可行性。相关函数：主逻辑在地址 0x00008704，config_set 在 0x000086b0。

---
### StackOverflow-config_set

- **File/Directory Path:** `bin/config`
- **Location:** `Address 0x87c4 in function at 0x8768`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability exists in the 'config set' command. The attack chain is: attacker-controlled command-line argument (argv[2] for 'config set') is copied directly to a 512-byte stack buffer using strcpy at address 0x87c4 without any bounds checking. If the argument length exceeds 512 bytes, it overflows the buffer, potentially overwriting return addresses and leading to arbitrary code execution. The trigger condition is when the 'config set' command is invoked with a name=value string longer than 512 bytes. This is exploitable because the buffer is on the stack, and no stack protections (e.g., canaries) are evident in the code, allowing control over execution flow.
- **Code Snippet:**
  ```
  0x000087bc      024c8de2       add r4, sp, 0x200      ; r4 points to stack buffer of size 0x200 (512 bytes)
  0x000087c0      0400a0e1       mov r0, r4             ; dest = stack buffer
  0x000087c4      95ffffeb       bl sym.imp.strcpy     ; strcpy(dest, src) where src is from argv[2]
  ```
- **Keywords:** command-line argument for 'config set'
- **Notes:** The stack buffer is fixed at 512 bytes. No input validation or length checks are performed before strcpy. Exploitability depends on the target environment (e.g., absence of ASLR or stack protections), but in embedded systems, such protections are often limited. Further analysis could involve testing crash reproducibility or identifying gadget chains for code execution.

---
### buffer-overflow-fcn.0000937c-keyvalue

- **File/Directory Path:** `bin/datalib`
- **Location:** `函数 fcn.0000937c 中的 strcpy 调用点：地址 0x00009574（用于键字符串）和 0x000094a4（用于值字符串）`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 基于键值对输入的缓冲区溢出漏洞。攻击链完整：攻击者可控的输入缓冲区（param_1，包含键值对字符串，如 'key=value'）被传入函数 fcn.000095a0。该函数解析字符串（使用 strchr 查找 '=' 分隔符），并循环调用 fcn.0000937c 处理每个键值对。在 fcn.0000937c 中，污点参数（键字符串 param_1 和值字符串 param_2）通过寄存器直接传播到 strcpy 调用，没有任何长度验证或边界检查。具体路径：fcn.000095a0 解析输入 → 调用 fcn.0000937c → strcpy 复制键和值字符串。触发条件：攻击者提供 param_1 缓冲区，其中键或值字符串长度超过目标缓冲区大小（目标缓冲区大小未知，但全局变量可能限制不足）。可利用性高，因为缺少清理和边界检查，strcpy 直接复制未验证输入，允许溢出覆盖相邻内存，可能导致任意代码执行或崩溃。
- **Code Snippet:**
  ```
  从 fcn.000095a0 反编译代码的解析部分：
  if (*(param_1 + 0xc) != '\0') {
      do {
          iVar1 = sym.imp.strchr(puVar2, 0x3d);  // 查找 '=' 分隔符
          puVar4 = iVar1 + 0;
          if (puVar4 == NULL) break;
          puVar3 = puVar4 + 1;
          *puVar4 = 0;
          fcn.0000937c(puVar2, puVar3);  // 调用处理函数，传递键和值
          *puVar4 = 0x3d;
          iVar1 = sym.imp.strlen(puVar3);
          puVar2 = puVar3 + iVar1 + 1;
      } while (puVar3[iVar1 + 1] != '\0');
  }
  
  从 fcn.0000937c 反编译代码的 strcpy 调用部分：
  // 键字符串的 strcpy 调用
  sym.imp.strcpy(puVar6 + 3, param_1);  // 地址 ~0x00009574
  // 值字符串的 strcpy 调用
  puVar1 = sym.imp.strcpy(iVar7, param_2);  // 地址 ~0x000094a4
  ```
- **Keywords:** fcn.000095a0, fcn.0000937c, sym.imp.strcpy, 键值对字符串输入
- **Notes:** 证据基于反编译代码和污点传播分析，显示完整攻击链。建议进一步验证：1) param_1 输入源的具体来源（可能来自网络接口、IPC 或 NVRAM），2) 目标缓冲区的实际大小和布局，3) 实际利用中如何控制输入和触发溢出。相关函数：fcn.000095a0（入口）、fcn.0000937c（处理）、sym.imp.strcpy（危险汇聚点）。

---
### buffer-overflow-fcn.0000937c-network

- **File/Directory Path:** `bin/datalib`
- **Location:** `函数 fcn.0000937c 中的 strcpy 调用点：地址 0x000094a4（用于 param_2）`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 基于网络输入的缓冲区溢出漏洞。攻击链完整：攻击者通过网络接口（使用 sym.imp.recvfrom）发送恶意数据，数据被接收并存储到栈位置 [sp+0x38]。污点数据随后传播到 [sp+0xc]，并作为参数 param_2 传入函数 fcn.0000937c。在 fcn.0000937c 中，param_2 直接用于 strcpy 调用，没有任何边界检查。具体路径：sym.imp.recvfrom 接收网络数据 → 数据存储到栈 → 调用 fcn.0000937c → strcpy 复制 param_2。触发条件：程序执行到包含 recvfrom 的代码路径时，攻击者发送网络数据即可触发 strcpy 操作。可利用性高，因为 strcpy 缺少边界检查，攻击者可控的 param_2 数据可导致缓冲区溢出，覆盖相邻内存，可能实现任意代码执行或拒绝服务。
- **Code Snippet:**
  ```
  从反编译代码显示数据流和 strcpy 调用：
  // 在接收网络数据的函数中（地址 ~0x8a98）：
  sym.imp.recvfrom(..., [sp+0x38], ...);  // 接收数据并存储到栈
  // 数据传播（地址 ~0x8b08）：
  ldr r2, [sp, #0x38]; str r2, [sp, #0xc];  // 污点数据移动到 [sp+0xc]
  // 调用 fcn.0000937c（地址 ~0x8f5c）：
  bl fcn.0000937c;  // 参数 param_2 从 [sp+0xc] 加载
  
  从 fcn.0000937c 反编译代码的 strcpy 调用部分：
  if ((puVar6[1] == 0) || (iVar2 = sym.imp.strcmp(puVar6[1], param_2), iVar2 != 0)) {
      iVar7 = *0x958c + 0x9920 + iVar7;
      puVar6[1] = iVar7;
      puVar1 = sym.imp.strcpy(iVar7, param_2);  // 危险操作，param_2 未经验证
      // ...
  }
  ```
- **Keywords:** sym.imp.recvfrom, fcn.0000937c, sym.imp.strcpy, 网络接口
- **Notes:** 证据基于反编译代码和污点传播分析，攻击链从网络输入到 strcpy 完整可验证。建议进一步验证：1) 网络接口的具体协议和端口，2) 目标缓冲区的实际大小，3) 其他相关函数（如 fcn.000097f4）的交互。此漏洞可能被远程攻击者利用，需优先修复。

---
### BufferOverflow-fcn.00011f5c

- **File/Directory Path:** `bin/ookla`
- **Location:** `Function fcn.00011f5c at address 0x00011f8c (vsnprintf call)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A complete attack chain exists from the --configurl command-line input to a dangerous vsnprintf operation. The chain begins with user-provided input through --configurl, which is processed by fcn.00017790. This function retrieves configuration data via fcn.0000b644 and passes it through a series of functions (fcn.0000a584, fcn.0000a694) using pipe writes and reads, ultimately storing the data in a global variable. The tainted data is then loaded and passed to vsnprintf in fcn.00011f5c without bounds checking, allowing buffer overflow. Trigger condition: when the program is executed with --configurl and malicious configuration data. Exploitable due to lack of input validation and size checks, enabling arbitrary code execution or crashes.
- **Code Snippet:**
  ```
  Key code snippets from decompilation:
    - fcn.00017790: iVar1 = fcn.0000b644(piVar4[-3]); // piVar4[-3] is --configurl input
    - fcn.0000a584: sym.imp.write(fildes, ptr, var_1ch); // Write to pipe
    - fcn.00011f5c: sym.imp.vsnprintf(s, size, format, ...); // s is tainted data
  ```
- **Keywords:** --configurl, global variable 0x24318, pipe file descriptor
- **Notes:** Assumes --configurl input is user-controlled and program runs with privileges. Recommend further validation of vsnprintf buffer sizes and analysis of other input paths like network interfaces.

---
### HeapBufferOverflow-fcn.0000d20c

- **File/Directory Path:** `bin/ookla`
- **Location:** `Function fcn.0000d20c at addresses 0xd7c4 (memcpy) and 0xd260 (recv)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A heap buffer overflow occurs in HTTP response parsing due to improper validation of Content-Length header. The attack chain starts with network data received via recv calls (e.g., at 0xd260 in fcn.0000d20c), storing data in a buffer. The function parses the Content-Length header and allocates a heap buffer of size Content-Length + 1. However, during data copying via memcpy (at 0xd7c4), the actual body data length (from received data) is used as the copy size without checking against the allocated size. If an attacker sends a response with a small Content-Length but large body, memcpy overflows the heap buffer. Trigger condition: when Content-Length value is less than the actual body data length in an HTTP response. Exploitable as it can corrupt heap metadata or overwrite function pointers, leading to arbitrary code execution.
- **Code Snippet:**
  ```
  From decompilation:
    0x0000d260: bl sym.imp.recv ; Receive network data
    0x0000d684: ldr r3, [var_38h] ; Load Content-Length
    0x0000d688: add r2, r3, 1 ; Allocation size
    0x0000d7c4: bl sym.imp.memcpy ; Copy without bounds check
  ```
- **Keywords:** recv, memcpy
- **Notes:** Vulnerability is remotely exploitable via network input. Further analysis of related functions (e.g., fcn.0001766c) is advised to identify additional attack vectors.

---
### integer-overflow-proccgi

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `proccgi:0x000088a8 [fcn.000088a8]`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在 'proccgi' 文件中发现一个整数溢出漏洞，可能导致堆缓冲区溢出和任意代码执行。攻击链如下：
- **输入点**：攻击者可控的 CONTENT_LENGTH 环境变量（通过 HTTP POST 请求设置）。
- **数据流**：CONTENT_LENGTH 值通过 getenv 获取，传递给 atoi 转换为整数。如果攻击者设置 CONTENT_LENGTH 为负值（如 '-1'），atoi 返回负整数（如 -1）。该值用于 malloc(atoi() + 1) 分配内存，但由于整数溢出，负值被解释为无符号大数（例如 malloc(0) 可能分配最小块）。随后，fread 使用原始负值作为大小参数（被解释为无符号大数，如 0xFFFFFFFF），从输入流读取大量数据，溢出分配的缓冲区。
- **触发条件**：REQUEST_METHOD 为 'POST'，且 CONTENT_LENGTH 设置为负值字符串。
- **可利用性分析**：此漏洞可利用是因为 atoi 对负值处理不当，导致内存分配不足，而 fread 无视实际缓冲区大小读取数据，造成堆溢出。攻击者可精心构造 POST 数据，覆盖堆内存中的关键数据结构，实现代码执行。
- **Code Snippet:**
  ```
  关键代码片段来自 fcn.000088a8 反编译：
  \`\`\`
  iVar3 = sym.imp.getenv(*0x89e8); // 获取 CONTENT_LENGTH
  iVar3 = sym.imp.atoi(); // 转换为整数，可能返回负值
  iVar4 = iVar3 + 0;
  if (iVar4 != 0) {
      iVar5 = sym.imp.malloc(iVar4 + 1); // 整数溢出：如果 iVar4 负，iVar4+1 可能为 0
      iVar7 = iVar5 + 0;
      if (iVar7 != 0) {
          // ...
          iVar5 = sym.imp.fread(iVar5, 1, iVar4, ...); // fread 使用 iVar4（负值被解释为大无符号数），导致缓冲区溢出
          // ...
      }
  }
  \`\`\`
  ```
- **Keywords:** CONTENT_LENGTH, REQUEST_METHOD
- **Notes:** 此漏洞需要进一步验证动态行为，例如 malloc(0) 的具体实现和堆布局。建议测试不同负值（如 -1、-100）对分配大小的影响。相关函数包括 fcn.000088a8（主处理逻辑）和 fcn.000086c8（调用链）。后续可分析堆溢出后的代码路径以评估利用稳定性。

---
### command-injection-RECORD_STA_MAC

- **File/Directory Path:** `etc/hotplug.d/wps/00-wps`
- **Location:** `Case statement for RECORD_STA_MAC in the shell script`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Command injection vulnerability in the RECORD_STA_MAC action. The environment variable $STAMAC is used unquoted in the command '/usr/sbin/stamac set $STAMAC', allowing an attacker to execute arbitrary commands by crafting $STAMAC with shell metacharacters (e.g., STAMAC='; malicious_command ;'). Attack chain: untrusted input from STAMAC environment variable -> direct use in shell command without quoting or sanitization -> command execution with root privileges. The script runs with elevated permissions, making this highly exploitable if the caller (e.g., hostapd) sets STAMAC from external input.
- **Code Snippet:**
  ```
  RECORD_STA_MAC)
  		/usr/sbin/stamac set $STAMAC
  		;;
  ```
- **Keywords:** STAMAC
- **Notes:** Exploitability depends on whether /usr/sbin/stamac is a script or binary that interprets shell metacharacters. Further analysis of stamac is recommended to confirm the vulnerability. The script context suggests it is called during WPS events, so if an attacker can influence STAMAC via WPS protocols, this could be triggered.

---
### 漏洞-mm内存写入

- **File/Directory Path:** `bin/mm`
- **Location:** `busybox 二进制文件中的内存操作函数（具体地址因符号剥离未明确，但通过字符串引用定位）`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** 文件 'mm' 是 busybox 的一个符号链接，对应内存写入 applet。该工具允许用户通过 'mm address value' 命令直接写入物理内存地址。攻击链如下：攻击者通过命令行参数（argv）提供地址和值作为输入，这些数据被解析并直接写入 /dev/armem 设备，从而修改内存。缺少对地址和值的充分验证（如边界检查、权限验证），可能导致任意内存写入。触发条件：攻击者需具有 root 权限或通过其他漏洞提升权限后执行 'mm' 命令。可利用性分析：由于缺少输入清理，攻击者可以写入敏感内存区域（如内核空间、进程内存），导致权限提升、系统崩溃或代码执行。
- **Code Snippet:**
  ```
  从字符串分析中获取的代码模式：
  Usage: md address [count]
  mm address value
  open: /dev/armem
  Create using: mknod /dev/armem c 1 13
  相关函数涉及对 sym.imp.open64 的调用（如 fcn.00035c00、fcn.00036954 等），但具体反编译代码因符号剥离无法完整获取。证据显示输入参数直接用于内存写入操作。
  ```
- **Keywords:** /dev/armem, mm
- **Notes:** 分析基于字符串证据和交叉引用，但符号被剥离，无法获取完整函数名和代码。建议进一步动态分析或使用调试器验证。'mm' 命令通常需要 root 权限，但如果系统配置不当或存在其他漏洞，可能被利用。相关命令 'md'（内存读取）也可能存在类似问题。

---
### FTP-Update-RCE

- **File/Directory Path:** `sbin/cloud`
- **Location:** `update 函数，在脚本的 case 语句中处理 'update' 参数时调用`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** 在 update 函数中，脚本从 FTP 服务器 (ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/) 下载并执行 tar 归档文件，缺少完整性验证（如数字签名），仅依赖文件大小检查。攻击者可通过中间人攻击、DNS 欺骗或劫持 FTP 服务器提供恶意 tar 文件，其大小与预期相同，从而绕过验证。恶意文件被解压并复制到系统目录 (/overlay)，可能导致任意文件写入和远程代码执行（例如，通过覆盖系统二进制文件或脚本）。攻击链完整：不可信 FTP 响应 → curl 下载 → 大小检查 → tar 解压 → cp 到系统目录 → 执行启动脚本（如 /opt/xagent/run-xagent.sh）。触发条件：当脚本以 'update' 参数运行时（例如，通过系统服务或定时任务）。可利用性分析：缺少清理和验证逻辑，攻击者可控制文件内容并获得 root 权限。
- **Code Snippet:**
  ```
  update() {
  	[ -f /tmp/.cloud_updated ] && return 1
  	PID_file=/var/run/cloud.pid
  	[ -f $PID_file ] && return 1
  	echo "$$" > $PID_file
  	echo "start to get info from ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/"
  	retry_count=0
  	while [ 1 ]; do
  		curl ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/ 2>/dev/null | grep readygeniecloud-r9000-$version-.*.tar.gz > /tmp/cloud_info
  		[ -s /tmp/cloud_info ] && break
  		echo "cannot access ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/ or don't find readygeniecloud tarball with version $version"
  		dynamic_sleep
  	done
  	fullversion=\`tail -1 /tmp/cloud_info | awk '{print $9}'\`
  	if [ -f /opt/version -a "x$(cat /opt/version)" = "x$fullversion" ]; then
  		rm -f /tmp/cloud_info
  		touch /tmp/.cloud_updated
  		rm -f $PID_file
  		echo "the readygeniecloud on update server is same as on R/W filesystem"
  		start
  		return 1
  	fi
  	size=\`tail -1 /tmp/cloud_info | awk '{print $5}'\`
  	echo "start to download ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/$fullversion"
  	retry_count=0
  	while [ 1 ]; do
  		curl ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/$fullversion -o /tmp/cloud.tar.gz 2>/dev/null
  		[ "$(wc -c /tmp/cloud.tar.gz | awk '{print $1}')" = "$size" ] && break
  		echo "fail to download ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/readygeniecloud-r9000-$fullversion"
  		dynamic_sleep
  	done
  	uninstall
  	mkdir /tmp/clouddir
  	tar xf /tmp/cloud.tar.gz -C /tmp/clouddir
  	echo $fullversion > /tmp/clouddir/opt/version
  	touch /tmp/clouddir/opt/filelist
  	find /tmp/clouddir -type f | sed 's/\/tmp\/clouddir/\/overlay/' > /tmp/clouddir/opt/filelist
  	cp -fpR /tmp/clouddir/* /
  	rm -f /tmp/cloud_info
  	rm -f /tmp/cloud.tar.gz
  	rm -rf /tmp/clouddir
  	touch /tmp/.cloud_updated
  	echo "install ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/$fullversion to R/W filesystem successfully"
  	start
  	rm -f $PID_file
  }
  ```
- **Keywords:** FTP_URL: ftp://updates1.netgear.com/sw-apps/ready-genie-cloud/r9000/, 文件路径: /tmp/cloud_info, 文件路径: /tmp/cloud.tar.gz, 文件路径: /tmp/clouddir, 文件路径: /overlay, 环境变量: version, 函数符号: update
- **Notes:** 攻击链完整且可验证，但需要外部条件：攻击者必须能控制 FTP 流量或服务器，且脚本需以 'update' 参数运行（可能通过系统服务或定时任务）。建议进一步验证脚本的调用机制（如检查 init 脚本或 cron 条目）和网络安全性（如使用 HTTPS 或签名验证）。相关文件：/cloud_version（影响版本检查）、/var/run/cloud.pid（进程锁）。

---
### Untitled Finding

- **File/Directory Path:** `sbin/cmddlna`
- **Location:** `In the 'print_dlna_conf' function and its call site in 'dlna_start', where NVRAM variables are written to minidlna.conf`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A configuration injection vulnerability exists in the 'cmddlna' script that allows arbitrary file directory exposure through the DLNA media server. The attack chain is as follows: 1) Attacker controls NVRAM variables 'upnp_serverName' or 'Device_name' (e.g., via web interface or other services) and sets them to values containing newlines and malicious 'media_dir' directives. 2) During DLNA startup, the script reads these variables and passes them unsanitized to the 'print_dlna_conf' function. 3) The function uses heredoc to write the minidlna.conf file, where the injected newlines allow adding arbitrary 'media_dir' lines. 4) minidlna serves files from the injected directories, leading to information disclosure of sensitive files (e.g., /etc/passwd). The vulnerability is exploitable due to lack of input sanitization for newlines and the ability to inject valid minidlna configuration directives.
- **Code Snippet:**
  ```
  print_dlna_conf() {
  cat <<EOF
  port=8200
  network_interface=br0
  friendly_name=$3
  album_art_names=Cover.jpg/cover.jpg/AlbumArtSmall.jpg/albumartsmall.jpg/AlbumArt.jpg/albumart.jpg/Album.jpg/album.jpg/Folder.jpg/folder.jpg/Thumb.jpg/thumb.jpg
  inotify=yes
  enable_tivo=$4
  strict_dlna=yes
  presentation_url=http://www.routerlogin.net
  notify_interval=900
  serial=12345678
  model_name=$5
  model_number=1
  EOF
  }
  
  # In dlna_start:
  name=$($config get upnp_serverName)
  [ "x$name" = "x" ] && name=$($config get Device_name)
  [ "x$name" = "x" ] && name="ReadyDLNA: $(cat /module_name)"
  print_dlna_conf "$($config get lan_ipaddr)" "$($config get lan_netmask)" "$name" "$($config get upnp_enable_tivo)" "$($config get Device_name)" > $MINIDLNA_CONF
  ```
- **Keywords:** upnp_serverName, Device_name
- **Notes:** This vulnerability requires the attacker to have the ability to set NVRAM variables, which is typically possible through the web administration interface or other exposed services. The script must be executed (e.g., via 'cmddlna start'), which occurs when DLNA is enabled. Mitigation involves sanitizing NVRAM inputs by removing or escaping newlines before using them in configuration files. Additional analysis could verify if other NVRAM variables (e.g., those used in shared folder settings) are similarly vulnerable.

---
### command-injection-event_notify

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/app_register.sh`
- **Location:** `event_notify 函数中的命令执行行`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** 在 event_notify 函数中，脚本使用未引用的变量 ${app} 和 $@ 执行应用命令。如果应用目录名（来自文件系统）或事件参数（来自命令行）包含 shell 元字符（如分号、反引号），可能导致任意命令执行。完整攻击链：1. 攻击者通过其他方式（如文件上传漏洞）在 APP_FOLDER (/storage/system/apps) 中创建恶意目录，目录名包含命令注入序列（例如 'malicious; echo hacked'）。2. 攻击者调用 event_notify（例如通过命令行或 IPC），传递事件类型和参数。3. 在 event_notify 循环中，对于恶意目录，脚本执行命令 `${APP_FOLDER}/${app}/program/${app} event $@ &`，其中 ${app} 是恶意目录名，导致 shell 解析并执行注入的命令。触发条件：event_notify 被调用且存在恶意目录。可利用性分析：由于变量未引用，shell 会对目录名和参数进行分词和元字符解释，缺少输入净化和验证。
- **Code Snippet:**
  ```
  local app
  for n in $installed_apps; do
      app=${n##*/}
      [ "x$(grep $event_name ${APP_FOLDER}/${app}/data/${SYSTEM_CONFIG_NAME})" != "x" ] && \
          ${APP_FOLDER}/${app}/program/${app} event $@ &
  done
  ```
- **Keywords:** filesystem_paths, command_line_parameters
- **Notes:** 攻击者需要能创建恶意目录在 /storage/system/apps 中，可能通过其他漏洞或文件上传功能。建议验证应用安装机制是否允许任意目录创建。后续分析应检查如何调用此脚本（如通过 web 接口或 IPC）以及目录创建权限。

---
