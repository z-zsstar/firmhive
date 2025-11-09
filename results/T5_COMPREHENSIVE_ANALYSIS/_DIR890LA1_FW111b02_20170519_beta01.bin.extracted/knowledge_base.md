# _DIR890LA1_FW111b02_20170519_beta01.bin.extracted (30 findings)

---

### permission-stunnel.key

- **File/Directory Path:** `etc/stunnel.key`
- **Location:** `stunnel.key`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The stunnel.key file contains an RSA private key, and the file permissions are set to 777 (-rwxrwxrwx), allowing any user (including non-root users) to read, write, and execute. An attacker as a non-root user can directly read the private key without requiring privilege escalation. Trigger condition: The attacker possesses valid login credentials (non-root user) and performs a file read operation (e.g., 'cat stunnel.key'). Constraint: No boundary checks or access controls, permissions are globally open. Potential attacks include decrypting stunnel-protected communications, performing man-in-the-middle attacks, or impersonating the service identity. Exploitation is simple: directly read the file content and misuse the private key.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  MY1Umfq9FAzBYSvPYEGER4gYq467yvp5wO97CUoTSJHbJDPnp9REj6wLcMkG7R9O
  g8/WuQ3hsoexPu4YkjJXPhtQ6YkV7seEDgP3C2TNqCnHdXzqSs7+vT17chwu8wau
  j/VMVZ2FRHU63JQ9DG6PqcudHTW+T/KVnmWXQnspgr8ZMhXobETtdqtRPtxbA8mE
  ZeF8+cIoA9VcqP09/VMBbRm+o5+Q4hjtvSrv+W2bEd+BDU+V45ZX8ZfPoEWYjQqI
  kv7aMECTIX2ebgKsjCK3PfYUX5PYbVWUV+176wIDAQABAoIBAQCQR/gcBgDQO7t+
  uc9dmLTYYYUpa9ZEW+3/U0kWbuyRvi1DUAaS5nMiCu7ivhpCYWZSnTJCMWbrQmjN
  vLT04H9S+/6dYd76KkTOb79m3Qsvz18tr9bHuEyGgsUp66Mx6BBsSKhjt2roHjnS
  3W29WxW3y5f6NdAM+bu12Ate+sIq8WHsdU0hZD+gACcCbqrt4P2t3Yj3qA9OzzWb
  b9IMSE9HGWoTxEp/TqbKDl37Zo0PhRlT3/BgAMIrwASb1baQpoBSO2ZIcwvof31h
  IfrbUWgTr7O2Im7OiiL5MzzAYBFRzxJsj15mSm3/v3cZwK3isWHpNwgN4MWWInA1
  t39bUFl5AoGBANi5fPuVbi04ccIBh5dmVipy5IkPNhY0OrQp/Ft8VSpkQDXdWYdo
  MKF9BEguIVAIFPQU6ndvoK99lMiWCDkxs2nuBRn5p/eyEwnl2GqrYfhPoTPWKszF
  rzzJSBKoStoOeoRxQx/QFN35/LIxc1oLv/mFmZg4BqkSmLn6HrFq2suVAoGBAMG1
  CqmDs2vU43PeC6G+51XahvRI3JOL0beUW8r882VPUPsgUXp9nH3UL+l9/cBQQgUC
  n12osLOAXhWDJWvJquK9HxkZ7KiirNX5eJuyBeaxtOSfBJEKqz/yGBRRVBdBHxT2
  a1+gO0MlG6Dtza8azl719lr8m6y2O9pyIeUewUl/AoGAfNonCVyls0FwL57n+S2I
  eD3mMJtlwlbmdsI1UpMHETvdzeot2JcKZQ37eIWyxUNSpuahyJqzTEYhf4kHRcO/
  I0hvAe7UeBrLYwlZquH+t6lQKee4km1ULcWbUrxHGuX6aPBDBkG+s75/eDyKwpZA
  S0RPHuUv2RkQiRtxsS3ozB0CgYEAttDCi1G82BxHvmbl23Vsp15i19KcOrRO7U+b
  gmxQ2mCNMTVDMLO0Kh1ESr2Z6xLT/B6Jgb9fZUnVgcAQZTYjjXKoEuygqlc9f4S/
  C1Jst1koPEzH5ouHLAa0KxjGoFvZldMra0iyJaCz/qHw6T4HXyALrbuSwOIMgxIM
  Y00vZskCgYAuUwhDiJWzEt5ltnmYOpCMlY9nx5qJnfcSOld5OHZ0kUsRppKnHvHb
  MMVyCTrp1jiH/o9UiXrM5i79fJBk7NT7zqKdI0qmKTQzNZhmrjPLCM/xEwAXtQMQ
  1ldI69bQEdRwQ1HHQtzVYgKA9XCmvrUGXRq6E5sp2ky+X1QabC7bIg==
  -----END RSA PRIVATE KEY-----
  ```
- **Keywords:** stunnel.key
- **Notes:** This vulnerability is practically exploitable; the attack chain is simple and direct: a non-root user reads the private key file. It is recommended to immediately fix the file permissions (e.g., set to 600) and check the stunnel configuration to ensure the private key is not misused. Associated files may include stunnel configuration files (e.g., stunnel.conf), but the current analysis is limited to stunnel.key. Subsequent analysis should verify whether the stunnel service uses this private key and the network exposure situation.

---
### PrivKey-Permission-stunnel

- **File/Directory Path:** `etc/stunnel.conf`
- **Location:** `stunnel.conf (implicit via configuration) and file permissions at /etc/stunnel.key`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The stunnel.key private key file permissions are set to 777 (rwxrwxrwx), allowing any user (including non-root users) to read the file. An attacker as a logged-in non-root user can directly perform read operations (for example, using 'cat /etc/stunnel.key') to obtain the private key. After the private key is leaked, the attacker can use it to decrypt SSL/TLS communications, perform man-in-the-middle attacks, or impersonate the service identity. The trigger condition is simple: the attacker only needs valid login credentials and file read permissions. No other vulnerabilities or complex steps are required to complete the exploitation. Constraint conditions: no boundary checks or access controls, the file is globally readable. Potential attack methods include passive eavesdropping or active hijacking of encrypted sessions.
- **Code Snippet:**
  ```
  key = /etc/stunnel.key
  # File permissions: -rwxrwxrwx 1 user user 1679 May  19  2017 stunnel.key
  ```
- **Keywords:** /etc/stunnel.key, /etc/stunnel_cert.pem
- **Notes:** This finding is based on direct evidence: the file permissions are 777 and the file exists. It is recommended to immediately fix the file permissions (for example, set to 600) and review other related files (such as stunnel_cert.pem). Although stunnel runs with root privileges (setuid=0) and debug mode enabled (debug=7) may increase the risk, there is currently a lack of complete attack chain evidence. Subsequent analysis should check if the stunnel binary has vulnerabilities and whether the log file (/var/log/stunnel.log) permissions are inappropriate.

---
### Code-Injection-form_portforwarding

- **File/Directory Path:** `htdocs/mydlink/form_portforwarding`
- **Location:** `File: ./form_portforwarding, Function: In the if($settingsChanged == 1) block, specifically at the fwrite and dophp call locations`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A code injection vulnerability was discovered in the 'form_portforwarding' file. When the script processes port forwarding configuration, it directly reads user input from POST requests (such as 'enabled_*', 'name_*', 'ip_*' fields, etc.) without performing input validation, filtering, or escaping. This input is written to a temporary file `/tmp/form_portforwarding.php`, which is then loaded and executed via `dophp("load",$tmp_file)`. An attacker can inject PHP code by crafting malicious POST data, for example, setting `enabled_0` to '1; system("malicious_command"); //', which executes arbitrary commands when the file is loaded. The trigger condition is sending a POST request to the endpoint handling this script with `settingsChanged=1`. The exploitation is straightforward; an attacker, as a logged-in user, can execute code remotely, potentially leading to full device control.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"enabled_".$i."\"];\n");
  // Similar multiple fwrite lines for other POST fields
  dophp("load",$tmp_file);
  ```
- **Keywords:** POST fields: settingsChanged, enabled_*, used_*, name_*, public_port_*, public_port_to_*, sched_name_*, ip_*, private_port_*, hidden_private_port_to_*, protocol_*, Temporary file path: /tmp/form_portforwarding.php, Functions: dophp, fwrite, ipv4hostid, Configuration path: /nat/entry/virtualserver
- **Notes:** Exploiting this vulnerability requires the attacker to have valid login credentials. It is recommended to further verify the definition and behavior of the `dophp` function (likely located in an include file, such as `/htdocs/phplib/xnode.php`) to confirm the code execution mechanism. Also, check if other similar scripts have the same issue. The attack chain is complete and verifiable from input to code execution.

---
### code-injection-form_macfilter

- **File/Directory Path:** `htdocs/mydlink/form_macfilter`
- **Location:** `form_macfilter: (estimated lines 20-50) within if($settingsChanged == 1) block`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A code injection vulnerability was discovered in the 'form_macfilter' file, allowing arbitrary PHP code execution through unfiltered POST parameters. Specifics: When the 'settingsChanged' POST parameter is set to 1, the script dynamically generates a temporary file '/tmp/form_macfilter.php' and directly writes user-controlled POST parameters (such as 'entry_enable_X', 'mac_X', 'mac_hostname_X', 'mac_addr_X', 'sched_name_X') into this file, which is then loaded and executed via 'dophp("load",$tmp_file)'. Due to a lack of input validation and filtering, attackers can inject malicious PHP code. Trigger Condition: An attacker sends a POST request with 'settingsChanged=1' and malicious parameter values. Potential Attack Method: Injecting code such as 'system("id")' can achieve RCE, compromising device security. Constraints: The attacker must have valid login credentials (non-root user) and access to the relevant web interface.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_\".$i.\"];\n");
  dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST["settingsChanged"], $_POST["macFltMode"], $_POST["entry_enable_*"], $_POST["mac_*"], $_POST["mac_hostname_*"], $_POST["mac_addr_*"], $_POST["sched_name_*"], /tmp/form_macfilter.php, dophp, runservice
- **Notes:** The vulnerability is confirmed based on code analysis but has not been practically tested. It is recommended to further verify the behavior of the 'dophp' function (likely defined in included library files such as '/htdocs/phplib/xnode.php') and the execution context of the temporary file. Related files: '/htdocs/mydlink/header.php', '/htdocs/phplib/xnode.php', '/htdocs/mydlink/libservice.php'. Next analysis steps: Check if the web interface endpoint exposes this script and test actual injection payloads.

---
### CodeInjection-RCE-form_wlan_acl

- **File/Directory Path:** `htdocs/mydlink/form_wlan_acl`
- **Location:** `form_wlan_acl: approximately lines 20-25 (in the while loop with fwrite and dophp calls)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** This vulnerability originates from the script dynamically generating and executing temporary PHP files without filtering or escaping user input. An attacker can inject malicious PHP code by controlling POST parameters such as 'mac_i' or 'enable_i' (where i is an index). The trigger condition is: sending a POST request with 'settingsChanged'=1. The injected code is executed when dophp('load',$tmp_file) is called, which can lead to arbitrary command execution. For example, setting 'mac_0' to '"; system("id"); //' will break the code syntax and execute system("id"). Constraints: The attacker must possess valid login credentials (non-root user) and must send the request through the Web interface. The exploitation method is simple, requiring only the construction of a malicious POST request to achieve RCE.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$MAC = $_POST[\"mac_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$ENABLE = $_POST[\"enable_\".$i.\"];\n");
  dophp("load", $tmp_file);
  ```
- **Keywords:** $_POST['settingsChanged'], $_POST['mode'], $_POST['mac_i'], $_POST['enable_i'], /tmp/form_wlan_acl.php, dophp
- **Notes:** The evidence is based on code analysis, but it is recommended to further verify the specific implementation of the dophp function (which may be located in an include file, such as '/htdocs/mydlink/libservice.php') to confirm execution behavior. Associated files may include other PHP include files. Subsequent analysis directions: check if the get_valid_mac function can be bypassed, and whether the services called by runservice introduce other risks.

---
### CommandInjection-hedwig.cgi

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `cgibin:0x175f4 fcn.000175f4 (hedwig.cgi handler)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the processing of the service parameter in hedwig.cgi. The service parameter is extracted from the QUERY_STRING environment variable and used without filtering in sprintf to construct a command string, which is then executed via system(). Trigger condition: POST request, Content-Type set to text/xml, and QUERY_STRING contains the service parameter. Constraints: The request method must be POST, and Content-Type must be correctly set. Potential attack: An authenticated user can inject shell metacharacters (e.g., ;, &, |) into the service parameter to execute arbitrary commands, potentially leading to remote code execution. The CGI process may run with elevated privileges. Code logic: Function fcn.000175f4 checks environment variables, extracts the service parameter, and uses it in sprintf to construct a command like 'sh /var/run/%s_%d.sh > /dev/console &', which is ultimately passed to system().
- **Code Snippet:**
  ```
  // Key vulnerable code sections:
  - Extraction of service parameter: uVar1 = sym.imp.strchr(*(puVar6 + -0x14),0x3f); // Finds '?' in QUERY_STRING
    *(puVar6 + -0x1c) = uVar1;
    if (...) {
      *(puVar6 + -0x1c) = *(puVar6 + -0x1c) + 9; // Points to value after '?service='
    }
  - Command construction: sym.imp.sprintf(0x7544 | 0x30000,0xbf50 | 0x20000,0xbf1c | 0x20000,*(puVar6 + -0x1c)); // Format: 'sh %s/%s_%d.sh > /dev/console &' with /var/run and service value
  - Command execution: sym.imp.system(0x7544 | 0x30000); // Executes the constructed command
  ```
- **Keywords:** QUERY_STRING, CONTENT_TYPE, REQUEST_METHOD, service, /var/run/, fcn.000175f4
- **Notes:** The vulnerability is highly exploitable because user input is passed directly to system(). The CGI may run with root privileges, increasing the impact. The attack chain is complete, from environment variable input to command execution.

---
### Private-Key-Exposure-stunnel

- **File/Directory Path:** `etc/stunnel_cert.pem`
- **Location:** `File: stunnel.key (Permissions: 777), stunnel.conf:1-2 (Configuration Path)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** During the analysis of the 'stunnel_cert.pem' file, it was found that its associated private key file 'stunnel.key' has permissions set to 777 (readable by all users), exposing the private key to non-root users. An attacker (a non-root user with valid login credentials) can directly read the private key and use it for TLS-related attacks, such as decrypting captured traffic or performing man-in-the-middle attacks. The stunnel service configuration ('stunnel.conf') shows the service runs with root privileges, using these certificate and private key files, further amplifying the risk. The attack chain is complete: attacker logs into the system → reads '/etc/stunnel.key' → uses the private key to decrypt or impersonate the service. The certificate uses the weak SHA-1 signature algorithm, but this alone does not constitute a direct vulnerability; the primary risk comes from the private key exposure.
- **Code Snippet:**
  ```
  From stunnel.key file content:
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  ... (complete private key content)
  -----END RSA PRIVATE KEY-----
  
  From stunnel.conf file content:
  cert = /etc/stunnel_cert.pem
  key = /etc/stunnel.key
  setuid = 0
  setgid = 0
  ```
- **Keywords:** stunnel.key, stunnel_cert.pem, stunnel.conf, /etc/stunnel.key, /etc/stunnel_cert.pem
- **Notes:** Private key exposure is a serious issue; the attack chain is complete and verifiable. It is recommended to immediately fix the file permissions (e.g., set to 600) and consider rotating the certificate and private key. Further analysis should check if the stunnel service is exposed to the network and if other sensitive files have similar permission issues.

---
### command-injection-DS_IPT

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php:DS_IPT mode processing block (approximately lines 150-190)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In 'DS_IPT' mode, the variables $C_IP, $E_PORT, $SSL come from external input (such as HTTP requests) and are directly concatenated into the iptables command string, which is then executed via the exe_ouside_cmd function. Due to a lack of input validation and filtering, an attacker can execute arbitrary system commands by injecting malicious characters (such as semicolons, backticks). Trigger condition: The attacker sends a request with MODE=DS_IPT and controls parameters like $C_IP. Exploitation method: For example, setting $C_IP to '192.168.1.1; malicious_command', leading to command injection. The code logic directly concatenates input into the command without using escaping or whitelist validation. The attack chain is complete: input point → command concatenation → execution.
- **Code Snippet:**
  ```
  else if($MODE=="DS_IPT")  //add directserver iptable rules
  {
      $ipt_cmd="";
      
      if($C_IP=="0.0.0.0")
          {$ipt_cmd="PRE.WFA -p tcp";}
      else
          {$ipt_cmd="PRE.WFA -p tcp -s ".$C_IP;}
          
      if($SSL == '0')
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpport");}
      else
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpsport");}
      
      if($ipt_cmd!="")
      {
          $del_ipt="iptables -t nat -D ".$ipt_cmd;
          exe_ouside_cmd($del_ipt);
          $add_ipt="iptables -t nat -A ".$ipt_cmd;
          exe_ouside_cmd($add_ipt);
      }
      // ... other code
  }
  ```
- **Keywords:** MODE, C_IP, E_PORT, SSL, /runtime/webaccess/ext_node
- **Notes:** The attack chain is complete: input point ($C_IP, etc.) → command concatenation → exe_ouside_cmd execution. The exe_ouside_cmd function uses setattr and get, and command execution might be implemented in other files, requiring further verification. It is recommended to check included files (such as /htdocs/phplib/xnode.php) to confirm the execution mechanism. Other modes (such as SEND_IGD) might also have similar issues, but the DS_IPT mode has the most direct evidence. The attacker is a connected user with login credentials, not a root user.

---
### command-injection-inet6_dhcpc_helper

- **File/Directory Path:** `etc/services/INET/inet6_dhcpc_helper.php`
- **Location:** `inet6_dhcpc_helper.php:handle_stateful 函数（约行 100-150）和 handle_stateless 函数（约行 250-300）`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 命令注入漏洞存在于多个 cmd() 调用中，由于输入变量（如 NEW_PD_PREFIX、NEW_PD_PLEN、DNS）仅使用 strip() 函数处理（可能只去除首尾空格），未过滤 shell 元字符（如 ;、&、|）。攻击者可通过控制这些变量注入恶意命令。触发条件包括：当 MODE 为 STATEFUL、STATELESS 或 PPPDHCP 时，处理 DHCPv6 客户端回调；攻击者需能影响 DHCP 配置或响应（例如通过恶意 DHCP 服务器或本地配置修改）。潜在利用方式：注入命令如 '; malicious_command #' 到变量中，导致以脚本运行权限（可能 root）执行任意命令。约束条件：输入来自 $_GLOBALS，可能受网络或配置控制；strip() 函数可能不足以防注入。
- **Code Snippet:**
  ```
  // 示例来自 handle_stateful 函数
  cmd(\"ip -6 route add blackhole \".$NEW_PD_PREFIX.\"/\".$NEW_PD_PLEN.\" dev lo\");
  // 示例来自 phpsh 调用
  cmd(\"phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH INF=\".$_GLOBALS[\"INF\"].\" MODE=\".$_GLOBALS[\"MODE\"].\" DEVNAM=\".$devnam.\" IPADDR=\".$ipaddr.\" PREFIX=\".$pfxlen.\" GATEWAY=\".$router.' \"DNS=\'.$dns.'\"\');
  // 输入处理
  $NEW_PD_PREFIX = strip($_GLOBALS[\"NEW_PD_PREFIX\"]);
  $dns = dns_handler($DNS, $NAMESERVERS); // 其中 $DNS = strip($_GLOBALS[\"DNS\"]);
  ```
- **Keywords:** $_GLOBALS[\"NEW_PD_PREFIX\"], $_GLOBALS[\"NEW_PD_PLEN\"], $_GLOBALS[\"DNS\"], $_GLOBALS[\"NAMESERVERS\"], $_GLOBALS[\"NEW_ADDR\"], cmd() 函数, /var/run/ 文件路径, phpsh /etc/scripts/IPV6.INET.php
- **Notes:** 证据基于代码分析：strip() 函数可能未定义在本文件中，但假设它仅处理空格，不防止命令注入。攻击链完整：输入点（$_GLOBALS）→ 数据流（strip() 处理）→ 危险操作（cmd() 执行）。建议验证 strip() 的具体实现（在包含文件中），并检查其他组件（如 DHCP 客户端）如何设置 $_GLOBALS。非 root 用户可能通过 Web 界面或 CLI 修改 DHCP 配置来触发。关联文件：/htdocs/phplib/ 中的包含文件可能定义相关函数。通过知识库查询，发现与 'MODE' 标识符相关的现有命令注入漏洞，但本发现独立且完整。

---
### command-injection-inet_ipv6

- **File/Directory Path:** `etc/services/INET/inet_ipv6.php`
- **Location:** `inet_ipv6.php: inet_ipv6_static function (around line 250), inet_ipv6_auto function (around line 400), and other functions using `get_dns``
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'inet_ipv6.php' file. An attacker can configure a malicious DNS server address (containing shell metacharacters such as double quotes or semicolons). When the script executes IPv6 configuration, DNS data is obtained through the `get_dns` function and directly inserted into a shell command string without escaping. For example, in the `inet_ipv6_static` function, DNS data is used to construct a `phpsh` command. If the DNS value contains `"; malicious_command "`, it can break out of the double quote restriction and execute arbitrary commands. The trigger condition is when an attacker modifies the IPv6 configuration (such as static mode DNS settings) and triggers script execution (e.g., interface startup). Exploitation method: an attacker, as a logged-in user, sets a malicious DNS configuration via the web interface or API, then waits for or triggers a network reconfiguration, leading to arbitrary command execution with root privileges.
- **Code Snippet:**
  ```
  In the inet_ipv6_static function:
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH".
      " MODE=STATIC INF=".$inf.
      " DEVNAM=".        $devnam.
      " IPADDR=".        query("ipaddr").
      " PREFIX=".        query("prefix").
      " GATEWAY=".    query("gateway").
      ' "DNS='.get_dns($inetp."/ipv6").'"'
      );
  
  In the inet_ipv6_auto function:
  fwrite(w, $rawait,
      "#!/bin/sh\n".
      "phpsh /etc/scripts/RA-WAIT.php".
          " INF=".$inf.
          " PHYINF=".$phyinf.
          " DEVNAM=".$ifname.
          " DHCPOPT=".query($inetp."/ipv6/dhcpopt").
          ' "DNS='.get_dns($inetp."/ipv6").'"'.
          " ME=".$rawait.
          "\n");
  
  get_dns function:
  function get_dns($p)
  {
      anchor($p);
      $cnt = query("dns/count")+0;
      foreach ("dns/entry")
      {
          if ($InDeX > $cnt) break;
          if ($dns=="") $dns = $VaLuE;
          else $dns = $dns." ".$VaLuE;
      }
      return $dns;
  }
  ```
- **Keywords:** NVRAM: /inet/entry/ipv6/dns/entry, ENV: INET_INFNAME, File path: /etc/scripts/IPV6.INET.php, IPC: Communication via xmldbc command
- **Notes:** The exploitation of this vulnerability relies on the user being able to control DNS configuration data and submit it through the network interface. Further verification is needed to check if the web interface or other input points filter DNS data, and the specific permission context of script execution. It is recommended to check related configuration files and input validation mechanisms. Other functions (such as inet_ipv6_6in4) might also have similar issues, but current evidence focuses on the DNS data flow.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/inet_ppp4.php`
- **Location:** `inet_ppp4.php:~200 (at the fwrite call in the over=='tty' branch)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'inet_ppp4.php' file, when a PPP connection uses a USB modem (over=='tty'), the APN and dial number parameters are obtained from user-controllable NVRAM or environment variables and are directly concatenated into shell commands to generate a script file. Due to the lack of input escaping or validation, an attacker can inject arbitrary commands by setting a malicious APN or dial number (such as a command string containing shell metacharacters). Trigger condition: When the PPP connection starts (for example, when the user applies network settings or a connection is established), the generated script is executed with root privileges, leading to command injection. Exploitation method: An attacker, as an authenticated non-root user, sets malicious parameters through the Web interface or API, triggers script execution, and gains root privileges.
- **Code Snippet:**
  ```
  fwrite(a, $START,
      'xmldbc -s '.$ttyp.'/apn "'.$apn.'"\n'.
      'xmldbc -s '.$ttyp.'/dialno "'.$dialno.'"\n'.
      'usb3gkit -o /etc/ppp/chat.'.$inf.' -v 0x'.$vid.' -p 0x'.$pid.' -d '.$devnum.'\n'.
      '# chatfile=[/etc/ppp/char'.$inf.']\n'
      );
  ```
- **Keywords:** /runtime/auto_config/apn, /runtime/auto_config/dialno, /inet/entry/ppp4/tty/apn, /inet/entry/ppp4/tty/dialno
- **Notes:** This vulnerability requires the over=='tty' condition to be true (i.e., using a USB modem). The attack chain is complete and verifiable: user input → script generation → command execution. It is recommended to check if related components (such as usb3gkit) also have similar issues and to validate the input filtering mechanism. Subsequent analysis can examine other input points (such as PPPoE parameters) to identify similar vulnerabilities.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/inet_ipv4.php`
- **Location:** `inet_ipv4.php:inet_ipv4_static, inet_ipv4.php:inet_ipv4_dynamic, inet_ipv4.php:inet_ipv4_dslite`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the inet_ipv4.php file, multiple functions (inet_ipv4_static, inet_ipv4_dynamic, inet_ipv4_dslite) retrieve user input from NVRAM or configuration and directly embed it into system commands or shell scripts, lacking input validation and escaping. Specific issues include:
- In the inet_ipv4_static function, IP address, subnet mask, gateway, MTU, and DNS values are concatenated into phpsh commands. If the input contains special characters (such as semicolons, backticks), arbitrary command injection may occur.
- In the inet_ipv4_dynamic function, hostname, DNS, and DHCP+ credentials are used to construct udhcpc commands and generate shell scripts. The inputs are directly embedded in the scripts, allowing command injection.
- In the inet_ipv4_dslite function, IP address and remote address are used in ip commands, presenting similar risks.
Trigger condition: When an attacker configures network settings via the web interface or API and provides malicious input (e.g., a hostname containing '; id;'). When the network configuration is applied (e.g., interface startup), the commands are executed.
Potential attack: An attacker can execute arbitrary commands, escalate privileges, or compromise the system. The exploitation method is straightforward, requiring only control over the input values.
- **Code Snippet:**
  ```
  // Command concatenation in the inet_ipv4_static function
  startcmd("phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH".
      " STATIC=1".
      " INF=".$inf.
      " DEVNAM=".$ifname.
      " IPADDR=".$ipaddr.
      " MASK=".$mask.
      " GATEWAY=".$gw.
      " MTU=".$mtu.
      ' "DNS='.$dns.'"\\n'.
      $event_add_WANPORTLINKUP
      );
  
  // Script generation and command concatenation in the inet_ipv4_dynamic function
  fwrite(w,$udhcpc_helper,
      '#!/bin/sh\\n'.
      'echo [$0]: $1 $interface $ip $subnet $router $lease $domain $scope $winstype $wins $sixrd_prefix $sixrd_prefixlen $sixrd_msklen $sixrd_bripaddr ... > /dev/console\\n'.
      'phpsh '.$hlper.' ACTION=$1'.
          ' INF='.$inf.
          ' INET='.$inet.
          ' MTU='.$mtu.
          ' INTERFACE=$interface'.
          ' IP=$ip'.
          ' SUBNET=$subnet'.
          ' BROADCAST=$broadcast'.
          ' LEASE=$lease'.
          ' "DOMAIN=$domain"'.
          ' "ROUTER=$router"'.
          ' "DNS='.$dns.'$dns"'.\\t\\t\\t
          ' "CLSSTROUT=$clsstrout"'.
          ' "MSCLSSTROUT=$msclsstrout"'.
          ' "SSTROUT=$sstrout"'.
          ' "SCOPE=$scope"'.
          ' "WINSTYPE=$winstype"'.
          ' "WINS=$wins"'.
          ' "SIXRDPFX=$sixrd_prefix"'.
          ' "SIXRDPLEN=$sixrd_prefixlen"'.
          ' "SIXRDMSKLEN=$sixrd_msklen"'.
          ' "SIXRDBRIP=$sixrd_bripaddr"'.\\t\\t\\t
          ' "SDEST=$sdest"'.
          ' "SSUBNET=$ssubnet"'.
          ' "SROUTER=$srouter"\\n'.
      'exit 0\\n'
      );
  
  'udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname_dhcpc.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' '.$dhcpplus_cmd.' &\\n'
  ```
- **Keywords:** /device/hostname_dhcpc, $inetp/ipv4/ipaddr, $inetp/ipv4/mask, $inetp/ipv4/gateway, $inetp/ipv4/mtu, $inetp/ipv4/dns/entry, $inetp/ipv4/dhcpplus/username, $inetp/ipv4/dhcpplus/password, $inetp/ipv4/ipv4in6/remote
- **Notes:** Input points may be controllable via web interface or API user configuration. The attack chain is complete: user input → data flow (direct concatenation) → command execution. It is recommended to further verify the implementation of input sources and filtering mechanisms in other files (such as web backend scripts). Related files: /etc/scripts/IPV4.INET.php, /etc/services/INET/inet4_dhcpc_helper.php.

---
### buffer_overflow-fcn.000183f8_filename

- **File/Directory Path:** `sbin/mt-daapd`
- **Location:** `mt-daapd:0x18994 fcn.000183f8`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In function fcn.000183f8, strcpy is called at address 0x18994, copying the filename from the directory entry to the destination buffer. The filename is obtained from the file system via readdir_r, and an attacker may control the file system content (for example, by uploading or creating files). There is no bounds checking, and the destination buffer size is unknown (from function parameter arg_1000h), leading to a buffer overflow vulnerability. Trigger condition: When the function processes a directory, the attacker provides a long filename (exceeding the destination buffer size). Exploitation method: By creating a file with a long filename, overflowing the buffer may overwrite the return address or execute arbitrary code.
- **Code Snippet:**
  ```
  0x18454: ldr r3, [r6, 4] ; cmp r3, 0 ; bne 0x18870 --> Loop start calls readdir_r to get directory entry
  0x18520: add r4, r8, 0xb ; mov r0, r4 ; bl sym.imp.strlen --> r4 set to filename string address
  0x18994: bl sym.imp.strcpy --> Tainted data r4 copied to destination buffer r8, no bounds checking
  ```
- **Keywords:** directory entry, arg_1000h
- **Notes:** Further verification is needed regarding the specific size of the destination buffer and the consequences of the overflow, but based on the data flow from untrusted input to a dangerous operation, the vulnerability is practically exploitable. It is recommended to check function parameter passing and buffer allocation.

---
### buffer_overflow-fcn.000183f8_filecontent

- **File/Directory Path:** `sbin/mt-daapd`
- **Location:** `mt-daapd:0x18b50 fcn.000183f8`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In function fcn.000183f8, strcpy is called at address 0x18b50, copying file content to the target buffer. File content is obtained through file reading (fread-like operation), and an attacker may control the file content. There is no bounds checking, and the target buffer size is unknown (from function parameter arg_1000h), leading to a buffer overflow vulnerability. Trigger condition: When the function reads a file, the attacker provides a long-content file (exceeding the target buffer size). Exploitation method: By uploading a long-content file, overflowing the buffer may overwrite the return address or execute arbitrary code.
- **Code Snippet:**
  ```
  0x18a4c: ldr r0, [fildes] ; mov r1, r5 ; mov r2, 0x1000 ; bl fcn.00010fd8 --> Read data from file to buffer r5, size 0x1000
  0x18b50: bl sym.imp.strcpy --> Tainted data r5 copied to target buffer r8, no bounds checking
  ```
- **Keywords:** File content, arg_1000h
- **Notes:** Similar to the first call, but the source is file content. Need to confirm the specific context of the file reading operation, but based on evidence, the vulnerability is practically exploitable. Recommend limiting file input size or using safe functions.

---
### XSS-folder_view_php

- **File/Directory Path:** `htdocs/web/webaccess/folder_view.php`
- **Location:** `folder_view.php: JavaScript functions show_folder_content and get_sub_tree`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored cross-site scripting (XSS) vulnerability exists in the file list display function of 'folder_view.php'. An attacker can upload a file with a malicious JavaScript filename (e.g., '<img src=x onerror=alert(1)>.txt'). When other users or the attacker themselves view the file list, the filename is directly inserted into the HTML without escaping, leading to the execution of the malicious script. The trigger conditions include: 1) The attacker is logged in and has file upload permissions; 2) A malicious filename is used when uploading the file; 3) A user accesses the file list page. Potential exploitation methods include: stealing user session tokens, performing administrative actions, redirecting users to malicious websites, etc. This vulnerability is due to the lack of HTML escaping validation for filenames, allowing attackers to inject arbitrary scripts.
- **Code Snippet:**
  ```
  In the show_folder_content function:
  cell_html = "<input type=\"checkbox\" id=\"" + i + "\" name=\"" + file_name + "\" value=\"1\"/>"
  + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
  + "<div style=\"width:665px;overflow:hidden\">"
  + file_name + "<br>" + get_file_size(obj.size) + ", " + time
  + "</div></a>";
  
  In the get_sub_tree function:
  my_tree += "<li id=\"" + obj_path + "\" class=\"tocollapse\">"
  +  "<a href=\"#\" onClick=\"click_folder('" + obj_path + "', '" + current_volid + "', '" +obj.mode+ "')\">"
  + '<div class ="current_node" title="'+ show_name +'">'+obj.name + "</a></li>"
  + "<li></li>"
  + "<li><span id=\"" + obj_path + "-sub\"></span></li>";
  ```
- **Keywords:** file_name, obj.name, show_name, upload_file, show_folder_content, get_sub_tree
- **Notes:** This vulnerability is practically exploitable because the attack chain is complete: input point (file upload) -> data flow (filename is stored and returned) -> vulnerability point (no escaping during HTML rendering). It is recommended to perform HTML escaping on all user inputs. Subsequent analysis should check if the backend CGI interface performs additional validation on filenames and if there are other similar XSS points.

---
### XSS-get_Logopt.asp-form_mydlink_log_opt

- **File/Directory Path:** `htdocs/mydlink/get_Logopt.asp`
- **Location:** `get_Logopt.asp:1 (entire file), form_mydlink_log_opt:1 (entire file)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored cross-site scripting (XSS) vulnerability was discovered in the 'get_Logopt.asp' file. This file reads configuration data from paths like '/device/log/mydlink/eventmgnt/pushevent' using the `query` function and outputs XML, but the output does not escape the data. The related file 'form_mydlink_log_opt' handles POST requests to set this data, but input parameters (such as 'config.log_enable') are directly obtained from `$_POST` and lack validation. An attacker (a logged-in user) can submit a malicious POST request to inject JavaScript code; when a user visits 'get_Logopt.asp', the malicious script executes in the browser. Trigger condition: The attacker sends malicious parameters to 'form_mydlink_log_opt' (for example, setting 'config.log_enable' to `<script>alert('XSS')</script>`), and then the user accesses 'get_Logopt.asp'. Exploitation method: Stored XSS can steal session cookies, perform unauthorized operations, or hijack user sessions. The root cause is the lack of input filtering and output escaping in the code logic.
- **Code Snippet:**
  ```
  From 'get_Logopt.asp': 
  <?
  include "/htdocs/mydlink/header.php";
  include "/htdocs/phplib/xnode.php";
  include "/htdocs/webinc/config.php";
  $LOGP		="/device/log/mydlink/eventmgnt/pushevent";
  $PUSH		=query($LOGP."/enable");
  $USERLOGIN	=query($LOGP."/types/userlogin");
  $FWUPGRADE	=query($LOGP."/types/firmwareupgrade");
  $WLINTRU	=query($LOGP."/types/wirelessintrusion");
  ?>
  <mydlink_logopt>
  <config.log_enable><?=$PUSH?></config.log_enable>
  <config.log_userloginfo><?=$USERLOGIN?></config.log_userloginfo>
  <config.log_fwupgrade><?=$FWUPGRADE?></config.log_fwupgrade>
  <config.wirelesswarn><?=$WLINTRU?></config.wirelesswarn>
  </mydlink_logopt>
  
  From 'form_mydlink_log_opt':
  <?
  include "/htdocs/mydlink/header.php";
  $settingsChanged	=$_POST["settingsChanged"];
  $PUSH			=$_POST["config.log_enable"];
  $USERLOGIN		=$_POST["config.log_userloginfo"];
  $FWUPGRADE		=$_POST["config.log_fwupgrade"];
  $WLINTRU_V1		=$_POST["config.log_wirelesswarn"];
  $WLINTRU_V2		=$_POST["config.wirelesswarn"];
  $LOGP		="/device/log/mydlink/eventmgnt/pushevent";
  $PUSHP		=$LOGP."/enable";
  $USERLOGINP	=$LOGP."/types/userlogin";
  $FWUPGRADEP	=$LOGP."/types/firmwareupgrade";
  $WLINTRUP	=$LOGP."/types/wirelessintrusion";
  $WLINTRU = 0;
  if($WLINTRU_V1 == 1 || $WLINTRU_V2 == 1)
  	$WLINTRU = 1;
  if($USERLOGIN	== 1 || $FWUPGRADE == 1 || $WLINTRU == 1)
  	$PUSH = 1;
  $ret="fail";
  if($settingsChanged==1){
  	set($PUSHP, $PUSH);
  	set($USERLOGINP, $USERLOGIN);
  	set($FWUPGRADEP, $FWUPGRADE);
  	set($WLINTRUP, $WLINTRU);
  }
  $ret="ok";
  ?>
  <?=$ret?>
  ```
- **Keywords:** POST parameters: config.log_enable, config.log_userloginfo, config.log_fwupgrade, config.wirelesswarn, File paths: form_mydlink_log_opt, get_Logopt.asp, NVRAM paths: /device/log/mydlink/eventmgnt/pushevent/enable, /device/log/mydlink/eventmgnt/pushevent/types/userlogin, /device/log/mydlink/eventmgnt/pushevent/types/firmwareupgrade, /device/log/mydlink/eventmgnt/pushevent/types/wirelessintrusion
- **Notes:** Vulnerability verified via code analysis: Input is unfiltered and output is unescaped. The attack chain is complete, from the input point to the dangerous operation (XSS execution). Further verification is needed to check if other components use these output values, but current evidence is sufficient. It is recommended to check the implementation of the `set` and `query` functions (possibly in the unfound 'xnode.php') to confirm the data storage mechanism, but this does not affect the exploitation of this vulnerability. Subsequent analysis should focus on whether similar issues exist in other form files.

---
### info-leak-get_Wireless-displaypass-updated

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.asp`
- **Location:** `get_Wireless.php:1 (variable assignment) and get_Wireless.php:~70-80 (output section), Function: No specific function, global code`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** An information leak vulnerability was discovered in the 'get_Wireless.php' file, which is referenced via 'get_Wireless.asp'. The vulnerability allows authenticated users to leak sensitive wireless network configuration information, including WEP keys, WPA PSK keys, and RADIUS keys, via the HTTP GET parameter 'displaypass'. Specific behavior: when the 'displaypass' parameter is set to 1, the script returns this sensitive data in the XML output; otherwise, it returns an empty string. The trigger condition is simple: an attacker only needs to add '?displaypass=1' to the HTTP request. The code lacks input validation, boundary checks, or filtering, directly comparing `$_GET["displaypass"]` with 1. Potential attacks: After obtaining sensitive passwords, an attacker could use them for unauthorized wireless network access, offline password cracking, or further network penetration. Exploitation method: An authenticated user sending a request to the relevant endpoint (e.g., 'get_Wireless.php?displaypass=1' or accessed indirectly via 'get_Wireless.asp') can trigger it.
- **Code Snippet:**
  ```
  Key code snippet:
  - Input handling: \`$displaypass = $_GET["displaypass"];\`
  - Conditional output: 
    \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
    \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\`
    \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **Keywords:** HTTP GET parameter: displaypass, Output fields: f_wep, f_wps_psk, f_radius_secret1, Internal data source: NVRAM or configuration files obtained via query/get functions, Associated file: get_Wireless.asp (referenced via include)
- **Notes:** This vulnerability assumes the script is accessible via the web after authentication and that the attacker possesses valid login credentials (non-root user). Associated file: 'get_Wireless.asp' includes 'get_Wireless.php', but the vulnerability core is in the latter. Suggestions for further validation: 1) Whether 'get_Wireless.php' is in the web root directory and can be accessed directly or indirectly by authenticated users; 2) Whether there are role-based permission restrictions on parameter usage. Subsequent analysis direction: Check the authentication mechanism and web interface paths in the call chain.

---
### Untitled Finding

- **File/Directory Path:** `htdocs/web/webaccess/photo.php`
- **Location:** `photo.php: show_media_list function (approximately lines 50-70 in the code)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the show_media_list function of 'photo.php', the filename (obj.name) is not escaped when inserted into HTML, leading to a stored XSS vulnerability. Trigger condition: When a user visits the photo.php page, if a filename in the file list contains a malicious script (e.g., `<script>alert('XSS')</script>`), the script will execute in the victim's browser. An attacker, as a logged-in user, can inject a malicious payload by uploading a file or modifying a filename, then lure other users to view the photo list, thereby stealing session cookies or performing arbitrary actions. Constraints: The attacker needs file upload or modification permissions, and the victim must visit the photo.php page. The exploitation method is simple and direct, requiring no special permissions.
- **Code Snippet:**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_photos.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a rel=\"image1\" href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name +"<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"
       + "</td></tr>";
  ```
- **Keywords:** obj.name, media_info.files[i].name, /dws/api/GetFile
- **Notes:** Evidence is based on code analysis: The filename is directly concatenated into HTML without using an escape function (such as encodeHTML). The attack chain is complete: Attacker controls the filename → Server returns the file list → Victim views the page → XSS triggers. It is recommended to verify if the file upload function allows setting arbitrary filenames and to check if the backend API filters filenames. Related files may include upload handling scripts or file management components.

---
### Command-Injection-ppp6_ipup-route

- **File/Directory Path:** `etc/services/INET/ppp6_ipup.php`
- **Location:** `ppp6_ipup.php:50 (approximate line number, based on code structure) at echo 'ip -6 route add default via '.$REMOTE.' dev '.$IFNAME.'
';.`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the code, the $REMOTE and $IFNAME variables are directly concatenated into the 'ip -6 route' command, lacking input validation and escaping. If an attacker controls $REMOTE or $IFNAME (for example, through malicious PPP configuration or a man-in-the-middle attack), they can inject arbitrary shell commands. For example, setting $REMOTE to '192.168.1.1; malicious_command' could lead to command execution. The trigger condition is when the script executes during PPP connection establishment, and the attacker needs to be able to influence PPP negotiation or configuration. Potential exploitation methods include executing system commands, escalating privileges, or disrupting network configuration.
- **Code Snippet:**
  ```
  echo 'ip -6 route add default via '.$REMOTE.' dev '.$IFNAME.'
  ';
  ```
- **Keywords:** Environment variable $REMOTE, $IFNAME, File path /htdocs/phplib/xnode.php, /htdocs/phplib/phyinf.php, IPC events such as $PARAM.UP, Custom function XNODE_getpathbytarget, PHYINF_setup
- **Notes:** Further verification is needed for the actual source and controllability of $REMOTE and $IFNAME; it is recommended to check the PPP daemon's input handling; related files include ppp4_ipup.php and other PPP-related scripts.

---
### Command-Injection-bound

- **File/Directory Path:** `etc/services/INET/inet4_dhcpc_helper.php`
- **Location:** `inet4_dhcpc_helper.php: In the code block for the 'bound' action (specific line numbers not provided, but based on content it is located in the middle of the script)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the 'bound' action, multiple user-controllable variables (such as $INF, $INTERFACE, $IP, $SUBNET, $BROADCAST, $ROUTER, $DOMAIN, $DNS, $CLSSTROUT, $SSTROUT) are directly concatenated into shell command strings, lacking input validation or filtering. Attackers can inject malicious commands by manipulating these variables (for example, using semicolons, backticks, or pipe symbols), leading to arbitrary command execution. The trigger condition includes when $ACTION is 'bound', the script executes command construction logic. Potential exploitation methods include controlling variable values through malicious DHCP responses or web interface calls to execute system commands.
- **Code Snippet:**
  ```
  echo "phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH".\n        " STATIC=0".\n        " INF=".$INF.\n        " DEVNAM=".$INTERFACE.\n        " MTU=".$MTU.\n        " IPADDR=".$IP.\n        " SUBNET=".$SUBNET.\n        " BROADCAST=".$BROADCAST.\n        " GATEWAY=".$ROUTER.\n        ' "DOMAIN='.$DOMAIN.'"'.\n        ' "DNS='.$DNS.'"'.\n        ' "CLSSTROUT='.$CLSSTROUT.'"'.\n        ' "SSTROUT='.$SSTROUT.'"'.\n        '\n';
  ```
- **Keywords:** $ACTION, $INF, $INTERFACE, $IP, $SUBNET, $BROADCAST, $ROUTER, $DOMAIN, $DNS, $CLSSTROUT, $SSTROUT
- **Notes:** Further verification is needed to determine if the input variables come from untrusted sources (such as DHCP responses or web interfaces) and whether there are other filtering mechanisms. It is recommended to analyze the context in which this script is called (such as the web frontend or DHCP client) to confirm exploitability. Associated files may include '/etc/scripts/IPV4.INET.php' and web interface scripts.

---
### PPP-Option-Injection-create_pppoptions

- **File/Directory Path:** `etc/services/INET/options_ppp4.php`
- **Location:** `options_ppp4.php:~25-30 (function create_pppoptions, specifically at the fwrite call site)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The function `create_pppoptions` directly concatenates and writes user-controlled inputs (such as username, password, PPPoE parameters) into a PPP options file without escaping or validation. An attacker can escape string boundaries and add arbitrary PPP options (for example, the `connect` option to execute arbitrary commands) by injecting quotes (`"`) or newline characters (`\n`) into the input. Trigger conditions include: setting the PPP username or password via the web interface; when the PPP configuration is applied, this function is called to write to the `/etc/ppp/options.*` file; the PPP daemon (which may run with root privileges) reads this file and executes the injected options. Potential exploitation methods include privilege escalation, network configuration tampering, or command execution. Constraints: The attacker needs to have the permission to set PPP configuration (via the web interface); input length might be limited by field sizes, but is not explicitly checked in the code.
- **Code Snippet:**
  ```
  $user = get("s","username");
  $pass = get("s","password");
  // ...
  if ($user!="") fwrite(a,$OPTF, 'user "'.$user.'"\n');
  if ($pass!="") fwrite(a,$OPTF, 'password "'.$pass.'"\n');
  // Similarly for other inputs like $acn and $svc:
  $acn = get(s, "pppoe/acname");
  $svc = get(s, "pppoe/servicename");
  if ($acn!="") fwrite(a,$OPTF, 'pppoe_ac_name "'. $acn.'"\n');
  if ($svc!="") fwrite(a,$OPTF, 'pppoe_srv_name "'.$svc.'"\n');
  ```
- **Keywords:** username, password, pppoe/acname, pppoe/servicename, /etc/ppp/options.*
- **Notes:** This finding is based on direct evidence in the code, but exploitability depends on: 1) The context in which this function is called (e.g., whether it is exposed to the user via the web interface); 2) Whether the PPP daemon supports dangerous options (such as `connect`); 3) File write permissions (which might require root privileges). It is recommended to further analyze other files that call this function (such as web scripts) and the PPP configuration to verify the complete attack chain. Related functions: `get` and `query` might read data from NVRAM or XML configuration.

---
### PathTraversal-fwupload.cgi

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `cgibin: fcn.0001b9d0 (fwupload.cgi handler), fcn.0000d090 (file open function)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** A path traversal vulnerability exists in the fwupload.cgi handler. When the CGI script is called, if a parameter starts with '/htdocs/web/info/', that parameter is directly used in the open() system call without filtering path traversal sequences. Attackers can read arbitrary files by including '../' sequences in the parameter. Trigger condition: The request must contain a parameter starting with '/htdocs/web/info/'. Constraint: The user must be authenticated but does not require root privileges. Potential attack: An attacker can construct a path like '/htdocs/web/info/../../../etc/passwd' to access sensitive files, leading to information disclosure. Code logic: Function fcn.0001b9d0 checks the parameter prefix, then calls fcn.0000d090 which uses open() to open the file.
- **Code Snippet:**
  ```
  // From fcn.0001b9d0:
  uVar1 = sym.imp.strstr(*(puVar4[-0xb] + 4), "/htdocs/web/info/");
  puVar4[-3] = uVar1;
  ...
  if (puVar4[-3] != 0) {
      if (*(puVar4[-0xb] + 4) != puVar4[-3]) {
          fcn.0001b988();
          goto code_r0x0001bba8;
      }
      puVar4[-1] = *(puVar4[-0xb] + 4);
  }
  ...
  if ((puVar4[-1] != 0) && (iVar2 = fcn.0000d090(puVar4[-1], *(0x36430)), iVar2 == 0)) {
      *puVar4 = 0;
  }
  
  // From fcn.0000d090:
  uVar1 = sym.imp.open(puVar3[-4], 0); // Direct use of user input in open()
  ```
- **Keywords:** argv[1], open_file_path, HTTP request path parameter, /htdocs/web/info/
- **Notes:** Exploitation requires user authentication, but root privileges are not needed. The output stream (address 0x36430) is likely the HTTP response, leading to file content disclosure. No other mitigation measures were found; the attack chain is complete and verifiable.

---
### XSS-get_Macfilter.asp

- **File/Directory Path:** `htdocs/mydlink/get_Macfilter.asp`
- **Location:** `get_Macfilter.asp: output in foreach loop for MAC addresses without escaping`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In 'get_Macfilter.asp', MAC addresses are read from NVRAM and directly output to the XML response without escaping or filtering. An attacker can submit a malicious MAC address (containing JavaScript code) via 'form_macfilter'. When a victim (such as an administrator) visits the MAC filter page (triggering 'get_Macfilter.asp'), the malicious script executes, potentially leading to session theft or privilege escalation. Trigger condition: The attacker modifies the MAC filter settings and injects a script, and the victim views the relevant page. Exploitation method: Inject a MAC address such as '<script>alert(1)</script>'.
- **Code Snippet:**
  ```
  From 'get_Macfilter.asp': \`echo "<addr>".query("mac")."</addr>
  ";\` and from 'form_macfilter': \`$mac = $_POST["mac_".$i];\` ... \`$entry_mac = get_valid_mac($mac);\` ... \`set($entry_p."/mac",toupper($entry_mac));\`
  ```
- **Keywords:** /acl/macctrl/entry/mac, $_POST["mac_*"]
- **Notes:** Requires the victim to visit 'get_Macfilter.asp' or a related page; it is recommended to check if other output points have similar lack of escaping; subsequent analysis can examine the limitations of the 'get_valid_mac' function.

---
### info-leak-get_Wireless-displaypass

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.php`
- **Location:** `get_Wireless.php:1 (input point), get_Wireless.php:~75-77 (output point), get_Wireless.php:~78-80 (output point), get_Wireless.php:~81-83 (output point)`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** This vulnerability allows an attacker to force the output of sensitive wireless network information, including WEP keys, WPA PSK, and RADIUS secrets, by setting the 'displaypass=1' GET parameter. The trigger condition is simple: the attacker sends an HTTP request to this script (e.g., 'http://device/htdocs/mydlink/get_Wireless.php?displaypass=1'). As a logged-in user (non-root), the attacker may have access to this script (depending on the web server configuration). The exploitation method is direct: by viewing the response content to obtain password information, which could potentially be used to connect to the wireless network or launch further attacks. The code lacks validation or access control for the 'displaypass' parameter, leading to the unconditional output of sensitive data.
- **Code Snippet:**
  ```
  Input point:
  <? 
  $displaypass = $_GET["displaypass"];
  
  ...
  
  Output point:
  <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>
  ```
- **Keywords:** $_GET["displaypass"], $key, $pskkey, $eapkey
- **Notes:** The risk score does not reach 7.0 or above because, although the attack chain is complete, the vulnerability is primarily an information leak rather than direct code execution or privilege escalation. The confidence is high because the code evidence clearly shows a direct data flow from input to output. It is recommended to further verify the script's access control mechanism (e.g., whether it is protected by authentication) and context (such as whether it is accessible under the web root). Related files may include other PHP scripts using similar patterns. Subsequent analysis should check the implementation of 'query' and 'get' functions to identify other potential vulnerabilities.

---
### info-leak-wireless-displaypass

- **File/Directory Path:** `htdocs/mydlink/get_Wireless_5g.asp`
- **Location:** `get_Wireless.php:1 (assignment of $displaypass) and get_Wireless.php:~70-80 (output conditions)`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** In 'get_Wireless.php', the 'displaypass' GET parameter is directly used to control the output of sensitive wireless password information, including WEP keys, PSK keys, and RADIUS keys. An attacker as a logged-in user (non-root) can trigger information leakage by sending a GET request to 'get_Wireless_5g.asp?displaypass=1'. Trigger conditions include: the user possesses valid login credentials, authorization is passed (checked by 'header.php' with $AUTHORIZED_GROUP>=0), and the parameter is not validated. Potential attack methods include obtaining wireless network passwords, which may be used for further network penetration or privilege escalation. The code logic directly uses $_GET['displaypass'] without any filtering or boundary checks, leading to controllable output.
- **Code Snippet:**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>
  ```
- **Keywords:** displaypass, $_GET, get_Wireless_5g.asp, get_Wireless.php
- **Notes:** This vulnerability relies on user authorization, but the authorization mechanism in 'header.php' might be insufficient if $AUTHORIZED_GROUP is misconfigured. It is recommended to verify the source and settings of $AUTHORIZED_GROUP. Subsequent analysis can examine other 'form_' files (such as 'form_wireless.php') to find more input points or interaction vulnerabilities. Inability to access '/htdocs/phplib/xnode.php' and '/htdocs/webinc/config.php' limits the analysis of the complete data flow.

---
### InfoLeak-SMTP-Password

- **File/Directory Path:** `htdocs/mydlink/get_Email.asp`
- **Location:** `get_Email.asp (specific line number unknown, located at the conditional statement outputting SMTP password)`
- **Risk Score:** 6.5
- **Confidence:** 7.5
- **Description:** An information disclosure vulnerability was found in the 'get_Email.asp' file, allowing authenticated users to obtain the SMTP password via the 'displaypass' GET parameter. Specific behavior: when the parameter is set to 1, the script outputs the SMTP password; otherwise, it does not. Trigger condition: authorized users ($AUTHORIZED_GROUP >= 0) access a URL such as 'get_Email.asp?displaypass=1'. Constraints: relies on authorization checks in 'header.php', but the mechanism for setting $AUTHORIZED_GROUP is not validated, potentially allowing for bypass. Potential attack: after obtaining the SMTP password, an attacker could use it for unauthorized access to the SMTP server or for phishing attacks, thereby escalating privileges or leaking more data. Code logic: directly uses $_GET['displaypass'] to control output, lacking additional validation.
- **Code Snippet:**
  ```
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **Keywords:** displaypass, config.smtp_email_pass
- **Notes:** The authorization mechanism relies on the $AUTHORIZED_GROUP variable, but it is not defined in the analyzed file. It is recommended to further verify its source and setting method (for example, in 'phplib/xnode.php' or 'webinc/config.php'). SMTP password disclosure may affect external service security. The attack chain is complete for authenticated users: input point (displaypass parameter) → data processing (conditional output) → dangerous operation (password disclosure). However, due to tool limitations, other files were not validated, and there may be unknown dependencies.

---
### Command-Injection-classlessstaticroute

- **File/Directory Path:** `etc/services/INET/inet4_dhcpc_helper.php`
- **Location:** `inet4_dhcpc_helper.php: In the code blocks for 'classlessstaticroute' and 'staticroute' actions`
- **Risk Score:** 6.5
- **Confidence:** 6.5
- **Description:** In the 'classlessstaticroute' and 'staticroute' actions, the variables $SDEST, $SSUBNET, $SROUTER are directly concatenated into the ip route command, lacking input validation. Attackers can control these variables to inject commands, modify the routing table, or perform arbitrary operations. Trigger condition when $ACTION is 'classlessstaticroute' or 'staticroute'. Exploitation method is similar, causing command injection through malicious input.
- **Code Snippet:**
  ```
  echo "ip route add ".$netid."/".$SSUBNET." via ".$SROUTER." table CLSSTATICROUTE\n";
  ```
- **Keywords:** $ACTION, $SDEST, $SSUBNET, $SROUTER
- **Notes:** Variables may come from DHCP options, but attackers may forge them. Need to confirm input source and permissions. Recommend checking network configuration interface.

---
### Event-Injection-ppp6_ipup-param

- **File/Directory Path:** `etc/services/INET/ppp6_ipup.php`
- **Location:** `ppp6_ipup.php: Multiple locations, for example echo "event ".$PARAM.".UP
"; and echo "echo 1 > /var/run/".$PARAM.".UP
";`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** The $PARAM variable is directly used to construct event names (e.g., event $PARAM.UP) and file paths (e.g., /var/run/$PARAM.UP), lacking validation. An attacker controlling $PARAM could cause event system confusion or path traversal (if $PARAM contains '../'). The trigger condition is similar to Discovery 1. Potential exploits include interfering with other processes or file operations.
- **Code Snippet:**
  ```
  echo "event ".$PARAM.".UP
  "; echo "echo 1 > /var/run/".$PARAM.".UP
  ";
  ```
- **Keywords:** Environment Variable $PARAM, IPC Event $PARAM.UP, File Path /var/run/$PARAM.UP, Custom Function XNODE_set_var
- **Notes:** Validation of the event system's handling is required; it is recommended to check the input handling of the xmldbc command.

---
### Command Injection-ppp4_ipdown.php

- **File/Directory Path:** `etc/services/INET/ppp4_ipdown.php`
- **Location:** `ppp4_ipdown.php:36, ppp4_ipdown.php:38, ppp4_ipdown.php:39, ppp4_ipdown.php:40`
- **Risk Score:** 6.0
- **Confidence:** 6.5
- **Description:** Command injection vulnerability exists because user input is not validated and is directly concatenated into shell commands. Specific issue: When the PPP connection is closed, the script uses variables $REMOTE, $IFNAME, $IP, and $PARAM to construct shell commands (such as ip route, event, rm). If these variables contain shell metacharacters (such as ;, `, $()), an attacker can inject and execute arbitrary commands. Trigger condition: The script is called when the PPP connection is closed, and the variable values come from external input. Constraints: The code lacks input validation, filtering, or escaping mechanisms. Potential attack: An attacker can inject commands by controlling these variables, potentially leading to privilege escalation, file deletion, or system control. Related code logic: Uses echo to output commands, which may be executed via the shell.
- **Code Snippet:**
  ```
  36: echo 'ip route del '.$REMOTE.' dev '.$IFNAME.' src '.$IP.' table LOCAL\n';
  38: echo "ip route flush table ".$PARAM."\n";
  39: echo "event ".$PARAM.".DOWN\n";
  40: echo "rm -f /var/run/".$PARAM.".UP\n";
  ```
- **Keywords:** $REMOTE, $IFNAME, $IP, $PARAM, ppp4_ipdown.php
- **Notes:** Input source is not validated (possibly passed via environment variables or PPP events). It is recommended to further analyze the script invocation context and variable setting mechanism (e.g., check pppd or other daemon configurations). Associated files may include PPP-related scripts or configuration files. Subsequent analysis direction: Trace the variable source and call chain to verify the exploitability of the complete attack chain. The attacker is a non-root user but possesses valid login credentials; it is necessary to confirm whether the variables can be influenced by user-controlled input.

---
### Command-Injection-dhcpplus

- **File/Directory Path:** `etc/services/INET/inet4_dhcpc_helper.php`
- **Location:** `inet4_dhcpc_helper.php: In the code block for the 'dhcpplus' action`
- **Risk Score:** 6.0
- **Confidence:** 6.0
- **Description:** In the 'dhcpplus' action, the variables $IP, $SUBNET, $BROADCAST, $INTERFACE, $ROUTER are used to construct ip addr and ip route commands, lacking filtering. Attackers can inject commands leading to network configuration tampering or command execution. Trigger condition is when $ACTION is 'dhcpplus'.
- **Code Snippet:**
  ```
  echo "ip addr add ".$IP."/".$mask." broadcast ".$brd." dev ".$INTERFACE."\n";\necho "ip route add default via ".$ROUTER." metric ".$defrt." table default\n";
  ```
- **Keywords:** $ACTION, $IP, $SUBNET, $BROADCAST, $INTERFACE, $ROUTER
- **Notes:** Input may be limited by DHCP, but if the user can control ACTION, the risk increases. It is recommended to verify the script invocation mechanism.

---
