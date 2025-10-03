# R7800 (73 alerts)

---

### Private-Key-Exposure-client_key.pem

- **File/Directory Path:** `etc/ssl/private/client_key.pem`
- **Location:** `client_key.pem`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** 文件 'client_key.pem' 包含一个完整的 RSA 私钥，以 PEM 格式存储。攻击链完整且简单：攻击者通过文件系统漏洞、未授权访问或固件提取获取该文件后，可直接使用私钥进行攻击（例如，在 TLS 通信中冒充客户端或解密数据）。触发条件是攻击者能够访问该文件。可利用性高，因为私钥缺少保护措施（如加密或访问控制），且暴露的私钥允许直接滥用。
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIJKQIBAAKCAgEAx1R6uIxTBHbvy95FU9PJ05aYOu1CSOBOQM3zRi5isE1CUwNt
  ...（完整内容已省略以节省空间，但证据基于实际文件内容）
  -----END RSA PRIVATE KEY-----
  ```
- **Keywords:** client_key.pem
- **Notes:** 假设该私钥在运行时被用于身份验证或加密通信。建议进一步验证：1. 该私钥是否被其他组件（如网络服务）引用；2. 是否在固件中硬编码；3. 访问控制机制是否足够。后续分析应检查相关代码或配置文件以确认使用上下文。

---
### command-injection-wait_for_iface_get_netaddr_get_netmask

- **File/Directory Path:** `etc/appflow/streamboost.d/52_p0f`
- **Location:** `Functions: wait_for_iface, get_netaddr, get_netmask in file etc/appflow/streamboost.d/52_p0f`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** 验证确认命令注入漏洞存在。完整攻击链：1) 攻击者控制 LAN_IFACE 环境变量（未信任输入源），2) 脚本设置 IFACE="$LAN_IFACE" 而没有输入清理或验证，3) 在函数 wait_for_iface、get_netaddr 和 get_netmask 中，IFACE 在 ifconfig 和 route 命令中未加引号使用，允许 shell 元字符（如分号或反引号）执行任意命令。触发条件：当脚本被执行（例如在系统启动时通过 boot 函数或通过 action 调用 start 函数）且这些函数被调用。可利用性高，因为缺少输入验证和直接命令执行，导致任意代码执行。
- **Code Snippet:**
  ```
  IFACE="$LAN_IFACE"
  wait_for_iface() {
      ...
      ifconfig ${IFACE} | grep "inet addr" > /dev/null
      ...
  }
  get_netaddr() {
      ...
      route -n | grep ${IFACE} | awk '{ print $1 }'
      ...
  }
  get_netmask() {
      echo $(ifconfig ${IFACE} | grep "inet addr" | awk -F' ' '{ print $4 }' | awk -F: '{ print $2 }')
  }
  ```
- **Keywords:** LAN_IFACE
- **Notes:** 验证基于文件内容分析。漏洞可利用性高，因为 LAN_IFACE 是环境变量，攻击者可控制它。脚本在启动或动作执行时调用易受攻击函数。建议修复：对 IFACE 变量使用引号（例如 "${IFACE}"）或进行输入验证。

---
### PathTraversal-mount1

- **File/Directory Path:** `sbin/cmdftp`
- **Location:** `cmdftp: [mount1] [scan_sharefoler_in_this_disk]`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 攻击链：攻击者通过 Web 接口或直接修改 NVRAM 配置变量 'shared_usb_folder*'（如 shared_usb_folder0），设置恶意共享名称（如 '../../../bin'）。当 FTP 服务启动或重启时，'cmdftp' 脚本运行，在 'mount1' 函数中，共享名称直接用于创建目录和执行 'chmod -R 777'，导致路径遍历。例如，共享名称 '../../../bin' 会使 'chmod -R 777 /tmp/ftpadmin/shares/../../../bin' 改变 '/bin' 目录权限，允许非特权用户修改系统二进制文件。触发条件是攻击者能修改共享文件夹配置并触发 FTP 服务重启。可利用性高，因为缺少输入验证和清理，逻辑缺陷允许任意路径访问。
- **Code Snippet:**
  ```
  在 'mount1' 函数中：
  \`\`\`sh
  mount1() {
      mkdir -p /tmp/$4/shares/"$3"
      mount -o utf8=yes,fmask=0000,dmask=0000 /mnt/$1"$2" /tmp/$4/shares/"$3"
      if [ $? -ne 0 ];then
          mount /mnt/$1"$2" /tmp/$4/shares/"$3"
          if [ $? -eq 0 ];then
              case "$5" in
                  0) chmod -R 777 /tmp/$4/shares/"$3";;
                  # ... 其他情况
              esac
          fi
      fi
  }
  \`\`\`
  在 'scan_sharefoler_in_this_disk' 中调用：
  \`\`\`sh
  mount1 "$1" "$relative_path" "$sharename" ftpadmin 0
  \`\`\`
  共享名称来自配置：
  \`\`\`sh
  sharename=\`echo "$sharefolder_item" | awk -F* '{print $1}' | sed 's/ //g'\`
  \`\`\`
  ```
- **Keywords:** shared_usb_folder* (NVRAM 变量，如 shared_usb_folder0, shared_usb_folder1), sharename* (NVRAM 变量，如 sharename1, sharename2)
- **Notes:** 假设攻击者能通过 Web 接口或其他方式修改 NVRAM 配置。建议验证配置输入是否在 Web 接口端有过滤，但脚本级别缺少验证。后续可检查其他类似输入点，如 'relative_path'。

---
### command-injection-RECORD_STA_MAC

- **File/Directory Path:** `etc/hotplug.d/wps/00-wps`
- **Location:** `脚本中的 `RECORD_STA_MAC` case 分支，具体代码行：/usr/sbin/stamac set $STAMAC`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 `RECORD_STA_MAC` 操作分支中，环境变量 `STAMAC` 被直接用于 shell 命令执行，没有进行适当的验证或转义。攻击者可以通过控制 `STAMAC` 环境变量注入任意命令。例如，如果 `STAMAC` 设置为 '; rm -rf /'，则命令 '/usr/sbin/stamac set ; rm -rf /' 会被执行，导致任意命令执行。攻击链：不可信输入（环境变量 STAMAC） → 直接传播到 shell 命令 → 危险操作（任意命令执行）。触发条件：当脚本以 `ACTION=RECORD_STA_MAC` 和可控的 `STAMAC` 环境变量执行时。可利用性分析：由于缺少输入清理和直接使用未引用的变量，攻击者可以注入 shell 元字符来执行任意命令。
- **Code Snippet:**
  ```
  RECORD_STA_MAC)
      /usr/sbin/stamac set $STAMAC
      ;;
  ```
- **Keywords:** STAMAC
- **Notes:** 此漏洞可能导致远程代码执行，具体取决于脚本的执行上下文和权限。建议验证环境变量输入并使用引号或适当转义。

---
### command-injection-SET_AP_PIN_FAILURES

- **File/Directory Path:** `etc/hotplug.d/wps/00-wps`
- **Location:** `脚本中的 `SET_AP_PIN_FAILURES` case 分支，具体代码行：$command set wps_pin_history_failures=$AP_PIN_FAILURES`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 `SET_AP_PIN_FAILURES` 操作分支中，环境变量 `AP_PIN_FAILURES` 被直接用于 shell 命令执行，没有进行适当的验证或转义。攻击者可以通过控制 `AP_PIN_FAILURES` 环境变量注入任意命令。例如，如果 `AP_PIN_FAILURES` 设置为 '1; rm -rf /'，则命令 '/bin/config set wps_pin_history_failures=1; rm -rf /' 会被执行，导致任意命令执行。攻击链：不可信输入（环境变量 AP_PIN_FAILURES） → 直接传播到 shell 命令 → 危险操作（任意命令执行）。触发条件：当脚本以 `ACTION=SET_AP_PIN_FAILURES` 和可控的 `AP_PIN_FAILURES` 环境变量执行时。可利用性分析：由于缺少输入清理和直接使用未引用的变量，攻击者可以注入 shell 元字符来执行任意命令。
- **Code Snippet:**
  ```
  SET_AP_PIN_FAILURES)
      $command set wps_pin_history_failures=$AP_PIN_FAILURES
      ;;
  ```
- **Keywords:** AP_PIN_FAILURES
- **Notes:** 此漏洞可能导致远程代码执行，具体取决于脚本的执行上下文和权限。建议验证环境变量输入并使用引号或适当转义。

---
### Command-Injection-net-wan-script

- **File/Directory Path:** `etc/init.d/net-wan`
- **Location:** `net-wan 脚本: [setup_interface_static_ip, setup_interface_dhcp, setup_wan_interface] 中的命令执行点`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 'net-wan' 脚本中，多个函数使用未引用的 NVRAM 变量直接构建 shell 命令，导致命令注入漏洞。攻击者可以通过 Web 界面或 API 设置恶意的 NVRAM 变量（如 wan_ipaddr、wan_netmask、wan_gateway、wan_hostname），当脚本执行时，这些变量被用于命令如 ifconfig、route、udhcpc，由于缺少输入验证和引用，允许注入任意命令。完整攻击链：攻击者控制 NVRAM 变量 → 变量在脚本中未引用用于 shell 命令 → 命令注入执行任意代码（以 root 权限）。触发条件：当脚本启动或重启网络接口时（例如，系统启动或手动调用 /etc/init.d/net-wan restart）。可利用性分析：缺少输入清理和变量引用，使攻击者能够注入 shell 元字符（如分号、空格）来分割命令并执行恶意操作。
- **Code Snippet:**
  ```
  示例来自 setup_interface_static_ip():
  ifconfig $WAN_IF $($CONFIG get wan_ipaddr) netmask $($CONFIG get wan_netmask)
  route add default gw $($CONFIG get wan_gateway)
  
  示例来自 setup_interface_dhcp():
  udhcpc -b -i $WAN_IF -h $u_hostname -r $($CONFIG get wan_dhcp_ipaddr) -N $($CONFIG get wan_dhcp_oldip) ${u_wan_domain:+-d $u_wan_domain} &
  
  示例来自 set_dns():
  echo "nameserver $($CONFIG get wan_ether_dns1)" > /tmp/resolv.conf
  ```
- **Keywords:** wan_proto, wan_ipaddr, wan_netmask, wan_gateway, wan_hostname, wan_dhcp_ipaddr, wan_dhcp_oldip, wan_ether_dns1, wan_ether_dns2, Device_name
- **Notes:** 漏洞广泛存在于脚本中多个命令执行点。建议对所有变量使用引号（如 "$var"）并实施输入验证。相关函数包括 check_qca_nss()、wanmac()、same_subnet()，但主要风险在接口设置函数中。后续分析应验证外部脚本（如 /lib/network/ppp.sh）是否类似漏洞。

---
### stack-buffer-overflow-nvram-set

- **File/Directory Path:** `bin/nvram`
- **Location:** `函数 fcn.000086d0，地址 0x00008760（strcpy 调用）`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** **完整攻击链**：攻击者通过命令行执行 `./nvram set <name=value>`，其中 `<name=value>` 是用户控制的字符串。程序在处理 'set' 命令时，使用 `strcpy` 将整个字符串复制到固定大小的栈缓冲区（地址 0x00008760）。由于没有边界检查，如果字符串长度超过 393756 字节，将溢出缓冲区并覆盖保存的返回地址（lr 寄存器）。覆盖返回地址后，攻击者可以控制程序执行流，执行任意代码。

**触发条件**：命令行参数字符串长度 > 393756 字节。
**可利用性分析**：漏洞可利用是因为：1) 输入完全可控且无过滤；2) strcpy 缺乏长度检查；3) 栈布局允许精确覆盖返回地址；4) 程序可能以特权运行（如 setuid），放大影响。
- **Code Snippet:**
  ```
  0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** 命令行参数, NVRAM 变量通过 config_set 设置
- **Notes:** 需要验证目标系统的命令行参数长度限制（通常 >= 384KB 才可利用）。建议检查其他命令（如 'list'）中的 sprintf 使用，但攻击链不如本例直接。后续分析应关注 config_set 等函数的数据流。

---
### Command-Injection-IFNAME-wps-hostapd-update-uci

- **File/Directory Path:** `lib/wifi/wps-hostapd-update-uci`
- **Location:** `wps-hostapd-update-uci: multiple locations including case statement for WPS-NEW-AP-SETTINGS and set_other_radio_setting function`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Command Injection via IFNAME Parameter. Complete Attack Chain: The attack chain begins when an attacker controls the IFNAME parameter passed to the script. IFNAME is used directly in multiple shell commands without proper quoting or sanitization. For example, in commands like `hostapd_cli -i${IFNAME} ...`, if IFNAME contains shell metacharacters (e.g., semicolons), the shell interprets them, leading to arbitrary command execution. The path is: Attacker-controlled IFNAME → Used in hostapd_cli or other commands → Shell metacharacters trigger command injection → Arbitrary commands executed with script privileges. Precise Trigger Conditions: The script must be executed with IFNAME containing shell metacharacters (e.g., `;`, `&`, `|`) and the specific command branches (e.g., WPS-NEW-AP-SETTINGS or set_other_radio_setting) must be triggered via the CMD parameter. Exploitability Analysis: This is exploitable because the script fails to validate or quote IFNAME before using it in command execution contexts. The lack of input sanitization allows attackers to break command boundaries and execute arbitrary commands, potentially with elevated privileges (e.g., root), as the script handles network configuration.
- **Code Snippet:**
  ```
  hostapd_cli -i$IFNAME -p/var/run/hostapd-$parent get_config
  ```
- **Keywords:** IFNAME, hostapd_cli, /var/run/hostapd-${IFNAME}.conf, /var/run/hostapd_cli-${IFNAME}.pid
- **Notes:** The script likely runs with elevated privileges (e.g., as part of WPS handling), increasing the impact. Further verification is recommended on how the script is invoked in practice (e.g., by hostapd or other components) to confirm exploitability in real-world scenarios.

---
### Command-Injection-bridge-WPS

- **File/Directory Path:** `lib/wifi/wpa_supplicant.sh`
- **Location:** `wpa_supplicant.sh:155 [wps_pbc block]`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 攻击链从不可信输入点 'bridge' 配置值开始。当 WPS PBC 被启用时，脚本执行 `macaddr=$(cat /sys/class/net/${bridge}/address)`，其中 'bridge' 变量未经验证或转义。如果攻击者控制 'bridge' 值（例如通过 UCI 配置），并注入 shell 元字符（如 `;`），可执行任意命令。例如，设置 'bridge' 为 "eth0; rm -rf /" 会导致命令 `cat /sys/class/net/eth0; rm -rf //address` 执行，删除系统文件。触发条件：WPS PBC 启用（`wps_pbc -gt 0`）且 `config_methods` 非空。可利用性高，因为缺少输入清理，且脚本可能以高权限（如 root）运行。
- **Code Snippet:**
  ```
  config_get_bool wps_pbc "$vif" wps_pbc 0
  [ "$wps_pbc" -gt 0 ] && append config_methods push_button
  [ -n "$config_methods" ] && {
      wps_cred="wps_cred_processing=2"
      wps_config_methods="config_methods=$config_methods"
      update_config="update_config=1"
      macaddr=$(cat /sys/class/net/${bridge}/address)
      uuid=$(echo "$macaddr" | sed 's/://g')
      [ -n "$uuid" ] && {
          uuid_config="uuid=87654321-9abc-def0-1234-$uuid"
      }
  }
  ```
- **Keywords:** bridge, /var/run/wpa_supplicant-$ifname.conf, /var/run/wpa_supplicant-$ifname
- **Notes:** 需要验证脚本运行权限（可能以 root 运行）；建议检查调用上下文以确认 'bridge' 输入源；相关函数如 `config_get` 可能来自 UCI 系统；后续应分析其他组件（如 wpa_supplicant）以评估整体影响。

---
### command-injection-start_dhcp6c

- **File/Directory Path:** `etc/net6conf/6autoconf`
- **Location:** `函数 'start_dhcp6c' 中的命令执行：/usr/sbin/dhcp6c -c /tmp/dhcp6c.conf -3 ${U_CLADATA:+-u $U_CLADATA} ${U_DOMAIN:+-U $U_DOMAIN} $WAN`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 攻击链：攻击者通过 web 界面或 API 设置 NVRAM 变量 'ipv6_autoConfig_userClass' 或 'ipv6_autoConfig_domainName' 为恶意值（例如，包含 shell 元字符如 ';' 或 '&'）。当脚本启动时（例如系统启动或网络重新配置），在函数 'start_dhcp6c' 中，这些变量通过 '$CONFIG get' 获取并直接传递给 'dhcp6c' 命令，未经过滤。由于变量在 shell 命令中拼接，恶意命令得以执行。触发条件：脚本以 root 权限运行（常见于初始化脚本），且变量值可控。可利用性分析：缺少输入验证和过滤，导致命令注入；攻击者可以注入任意命令，获得 root 权限。
- **Code Snippet:**
  ```
  start_dhcp6c() {
  	local U_CLADATA=\`$CONFIG get ipv6_autoConfig_userClass\`
  	local U_DOMAIN=\`$CONFIG get ipv6_autoConfig_domainName\`
  	...
  	/usr/sbin/dhcp6c -c /tmp/dhcp6c.conf -3 ${U_CLADATA:+-u $U_CLADATA} ${U_DOMAIN:+-U $U_DOMAIN} $WAN
  }
  ```
- **Keywords:** ipv6_autoConfig_userClass, ipv6_autoConfig_domainName
- **Notes:** 证据基于脚本代码片段；假设 '$CONFIG' 命令从 NVRAM 获取值，且这些值外部可控（常见于嵌入式系统）。建议验证 'dhcp6c' 命令的行为，但漏洞在 shell 层面已确认。后续分析应检查 '/etc/net6conf/6data.conf' 以确认变量来源，但当前文件已提供足够证据。

---
### command-injection-band-check

- **File/Directory Path:** `etc/bandcheck/band-check`
- **Location:** `Multiple functions in band-check: re_check_test_router, update_test_router, find_test_router`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Command injection vulnerability due to unquoted variable usage in command substitutions. Attack chain: 1) Untrusted input from network via traceroute output written to /tmp/traceroute_list. 2) Script reads lines from the file and uses `echo $line` in command substitutions without quoting, allowing shell metacharacters (e.g., semicolons, backticks) in $line to execute arbitrary commands. 3) Dangerous operation: command execution with root privileges, leading to full system compromise. Trigger condition: When the script is executed (e.g., during bandwidth checks) and traceroute output contains shell metacharacters, which can be influenced via DNS spoofing or network manipulation. Exploitable because the script lacks input sanitization and runs with high privileges.
- **Code Snippet:**
  ```
  Example from re_check_test_router:
  \`\`\`sh
  ttl1=\`echo $line | awk -F " " '{print $1}'\`
  \`\`\`
  Example from update_test_router:
  \`\`\`sh
  local ttl1=\`echo $line | awk -F " " '{print $1}'\`
  local pt_unrea=\`echo $line | grep "ms" | awk -F " " '{print $6}'\`
  local ip=\`echo $line | grep "ms" | awk -F " " '{print $2}'\`
  \`\`\`
  Example from find_test_router:
  \`\`\`sh
  ttl=\`echo $line | awk -F " " '{print $1}'\`
  local pt_unrea=\`echo $line | grep "ms" | awk -F " " '{print $6}'\`
  local ip=\`echo $line | grep "ms" | awk -F " " '{print $2}'\`
  \`\`\`
  ```
- **Keywords:** /tmp/traceroute_list, /tmp/check_again_list, /tmp/check_again_result, band-check script, /bin/config (for NVRAM access)
- **Notes:** Assumes the script runs with root privileges, which is common in firmware contexts. Further verification could involve testing in a controlled environment or checking how the script is invoked (e.g., via cron jobs or other components). The CONFIG binary (/bin/config) might have additional vulnerabilities, but this finding is specific to the shell script.

---
### Untitled Finding

- **File/Directory Path:** `etc/aMule/amule.sh`
- **Location:** `amule.sh, start function, line containing 'amuled -c $emule_work_dir &'`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'amule.sh' script due to improper sanitization of command-line arguments. The complete attack chain is as follows:
- **Source**: The second command-line argument ($2) when the script is invoked with 'start' or 'restart' actions. This argument is controllable by an attacker if the script is called from an untrusted context (e.g., web interface, IPC).
- **Propagation**: The argument $2 is passed to the start function (as $1) and assigned to emule_work_dir without any validation or sanitization. It is then used directly in the shell command `amuled -c $emule_work_dir &`.
- **Sink**: The shell command execution point where $emule_work_dir is interpolated. If $emule_work_dir contains shell metacharacters (e.g., ;, &, |, backticks), arbitrary commands can be executed with the privileges of the script.
- **Trigger Condition**: The script must be invoked with the first argument as 'start' or 'restart' and a malicious second argument containing shell metacharacters.
- **Exploitability Analysis**: This is highly exploitable because the input is used unsanitized in a shell command. An attacker can craft a payload like '/tmp; rm -rf /' to execute arbitrary commands, leading to full compromise if the script runs with sufficient privileges.
- **Code Snippet:**
  ```
  start() {
  	emule_work_dir=$1
  	...
  	amuled -c $emule_work_dir &
  }
  ...
  [ $1 = "start" ] && start $2
  [ $1 = "restart" ] && restart $2
  ```
- **Keywords:** amule.sh, command-line argument $1, command-line argument $2
- **Notes:** This vulnerability requires that the script is invoked with untrusted input for $2. In the context of firmware, if this script is exposed via a network service or IPC mechanism, it could be exploited remotely. Further analysis should verify how 'amule.sh' is invoked (e.g., from init scripts or services) to confirm exploitability. Additionally, other issues like insecure file permissions (chmod 777) were noted but are less critical without a direct exploit chain.

---
### RCE-streamboost-sys-config

- **File/Directory Path:** `etc/appflow/rc.appflow`
- **Location:** `脚本开头部分，环境变量定义和源命令处`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 攻击者可以通过操纵环境变量 STREAMBOOST_SYS_CFG 或 STREAMBOOST_SYS_DEFAULTS 来指向恶意配置文件，当脚本源（.）这些文件时，会执行文件中的任意代码。完整攻击链：攻击者设置环境变量 -> 脚本使用这些变量定义配置文件路径 -> 脚本检查文件是否存在，如果不存在则创建，但最终源这两个文件 -> 如果文件包含恶意代码，它将以脚本执行权限运行。触发条件是脚本被调用（例如，在系统启动或管理操作中），并且环境变量被恶意设置。可利用性高，因为缺少对环境变量和文件内容的验证，可能导致特权升级（如果脚本以 root 权限运行）。
- **Code Snippet:**
  ```
  STREAMBOOST_SYS_CFG=${STREAMBOOST_SYS_CFG:-"${STREAMBOOST_RUNDIR:-/var/run/appflow}/streamboost.sys.conf"}
  STREAMBOOST_SYS_DEFAULTS=${STREAMBOOST_SYS_DEFAULTS:-"${STREAMBOOST_CFGDIR:-/etc/appflow}/streamboost.sys.conf"}
  [ -f $STREAMBOOST_SYS_CFG ] || {
  	mkdir -p $(dirname $STREAMBOOST_SYS_CFG)
  	sed "s/%UBUS_LAN_DEV%/$(print_interface_device lan)/" <$STREAMBOOST_SYS_DEFAULTS | \
  	sed "s/%UBUS_WAN_DEV%/$(print_interface_device wan)/" >$STREAMBOOST_SYS_CFG
  }
  . $STREAMBOOST_SYS_DEFAULTS
  . $STREAMBOOST_SYS_CFG
  ```
- **Keywords:** STREAMBOOST_SYS_CFG, STREAMBOOST_SYS_DEFAULTS, STREAMBOOST_RUNDIR, STREAMBOOST_CFGDIR
- **Notes:** 此攻击链假设脚本以特权（如 root）运行，这在初始化脚本中常见。需要进一步验证环境变量的实际控制点（例如，通过其他组件或启动脚本）。建议检查系统调用此脚本的上下文，以确认环境变量是否可由远程攻击者设置。

---
### Command-Injection-6autodet-NVRAM-chain

- **File/Directory Path:** `etc/net6conf/6autodet`
- **Location:** `Multiple scripts in /etc/net6conf: 6to4 (start_6to4 function), 6rd (to_upper function), 6dhcpc (start_dhcp6c function), 6autoconf (start_dhcp6c function), 6bridge (start_service function)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The '6autodet' script acts as a trigger for multiple command injection vulnerabilities in subordinate scripts through its execution based on the '/tmp/ipv6_auto_output' file content. Although '6autodet' itself uses a world-writable temporary file, the primary exploitable chain involves NVRAM variables. Attack chain: 1) Attacker controls NVRAM variables (e.g., 'ipv6_6to4_relay', 'Ipv6rdPrefix', 'ipv6_dhcp_userClass') via network interfaces or APIs by setting them to malicious values (e.g., '192.168.1.1; malicious_command'). 2) When '6autodet' is executed (e.g., during system startup or IPv6 auto-detection), it calls scripts like 6to4, 6rd, etc., based on the output file. 3) These scripts retrieve the NVRAM variables using '$CONFIG get' and use them unquoted in shell commands (e.g., in '6to4': '$IP tunnel add sit1 mode sit ttl 128 remote $remoteip4 local $localip4'), allowing command injection due to lack of input validation and quoting. Trigger condition: '6autodet' must be run with 'start' or 'restart' arguments, which typically occurs during IPv6 service initialization. Exploitable because the scripts run with root privileges, and the unsanitized input leads to arbitrary command execution, providing full system compromise.
- **Code Snippet:**
  ```
  From 6to4:
  if [ \`$CONFIG get ipv6_6to4_relay_type\` = "0" ]; then
      remoteip4="192.88.99.1"
  else
      remoteip4=\`$CONFIG get ipv6_6to4_relay\`
  fi
  $IP tunnel add sit1 mode sit ttl 128 remote $remoteip4 local $localip4
  
  From 6rd:
  to_upper() {
      local prefix=$1
      local part1=\`echo $prefix|cut -f1 -d:\`
      ...
  }
  
  From 6dhcpc:
  local U_CLADATA=\`$CONFIG get ipv6_dhcp_userClass\`
  /usr/sbin/dhcp6c -c /tmp/dhcp6c.conf -3 ${U_CLADATA:+-u $U_CLADATA} $WAN
  ```
- **Keywords:** ipv6_6to4_relay, Ipv6rdPrefix, ipv6_dhcp_userClass, ipv6_dhcp_domainName, ipv6_autoConfig_userClass, ipv6_autoConfig_domainName, wan_ifname, lan_ifname, /tmp/ipv6_auto_output, CONFIG
- **Notes:** The vulnerabilities are verified through code analysis of the subordinate scripts. While '6autodet' uses a temporary file that could be manipulated, the NVRAM-based command injection provides a more reliable and direct attack vector. It is recommended to quote all variables in shell commands and implement input validation for NVRAM variables. Further analysis could explore how NVRAM variables are set (e.g., via web interfaces) to confirm exploitability in practice. This finding complements existing discoveries (e.g., in 6pppoe and 6bridge) by providing a broader view of the vulnerability chain across multiple scripts.

---
### Command-Injection-start_dhcp6c_6autoconf

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `start_dhcp6c` 在 /etc/net6conf/6autoconf`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 '6autoconf' 脚本的 `start_dhcp6c` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `ipv6_autoConfig_userClass` 和 `ipv6_autoConfig_domainName`；2) 变量通过 `$CONFIG get` 获取并存储在 `U_CLADATA` 和 `U_DOMAIN` 中，未经验证；3) 变量直接用于 `dhcp6c` 命令参数（`${U_CLADATA:+-u $U_CLADATA}` 和 `${U_DOMAIN:+-U $U_DOMAIN}`），如果包含 shell 元字符，将注入命令。触发条件：当脚本以 `start` 参数执行时。可利用性分析：缺少输入清理，允许任意命令执行。
- **Code Snippet:**
  ```
  start_dhcp6c() {
  	local U_CLADATA=\`$CONFIG get ipv6_autoConfig_userClass\`
  	local U_DOMAIN=\`$CONFIG get ipv6_autoConfig_domainName\`
  	/usr/sbin/dhcp6c -c /tmp/dhcp6c.conf -3 ${U_CLADATA:+-u $U_CLADATA} ${U_DOMAIN:+-U $U_DOMAIN} $WAN
  }
  ```
- **Keywords:** ipv6_autoConfig_userClass, ipv6_autoConfig_domainName
- **Notes:** 漏洞以 root 权限执行，风险高。建议使用引号包裹变量或参数化执行。

---
### Command-Injection-start_6to4

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `start_6to4` 在 /etc/net6conf/6to4`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 在 '6to4' 脚本的 `start_6to4` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `ipv6_6to4_relay`；2) 变量通过 `remoteip4=\`$CONFIG get ipv6_6to4_relay\`` 获取；3) 变量直接用于 `$IP tunnel ... remote $remoteip4 ...` 命令，允许命令注入。触发条件：当 `ipv6_6to4_relay_type` 不为 '0' 时，脚本执行 `start_6to4` 函数。可利用性分析：缺少输入验证，导致任意命令执行。
- **Code Snippet:**
  ```
  remoteip4=\`$CONFIG get ipv6_6to4_relay\`
  $IP tunnel add sit1 mode sit ttl 128 remote $remoteip4 local $localip4
  ```
- **Keywords:** ipv6_6to4_relay, ipv6_6to4_relay_type
- **Notes:** 漏洞以 root 权限执行，风险极高。建议使用引号包裹变量并进行输入验证。

---
### command-injection-52_p0f-functions

- **File/Directory Path:** `etc/appflow/streamboost.d/52_p0f`
- **Location:** `Functions: wait_for_iface, get_netaddr, get_netmask in file 52_p0f`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Command injection vulnerability via unquoted IFACE variable in shell commands. The attack chain is: 1) Attacker controls the LAN_IFACE environment variable (untrusted input source). 2) The script sets IFACE="$LAN_IFACE" without sanitization. 3) In functions wait_for_iface, get_netaddr, and get_netmask, IFACE is used unquoted in ifconfig and route commands, allowing shell metacharacters to execute arbitrary commands. Trigger condition: When the script is executed (e.g., during boot or via action) and these functions are called. Exploitability is high due to lack of input validation and direct command execution.
- **Code Snippet:**
  ```
  wait_for_iface: ifconfig ${IFACE} | grep "inet addr" > /dev/null
  get_netaddr: route -n | grep ${IFACE} | awk '{ print $1 }'
  get_netmask: ifconfig ${IFACE} | grep "inet addr" | awk -F' ' '{ print $4 }' | awk -F: '{ print $2 }'
  ```
- **Keywords:** LAN_IFACE environment variable
- **Notes:** The vulnerability requires that LAN_IFACE is set from an untrusted source, which might occur through configuration, NVRAM, or web interfaces. Further analysis of rc.appflow or other components may reveal how LAN_IFACE is populated. Additionally, review the p0f binary for other vulnerabilities, but this script-level issue is independently exploitable.

---
### heap-buffer-overflow-usblp_write

- **File/Directory Path:** `lib/modules/3.4.103/NetUSB.ko`
- **Location:** `NetUSB.ko sym.usblp_write at addresses 0x08017988 (__kmalloc call), 0x080179d8 (copy_from_user call), and 0x080179f0 (__memzero call)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A heap buffer overflow vulnerability exists in sym.usblp_write due to missing size validation when copying user data. The attack chain is as follows: 1) An attacker controls the size parameter (arg2) and data buffer (arg1) when invoking the usblp_write system call. 2) The function allocates a fixed-size kernel buffer of 0xd0 bytes (208 bytes) via __kmalloc. 3) Without checking if the user-provided size exceeds 0xd0, copy_from_user copies the data directly into the kernel buffer. 4) If the size is larger than 0xd0, this results in a heap overflow, overwriting adjacent kernel memory. Alternatively, if a bounds check on the user pointer fails, __memzero is called with the same unchecked size, leading to a similar overflow. The trigger condition is providing a size value greater than 208 bytes. This is exploitable because the lack of bounds checks allows arbitrary kernel memory corruption, which can lead to privilege escalation or kernel panic.
- **Code Snippet:**
  ```
  0x08017984      d010a0e3       mov r1, 0xd0                ; size for kmalloc
  0x08017988      feffffeb       bl reloc.__kmalloc          ; allocate 208-byte buffer
  0x080179d8      feffffeb       bl reloc.__copy_from_user   ; copy user data without size check
  0x080179ec      0510a0e1       mov r1, r5                  ; unchecked size for __memzero
  0x080179f0      feffffeb       bl __memzero                ; zero buffer without size check
  ```
- **Keywords:** sym.usblp_write, reloc.__copy_from_user, reloc.__kmalloc, __memzero
- **Notes:** The vulnerability is confirmed through disassembly. Dynamic testing with a payload size > 208 bytes can verify exploitability. Related functions like mutex_lock_interruptible do not mitigate the overflow. This is a high-risk issue due to direct attacker control over size and data.

---
### command-injection-band-check-router-functions

- **File/Directory Path:** `etc/bandcheck/band-check`
- **Location:** `Functions: re_check_test_router, update_test_router, find_test_router in band-check`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** 验证确认命令注入漏洞存在。攻击链：1) 不可信输入来自网络：traceroute 命令输出写入 /tmp/traceroute_list，攻击者可通过 DNS 欺骗或网络操纵控制输出内容。2) 脚本读取文件行并使用 `echo $line` 在命令替换中未引用变量，允许 shell 元字符（如 ;、&、|、反引号）在 $line 中执行任意命令。例如，如果 $line 为 '1; malicious_command'，则 `echo 1; malicious_command` 会执行恶意命令。3) 危险操作：脚本以 root 权限运行（系统脚本典型上下文），导致完全系统妥协。触发条件：当脚本执行（如带宽检查期间）且 traceroute 输出包含 shell 元字符。可利用性分析：脚本缺乏输入清理，变量未引用，且攻击者可控输入通过网络路径可达。
- **Code Snippet:**
  ```
  From re_check_test_router:
  ttl1=\`echo $line | awk -F " " '{print $1}'\`
  
  From update_test_router:
  local ttl1=\`echo $line | awk -F " " '{print $1}'\`
  local pt_unrea=\`echo $line | grep "ms" | awk -F " " '{print $6}'\`
  local ip=\`echo $line | grep "ms" | awk -F " " '{print $2}'\`
  
  From find_test_router:
  ttl=\`echo $line | awk -F " " '{print $1}'\`
  local pt_unrea=\`echo $line | grep "ms" | awk -F " " '{print $6}'\`
  local ip=\`echo $line | grep "ms" | awk -F " " '{print $2}'\`
  ```
- **Keywords:** /tmp/traceroute_list, /tmp/check_again_list, line, traceroute
- **Notes:** 证据基于文件内容分析。漏洞实际可利用，因为攻击者可通过网络操纵 traceroute 输出，且脚本以高权限运行。建议修复：在命令替换中引用变量，如使用 `echo "$line"` 或避免使用命令替换。

---
### stack-buffer-overflow-fcn.000086d0

- **File/Directory Path:** `bin/config`
- **Location:** `函数 fcn.000086d0（主函数）中的 'config set' 分支，具体在 strcpy 调用点。`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 'config' 可执行文件中发现栈缓冲区溢出漏洞，源于 'config set' 命令处理用户输入时使用 strcpy 函数而不进行边界检查。攻击链如下：
- **攻击者可控源**：命令行参数中的 'value' 部分（例如，执行 `config set name=value`）。
- **数据流传播**：用户输入通过 strcpy 直接复制到栈缓冲区（auStack_60220），没有任何长度验证或过滤。
- **危险汇聚点**：strcpy 调用点（地址 0x000086d0 附近），溢出固定大小的栈缓冲区（393216 字节）。
- **触发条件**：当攻击者提供长度超过 393216 字节的 'value' 时，栈缓冲区被溢出，覆盖返回地址或其他关键栈数据。
- **可利用性分析**：这是实际可利用的，因为：
  - strcpy 缺乏边界检查，允许攻击者控制栈内容。
  - 在 ARM 架构上，栈溢出可覆盖链接寄存器（LR）或返回地址，导致任意代码执行（例如，通过 ROP 链）。
  - 漏洞触发无需特殊权限，只需执行 'config set' 命令。
- **Code Snippet:**
  ```
  else if (*(param_2 + 8) != 0) {
      sym.imp.strcpy(puVar11 + -0x60204);  // 直接复制用户输入到栈缓冲区，无边界检查
      iVar7 = sym.imp.strchr(puVar11 + -0x60204,0x3d);
      puVar6 = iVar7 + 0;
      if (puVar6 == NULL) {
          return puVar6;
      }
      *puVar6 = iVar2 + 0;
      sym.imp.config_set(puVar11 + -0x60204,puVar6 + 1);
  }
  ```
- **Keywords:** 命令行参数（name=value）, NVRAM 变量通过 config_set 函数
- **Notes:** 证据基于反编译代码，显示 strcpy 使用无边界检查。缓冲区大小较大（393216 字节），但攻击者仍可通过精心构造的输入利用。建议进一步验证栈布局和利用可行性，例如通过动态测试或查看 libconfig.so 的实现。相关函数：fcn.000086d0（主函数）、sym.imp.strcpy。

---
### command-injection-wget

- **File/Directory Path:** `etc/openvpn/push_routing_rule`
- **Location:** `push_routing_rule:50 [wget command]`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击者可以通过控制 `$trusted_ip` 环境变量注入任意命令。完整攻击链：不可信输入 `$trusted_ip` → 在 `wget` 命令中未加引号使用 → shell 解释特殊字符（如分号或空格）→ 执行任意命令。触发条件：当 `vpn_access_mode` 为 'auto' 时，脚本执行 `wget` 命令。可利用性分析：由于 `$trusted_ip` 直接插入命令字符串且未经验证，攻击者可以注入额外命令（例如，`127.0.0.1; id` 会执行 `id` 命令），如果脚本以高权限（如 root）运行，可导致完全系统控制。
- **Code Snippet:**
  ```
  /usr/sbin/wget -T 10 http://www.speedtest.net/api/country?ip=$trusted_ip -O /tmp/openvpn/client_location
  ```
- **Keywords:** $trusted_ip
- **Notes:** 证据来自脚本内容；假设 `$trusted_ip` 来自不可信源（如 OpenVPN 客户端连接）。需要验证脚本运行权限和 `$trusted_ip` 的输入上下文。建议对 `$trusted_ip` 进行输入验证和引号转义。

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `In the 'internet_con' function, specifically the line: eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'internet_con' function due to improper use of 'eval' on the value of the NVRAM variable 'swapi_persistent_conn'. The complete attack chain is as follows: 1) An attacker sets 'swapi_persistent_conn' to a malicious value containing shell commands (e.g., "'; malicious_command; '") via the 'nvram set' command exposed by the script. 2) The attacker then calls the 'internet_con' function with any arguments (e.g., 'internet_con set connection appname 1'). 3) In 'internet_con', the line 'eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\' retrieves the malicious value and evaluates it, executing the embedded commands due to inadequate quoting. The trigger condition is simply calling 'internet_con' after setting the variable. This is exploitable because 'eval' interprets shell metacharacters in the unsanitized data, allowing arbitrary command execution.
- **Code Snippet:**
  ```
  internet_con()
  {
  	local tvalue
  	local exist=0
  
  	eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'\n	if [ "x$(printf "$tvalue" | grep "$2\\ [01]")" != "x" ]; then
  		$CONFIG set $SWAPI_PERSISTENT_CONN="$(printf "$tvalue"|sed "s/$2\\ [01]/$2\\ $3/")"
  	else
  		$CONFIG set $SWAPI_PERSISTENT_CONN="${tvalue:+${tvalue};}$2 $3"
  	fi
  	$CONFIG commit
  
  	local proto=$($CONFIG get wan_proto)
  	local dod=$($CONFIG get wan_endis_dod)
  	if [ $3 -eq 1 ] && [ $proto = pppoe -o $proto = pptp -o $proto = l2tp ] && [ $dod -ne 0 ] ; then
  		$CONFIG set wan_endis_dod=0
  		/etc/init.d/net-wan restart
  	fi
  }
  ```
- **Keywords:** swapi_persistent_conn, /etc/scripts/ntgr_sw_api/ntgr_sw_api.sh
- **Notes:** The vulnerability requires the attacker to have access to call the script's commands, which might be exposed via network interfaces or IPC. Further analysis could verify if '/bin/config' properly sanitizes inputs during 'nvram set', but the eval usage here is inherently unsafe. No other exploitable chains were found in this file under the current analysis scope.

---
### auth-bypass-setup_interface_ppp

- **File/Directory Path:** `lib/network/ppp.sh`
- **Location:** `setup_interface_ppp 函数中的用户输入处理部分，具体在写入 /etc/ppp/ipv4-secrets 和 /etc/ppp/chap-secrets 的代码段`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 'ppp.sh' 的 `setup_interface_ppp` 函数中，用户名和密码从 NVRAM 配置获取后，仅转义反斜杠、井号和双引号，但未转义换行符。当用户名包含换行符时，攻击者可在 PPP 秘密文件（如 /etc/ppp/chap-secrets）中注入额外用户条目，导致认证绕过。完整攻击链：攻击者通过 Web 接口或其他方式控制 NVRAM 变量（如 wan_pppoe_username）-> 脚本读取变量并处理 -> 由于换行符未转义，写入秘密文件时添加恶意用户条目 -> PPP 认证时使用注入的凭据，允许未授权访问。触发条件：用户名包含换行符（如 'alice\nbob'）。可利用性分析：缺少对换行符的清理，使攻击者能添加任意用户，直接导致认证绕过。
- **Code Snippet:**
  ```
  user=$(echo ${user} | sed 's/\\/\\\\/g' | sed 's/\#/\\#/g' | sed 's/"/\\"/g')
  passwd=$(echo ${passwd} | sed 's/\\/\\\\/g' | sed 's/\#/\\#/g' | sed 's/"/\\"/g')
  echo "${user} * \"${passwd}\"" > $IPV4_PPPS
  ```
- **Keywords:** wan_pppoe_username, wan_pptp_username, wan_l2tp_username
- **Notes:** 需要验证 NVRAM 配置接口是否允许换行符输入；建议检查 PPP 服务是否在默认配置下运行；后续可分析其他脚本（如 Web CGI）是否对 NVRAM 输入有过滤。

---
### command-injection-RADARDETECT

- **File/Directory Path:** `lib/wifi/wireless_event`
- **Location:** `wireless_event: for loop in RADARDETECT case`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击者可以控制 CHANNEL 环境变量，当 ACTION 设置为 'RADARDETECT' 时，脚本循环遍历 CHANNEL 值（逗号分隔）并执行 `/usr/sbin/radardetect_cli -a $chan`。由于 $chan 没有引号，如果 CHANNEL 包含命令分隔符（如分号），shell 会解析并执行注入的命令。例如，如果 CHANNEL='1; ls'，它会执行 'ls' 命令。攻击链：不可信输入（CHANNEL 环境变量） → 数据传播（通过 echo 和 sed 处理） → 危险操作（命令执行 without quoting）。触发条件：ACTION='RADARDETECT' 且 CHANNEL 被恶意控制。可利用性分析：缺少对 CHANNEL 的验证和转义，以及 $chan 未引用，允许命令注入。
- **Code Snippet:**
  ```
  #!/bin/sh
  
  case "$ACTION" in
      RADARDETECT)
          [ -f /tmp/radardetect.pid ] || /usr/sbin/radardetect
  
          for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do 
              /usr/sbin/radardetect_cli -a $chan
          done
  esac
  ```
- **Keywords:** ACTION, CHANNEL
- **Notes:** 假设脚本以足够权限（如 root）运行，且环境变量从不可信源（如网络接口或 IPC）设置。建议对 $chan 使用引号（如 radardetect_cli -a "$chan"）来防止注入。进一步验证可能需要检查调用此脚本的组件以确认环境变量的来源。

---
### RCE-streamboost-init

- **File/Directory Path:** `etc/init.d/streamboost`
- **Location:** `脚本开头（第2行）和 apply_action 函数中的循环执行部分`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击者可以通过设置 STREAMBOOST_CFGDIR 环境变量指向恶意目录，该目录包含恶意的 rc.appflow 文件。当脚本执行时，它会加载此文件并覆盖 INITDIR 变量，指向攻击者控制的目录。随后，在 apply_action 函数中，脚本会从 INITDIR 执行任意脚本，导致特权升级和任意代码执行。攻击链完整：从环境变量（不可信输入）到脚本执行（危险操作）。触发条件：脚本以高权限（如 root）运行，且 STREAMBOOST_CFGDIR 环境变量可被攻击者控制（例如通过其他漏洞或配置错误）。可利用性分析：缺少对环境变量和加载文件路径的验证，允许任意文件包含和代码执行。
- **Code Snippet:**
  ```
  #!/bin/sh
  [ -f ${STREAMBOOST_CFGDIR:-/etc/appflow}/rc.appflow ] && . ${STREAMBOOST_CFGDIR:-/etc/appflow}/rc.appflow
  ...
  INITDIR=${INITDIR:-"$CFGDIR/$NAME.d"}
  ...
  apply_action() {
      ...
      target="$(ls $INITDIR/??_*)"
      for i in $target; do
          ...
          $i $action "$@" >$STREAMBOOST_TMPFILE 2>&1
          ...
      done
      ...
  }
  ```
- **Keywords:** STREAMBOOST_CFGDIR, /etc/appflow/rc.appflow, INITDIR, CFGDIR
- **Notes:** 这个攻击链依赖于环境变量控制，在 init 脚本上下文中可能以 root 权限运行。建议添加对 STREAMBOOST_CFGDIR 和 INITDIR 路径的验证，限制为可信目录。后续可分析其他初始化脚本以寻找类似模式。

---
### Command-Injection-vlan_create_brs_and_vifs

- **File/Directory Path:** `lib/cfgmgr/opmode.sh`
- **Location:** `函数 vlan_create_brs_and_vifs 和 vlan_create_br_and_vif 在 'opmode.sh' 中`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击者可以通过设置恶意的 vlan_tag_$i NVRAM 变量（例如，通过 Web UI 或 API），在设备进入 VLAN 模式时注入任意命令。完整攻击链：1) 不可信输入源为 NVRAM 变量 vlan_tag_1 到 vlan_tag_10；2) 数据流：在 vlan_create_brs_and_vifs 函数中，tv 变量从 $CONFIG get vlan_tag_$i 获取，通过 set - $(echo $tv) 解析，vid ($3) 传递给 vlan_create_br_and_vif 函数；3) 危险操作：在 vlan_create_br_and_vif 中，vconfig add $RawEth $1 命令执行，其中 $1 (vid) 未加引号，如果包含 shell 元字符（如分号），会导致命令注入。触发条件：设备操作模式为 'vlan' 且至少一个 vlan_tag_$i 的 enable 字段设置为 '1'。可利用性分析：由于缺少输入验证和清理，vid 值直接拼接进命令，允许攻击者执行任意命令（如 rm -rf /），从而获得 root 权限或造成拒绝服务。
- **Code Snippet:**
  ```
  在 vlan_create_brs_and_vifs 中:
  for i in 0 1 2 3 4 5 6 7 8 9 10; do
      tv=$($CONFIG get vlan_tag_$i)
      [ -n "$tv" ] || continue
      set - $(echo $tv)
      # $1: enable, $2: name, $3: vid, $4: pri, $5:wports, $6:wlports
      [ "$1" = "1" ] || continue
      ...
      vlan_create_br_and_vif $3 $4
      ...
  done
  
  在 vlan_create_br_and_vif 中:
  vlan_create_br_and_vif() # $1: vid, $2: pri
  {
      local brx="br$1"
      ...
      vconfig add $RawEth $1 && ifconfig $RawEth.$1 up
      ...
  }
  ```
- **Keywords:** vlan_tag_1, vlan_tag_2, vlan_tag_3, vlan_tag_4, vlan_tag_5, vlan_tag_6, vlan_tag_7, vlan_tag_8, vlan_tag_9, vlan_tag_10
- **Notes:** 此漏洞需要设备处于 VLAN 模式，可能通过认证后访问，但假设攻击者能控制 NVRAM 变量（例如通过网络接口）。建议验证其他函数（如 iptv_create_brs_and_vifs）是否有类似问题，并检查输入清理机制。后续分析应关注 cfgmgr.sh 和 enet.sh 以获取更多上下文。

---
### Command-Injection-Redis-Persistence

- **File/Directory Path:** `etc/appflow/persistence.sh`
- **Location:** `Functions: persist_string, persist_hash, persist_list, persist_set, persist_zset, and restore in persistence.sh`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 发现一个完整的命令注入攻击链，导致任意代码执行。攻击链如下：
- **源**：攻击者控制的 Redis 键值（例如，通过未授权访问 Redis 或注入恶意数据）。Redis 键 'settings:*' 是硬编码的目标，但脚本可能处理其他键如果 PERSIST_KEYS 被修改。
- **传播路径**：当脚本运行 'persist' 操作时，从 Redis 读取键值，并使用函数如 persist_string 生成 redis-cli 命令字符串。键和值被直接插入到命令字符串中而没有转义（例如，在 persist_string 中：`echo "redis-cli SET ${key} $(redis-cli GET ${key})"`）。如果键或值包含 shell 元字符（如分号、反引号），恶意命令被嵌入到生成的持久化文件中。
- **汇聚点**：当脚本运行 'restore' 操作时，使用 `sh ${PERSIST_FILE}` 执行持久化文件内容。如果文件包含恶意命令，它们将以脚本的权限（可能为 root）执行。
- **触发条件**：攻击者需要能够写入 Redis 数据库（例如，Redis 未认证或网络暴露），并确保脚本被调用进行 'persist' 和 'restore' 操作（可能通过系统任务、定时任务或手动执行）。
- **可利用性分析**：这是由于缺少输入验证和转义导致的逻辑缺陷。攻击者可以注入任意 shell 命令，从而完全控制系统。漏洞实际可利用，因为 Redis 数据通常被视为不可信输入，且脚本可能以高权限运行。
- **Code Snippet:**
  ```
  Persist function example (persist_string):
  \`\`\`sh
  persist_string() {
      local key=$1
      echo "redis-cli SET ${key} $(redis-cli GET ${key})"
  }
  \`\`\`
  Restore function:
  \`\`\`sh
  restore() {
      sh ${PERSIST_FILE}
  }
  \`\`\`
  ```
- **Keywords:** Redis keys: settings:*, File path: /usr/lib/sbsaved/sb.persist.redis, Environment variable: PERSIST_KEYS
- **Notes:** 建议对从 Redis 读取的键和值进行适当的 shell 转义（例如，使用 `printf '%q'` 或引用变量）。此外，考虑使用 redis-cli 的 --raw 选项或避免通过 shell 生成命令。验证 Redis 访问控制和安全配置。后续分析可检查系统如何调用此脚本（例如，通过 cron 或其他组件）以评估实际攻击面。

---
### Command-Injection-6pppoe-start

- **File/Directory Path:** `etc/net6conf/6pppoe`
- **Location:** `函数 'start' 中的 'ifconfig $WAN_IF up' 命令`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6pppoe' 脚本中发现一个命令注入漏洞，攻击链完整且可验证：
- **攻击链**：攻击者通过控制 'wan_ifname' 配置值（不可信输入源）注入恶意命令。该值存储在 $WAN_IF 变量中，并在 'start' 函数中直接用于 'ifconfig $WAN_IF up' 命令。由于变量未引用，如果 $WAN_IF 包含特殊字符（如分号或空格），将导致命令注入。例如，若 $WAN_IF 设置为 'eth0; rm -rf /', 则命令 'ifconfig eth0; rm -rf / up' 会执行恶意操作。
- **触发条件**：当脚本以 'start' 参数运行时（例如，PPPoE 连接启动时），漏洞被触发。
- **可利用性分析**：漏洞可利用的原因是缺少输入验证和变量引用。用户可控数据直接插入 shell 命令中，允许攻击者执行任意命令。证据来自脚本代码：变量 $WAN_IF 通过 'config get wan_ifname' 获取，未经过滤或转义，并在危险操作中使用。
- **Code Snippet:**
  ```
  在 'start' 函数中：
  /sbin/ifconfig $WAN_IF up
  /usr/sbin/pppd call pppoe-ipv6 updetach &
  
  $WAN_IF 通过以下方式获取：
  WAN_IF=\`config get wan_ifname\`
  ```
- **Keywords:** wan_ifname
- **Notes:** 此漏洞需要攻击者能够修改 'wan_ifname' 配置值，可能通过 web 界面或其他配置机制。建议对所有用户输入进行验证和转义，并在使用变量时添加引号（例如 'ifconfig "$WAN_IF" up'）。此外，应检查脚本中其他类似命令（如 'rs_send' 中使用 $WAN_IF 和 $WAN 的地方）是否存在类似问题。

---
### Command-Injection-6bridge-start_service

- **File/Directory Path:** `etc/net6conf/6bridge`
- **Location:** `6bridge, start_service function: brctl addif $bridge $WAN_IF`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection via unsanitized NVRAM variables in shell commands. The attack chain is: attacker sets NVRAM variable (e.g., wan_ifname) to a string containing shell metacharacters (e.g., 'eth0; malicious_command') -> script retrieves it via 'config get' in '6data.conf' -> uses it unquoted in commands like 'brctl addif $bridge $WAN_IF' in '6bridge' -> shell interprets the metacharacters and executes the injected command. This is exploitable because the variables lack quoting or validation, and the script runs with root privileges.
- **Code Snippet:**
  ```
  brctl addif $bridge $WAN_IF
  ```
- **Keywords:** wan_ifname, lan_ifname
- **Notes:** Trigger condition: when the script is invoked with 'start', 'stop', or 'restart' arguments (e.g., during network setup). Assumes NVRAM variables are settable by attacker via exposed interfaces (e.g., web UI). Multiple other command injection points exist (e.g., in reset_iface_ip6 using ifconfig and ip commands).

---
### Command-Injection-6to4_start_6to4

- **File/Directory Path:** `etc/net6conf/6to4`
- **Location:** `文件 '6to4' 中的 `start_6to4` 函数，具体在 `ifconfig $WAN4` 命令使用处。`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 攻击者可通过设置 'wan_ifname' 配置值（例如，通过管理界面漏洞或默认凭证）注入恶意 shell 命令。当 6to4 隧道启动时（例如，通过 `net6conf start` 或 `6to4 start`），脚本在 `start_6to4` 函数中执行 `ifconfig $WAN4` 命令，其中 `$WAN4` 直接来自 `wan_ifname` 配置值。由于变量未用引号括起，如果值包含 shell 元字符（如分号、反引号），将导致命令注入。完整攻击链：1) 攻击者控制 `wan_ifname` 值（输入点）；2) 值通过 `$CONFIG get wan_ifname` 获取并赋给 `WAN4`（数据流）；3) 在 `start_6to4` 中，`ifconfig $WAN4` 执行时触发命令注入（危险操作）。可利用性高，因为缺少输入验证和过滤，且命令以 root 权限执行。
- **Code Snippet:**
  ```
  从 '6data.conf'：
  if [ "$wan4_type" = "pppoe" -o "$wan4_type" = "pptp" -o "$wan4_type" = "l2tp" ]; then
      WAN4="ppp0"
  else
      WAN4=\`$CONFIG get wan_ifname\`
  fi
  
  从 '6to4' 的 \`start_6to4\` 函数：
  localip4=\`ifconfig $WAN4 |grep "inet addr" |cut -f2 -d: |cut -f1 -d' '\`
  [ -z "$localip4" ] && exit
  ...
  wanmtu=\`ifconfig $WAN4 |grep "MTU" |cut -f2 -d: |cut -f1 -d' '\`
  ```
- **Keywords:** wan_ifname (NVRAM 变量)
- **Notes:** 攻击链已验证：输入点（wan_ifname）可通过网络接口（如 Web 管理）设置；数据流通过配置获取传播；危险操作（命令执行）在隧道启动时触发。建议修复：对所有配置值使用引号（例如 `ifconfig "$WAN4"`）并实施输入验证。相关文件：'6data.conf' 定义变量，'net6conf' 控制启动流程。

---
### Command-Injection-start_dhcp6c_6dhcpc

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `start_dhcp6c` 在 /etc/net6conf/6dhcpc`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6dhcpc' 脚本的 `start_dhcp6c` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `ipv6_dhcp_userClass` 和 `ipv6_dhcp_domainName`；2) 变量通过 `$CONFIG get` 获取并存储在 `U_CLADATA` 和 `U_DOMAIN` 中；3) 变量直接用于 `dhcp6c` 命令参数，允许命令注入。触发条件：脚本以 `start` 参数执行。可利用性分析：缺少输入清理，导致任意代码执行。
- **Code Snippet:**
  ```
  start_dhcp6c() {
  	local U_CLADATA=\`$CONFIG get ipv6_dhcp_userClass\`
  	local U_DOMAIN=\`$CONFIG get ipv6_dhcp_domainName\`
  	/usr/sbin/dhcp6c -c /tmp/dhcp6c.conf -3 ${U_CLADATA:+-u $U_CLADATA} ${U_DOMAIN:+-U $U_DOMAIN} $WAN
  }
  ```
- **Keywords:** ipv6_dhcp_userClass, ipv6_dhcp_domainName
- **Notes:** 漏洞可被远程触发，如果 DHCPv6 配置暴露。建议转义变量或使用安全函数。

---
### Command-Injection-start_6fixed

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `start` 和 `set_wan_ip` 在 /etc/net6conf/6fixed`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6fixed' 脚本的 `start` 和 `set_wan_ip` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量如 `ipv6_fixed_wan_ip`；2) 变量通过 `$CONFIG get` 获取；3) 变量直接用于 `$IP -6 addr add ${wan6_ip}/${wan6_prelen} dev $WAN` 命令，允许命令注入。触发条件：脚本以 `start` 或 `wan` 参数执行。可利用性分析：缺少输入验证，导致任意命令执行。
- **Code Snippet:**
  ```
  local wan6_ip=\`$CONFIG get ipv6_fixed_wan_ip\`
  local wan6_prelen=\`$CONFIG get ipv6_fixed_wan_prefix_len\`
  $IP -6 addr add ${wan6_ip}/${wan6_prelen} dev $WAN
  ```
- **Keywords:** ipv6_fixed_wan_ip, ipv6_fixed_lan_ip
- **Notes:** 漏洞常见于固件 Web 接口。建议对所有输入进行验证和转义。

---
### Command-Injection-start_6pppoe

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `start` 在 /etc/net6conf/6pppoe`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6pppoe' 脚本的 `start` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `wan_ifname`；2) 变量通过 `$CONFIG get` 获取并存储在 `WAN_IF` 中；3) 变量直接用于 `/sbin/ifconfig $WAN_IF up` 等命令，允许命令注入。触发条件：脚本以 `start` 参数执行。可利用性分析：缺少输入清理，导致任意代码执行。
- **Code Snippet:**
  ```
  start() {
      /sbin/ifconfig $WAN_IF up
      /usr/sbin/pppd call pppoe-ipv6 updetach &
  }
  ```
- **Keywords:** wan_ifname
- **Notes:** 漏洞以 root 权限执行。建议使用引号包裹变量（如 "$WAN_IF"）。

---
### Command-Injection-format_prefix

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `format_prefix` 在 /etc/net6conf/6service`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6service' 脚本的 `format_prefix` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `ipv6_fixed_lan_ip`；2) 变量通过 `$CONFIG get` 获取并传递给 `format_prefix`；3) 变量直接用于 `echo $lanip6 | cut ...` 命令，允许命令注入。触发条件：当 `w6_type` 设置为 'fixed' 时，脚本执行 `write_config` 函数。可利用性分析：缺少输入清理，导致任意代码执行。
- **Code Snippet:**
  ```
  value=\`echo $lanip6 | cut -f$i -d':'\`
  ```
- **Keywords:** ipv6_fixed_lan_ip, wan6_type
- **Notes:** 漏洞需要 `w6_type` 为 'fixed'，可能通过配置实现。建议对所有输入进行转义。

---
### stack-buffer-overflow-kc_read_proc

- **File/Directory Path:** `lib/modules/3.4.103/NetUSB.ko`
- **Location:** `NetUSB.ko sym.kc_read_proc at address 0x08018cdc (sprintf call)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability exists in sym.kc_read_proc due to unsafe use of sprintf without bounds checking. The attack chain is as follows: 1) An attacker controls device information strings (e.g., product, manufacturer, serial) by connecting a malicious USB device with long strings. 2) When the proc file is read, sym.kc_read_proc retrieves these strings via getStringItem calls and formats them into a fixed-size stack buffer of 0x324 bytes (804 bytes) using sprintf. 3) The sprintf call does not limit the output size, and data is accumulated in a loop that iterates up to 10 times. 4) If the formatted string exceeds 804 bytes, it overflows the stack buffer, corrupting adjacent kernel stack memory. The trigger condition is reading the proc file (e.g., /proc/netusb/device) while a malicious USB device is attached. This is exploitable for kernel stack corruption, potentially leading to code execution or information leakage.
- **Code Snippet:**
  ```
  0x08018cdc      feffffeb       bl reloc.sprintf            ; unsafe sprintf call
  ; Preceding setup: r0 = stack buffer, r1 = format string (e.g., "usblp%d\n%s\n%s\n%s\n%d\n"), r2 = loop index
  ; The loop at 0x08018cec runs up to 10 times, accumulating data without size checks
  ```
- **Keywords:** proc filesystem read handler, getStringItem function, device information strings (product, manufacturer, serial)
- **Notes:** The format string is loaded from 0x0801fb48 in static analysis. Dynamic testing with long device strings (e.g., > 804 bytes total) can confirm the overflow. This vulnerability requires physical access or compromised USB device, but it is exploitable in scenarios with attacker-controlled USB peripherals.

---
### command-injection-12_settings-loader-start

- **File/Directory Path:** `etc/appflow/streamboost.d/12_settings-loader`
- **Location:** `12_settings-loader: 在 start() 函数中，处理 uplimit 和 downlimit 的 awk 命令处`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 完整的攻击链：攻击者可以通过控制 NVRAM 配置变量（如 `uplimit`、`downlimit`、`ookla_uplimit`、`ookla_downlimit`）注入恶意命令。当脚本执行 `start()` 函数时，这些值从 `$DNI_CONFIG` 获取并直接用于 `awk` 命令而没有引号。如果值包含 shell 元字符（如分号、反引号），会导致命令注入，允许任意命令执行。触发条件：脚本以特权用户（如 root）运行，且攻击者能设置 NVRAM 值（例如通过未授权的 web 接口或已有漏洞）。可利用性分析：缺少输入清理和引号使用，使得命令注入可行；攻击者可能获得特权执行。
- **Code Snippet:**
  ```
  if [ "x$uplimit" != "x" ] && [ "x$downlimit" != "x" ]; then
  	uplimit=\`awk -v up=$uplimit 'BEGIN{printf "%.0f",up/0.9}'\`
  	downlimit=\`awk -v down=$downlimit 'BEGIN{printf "%.0f",down/0.9}'\`
  fi
  ```
- **Keywords:** bandwidth_type, uplimit, downlimit, ookla_uplimit, ookla_downlimit
- **Notes:** 证据基于代码分析；假设攻击者能控制 NVRAM 变量。建议验证 NVRAM 设置机制和脚本运行权限。相关文件：`/bin/config`（可能处理 NVRAM）、Redis 配置。后续可分析其他组件（如 web 接口）如何设置这些 NVRAM 值。

---
### injection-setup_interface_ppp

- **File/Directory Path:** `lib/network/ppp.sh`
- **Location:** `setup_interface_ppp 函数中的用户输入处理部分，具体在写入 /etc/ppp/ipv4-secrets 和 /etc/ppp/chap-secrets 的代码段`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 'ppp.sh' 的 `setup_interface_ppp` 函数中，用户名和密码从 NVRAM 配置（如 wan_pppoe_username、wan_pppoe_passwd）获取后，仅使用 sed 命令转义反斜杠、井号和双引号，但未转义换行符。当用户名包含换行符时，攻击者可在 PPP 秘密文件（如 /etc/ppp/ipv4-secrets、/etc/ppp/chap-secrets）中注入额外用户条目，导致认证绕过。完整攻击链：攻击者通过 Web 接口或其他方式控制 NVRAM 变量（如 wan_pppoe_username）→ 脚本读取变量并处理（使用 sed 转义特定字符但忽略换行符）→ 由于换行符未转义，写入秘密文件时通过 echo 命令添加恶意用户条目（例如，用户名 'alice\nbob' 会创建两个条目：'alice' 和 'bob'）→ PPP 认证时使用注入的凭据，允许未授权访问。触发条件：用户名包含换行符（如 'alice\nbob'）。可利用性分析：缺少对换行符的清理，使攻击者能通过注入换行符添加任意用户条目，直接导致认证绕过；代码路径在 PPP 连接设置时可达，且输入通过 NVRAM 可控。
- **Code Snippet:**
  ```
  user=$(echo ${user} | sed 's/\\/\\\\/g' | sed 's/\#/\\#/g' | sed 's/"/\\"/g')
  passwd=$(echo ${passwd} | sed 's/\\/\\\\/g' | sed 's/\#/\\#/g' | sed 's/"/\\"/g')
  echo "${user} * \"${passwd}\"" > $IPV4_PPPS
  ```
- **Keywords:** wan_pppoe_username, wan_pppoe_passwd, wan_pptp_username, wan_pptp_password, wan_l2tp_username, wan_l2tp_password, /etc/ppp/ipv4-secrets, /etc/ppp/chap-secrets, /etc/ppp/pap-secrets
- **Notes:** 证据基于文件内容分析；漏洞在多种协议（PPPoE、PPTP、L2TP）中存在；建议进一步验证实际部署中 NVRAM 变量的可控性和触发频率；相关函数包括 setup_interface_ppp 和 NVRAM 配置获取逻辑。

---
### command-injection-start

- **File/Directory Path:** `etc/net6conf/6pppoe`
- **Location:** `etc/net6conf/6pppoe: [start] /sbin/ifconfig $WAN_IF up`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 在 '6pppoe' 脚本中发现一个命令注入漏洞，攻击链完整且可验证：
- **攻击链**：攻击者通过控制 'wan_ifname' 配置值（不可信输入源）注入恶意命令。该值通过 'config get wan_ifname' 获取并存储在 $WAN_IF 变量中，未经过滤或转义。在 'start' 函数中，$WAN_IF 直接用于 '/sbin/ifconfig $WAN_IF up' 命令。由于变量未引用，如果 $WAN_IF 包含特殊字符（如分号或空格），将导致命令注入。例如，若 $WAN_IF 设置为 'eth0; rm -rf /', 则命令 'ifconfig eth0; rm -rf / up' 会执行恶意操作。
- **触发条件**：当脚本以 'start' 参数运行时（例如，PPPoE 连接启动时），'start' 函数被调用，漏洞被触发。
- **可利用性分析**：漏洞可利用的原因是缺少输入验证和变量引用。用户可控数据直接插入 shell 命令中，允许攻击者执行任意命令。证据来自脚本代码：变量 $WAN_IF 通过 'config get wan_ifname' 获取，未经过滤或转义，并在危险操作中使用。
- **Code Snippet:**
  ```
  WAN_IF=\`config get wan_ifname\`
  ...
  /sbin/ifconfig $WAN_IF up
  ```
- **Keywords:** wan_ifname
- **Notes:** 验证基于文件 'etc/net6conf/6pppoe' 的实际内容。攻击链完整，从源（wan_ifname 配置值）到汇聚点（ifconfig 命令）均有证据支持。假设 'config get' 命令从用户可控的配置存储中读取值，但未在文件中定义；然而，代码逻辑显示变量直接用于 shell 命令，无需额外假设即可确认漏洞。建议进一步验证 'config' 命令的实现以确认输入可控性。

---
### Command-Injection-6to4-start_6to4

- **File/Directory Path:** `etc/net6conf/6to4`
- **Location:** `文件 '6to4' 中的 `start_6to4` 函数，具体在 `ifconfig $WAN4` 命令使用处。`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 安全警报已验证。完整攻击链如下：1) 攻击者可控输入：通过管理界面或配置系统设置 'wan_ifname' 值（例如，设置为 'eth0; malicious_command'）；2) 数据流：在 '6data.conf' 中，当 wan4_type 不是 'pppoe'、'pptp' 或 'l2tp' 时，WAN4 变量通过 `WAN4=`$CONFIG get wan_ifname`` 直接赋值为攻击者控制的输入；3) 危险操作：在 '6to4' 文件的 `start_6to4` 函数中，执行 `ifconfig $WAN4` 命令（未加引号），如果 WAN4 包含 shell 元字符（如分号），将导致命令注入。触发条件：当执行 `net6conf start` 或 `6to4 start` 时，`start_6to4` 函数被调用。可利用性分析：缺少输入验证和过滤，命令以 root 权限执行，攻击者可实现任意命令执行。
- **Code Snippet:**
  ```
  从 '6data.conf':
  wan4_type=\`$CONFIG get wan_proto\`
  if [ "$wan4_type" = "pppoe" -o "$wan4_type" = "pptp" -o "$wan4_type" = "l2tp" ]; then
      WAN4="ppp0"
  else
      WAN4=\`$CONFIG get wan_ifname\`
  fi
  
  从 '6to4' 的 \`start_6to4\` 函数:
  localip4=\`ifconfig $WAN4 |grep "inet addr" |cut -f2 -d: |cut -f1 -d' '\`
  [ -z "$localip4" ] && exit
  ...
  wanmtu=\`ifconfig $WAN4 |grep "MTU" |cut -f2 -d: |cut -f1 -d' '\`
  ```
- **Keywords:** wan_ifname, WAN4
- **Notes:** 证据充分：从源（wan_ifname 配置）到汇聚点（ifconfig $WAN4）的完整路径已验证。假设攻击者可通过管理界面控制 wan_ifname，但未直接测试管理界面；代码逻辑表明配置值来自外部输入。建议进一步验证配置系统的输入处理。

---
### Command-Injection-set_interface_id

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `set_interface_id` 在 /etc/net6conf/net6conf`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** 在 'net6conf' 脚本的 `set_interface_id` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `ipv6_dhcps_interface_id`（例如通过 Web 接口）；2) 变量通过 `local ipv6_interface_id=\`$CONFIG get ipv6_dhcps_interface_id\`` 获取，未经验证；3) 变量直接用于 `$IP -6 addr add fe80::$ipv6_interface_id/64 dev $bridge` 命令，如果 `ipv6_interface_id` 包含 shell 元字符（如分号），将执行注入的命令。触发条件：当 `wan6_type` 为 'autoDetect'、'autoConfig'、'6to4'、'dhcp'、'pppoe' 或 '6rd' 时，脚本执行 `set_interface_id` 函数。可利用性分析：缺少输入清理，允许命令注入，可能导致系统完全妥协。
- **Code Snippet:**
  ```
  if [ "$wan6_type" = "autoDetect" -o "$wan6_type" = "autoConfig" -o "$wan6_type" = "6to4" -o "$wan6_type" = "dhcp" -o "$wan6_type" = "pppoe" -o "$wan6_type" = "6rd" ]; then  
  	$IP -6 addr del ${ip6} dev $bridge
  	$IP -6 addr add fe80::$ipv6_interface_id/64 dev $bridge
  fi
  ```
- **Keywords:** ipv6_dhcps_interface_id, wan6_type
- **Notes:** 漏洞依赖于 `wan6_type` 的设置，可能通过其他漏洞或配置修改触发。建议对 `ipv6_interface_id` 进行输入验证和转义。

---
### command-injection-vpn-firewall

- **File/Directory Path:** `etc/openvpn/vpn-firewall.sh`
- **Location:** `vpn-firewall.sh 中的多个 iptables 命令位置，例如：'iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT' 和 'iptables -t nat -A ${wan_interface}_masq -s $tun_subnet/$mask -j MASQUERADE'`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** 验证确认在 'vpn-firewall.sh' 中存在命令注入漏洞。完整攻击链：攻击者通过控制 NVRAM 变量（如 lan_ipaddr、lan_netmask）注入恶意值（例如包含分号或空格的字符串）→ 脚本使用 'config get' 获取这些值（如 'mask=$(config get lan_netmask)'）→ 值直接插入 iptables 命令中的 shell 变量扩展（如 'iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT'）→ 如果值包含 shell 元字符，shell 解释这些字符并执行任意命令（例如，如果 $mask 为 '24; malicious_command', 命令会变成 'iptables -I loc2net 5 -s $tun_subnet/24; malicious_command -j ACCEPT', 执行 malicious_command）。触发条件：当脚本执行时（例如，由于 VPN 配置更改），且攻击者已设置恶意 NVRAM 值。可利用性分析：实际可利用，因为脚本可能以 root 权限运行，缺少输入清理和引用，允许攻击者执行任意命令，从而完全控制系统。证据来自文件内容，显示变量直接使用而无引用。
- **Code Snippet:**
  ```
  wan_proto=$(config get wan_proto)
  lan_ipaddr=$(config get lan_ipaddr)
  mask=$(config get lan_netmask)
  tun_subnet=$(tun_net $lan_ipaddr $mask)
  # ...
  iptables -t nat -A ${wan_interface}_masq -s $tun_subnet/$mask -j MASQUERADE
  iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT
  ```
- **Keywords:** lan_ipaddr, lan_netmask, wan_proto, tun_subnet, mask, etc/openvpn/vpn-firewall.sh
- **Notes:** 验证基于文件内容证据，显示变量直接用于命令而无引用。假设脚本以 root 权限运行，但未在文件中直接证实；建议进一步验证执行上下文。相关函数 'tun_net' 未在文件中定义，可能引入额外风险，但未在本分析中探索。攻击链完整，从源到汇聚点可验证。

---
### IntegerOverflow-HeapOverflow-fcn.0000a60c

- **File/Directory Path:** `sbin/ubusd`
- **Location:** `函数 fcn.0000a60c 在地址 0xa60c 附近，具体在 strcpy 调用处`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在函数 fcn.0000a60c 的第一个分支中，当 param_2 匹配特定命令字符串时，函数解析 param_3 数据（来自 blobmsg 格式）并提取字符串 iVar8。使用 strlen(iVar8) 计算长度 iVar6，然后调用 calloc(1, iVar6 + 0x2d) 分配内存。如果 iVar6 值较大（例如 >= 0xffffffd4），iVar6 + 0x2d 会发生整数溢出，导致分配过小缓冲区。随后使用 strcpy(piVar5 + 0xb, iVar8) 复制字符串，由于目标缓冲区小，会导致堆缓冲区溢出。攻击者可通过控制 param_3 提供恶意 blobmsg 数据，使 iVar8 为长字符串或不以空字符结尾，触发溢出。完整攻击链：从不可信输入 param_3 → 解析提取 iVar8 → strlen 计算 iVar6 → calloc 分配（整数溢出）→ strcpy 溢出。触发条件：param_2 匹配命令字符串且 param_3 包含恶意数据。可利用性分析：堆溢出可能允许任意代码执行，因为缺少边界检查和清理。
- **Code Snippet:**
  ```
  反编译代码片段：
  if (iVar2 + 0 == 0) {
      ...
      iVar6 = sym.imp.strlen(iVar8);
      ...
      iVar6 = sym.imp.calloc(1, iVar6 + 0x2d);
      ...
      sym.imp.strcpy(piVar5 + 0xb, iVar8);
      ...
  }
  ```
- **Keywords:** param_2, param_3, *0xa82c (命令字符串), *0xa83c (blobmsg 格式)
- **Notes:** 漏洞可利用性高，建议替换 strcpy 为安全函数（如 strncpy）并在分配前检查 iVar6 + 0x2d 是否溢出。需要进一步验证硬编码地址的具体字符串值以确认输入点。相关函数 fcn.0000a4a8 和 fcn.000096e0 未发现其他漏洞。

---
### Command-Injection-vpn-firewall

- **File/Directory Path:** `etc/openvpn/vpn-firewall.sh`
- **Location:** `vpn-firewall.sh 中的多个 iptables 命令位置，例如：'iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT' 和 'iptables -t nat -A ${wan_interface}_masq -s $tun_subnet/$mask -j MASQUERADE'`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在 'vpn-firewall.sh' 中发现命令注入漏洞，源于缺少对 NVRAM 变量的验证和引用。完整攻击链：攻击者通过控制 NVRAM 变量（如 lan_ipaddr、lan_netmask）注入恶意值 → 脚本使用 'config get' 获取这些值 → 值直接插入 iptables 命令中的 shell 变量扩展（如 'iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT'）→ 如果值包含 shell 元字符（如分号或空格），shell 解释这些字符并执行任意命令。触发条件：当脚本执行时（例如，由于 VPN 配置更改），且攻击者已设置恶意 NVRAM 值。可利用性分析：实际可利用，因为脚本可能以 root 权限运行，缺少输入清理和引用，允许攻击者执行任意命令，从而完全控制系统。
- **Code Snippet:**
  ```
  从文件内容中提取的相关代码：
  wan_proto=$(config get wan_proto)
  lan_ipaddr=$(config get lan_ipaddr)
  mask=$(config get lan_netmask)
  tun_subnet=$(tun_net $lan_ipaddr $mask)
  # ...
  iptables -t nat -A ${wan_interface}_masq -s $tun_subnet/$mask -j MASQUERADE
  iptables -I loc2net 5 -s $tun_subnet/$mask -j ACCEPT
  ```
- **Keywords:** wan_proto, lan_ipaddr, lan_netmask
- **Notes:** 攻击链完整且基于文件内容证据，但假设攻击者可以通过其他漏洞（如 web 界面）控制 NVRAM 变量。tun_net 函数未在文件中定义，但其行为不影响主要命令注入漏洞，因为漏洞源于直接变量扩展在 iptables 命令中。建议在固件其他部分验证 NVRAM 输入源和添加变量引用以防止注入。关联发现：Command-Injection-net-wan-script（共享 NVRAM 变量注入模式）。

---
### Command-Injection-prefix_timeout

- **File/Directory Path:** `etc/net6conf/dhcp6c-script`
- **Location:** `dhcp6c-script: prefix_timeout 函数中，具体在命令替换行：`prefix_addr=\`echo $timeout_prefix |cut -f3 -d' ' |sed s/:://\```
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在 prefix_timeout 函数中，$timeout_prefix 变量被直接用于命令替换（通过反引号），缺少输入验证和清理。攻击链如下：攻击者通过恶意 DHCPv6 消息控制 $timeout_prefix 值 → 当 REASON 环境变量为 'prefix_timeout' 时，脚本调用 prefix_timeout 函数 → $timeout_prefix 被传递给 `echo` 命令在反引号中执行 → 如果 $timeout_prefix 包含 shell 元字符（如分号、反引号），则注入的命令会被执行。触发条件为：REASON='prefix_timeout' 且 $timeout_prefix 包含恶意负载。可利用性高，因为缺少输入清理允许直接命令执行。
- **Code Snippet:**
  ```
  prefix_timeout() {
  	# Remove the LAN side IPv6 address, which has been expired
  	# timeout_prefix would be like: 5600 2800 2000:458:ff01:3800:: 56
  	prefix_addr=\`echo $timeout_prefix |cut -f3 -d' ' |sed s/:://\`
  	lan6_ip=\`ifconfig $bridge |grep "inet6 addr: $prefix" |grep -v "Link" |awk '{print $3}'\`
  	echo "Try to delete $lan6_ip from $bridge" > /dev/console
  	[ "x$lan6_ip" != "x" ] && $IP -6 addr del $lan6_ip dev $bridge
  
  	#when prefix is timeout, remove old prefix info files
  	rm /tmp/dhcp6c_script_envs
  	rm $DHCP6C_PD
  	rm $DHCP6S_PD
  
  	#reload the LAN side IPv6 related services:
  	#rewrite config file: radvd_write_config, dhcp6s_write_config.
  	echo "reload 6service" > /dev/console
  	/etc/net6conf/6service reload
  }
  ```
- **Keywords:** timeout_prefix, REASON
- **Notes:** 此漏洞的利用依赖于 wide-dhcpv6 传递不可信的 $timeout_prefix 值，如脚本注释所示。建议对 $timeout_prefix 进行输入验证和清理，例如使用引号或避免直接命令替换。后续分析应验证 wide-dhcpv6 的输入处理机制。

---
### Command-Injection-reset_iface_ip6

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `reset_iface_ip6` 在 /etc/net6conf/6bridge`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在 '6bridge' 脚本的 `reset_iface_ip6` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `wan_ifname` 或 `lan_ifname`；2) 变量通过 `$CONFIG get` 获取并用于设置 `dev` 参数；3) `dev` 直接用于 `ifconfig $dev | grep ...` 命令，如果包含 shell 元字符，将注入命令。触发条件：当脚本执行 `stop` 或 `clear` 操作时。可利用性分析：缺少输入验证，允许命令注入。
- **Code Snippet:**
  ```
  reset_iface_ip6() {
  	local dev=$1
  	ip6s=\`ifconfig $dev |grep "inet6 addr" |grep "Link" |awk '{print $3}'\`
  	echo "$ip6s" |while read ip6; do
  		$IP -6 addr del ${ip6} dev $dev
  	done
  }
  ```
- **Keywords:** wan_ifname, lan_ifname
- **Notes:** 漏洞可能通过网络配置触发。建议对 `dev` 变量进行白名单验证。

---
### Command-Injection-to_upper_bin2hex

- **File/Directory Path:** `etc/net6conf/net6conf`
- **Location:** `函数 `to_upper` 和 `bin2hex` 在 /etc/net6conf/6rd`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在 '6rd' 脚本的 `to_upper` 和 `bin2hex` 函数中发现命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量如 `Ipv66rdPrefix`；2) 变量通过 `$CONFIG get` 获取；3) 变量直接用于 `echo $prefix | cut ...` 和 `bc` 命令，允许命令注入。触发条件：脚本以 `start` 参数执行，且 `wan6_type` 为 '6rd'。可利用性分析：缺少输入验证，导致任意命令执行。
- **Code Snippet:**
  ```
  local part1=\`echo $prefix|cut -f1 -d:\`
  local bin=\`echo "ibase=2;obase=10000;$1"|bc\`
  ```
- **Keywords:** Ipv66rdPrefix, Ipv66rdPrefixlen
- **Notes:** 漏洞可能通过配置修改触发。建议使用 `printf` 替代 `echo` 并进行输入验证。

---
### Command-Injection-reset_iface_ip6

- **File/Directory Path:** `etc/net6conf/6bridge`
- **Location:** `函数 `reset_iface_ip6` 在 /etc/net6conf/6bridge`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** 在文件 '/etc/net6conf/6bridge' 的 `reset_iface_ip6` 函数中验证了命令注入漏洞。攻击链：1) 攻击者控制 NVRAM 变量 `wan_ifname`；2) 变量通过 `config get wan_ifname` 获取并设置 `WAN_IF`；3) 在 `start_service` 或 `stop_service` 中，`reset_iface_ip6` 被调用 with `$WAN_IF` 作为 `dev` 参数；4) `dev` 直接用于 `ifconfig $dev | grep ...` 命令，由于未引用，如果 `wan_ifname` 包含 shell 元字符（如分号、反引号），将注入任意命令。触发条件：当脚本执行 `start` 或 `stop` 操作时。可利用性分析：缺少输入验证和引用，允许攻击者通过控制 `wan_ifname` 执行任意命令，造成实际安全损害。
- **Code Snippet:**
  ```
  reset_iface_ip6() {
  	local dev=$1
  	ip6s=\`ifconfig $dev |grep "inet6 addr" |grep "Link" |awk '{print $3}'\`
  	echo "$ip6s" |while read ip6; do
  		$IP -6 addr del ${ip6} dev $dev
  	done
  }
  ```
- **Keywords:** wan_ifname, /etc/net6conf/6bridge
- **Notes:** 证据基于文件内容确认了代码片段和调用链。但 `config get` 函数的具体实现（可能来自 /etc/net6conf/6data.conf）未直接验证，建议进一步检查其是否从 NVRAM 读取值以完全确认输入可控性。漏洞实际可利用，因攻击者可能通过设置 NVRAM 变量触发命令注入。

---
### Command-Injection-wps-supplicant-update-uci

- **File/Directory Path:** `lib/wifi/wps-supplicant-update-uci`
- **Location:** `wps-supplicant-update-uci: multiple lines [script]`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The script uses the command-line argument IFNAME directly in multiple shell commands without proper quoting or sanitization, allowing command injection if IFNAME contains shell metacharacters (e.g., semicolons, backticks). The complete attack chain is: untrusted IFNAME input -> propagated to commands like wpa_cli and hostapd_cli -> shell interprets metacharacters -> arbitrary command execution. Trigger condition: The script must be invoked with a malicious IFNAME value (e.g., "eth0; malicious_command") and CMD=CONNECTED (or other values that trigger command execution). Exploitable because the script lacks input validation and likely runs with elevated privileges (e.g., root), enabling full system compromise.
- **Code Snippet:**
  ```
  wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
  wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status
  hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPA2PSK CCMP $psk
  psk=$(awk 'BEGIN{FS="="} /psk=/ {print $0}' $conf |grep "psk=" |tail -n 1 | cut -f 2 -d= | sed -e 's/^"\(.*\)"/\1/')
  ```
- **Keywords:** Command-line arguments (IFNAME, CMD), environment variables (INTERFACE in hotplug-call), file paths (/var/run/wpa_supplicant-$IFNAME.conf, /var/run/wifi-wps-enhc-extn.conf)
- **Notes:** The script is likely invoked by system processes (e.g., WPS events), so if IFNAME is derived from an untrusted source (e.g., network input or manipulated process), exploitation is feasible. Further analysis of the calling context and other scripts (e.g., /sbin/hotplug-call) is recommended to assess overall impact. No other exploitable vulnerabilities with complete chains were found in this file.

---
### weak-auth-ExternalConnect

- **File/Directory Path:** `etc/aMule/amule.conf`
- **Location:** `amule.conf 文件中的 [ExternalConnect] 部分`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** 外部连接认证使用弱 MD5 哈希密码 '5f4dcc3b5aa765d61d8327deb882cf99'，该哈希对应常见密码 'password'。攻击链：攻击者通过不可信网络输入连接到 ECPort 4712（输入点），提供密码 'password'；程序读取配置中的 ECPassword 哈希并比较客户端提供的密码（数据流）；认证通过后，攻击者获得外部连接访问权限，可能执行危险操作如远程控制文件下载/上传（危险操作）。触发条件：攻击者能访问 ECPort 4712 并提供密码 'password'。可利用性分析：由于密码弱且公开已知，缺少强密码策略和哈希加盐，认证可被轻易绕过。
- **Code Snippet:**
  ```
  ECPassword=5f4dcc3b5aa765d61d8327deb882cf99
  ```
- **Keywords:** ECPassword
- **Notes:** 基于配置文件证据和公开知识（MD5 哈希易破解）。建议进一步分析程序二进制（如 aMule 主程序）以确认认证逻辑和外部连接功能的具体操作，确保没有其他缓解措施。

---
### Untitled Finding

- **File/Directory Path:** `etc/appflow/uci2streamboost`
- **Location:** `Functions update_from_uci and update_yn_from_uci in uci2streamboost script`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The script contains a command injection vulnerability in the update_from_uci and update_yn_from_uci functions due to unsanitized use of eval on UCI values. Attack chain: An attacker can set a UCI value (e.g., appflow.tccontroller.uplimit) to a malicious string via an exposed interface (e.g., web UI or API). When the script runs (during boot or configuration update), it fetches the UCI value and executes eval ${name}=${newval}, where newval contains the malicious string, leading to arbitrary command execution. Trigger condition: The script must be executed with a config file argument, and a UCI value must be set to a malicious string. Exploitable because eval interprets the string as shell commands without any validation or escaping.
- **Code Snippet:**
  ```
  update_from_uci() {
      local name=$1
      local uciname=${2:-$1}
      local newval=$(uci -q get appflow.tccontroller.${uciname})
      [ ! -z "${newval}" ] && {
          eval ${name}=${newval}
      }
  }
  ```
- **Keywords:** appflow.tccontroller.auto_update, appflow.tccontroller.opt_in, appflow.tccontroller.enable_streamboost, appflow.tccontroller.enable_auto, appflow.tccontroller.uplimit, appflow.tccontroller.downlimit, appflow.tccontroller.nss_qdisc, appflow.tccontroller.max_zone_id
- **Notes:** This vulnerability assumes that the script runs with high privileges (e.g., as root) and that UCI values can be set by an untrusted source. Further analysis should verify the execution context and how UCI values are populated (e.g., via network interfaces). The config file path argument ($1) may also be exploitable for path traversal or arbitrary file write, but command injection is more direct.

---
### command-injection-update_from_uci

- **File/Directory Path:** `etc/appflow/uci2streamboost`
- **Location:** `Function update_from_uci in etc/appflow/uci2streamboost`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** 验证确认 update_from_uci 函数存在命令注入漏洞，但 update_yn_from_uci 函数没有类似漏洞。完整攻击链：攻击者可通过暴露接口（如Web UI或API）设置 UCI 值（例如 appflow.tccontroller.uplimit）为恶意字符串（例如 'x; malicious_command'）。当脚本运行时（在启动或配置更新时），update_from_uci 函数获取 UCI 值并执行 eval ${name}=${newval}，其中 newval 包含恶意字符串，导致任意命令执行。触发条件：脚本必须执行且提供配置文件参数（如通过 ucitrack 或启动时），且 UCI 值被设置为恶意字符串。可利用性分析：eval 直接解释未清理的输入作为 shell 命令，缺少任何验证或转义，导致高危漏洞。update_yn_from_uci 函数使用 eval 但仅与硬编码字符串（'yes' 或 'no'）结合，且 newval 仅在数字条件检查中使用，因此没有命令注入。
- **Code Snippet:**
  ```
  update_from_uci() {\n    local name=\$1\n    local uciname=\${2:-\$1}\n    local newval=\$(uci -q get appflow.tccontroller.\${uciname})\n    [ ! -z "\${newval}" ] && {\n        eval \${name}=\${newval}\n    }\n}
  ```
- **Keywords:** appflow.tccontroller.uplimit, appflow.tccontroller.downlimit, appflow.tccontroller.max_zone_id
- **Notes:** 警报中提到的 update_yn_from_uci 函数没有命令注入漏洞，因为 eval 使用硬编码字符串。建议重点关注 update_from_uci 函数的修复。证据来自文件内容分析，攻击链完整且可验证。

---
### Untitled Finding

- **File/Directory Path:** `lib/wifi/wps-supplicant-update-uci`
- **Location:** `wps-supplicant-update-uci: CONNECTED case and related functions [script]`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** 验证确认脚本中存在命令注入漏洞。完整攻击链：攻击者通过命令行参数控制 IFNAME 输入 -> 在 CMD=CONNECTED 情况下，IFNAME 直接传播到多个未引用的 shell 命令（如 wpa_cli -i$IFNAME 和 hostapd_cli -i$IFNAME_AP）-> shell 解释 IFNAME 中的元字符（如分号、反引号）-> 导致任意命令执行。触发条件：脚本必须被调用且 CMD=CONNECTED（或其他值如 WPA2-PSK 案例中触发 hostapd_cli）。可利用性分析：脚本缺乏输入验证，IFNAME 未经过清理直接用于命令；且脚本可能以提升权限（如 root）运行， enabling full system compromise。证据来自文件内容显示未引用的变量使用。
- **Code Snippet:**
  ```
  wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
  ssid=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^ssid= | cut -f2- -d =)
  hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPA2PSK CCMP $psk
  ```
- **Keywords:** IFNAME, IFNAME_AP, /var/run/wpa_supplicant-$IFNAME, /var/run/hostapd-$parent
- **Notes:** 漏洞已验证基于文件内容证据。攻击链完整且可利用。建议添加输入验证和适当引用变量。其他 CMD 值（如 WPS-TIMEOUT）也使用 IFNAME 但风险较低，因在引号内。脚本可能由系统进程自动调用，增加现实可利用性。

---
### command-injection-sendmail

- **File/Directory Path:** `etc/email/email_log`
- **Location:** `email_log [sendmail 函数]`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** 攻击者可以通过设置 NVRAM `email_addr` 变量注入任意命令。当脚本执行电子邮件发送功能时（例如通过 `email_log` 或 `send_email_alert` 入口点），`sendmail` 函数中的 `$addr` 变量（来自 NVRAM）未加引号地传递给 `ssmtp` 命令。由于 shell 参数分词，如果 `email_addr` 包含分号或其它 shell 元字符，恶意命令将被执行。完整攻击链：1. 攻击者控制 NVRAM `email_addr`（例如通过其他漏洞或接口设置为 'user@example.com; malicious_command'）；2. 脚本被触发执行（需 `email_notify` 不为 '0'）；3. 在 `sendmail` 函数中，命令 `cat $email_file | $smtpc -C$conf $addr` 执行，注入的命令运行。可利用性高，因为缺少输入验证和转义，且脚本可能以 root 权限运行。
- **Code Snippet:**
  ```
  在 sendmail 函数中: cat $email_file | $smtpc -C$conf $addr >/dev/null 2>$err_file
  在 email_HDD_err_log 函数中: cat $email_file | $smtpc -C$conf $addr >/dev/null 2>$err_file
  ```
- **Keywords:** email_addr
- **Notes:** 攻击链完整，但需要攻击者能控制 NVRAM 变量（例如通过未认证的 Web 接口或其他漏洞）。建议对 NVRAM 输入进行验证和转义，或在调用命令时使用引号。

---
### DNS-Hijack-avahi-dnsconfd

- **File/Directory Path:** `etc/avahi/avahi-dnsconfd.action`
- **Location:** `avahi-dnsconfd.action, specifically in the sections handling DNS server updates (e.g., lines around the for loops and file writes).`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The 'avahi-dnsconfd.action' script handles DNS configuration updates based on Avahi discoveries but lacks input validation for environment variables set from mDNS packets. This allows an attacker to spoof mDNS responses and inject malicious DNS server addresses, leading to DNS hijacking. The complete attack chain is: 1) Attacker sends crafted mDNS packets with malicious DNS server addresses (e.g., 'malicious.ip'); 2) avahi-dnsconfd processes these packets and sets environment variables (AVAHI_DNS_SERVERS, AVAHI_INTERFACE_DNS_SERVERS) without sanitization; 3) This script uses these variables directly in critical operations like writing to /etc/resolv.conf or updating resolvconf, without validating the addresses; 4) The system's DNS configuration is updated to use attacker-controlled servers, enabling DNS spoofing and further attacks like phishing or malware distribution. The trigger condition is when a new DNS server is advertised via mDNS, causing the script to execute. This is exploitable due to the absence of validation checks for nameserver addresses, allowing arbitrary IP injection.
- **Code Snippet:**
  ```
  if [ "x$AVAHI_DNS_SERVERS" = "x" ] ; then
      test -f /etc/resolv.conf.avahi && mv /etc/resolv.conf.avahi /etc/resolv.conf
  else
      test -f /etc/resolv.conf.avahi || mv /etc/resolv.conf /etc/resolv.conf.avahi
  
      for n in $AVAHI_DNS_SERVERS ; do 
          echo "nameserver $n"
      done > /etc/resolv.conf
  fi
  ```
- **Keywords:** AVAHI_INTERFACE, AVAHI_INTERFACE_DNS_SERVERS, AVAHI_DNS_SERVERS, /etc/resolv.conf
- **Notes:** The vulnerability relies on the avahi-dnsconfd daemon not sanitizing input from mDNS packets. Further analysis of avahi-dnsconfd source code is recommended to confirm the initial input handling. Additionally, implementing validation for IP addresses in this script or in the daemon could mitigate the risk.

---
### Command-Injection-dnsmasq-start

- **File/Directory Path:** `etc/init.d/dnsmasq`
- **Location:** `在 start 函数中，wan ifname 配置部分和 static pptp 配置部分`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** 发现一个完整的攻击链，环境变量 `BR_IF` 和 `WAN_IF` 作为不可信输入点，被未经过滤地用于构建 dnsmasq 命令行参数和配置文件内容。攻击者可以通过控制这些环境变量注入额外命令行选项或恶意配置行，从而操纵 dnsmasq 行为。具体路径：
- 输入点：环境变量 `BR_IF` 和 `WAN_IF`（可能通过其他组件如网络接口或 IPC 设置）。
- 数据流：`BR_IF` 直接拼接到 `opt_argv` 字符串（`opt_argv="$opt_argv --wan-interface=$BR_IF"`），然后传递给 dnsmasq 命令；`WAN_IF` 用于写入 `/tmp/pptp.conf` 文件（`echo "interface $WAN_IF" > /tmp/pptp.conf`），该文件被 dnsmasq 使用。
- 汇聚点：`/usr/sbin/dnsmasq --except-interface=lo -r $resolv_file $opt_argv` 命令执行。
- 触发条件：对于 `BR_IF`，当 `ap_mode=1` 或 `bridge_mode=1` 时；对于 `WAN_IF`，当 `static_pptp_enable=1` 时（取决于多个配置条件）。
- 可利用性分析：由于输入未经过滤，攻击者可以注入空格或特殊字符来添加任意 dnsmasq 选项（例如 `--conf-file` 加载恶意配置）或注入恶意配置行到文件，可能导致 DNS 劫持、缓存投毒或其他安全影响。这是一个实际可利用的漏洞，因为攻击者可能通过控制环境变量来影响 dnsmasq 的配置和执行。
- **Code Snippet:**
  ```
  # wan ifname config 部分
  if [ "$($CONFIG get ap_mode)" = "1" -o "$($CONFIG get bridge_mode)" = "1" ]; then
      opt_argv="$opt_argv --wan-interface=$BR_IF"
  fi
  
  # static pptp config 部分
  if [ "$static_pptp_enable" = "1" ]; then
      echo "interface $WAN_IF" > /tmp/pptp.conf
      echo "myip $($CONFIG get wan_pptp_local_ip)" >> /tmp/pptp.conf
      echo "gateway $($CONFIG get pptp_gw_static_route)" >> /tmp/pptp.conf
      echo "netmask $($CONFIG get wan_pptp_eth_mask)" >> /tmp/pptp.conf
      echo "resolv /tmp/pptp-resolv.conf" >> /tmp/pptp.conf
      echo "nameserver $($CONFIG get wan_ether_dns1)" > /tmp/pptp-resolv.conf
      echo "nameserver $($CONFIG get wan_ether_dns2)" >> /tmp/pptp-resolv.conf
      opt_argv="$opt_argv --static-pptp"
  fi
  
  # 最终命令执行
  /usr/sbin/dnsmasq --except-interface=lo -r $resolv_file $opt_argv
  ```
- **Keywords:** BR_IF, WAN_IF
- **Notes:** 攻击链完整且可验证，但实际影响取决于 dnsmasq 二进制如何处理注入的选项或配置文件。建议进一步分析 dnsmasq 二进制以确认具体漏洞。环境变量 `BR_IF` 和 `WAN_IF` 可能由 init 系统或其他组件设置，需检查其来源。相关函数：start()、set_hijack()。

---
### FAILSAFE-Authentication-Bypass

- **File/Directory Path:** `bin/login`
- **Location:** `Condition in the if statement and subsequent exec call in the login script`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** 验证确认安全警报准确。攻击链完整：攻击者可在执行脚本前设置 FAILSAFE 环境变量为非空值，使条件 `[ -z "$FAILSAFE" ]` 为假，从而跳过密码检查块（检查 /etc/passwd 和 /etc/shadow 中 root 密码）并执行 `exec /bin/ash --login`，获得未经授权的 shell 访问。漏洞源于缺失对 FAILSAFE 环境变量的验证，允许绕过认证。证据来自文件内容：条件语句和 exec 调用直接可见。
- **Code Snippet:**
  ```
  #!/bin/sh
  # Copyright (C) 2006-2010 OpenWrt.org
  
  if grep -qs '^root:[^!]' /etc/passwd /etc/shadow && [ -z "$FAILSAFE" ]; then
  	echo "Login failed."
  	exit 0
  else
  cat << EOF
   === IMPORTANT ============================
    Use 'passwd' to set your login password
    this will disable telnet and enable SSH
   ------------------------------------------
  EOF
  fi
  
  exec /bin/ash --login
  ```
- **Keywords:** FAILSAFE
- **Notes:** 文件路径在警报中为 'bin/login'，但实际文件为 'login'（位于当前 bin 目录）。攻击链已验证完整，无需进一步分析。环境变量可控性基于标准 POSIX 行为，假设脚本在允许设置环境变量的上下文中执行。

---
### symlink-attack-write_config

- **File/Directory Path:** `etc/net6conf/6service`
- **Location:** `write_config 函数中的重定向操作，具体在调用 radvd_write_config 和 dhcp6s_write_config 时`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** 安全警报已验证。完整攻击链：1) 攻击者在 /tmp 目录创建符号链接（如 ln -sf /etc/passwd /tmp/radvd.conf）；2) 攻击者触发服务重载（通过调用 '6service reload' 或类似管理接口请求）；3) reload 函数调用 write_config；4) write_config 调用 radvd_write_config 和 dhcp6s_write_config，输出重定向到 $RADVD_CONF 和 $DHCP6S_CONF（由于符号链接，实际写入敏感文件）；5) 敏感文件被覆盖，导致拒绝服务或权限提升。触发条件：攻击者能创建符号链接在 /tmp 目录并触发服务重载。可利用性分析：缺少文件路径验证，允许符号链接攻击；输入部分可控（PREFIX 和 PRELEN 来自 /tmp/dhcp6s_pd 等外部文件），允许数据注入。
- **Code Snippet:**
  ```
  radvd_write_config "$DHCP6S_ENABLE" "$prefix" "64" "$lease_time" "$prefer_time" "$rdns" > $RADVD_CONF
  dhcp6s_write_config "$lease_time" "$prefix" "$prefix_len" "$prefer_time" > $DHCP6S_CONF
  echo $PD_INFO >$OLD_PD
  ```
- **Keywords:** RADVD_CONF=/tmp/radvd.conf, DHCP6S_CONF=/tmp/dhcp6s.conf, OLD_PD=/tmp/pd_info, DHCP6S_PD=/tmp/dhcp6s_pd
- **Notes:** 证据来自 6service 和 6data.conf 文件的实际内容。变量定义在 6data.conf 中确认。重载功能通过 reload 函数实现。输入可控性通过 get_prefix 函数从 /tmp/dhcp6s_pd 等文件读取数据支持。没有发现符号链接验证代码。建议添加文件存在性检查和符号链接检测。

---
### symlink-attack-write_config

- **File/Directory Path:** `etc/net6conf/6service`
- **Location:** `write_config 函数中的重定向操作，具体在调用 radvd_write_config 和 dhcp6s_write_config 时`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** 攻击者可以通过创建符号链接从 /tmp/radvd.conf 到敏感系统文件（如 /etc/passwd），然后触发 6service 重载（例如通过网络请求到管理接口），导致敏感文件被覆盖。当 radvd_write_config 函数执行并输出配置到 $RADVD_CONF 时，由于符号链接，实际写入敏感文件。配置内容部分依赖于攻击者可控的输入（如 PREFIX 和 PRELEN），允许注入恶意数据。完整攻击链：1) 攻击者创建符号链接；2) 攻击者触发服务重载；3) write_config 函数调用 radvd_write_config；4) 输出重定向到符号链接目标文件；5) 敏感文件被覆盖，导致拒绝服务或权限提升。触发条件：攻击者能创建符号链接在 /tmp 目录并触发服务重载。可利用性分析：缺少文件路径验证，允许符号链接攻击；部分输入可控，允许数据注入。
- **Code Snippet:**
  ```
  radvd_write_config "$DHCP6S_ENABLE" "$prefix" "64" "$lease_time" "$prefer_time" "$rdns" > $RADVD_CONF
  dhcp6s_write_config "$lease_time" "$prefix" "$prefix_len" "$prefer_time" > $DHCP6S_CONF
  echo $PD_INFO >$OLD_PD
  ```
- **Keywords:** /tmp/radvd.conf, /tmp/dhcp6s.conf, /tmp/pd_info
- **Notes:** 需要验证触发重载的方式（如通过 web 接口）和权限要求（攻击者是否需要本地访问创建符号链接）。建议添加文件路径验证或使用安全文件创建机制。

---
### Untitled Finding

- **File/Directory Path:** `bin/login`
- **Location:** `Condition in the if statement and subsequent exec call in the login script`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The login script uses the FAILSAFE environment variable to bypass password authentication, creating a complete and exploitable attack chain. An attacker who can set the FAILSAFE environment variable to any non-empty value before script execution can bypass the password check (which verifies if root has a password set in /etc/passwd or /etc/shadow) and gain a shell via /bin/ash without authentication. The vulnerability arises from the condition `[ -z "$FAILSAFE" ]` which, when false (FAILSAFE is set), avoids the login failure block and proceeds to execute the shell. This missing validation of the environment variable allows unauthorized access.
- **Code Snippet:**
  ```
  if grep -qs '^root:[^!]' /etc/passwd /etc/shadow && [ -z "$FAILSAFE" ]; then
      echo "Login failed."
      exit 0
  else
  cat << EOF
   === IMPORTANT ============================
    Use 'passwd' to set your login password
    this will disable telnet and enable SSH
   ------------------------------------------
  EOF
  fi
  exec /bin/ash --login
  ```
- **Keywords:** FAILSAFE
- **Notes:** This finding assumes the attacker can control the FAILSAFE environment variable during script execution, which might be possible through other vulnerabilities or misconfigurations in the system (e.g., via remote services or IPC). The script is typically used in login processes, so if run with privileges, it could grant root access. Further analysis of the script's invocation context is recommended to confirm exploitability in practice.

---
### Command-Injection-hotplug2-exec

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `fcn.0000b510 (execvp call at 0xbc28), %-substitution logic at 0xb690-0xb720`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in hotplug2's handling of 'exec' directives in rules files. The attack chain is as follows: 1) Attacker sends crafted uevent data via netlink socket (input point). 2) hotplug2 parses the uevent and sets environment variables from the key-value pairs (data flow). 3) When a rule with an 'exec' directive is triggered, hotplug2 processes the directive and builds the command arguments using %-substitution for environment variables (data flow). 4) The environment variable values are incorporated directly into the command string without sanitization using memcpy (lack of sanitization). 5) execvp is called with the manipulated arguments, leading to command execution if the environment variable contains malicious content (dangerous operation). The trigger condition is the presence of a rule that uses %-substitution for an environment variable controllable by the attacker. Exploitable because the lack of sanitization allows injection of shell metacharacters or additional commands, potentially leading to arbitrary code execution.
- **Code Snippet:**
  ```
  0x0000b690      250058e3       cmp r8, 0x25                ; 37
  0x0000b694      010088e2       add r0, r8, 1               ; size_t size
  0x0000b698      3ef6ffeb       bl sym.imp.malloc           ;  void *malloc(size_t size)
  0x0000b69c      012048e2       sub r2, r8, 1
  0x0000b6a0      011086e2       add r1, r6, 1               ; const void *s2
  0x0000b6a4      0090a0e1       mov sb, r0
  0x0000b6a8      28f6ffeb       bl sym.imp.memcpy           ; void *memcpy(void *s1, const void *s2, size_t n)
  0x0000b6ac      083089e0       add r3, sb, r8
  0x0000b6b0      0010a0e3       mov r1, 0
  0x0000b6b4      0900a0e1       mov r0, sb                  ; const char *name
  0x0000b6b8      011043e5       strb r1, [r3, -1]
  0x0000b6bc      17f6ffeb       bl sym.imp.getenv           ; char *getenv(const char *name)
  0x0000b6c0      00a0a0e1       mov sl, r0
  0x0000b6c4      0900a0e1       mov r0, sb                  ; void *ptr
  0x0000b6c8      d7f6ffeb       bl sym.imp.free             ; void free(void *ptr)
  0x0000b6cc      00005ae3       cmp sl, 0
  0x0000b6d0      3500000a       beq 0xb7ac
  0x0000b6d4      0a00a0e1       mov r0, sl                  ; const char *s
  0x0000b6d8      066064e0       rsb r6, r4, r6
  0x0000b6dc      bdf6ffeb       bl sym.imp.strlen           ; size_t strlen(const char *s)
  0x0000b6e0      0c309de5       ldr r3, [var_ch]
  0x0000b6e4      036086e0       add r6, r6, r3
  0x0000b6e8      001086e0       add r1, r6, r0              ; size_t size
  0x0000b6ec      0080a0e1       mov r8, r0
  0x0000b6f0      0700a0e1       mov r0, r7                  ; void *ptr
  0x0000b6f4      013041e2       sub r3, r1, 1
  0x0000b6f8      0c308de5       str r3, [var_ch]
  0x0000b6fc      6df6ffeb       bl sym.imp.realloc          ; void *realloc(void *ptr, size_t size)
  0x0000b700      0a10a0e1       mov r1, sl                  ; const void *s2
  0x0000b704      0820a0e1       mov r2, r8
  0x0000b708      016084e2       add r6, r4, 1
  0x0000b70c      00a0a0e3       mov sl, 0
  0x0000b710      0070a0e1       mov r7, r0
  0x0000b714      050080e0       add r0, r0, r5              ; void *s1
  0x0000b718      0cf6ffeb       bl sym.imp.memcpy           ; void *memcpy(void *s1, const void *s2, size_t n)
  0x0000b71c      085085e0       add r5, r5, r8
  0x0000b720      bcffffea       b 0xb618
  ...
  0x0000bc28      76f5ffeb       bl sym.imp.execvp
  ```
- **Keywords:** DEVPATH, DEVICENAME, SUBSYSTEM, SEQNUM, MAJOR, MINOR, MODALIAS
- **Notes:** The exploitability depends on the rules configuration using %-substitution for environment variables in 'exec' directives. An attacker must be able to send crafted uevents to trigger the vulnerability. Further analysis could verify the exact point where environment variables are set from uevents, but the data flow is supported by the use of getenv in command building. Recommended to review rules files for dangerous %-substitution patterns.

---
### RCE-43_flowmark-STREAMBOOST_CFGDIR

- **File/Directory Path:** `etc/appflow/streamboost.d/43_flowmark`
- **Location:** `脚本第1行：'. ${STREAMBOOST_CFGDIR:-/etc/appflow}/rc.appflow'`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** 攻击者可通过控制环境变量 STREAMBOOST_CFGDIR 指向恶意路径，从而在脚本加载时执行任意代码。完整攻击链：1. 攻击者设置 STREAMBOOST_CFGDIR 环境变量（例如，通过其他服务或接口）指向恶意目录；2. 恶意目录中包含精心构造的 rc.appflow 文件，包含任意命令；3. 当脚本执行 '. ${STREAMBOOST_CFGDIR:-/etc/appflow}/rc.appflow' 时，加载并执行恶意文件；4. 导致任意命令执行，可能提升权限或破坏系统。触发条件：脚本以高权限（如 root）运行，且 STREAMBOOST_CFGDIR 被恶意设置。可利用性分析：缺少对 STREAMBOOST_CFGDIR 值的验证，直接使用 '.' 命令执行文件内容，允许代码注入。
- **Code Snippet:**
  ```
  . ${STREAMBOOST_CFGDIR:-/etc/appflow}/rc.appflow
  ```
- **Keywords:** STREAMBOOST_CFGDIR
- **Notes:** 需要验证 STREAMBOOST_CFGDIR 是否可通过网络接口、IPC 或 NVRAM 设置。建议检查父进程或系统配置如何设置此变量。后续可分析 rc.appflow 文件内容以确认影响。

---
### RCE-43_flowmark-STREAMBOOST_USER_CFG

- **File/Directory Path:** `etc/appflow/streamboost.d/43_flowmark`
- **Location:** `脚本第14行：'. $STREAMBOOST_USER_CFG'`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** 攻击者可通过控制环境变量 STREAMBOOST_USER_CFG 指向恶意文件，从而在脚本加载时执行任意代码。完整攻击链：1. 攻击者设置 STREAMBOOST_USER_CFG 环境变量指向恶意文件；2. 恶意文件包含任意命令；3. 当脚本执行 '. $STREAMBOOST_USER_CFG' 时，加载并执行恶意文件；4. 导致任意命令执行。触发条件：脚本以高权限运行，且 STREAMBOOST_USER_CFG 被恶意设置。可利用性分析：缺少对 STREAMBOOST_USER_CFG 值的验证，直接使用 '.' 命令执行文件内容，允许代码注入。
- **Code Snippet:**
  ```
  . $STREAMBOOST_USER_CFG
  ```
- **Keywords:** STREAMBOOST_USER_CFG
- **Notes:** STREAMBOOST_USER_CFG 没有默认值，如果未设置可能报错，但一旦设置即可利用。建议检查固件中其他组件如何设置此变量。后续可分析 UCI 配置机制。

---
### Command-Injection-sw_configvlan_vlan

- **File/Directory Path:** `lib/cfgmgr/enet.sh`
- **Location:** `函数 `sw_configvlan_vlan` 中的 'add' 操作分支，具体在 `sw_tmpconf_add_vlan` 调用和文件 source 处。`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** 在 'enet.sh' 文件中，`sw_configvlan_vlan` 函数处理 VLAN 配置时，参数 `$3` (vid) 和 `$4` (mask) 被直接用于生成临时文件内容，且这些文件随后通过 `source` 命令执行。如果攻击者可控这些参数（例如通过网络配置或 IPC 调用），可注入恶意代码实现任意命令执行。攻击链：不可信输入 → `sw_configvlan_vlan` 函数参数 → `sw_tmpconf_add_vlan` 写入文件 → `source` 执行文件内容。触发条件：当 `sw_configvlan` 被调用且 `$1` 为 'vlan'，并传递恶意参数时。可利用性分析：由于缺少输入验证和过滤，shell 元字符（如分号、反引号）可被注入执行命令。
- **Code Snippet:**
  ```
  sw_tmpconf_add_vlan() # $1: vlanindex, $2: vid, $3: ports
  {
  	cat <<EOF > "$swconf.tmp$1"
  vid="$2"
  ports="$3"
  EOF
  }
  # 在 sw_tmpconf_adjust_vlan 或 sw_tmpconf_generate_swconf 中：
  . "$swconf.tmp$i"  # 这里执行文件内容
  ```
- **Keywords:** NVRAM: factory_tt3, 文件路径: /tmp/sw.conf.tmp*, IPC: 通过配置管理器调用
- **Notes:** 攻击链依赖于外部调用者（如配置管理器或网络接口）传递不可信参数。建议进一步分析调用脚本（如 cfgmgr.sh）以验证输入源和可控性。此外，检查其他函数如 `sw_configvlan_iptv` 是否存在类似问题。

---
### file-write-redirect

- **File/Directory Path:** `etc/openvpn/push_routing_rule`
- **Location:** `push_routing_rule:52,54,56,58,60 [output redirections]`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** 攻击者可以通过控制 `$2` 脚本参数导致任意文件写入。完整攻击链：不可信输入 `$2` → 用于输出重定向（如 `> $2` 或 `>> $2`）→ 写入或覆盖指定文件路径。触发条件：脚本被调用时提供 `$2` 参数（例如，作为输出文件）。可利用性分析：如果攻击者能控制 `$2` 的值（如设置为 `/etc/passwd`），并且脚本有写权限，可导致文件覆盖、数据破坏或后门部署。
- **Code Snippet:**
  ```
  push_na_rule > $2
  ```
- **Keywords:** $2
- **Notes:** 证据来自脚本内容；风险取决于 `$2` 的控制范围和脚本权限。建议对 `$2` 进行路径验证和限制写入目录。

---
### config-afpd-weak-auth

- **File/Directory Path:** `etc/netatalk/afpd.conf`
- **Location:** `afpd.conf: [配置选项 -uamlist 和 -passwdminlen]`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** 在 'afpd.conf' 配置文件中，认证模块列表（-uamlist）包含了 uams_guest.so，该模块允许访客访问，且密码最小长度被设置为0（-passwdminlen 0），这允许空密码。攻击者可以通过 AFP 网络协议发送认证请求，使用访客身份或空密码，绕过正常认证流程，获得未授权访问共享卷的权限。攻击链为：网络输入（AFP 请求） → 认证处理（uams_guest.so 或 uams_passwd.so 与空密码） → 访问共享资源。触发条件是客户端使用访客认证或空密码。可利用性分析：由于配置中缺少强制强认证和启用了无认证访问，攻击者可以轻松利用此漏洞访问敏感文件，如果共享卷配置不当。
- **Code Snippet:**
  ```
  -uamlist uams_guest.so,uams_passwd.so,uams_dhx_passwd.so,uams_randnum.so,uams_dhx.so,uams_dhx2.so -passwdminlen 0
  ```
- **Keywords:** uams_guest.so, uams_passwd.so, /etc/netatalk/afppasswd, /etc/netatalk/AppleVolumes.default
- **Notes:** 此发现基于配置文件内容，建议进一步分析 AppleVolumes.default 和 AppleVolumes.system 文件以评估共享卷的敏感性，并检查代码中认证模块的实现以验证攻击链。没有其他直接可利用的漏洞从本文件中识别出。

---
### Unauthenticated-Redis-Access

- **File/Directory Path:** `etc/appflow/redis.conf`
- **Location:** `redis.conf 配置文件`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** Redis 服务器配置为无密码认证（requirepass 被注释），并在 Unix 域套接字 /var/run/appflow/redis.sock 上监听，权限设置为 755。这允许系统上的任何本地用户连接到 Redis 实例并无需认证执行任意命令。攻击者可以利用此漏洞操纵或删除数据、更改配置，或如果 Redis 与其他系统组件集成，可能升级权限。完整攻击链为：本地用户 -> 连接到 /var/run/appflow/redis.sock -> 发送 Redis 命令 -> 执行危险命令（如 CONFIG SET、FLUSHALL 等）。触发条件为攻击者具有本地系统访问权限。可利用性分析：由于缺少认证和套接字权限宽松，攻击者可以直接利用此漏洞。
- **Code Snippet:**
  ```
  unixsocket /var/run/appflow/redis.sock
  unixsocketperm 755
  # requirepass foobared
  ```
- **Keywords:** Unix 套接字路径: /var/run/appflow/redis.sock
- **Notes:** 此漏洞假设系统存在多用户或其他服务可被利用以获取本地访问权限。建议进一步分析 /var/run/appflow/ 目录的权限以及 Redis 在应用程序中的使用方式，以评估实际风险。

---
### RCE-set_default_max_zone_id

- **File/Directory Path:** `etc/appflow/streamboost.d/11_sbsaved`
- **Location:** `函数 set_default_max_zone_id 中的 '. $STREAMBOOST_USER_CFG' 行`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** 验证确认漏洞存在。攻击链完整：攻击者可通过控制环境变量 STREAMBOOST_USER_CFG（源）指向恶意文件，当脚本执行 set_default_max_zone_id 函数时，使用点命令加载文件（传播），导致任意代码执行（汇聚点）。触发条件：服务以 start 或 boot 动作启动（例如系统启动时），且 Redis 键 'settings:max_zone_id' 不存在。可利用性分析：代码缺少对环境变量值的验证、路径检查或文件内容清理，允许攻击者注入并执行恶意代码。
- **Code Snippet:**
  ```
  set_default_max_zone_id() {
      . $STREAMBOOST_USER_CFG
  
      # note, zone ids are 0-based.
      # default to 3 but override based on system and user config
      local max=3
  
      if [ -n "${max_zone_id}" ]; then
          max="${max_zone_id}"
      elif nss_qdisc_is_installed && [ "${nss_qdisc}" = "yes" ]; then
          max=1
      fi
  
      redis-cli set "settings:max_zone_id" "${max}" >/dev/null
  }
  ```
- **Keywords:** STREAMBOOST_USER_CFG
- **Notes:** 证据来自文件内容分析。假设脚本以提升权限（如 root）运行，且环境变量在启动时可被攻击者控制（例如通过服务配置）。无需进一步验证；攻击链完整且基于实际代码逻辑。

---
### code-execution-set_default_max_zone_id

- **File/Directory Path:** `etc/appflow/streamboost.d/11_sbsaved`
- **Location:** `函数 set_default_max_zone_id 中的 '. $STREAMBOOST_USER_CFG' 行`
- **Risk Score:** 6.5
- **Confidence:** 7.5
- **Description:** 脚本在函数 set_default_max_zone_id 中直接使用环境变量 STREAMBOOST_USER_CFG 来加载文件，而没有进行任何验证或清理。攻击者可以通过控制 STREAMBOOST_USER_CFG 环境变量指向恶意文件，当脚本执行 set_default_max_zone_id 函数时，会加载并执行该文件中的任意代码，导致任意代码执行。攻击链：不可信环境变量（源） -> 文件加载（传播） -> 代码执行（汇聚点）。触发条件：服务启动时（例如通过 start 或 boot 动作），且 Redis 键 'settings:max_zone_id' 不存在。可利用性分析：缺少对环境变量的验证和文件内容的检查，使得攻击者可以注入恶意代码。
- **Code Snippet:**
  ```
  set_default_max_zone_id() {
      . $STREAMBOOST_USER_CFG
  
      # note, zone ids are 0-based.
      # default to 3 but override based on system and user config
      local max=3
  
      if [ -n "${max_zone_id}" ]; then
          max="${max_zone_id}"
      elif nss_qdisc_is_installed && [ "${nss_qdisc}" = "yes" ]; then
          max=1
      fi
  
      redis-cli set "settings:max_zone_id" "${max}" >/dev/null
  }
  ```
- **Keywords:** STREAMBOOST_USER_CFG
- **Notes:** 攻击链在脚本内是完整的，但环境变量 STREAMBOOST_USER_CFG 的实际可控性未验证（例如，是否由远程攻击者或本地用户控制）。建议进一步分析系统启动过程或相关服务以确认环境变量的设置机制。此外，脚本还使用其他环境变量（如 STREAMBOOST_CFGDIR）加载文件，类似漏洞可能存在。

---
### InfoDisclosure-capture_packet.sh

- **File/Directory Path:** `sbin/capture_packet.sh`
- **Location:** `Lines where variables are read from /tmp/ files and used in conditions to execute tcpdump.`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The script 'capture_packet.sh' reads control variables from world-writable files in /tmp/ (/tmp/debug_store_locate and /tmp/wanlan_capture) without sanitization or access controls. This allows an attacker to write to these files and enable unauthorized packet capture by setting wanlan_capture to '1'. The script then executes tcpdump to capture network traffic on interfaces br0 and brwan, storing the output in /tmp/ or USB storage. If the output is in /tmp/ (which is often world-readable), an attacker can read the pcap files to disclose sensitive network traffic. The attack chain is: attacker writes to /tmp/wanlan_capture -> script reads it and runs tcpdump -> pcap files are created in accessible location -> attacker reads pcap files. The trigger condition is the execution of this script with sufficient privileges (likely root) after the files are modified. This is exploitable due to missing input validation and reliance on insecure temporary files.
- **Code Snippet:**
  ```
  store_locate=\`cat /tmp/debug_store_locate\`
  wanlan_capture=\`cat /tmp/wanlan_capture\`
  ...
  if [ "X$wanlan_capture" = "X1" ]; then 
  	if [ "X$store_locate" = "X1" -a "X$dist_path" != "X" ]; then
  		echo "Save capture lan/wan packet in usb storage"
  		mkdir $dist_path/Capture
  		tcpdump -i br0 -s 0 -W 1 -w $dist_path/Capture/lan.pcap -C 100 &
  		tcpdump -i brwan -s 0 -W 1 -w $dist_path/Capture/wan.pcap -C 100 &
  	else
  		echo "Save capture lan/wan packet in SDRAM tmp dir"
  		tcpdump -i br0 -s 0 -W 1 -w /tmp/lan.pcap -C 5 &
  		tcpdump -i brwan  -s 0 -W 1 -w /tmp/wan.pcap -C 5 &
  	fi
  fi
  ```
- **Keywords:** /tmp/debug_store_locate, /tmp/wanlan_capture, store_locate, wanlan_capture, dist_path
- **Notes:** The risk score is moderate because information disclosure is possible, but it requires the script to be executed in a context where /tmp/ is world-readable and the attacker can trigger the script. The confidence is high for the input control issue, but the full exploit chain depends on external factors like script invocation and filesystem permissions. Further analysis should verify how this script is triggered (e.g., cron, service) and the permissions of /tmp/ and USB storage.

---
### NVRAM-iptables-rule-injection

- **File/Directory Path:** `etc/scripts/firewall/ntgr_sw_api.rule`
- **Location:** `In the while loop for both 'start' and 'stop' cases in the script.`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The script 'ntgr_sw_api.rule' dynamically configures iptables rules based on NVRAM variables without any validation or sanitization. An attacker who can set NVRAM variables (e.g., through a web interface or other vulnerability) can exploit this to add or remove arbitrary iptables rules, potentially allowing unauthorized network access or disabling firewall protections. The complete attack chain is: attacker sets malicious NVRAM variable (e.g., ntgr_api_firewall1) -> script reads via 'config get' -> value is split into $1, $2, $3 using 'set' -> used directly in iptables commands (e.g., iptables -I INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT). Trigger condition: the script must be executed with $1 as 'start' or 'stop'. Exploitable due to the lack of input validation, allowing control over firewall rules.
- **Code Snippet:**
  ```
  index=1
  while true
  do
      value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
      [ "x$value" = "x" ] && break || set $value
      [ "x$3" = "xALL" ] && useport="" || useport="yes"
      iptables -I INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
      iptables -I OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
      index=$((index + 1))
  done
  ```
- **Keywords:** ntgr_api_firewall*
- **Notes:** The exploitability hinges on the ability to set NVRAM variables from untrusted sources, which may require analysis of other components (e.g., web interfaces or APIs). No shell command injection is present due to safe parameter usage, but the logic flaw allows arbitrary iptables rule modification. Recommended to verify NVRAM access controls and script execution contexts.

---
### command-injection-qwrap_setup

- **File/Directory Path:** `lib/wifi/qwrap.sh`
- **Location:** `qwrap.sh: [qwrap_setup]`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** 攻击者可以通过修改 UCI 配置中的参数（如 wifi-device 名称或 vif 接口名称）注入恶意命令。当脚本执行时，config_get 获取配置值并用于构建命令参数（如文件路径），由于变量未加引号，如果输入包含 shell 元字符（如分号、& 等），可以在命令执行时注入额外命令，导致任意代码执行。完整攻击链：不可信输入（UCI 配置） -> 数据流（通过 config_get 获取变量） -> 危险操作（wpa_supplicant 或 wrapd 命令执行）。触发条件：当 qwrap_setup 或 qwrap_config 函数被调用时（例如系统启动或配置更改），且配置参数被恶意修改。可利用性分析：变量未加引号，shell 会解析整个命令字符串，允许命令注入。
- **Code Snippet:**
  ```
  wpa_supplicant -P $wrapd_supplicant_pid -g $wpa_supplicant_global_ctrl_iface -B
  wrapd ${iso} -P $wrapd_pid -D $device -c $wrapd_conf_file $wrapd_ifname -p $sta_ifname $wrapd_vma_conf -g $wrapd_ctrl_interface -w $wpa_supplicant_global_ctrl_iface &
  ```
- **Keywords:** UCI 无线配置参数（如 wifi-device 名称、vif 接口名称）, 文件路径（如 /tmp/qwrap_conf_filename）
- **Notes:** 需要进一步验证 UCI 配置是否可通过网络接口（如 HTTP API）修改，以及输入验证机制。建议检查 wrapd 和 wpa_supplicant 二进制对参数的处理。相关文件：UCI 配置文件（如 /etc/config/wireless）。

---
### DoS-uhttpd.sh-stop

- **File/Directory Path:** `www/cgi-bin/uhttpd.sh`
- **Location:** `uhttpd.sh 脚本中的 case 'stop' 分支和 uhttpd_stop 函数`
- **Risk Score:** 6.0
- **Confidence:** 10.0
- **Description:** 攻击者可以通过 HTTP 请求触发 uhttpd.sh 脚本的停止功能，导致拒绝服务。完整攻击链：攻击者发送 HTTP 请求到 /cgi-bin/uhttpd.sh/stop（路径参数 'stop'），Web 服务器执行脚本并传递 'stop' 作为 $1 参数，脚本匹配 case 'stop' 分支，调用 uhttpd_stop 函数，该函数执行 'kill -9 $(pidof uhttpd)' 命令，强制终止 uhttpd 进程。触发条件：uhttpd.sh 可通过 HTTP 访问且缺少认证机制。可利用性分析：缺少访问控制，允许未经认证的用户远程停止服务，易利用。
- **Code Snippet:**
  ```
  case "$1" in
  	stop)
  		uhttpd_stop
  	;;
  ...
  esac
  
  uhttpd_stop()
  {
  	kill -9 $(pidof uhttpd)
  }
  ```
- **Keywords:** /cgi-bin/uhttpd.sh, stop
- **Notes:** 假设 uhttpd.sh 可通过 HTTP 访问且没有认证。建议验证 Web 服务器配置和是否部署了访问控制。其他命令（如 'start' 或 'restart'）可能导致服务中断或冲突，但风险较低。没有证据表明 REALM 变量（从 /module_name 读取）可被利用用于代码执行。

---
### DoS-ath_proc_write

- **File/Directory Path:** `lib/modules/3.4.103/ath_dev.ko`
- **Location:** `sym.ath_proc_write at 0x0803a124`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** A potential denial-of-service (DoS) vulnerability was identified in 'ath_proc_write' due to missing copy_from_user. The function directly passes a user-space buffer pointer to simple_strtoul without copying the data to kernel space first. This violates kernel security practices and can cause a kernel oops or crash if an invalid pointer is provided. The attack chain is: attacker writes to the proc file → kernel accesses user-space memory directly → potential kernel fault leading to DoS. However, the vulnerability is limited to DoS, as there is no evidence of control over the storage pointer (r3) or propagation to dangerous operations like code execution. The function uses safe string conversion with simple_strtoul, and the stored integer may not influence critical kernel state without additional context.
- **Code Snippet:**
  ```
  0x0803a124      mov ip, sp
  0x0803a128      push {r4, r5, fp, ip, lr, pc}
  0x0803a12c      sub fp, ip, 4
  0x0803a130      mov r5, r2
  0x0803a134      mov r0, r1  ; User-space pointer passed directly
  0x0803a138      mov r2, 0xa
  0x0803a13c      mov r1, 0
  0x0803a140      mov r4, r3
  0x0803a144      bl simple_strtoul  ; Direct access to user memory
  0x0803a148      str r0, [r4]  ; Store result to kernel memory
  0x0803a14c      mov r0, r5
  0x0803a150      ldm sp, {r4, r5, fp, sp, pc}
  ```
- **Keywords:** proc_file_write_handler
- **Notes:** This finding is based on static code analysis. Exploitation for DoS is feasible, but further context (e.g., proc file name and caller) is needed to assess broader impact. The function may be part of Atheros driver proc operations, and dynamic testing could validate the DoS scenario.

---
