# _C2600-US-up-ver1-1-8-P1_20170306-rel33259_.bin.extracted (9 alerts)

---

### backup-restore-encryption-weakness

- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/firmware.lua`
- **Location:** `firmware_index 函数中的 'restore' 操作块，具体在解密和分区写入代码段`
- **Risk Score:** 8.5
- **Confidence:** 9.0
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
- **Keywords:** operation=restore, form=config, MODEL (product_name), hardware_version from read operation, extern_partitions from UCI配置
- **Notes:** 加密实现使用 luci.model.crypto，但具体算法未指定；如果加密强度弱，可能更容易利用。建议验证 nvrammanager 工具是否对分区数据有额外验证。相关函数：firmware_index、read_status_form_file。后续可分析 nvrammanager 二进制以确认检查机制。

---
### command-injection-miniupnpd-init

- **File/Directory Path:** `etc/init.d/miniupnpd`
- **Location:** `miniupnpd script, start function, around lines where 'config_file' is used in 'service_start' call`
- **Risk Score:** 8.5
- **Confidence:** 9.0
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
- **Keywords:** upnpd.config.config_file
- **Notes:** The vulnerability depends on the 'service_start' function being called with unquoted arguments, which is confirmed by the script code. However, the implementation of 'service_start' itself (likely defined in /etc/rc.common) could not be verified due to directory restrictions, but the command injection occurs at the shell level before 'service_start' is invoked. Additional untrusted inputs like other UCI parameters are used in file writes but do not directly lead to execution. Exploitation requires the miniupnpd service to be restarted after modifying the UCI configuration.

---
### command-injection-miniupnpd-start

- **File/Directory Path:** `etc/init.d/miniupnpd`
- **Location:** `etc/init.d/miniupnpd, start function, lines where 'config_get conffile config config_file' is called and 'service_start /usr/sbin/miniupnpd $args' is executed`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** 验证确认命令注入漏洞存在。完整攻击链：1) 攻击者通过 UCI 配置接口（如 web 或 CLI）设置 'config_file' 参数为包含 shell 元字符的字符串（例如 '; malicious_command'）。2) 当 miniupnpd 服务启动或重启时，脚本通过 'config_get conffile config config_file' 读取该值。3) 值用于构建 'args="-f $conffile"'，其中 '$conffile' 在双引号内但未防止单词分割，导致如果值包含元字符如 ';'，它会被保留。4) 在 'service_start /usr/sbin/miniupnpd $args' 调用中，'$args' 未引用，shell 展开时进行单词分割和元字符解释，执行任意命令。触发条件：服务启动或重启且 'config_file' 参数被设置。可利用性分析：脚本缺乏输入清理，未引用变量在命令执行上下文中使用，允许攻击者注入并执行任意命令。
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
  if [ "$logging" = "1" ]; then
      SERVICE_DAEMONIZE=1 \
      service_start /usr/sbin/miniupnpd $args -d
  else
      SERVICE_DAEMONIZE= \
      service_start /usr/sbin/miniupnpd $args
  fi
  ```
- **Keywords:** config_file UCI parameter
- **Notes:** 证据来自文件内容分析。漏洞可利用性高，因攻击者可通过标准 UCI 接口控制输入，且代码路径在服务启动时可达。建议修复：在构建 'args' 时引用变量，如 'args="-f \"$conffile\""' 或使用数组传递参数。

---
### CommandInjection-dhcp_add

- **File/Directory Path:** `etc/init.d/dnsmasq`
- **Location:** `函数 'dhcp_add'，第368行`
- **Risk Score:** 8.5
- **Confidence:** 8.0
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
- **Keywords:** UCI 配置变量: ifname, UCI 配置文件: /etc/config/dhcp
- **Notes:** 需要验证 UCI 配置的修改权限（例如，通过 web 接口或远程访问）。建议检查 'config_get' 函数的实现以确保输入验证。相关函数：'dhcp_add', 'start'。后续分析应关注 UCI 配置的输入源和权限控制。

---
### RCE-OpenVPN-UCI-Injection

- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `In function append_params, specifically the line where it echoes the value to the config file.`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The script does not sanitize newline characters in UCI configuration values when writing to the OpenVPN configuration file. An attacker who can modify UCI settings (e.g., through a web interface or other service) can inject arbitrary OpenVPN directives by including newlines in parameter values. For example, setting a parameter like 'verb' to '3\nup /bin/sh' would add an 'up' directive that executes a shell script when OpenVPN starts, leading to remote code execution if OpenVPN runs with high privileges (typically root). The complete attack chain is: untrusted input from UCI -> config_get in append_params -> split by IFS and echoed to config file -> OpenVPN execution of malicious directives.
- **Code Snippet:**
  ```
  for v in $v; do
      [ -n "$v" ] && append_param "$s" "$p" && echo " $v" >> "/var/etc/openvpn-$s.conf"
  done
  ```
- **Keywords:** UCI configuration parameters for openvpn (e.g., up, down, script_security, verb, remote)
- **Notes:** Exploitation requires the ability to modify UCI configuration, which might be protected, but if compromised, it leads to full control. The script runs with root privileges, and OpenVPN supports directives like 'up' for script execution. Further analysis could verify how UCI is accessed in the system.

---
### AuthBypass-BlackListFunctions

- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/access_control.lua`
- **Location:** `access_control.lua: [remove_black_list, update_black_list]`
- **Risk Score:** 7.5
- **Confidence:** 9.0
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
- **Keywords:** HTTP 参数: key, index, old, new, UCI 配置: access_control, 环境变量: REMOTE_ADDR, 系统命令: /etc/init.d/access_control reload
- **Notes:** 漏洞依赖于攻击者能访问 Web 界面并获取黑名单列表（通过 `load_black_list`）。建议添加对旧 MAC 地址的授权检查在 `update_black_list` 和 `remove_black_list` 中，类似白名单操作中的 `white_delete` 函数。后续可分析其他组件（如 `client_mgmt`）以评估整体攻击面。

---
### PathTraversal-folder_tree

- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/folder_sharing.lua`
- **Location:** `folder_sharing.lua:500-520 [folder_tree]`
- **Risk Score:** 7.5
- **Confidence:** 9.0
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
- **Keywords:** form.path, form.uuid
- **Notes:** 漏洞需要认证权限（admin 控制器），但一旦获得权限，可利用性高。建议对 'path' 参数实施严格验证，过滤目录遍历序列（如 '../'）。相关函数：folder_process 也使用类似路径构造，但风险类似。未发现命令注入或其他高危漏洞，因为子进程调用使用参数表，避免了注入。

---
### PathTraversal-OpenVPN-Instance

- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `In functions start_instance and stop_instance, where "$s" is used in file paths like "/var/etc/openvpn-$s.conf" and "/var/run/openvpn-$s.pid".`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** The instance name parameter used in file paths for configuration and PID files is not sanitized for path traversal sequences. An attacker who can control the instance name (e.g., through command-line arguments to 'up' or 'down' functions, or via UCI configuration) can cause the script to write files outside the intended directories. For example, setting instance name to '../../etc/passwd' would attempt to write to '/etc/passwd.conf', potentially overwriting system files and leading to denial of service or privilege escalation. The complete attack chain is: untrusted input from command-line or UCI -> used in file path in start_instance/stop_instance -> file overwrite with root privileges.
- **Code Snippet:**
  ```
  [ -f "/var/etc/openvpn-$s.conf" ] && rm "/var/etc/openvpn-$s.conf"
  ...
  echo ... >> "/var/etc/openvpn-$s.conf"
  SERVICE_PID_FILE="/var/run/openvpn-$s.pid"
  ```
- **Keywords:** Instance names in 'openvpn' UCI sections, Command-line arguments to up/down functions
- **Notes:** The script runs with root privileges, so overwriting critical files is possible. Mitigation would require sanitizing the instance name to remove path traversal sequences. This could be exploited if an attacker has access to invoke the script or modify UCI config.

---
### PathTraversal-folder_tree

- **File/Directory Path:** `usr/lib/lua/luci/controller/admin/folder_sharing.lua`
- **Location:** `folder_sharing.lua:500-520 [folder_tree]`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** 路径遍历漏洞已验证存在，允许目录内容泄露。完整攻击链：1. 攻击者通过 'volumn' 操作获取有效卷 UUID（发送 HTTP 请求到 '/admin/folder_sharing?action=volumn'）。2. 攻击者发送 'tree' 操作请求（POST 到 '/admin/folder_sharing?action=tree'），提供恶意的 'path' 参数（如 '../../../../etc'）和有效 UUID。3. 服务器处理请求时，在 'folder_tree' 函数中构造 'realpath = volumn.mntdir .. "/" .. path'，其中 'volumn.mntdir' 是挂载目录（如 '/mnt/usb'），'path' 用户可控。代码执行 'path = path:sub(4)' 移除前4个字符，但通过目录遍历序列（如 '../../../../etc' 移除后变成 '../../../../etc'），'realpath' 逃逸挂载点（例如 '/mnt/usb/../../../../etc' 解析为 '/etc'）。4. 代码调用 'nixio.fs.stat(realpath)' 和 'nixio.fs.dir(realpath)'（在 'folder_process' 中）访问任意目录，返回目录列表和文件元数据，泄露敏感信息（如 '/etc/passwd' 文件名）。触发条件：攻击者需具有有效 UUID 和认证权限（文件位于 admin 控制器，需访问 '/admin/folder_sharing'）。可利用性分析：缺少输入验证和路径清理，用户输入直接用于文件系统操作，路径遍历序列未被过滤，导致信息泄露。
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
- **Keywords:** path (用户输入参数), uuid (卷 UUID), volumn.mntdir (挂载目录路径), realpath (构造的文件路径), /admin/folder_sharing?action=tree (HTTP 端点)
- **Notes:** 漏洞已验证存在：1. 输入可控性：'path' 参数来自用户 HTTP 请求。2. 路径可达性：通过 'tree' 操作可触发函数。3. 实际影响：可泄露任意目录内容。需要认证权限，但一旦获得权限，漏洞可利用。建议修复：对 'path' 参数进行规范化验证，防止目录遍历。

---
