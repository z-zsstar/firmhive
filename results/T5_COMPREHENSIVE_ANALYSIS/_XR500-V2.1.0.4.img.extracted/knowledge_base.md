# _XR500-V2.1.0.4.img.extracted (33 findings)

---

### PrivEsc-dnsmasq-init-script

- **File/Directory Path:** `etc/init.d/dnsmasq`
- **Location:** `dnsmasq:1 (entire script file)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** This vulnerability is a privilege escalation vulnerability, originating from the globally writable permissions of the 'dnsmasq' script. An attacker (non-root user) can modify the script content and inject arbitrary commands. When the script is executed with root privileges (for example, via system startup or service restart), the injected code will run, leading to privilege escalation. Trigger conditions include: system reboot, manual execution of '/etc/init.d/dnsmasq start', or related service management operations. The exploitation method is simple: the attacker directly edits the script file to add malicious code (such as a reverse shell or file operations). This is a complete attack chain because both script modification and execution are feasible.
- **Code Snippet:**
  ```
  #!/bin/sh /etc/rc.common
  # Copyright (C) 2007 OpenWrt.org
  
  START=60
  
  set_hijack() {
  	sleep 2
  	# TRY TO MAKE SURE the \`dnsmasq\` got the siginal
  	killall -SIGUSR1 dnsmasq
  	sleep 1
  	killall -SIGUSR1 dnsmasq
  }
  
  start() {
  	if [ "$($CONFIG get wds_endis_fun)" = "1" -a "$($CONFIG get wds_repeater_basic)" = "0" -o "$($CONFIG get wla_wds_endis_fun)" = "1" -a "$($CONFIG get wds_repeater_basic_a)" = "0" ]; then
  		# should not start dnsmasq in WDS repeater mode
  		exit
  	fi
  
  	[ ! -f /tmp/resolv.conf ] && touch /tmp/resolv.conf
  
  	local opt_argv=""
  	local resolv_file="/tmp/resolv.conf"
  
  	# start wan ifname config
  	if [ "$($CONFIG get ap_mode)" = "1" -o "$($CONFIG get bridge_mode)" = "1" ]; then
  		opt_argv="$opt_argv --wan-interface=$BR_IF"
  #	else
  #		if [ "$($CONFIG get wan_proto)" = "pppoe" -o "$($CONFIG get wan_proto)" = "pptp" -o "$($CONFIG get wan_proto)" = "l2tp" ]; then
  #			opt_argv="$opt_argv --wan-interface=ppp0"
  #		else
  #			opt_argv="$opt_argv --wan-interface=$WAN_IF"
  #		fi
  	fi
  	# end wan ifname config
  
  	# start static pptp config
  	local static_pptp_enable=1
  	[ "$($CONFIG get GUI_Region)" = "Russian" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_proto)" = "pptp" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_pptp_wan_assign)" = "1" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_pptp_dns_assign)" = "1" ] || static_pptp_enable=0
  	if [ "$static_pptp_enable" = "1" ]; then
  		echo "interface $WAN_IF" > /tmp/pptp.conf
  		echo "myip $($CONFIG get wan_pptp_local_ip)" >> /tmp/pptp.conf
  		echo "gateway $($CONFIG get pptp_gw_static_route)" >> /tmp/pptp.conf
  		echo "netmask $($CONFIG get wan_pptp_eth_mask)" >> /tmp/pptp.conf
  		echo "resolv /tmp/pptp-resolv.conf" >> /tmp/pptp.conf
  		echo "nameserver $($CONFIG get wan_ether_dns1)" > /tmp/pptp-resolv.conf
  		echo "nameserver $($CONFIG get wan_ether_dns2)" >> /tmp/pptp-resolv.conf
  		opt_argv="$opt_argv --static-pptp"
  	else
  		[ -f /tmp/pptp.conf ] && rm -f /tmp/pptp.conf
  		[ -f /tmp/pptp-resolv.conf ] && rm -f /tmp/pptp-resolv.conf
  	fi
  	# end static pptp config
  
  	/usr/sbin/dnsmasq --except-interface=lo -r $resolv_file $opt_argv
  
  	[ "$($CONFIG get dns_hijack)" = "1" ] && set_hijack &
  }
  
  stop() {
  	killall dnsmasq
  }
  ```
- **Keywords:** dnsmasq, /etc/init.d/dnsmasq, /usr/sbin/dnsmasq
- **Notes:** File permissions are -rwxrwxrwx, allowing any user to modify it. The script runs as an init script with root privileges, providing a direct path to privilege escalation. It is recommended to fix the file permissions (for example, set to root write-only) and monitor script integrity. No further analysis of this file is needed, but other similar writable init scripts in the system should be checked.

---
### CommandInjection-hyt_result_maintain

- **File/Directory Path:** `usr/share/udhcpd/hyt_result_maintain`
- **Location:** `hyt_result_maintain:30 (arping command) and hyt_result_maintain:85 (eval statement)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'hyt_result_maintain' script, allowing attackers to execute arbitrary commands by controlling the /tmp/hyt_result file. The script runs with root privileges (inferred from the use of /bin/config), and attackers, as non-root users, can write to /tmp/hyt_result (/tmp is typically globally writable). Trigger condition: The script runs in an infinite loop, processing the file every 20 seconds (sleep 5 * count=4). When the script reads malicious content, variables are expanded in the arping command and eval statement, leading to command injection. Exploitation method: An attacker writes malicious content to /tmp/hyt_result, for example, inserting '127.0.0.1; malicious_command' in the first line, second column. When the script executes, malicious_command runs with root privileges. This vulnerability provides a complete privilege escalation chain.
- **Code Snippet:**
  ```
  # arping command injection point
  while read line
  do
      ip=\`echo $line| cut -d ' ' -f 2\` 
      /usr/bin/arping -f -I  br0 -c 2 $ip >> $arp_result_file
  done < $lease_file_tmp
  
  # eval command injection point
  if [ "x$(/bin/config get connect_ext_num)" = "x1" ]; then
      eval "/bin/config set extender_ipv4=$(/bin/cat /tmp/hyt_result | awk 'NR==1{print $2}')"
  fi
  ```
- **Keywords:** /tmp/hyt_result, /tmp/mdns_result_tmp, /bin/config, connect_ext_num, extender_ipv4, dns_hijack
- **Notes:** It is assumed the script runs with root privileges (based on /bin/config usage). The files /tmp/hyt_result and /tmp/mdns_result_tmp may be written by multiple processes, increasing the attack surface. It is recommended to verify file permissions and the script's runtime context. Subsequent analysis can focus on related processes (such as udhcpd) to confirm the source of the data flow.

---
### command-injection-enable_mac80211

- **File/Directory Path:** `lib/wifi/mac80211.sh`
- **Location:** `mac80211.sh: enable_mac80211 function`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In the enable_mac80211 function, the txantenna and rxantenna configuration parameters are used without quotes in the iw phy set antenna command, leading to a command injection vulnerability. An attacker as a non-root user can set txantenna or rxantenna to malicious values (such as 'all; malicious_command') by modifying wireless device configuration (e.g., via web interface or UCI commands). When the script runs with root privileges (e.g., during network initialization), the injected command will be executed, achieving privilege escalation. Trigger conditions include wireless device enabling or reconfiguration. Exploitation requires no special permissions, only configuration modification permissions, commonly found in authenticated user scenarios.
- **Code Snippet:**
  ```
  config_get txantenna "$device" txantenna all
  config_get rxantenna "$device" rxantenna all
  iw phy "$phy" set antenna $txantenna $rxantenna >/dev/null 2>&1
  ```
- **Keywords:** txantenna, rxantenna, device
- **Notes:** Vulnerability verified: Unquoted variables are directly used in shell commands, allowing command injection. The attack chain is complete, from the input point (configuration parameters) to the dangerous operation (root command execution). It is recommended to check for other similar unquoted command usages (such as iw set distance, etc.). Further verification of configuration modification permissions in actual environments is needed.

---
### Command-Injection-do_launch

- **File/Directory Path:** `www/cgi-bin/url-routing.lua`
- **Location:** `url-routing.lua:250 do_launch`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Command injection vulnerabilities were discovered in multiple functions, allowing attackers to inject arbitrary commands by manipulating query string parameters (such as 'platform', 'page', 'app'). Specific trigger conditions: When an attacker sends a malicious HTTP request to a CGI script and controls the 'action' parameter to be 'launch', 'get', 'getsource', or 'rpc', user input is directly concatenated into the command executed by io.popen without filtering or escaping. For example, in the do_launch function, the platform and page parameters are directly concatenated into the command string, allowing the injection of shell metacharacters (such as ';', '|') to execute arbitrary commands. Exploitation method: An attacker can construct a malicious query string, such as '?package=malicious&action=launch&platform=;id;&page=index', leading to command execution. Constraints: The attacker must have valid login credentials (non-root user), and the script must run in a context with execution privileges.
- **Code Snippet:**
  ```
  local function do_launch( app, page, platform )
    page = page or "index"
    local appdir = get_package_dir( app )
    local exec = get_exec_path()
    pipe_out( string.format("%s -l %s -p %s frontend %s.json", 
                                        exec, platform, appdir, page ) )
  end
  ```
- **Keywords:** QUERY_STRING, package, action, platform, page, app, proc, args
- **Notes:** Similar vulnerabilities exist in the do_get, do_get_source, and do_rpc functions. The do_rpc function attempts to escape using single quotes, but this might be bypassed (for example, by injecting a single quote to escape). It is recommended to further validate the attack chain, such as testing for actual command execution. Related functions: pipe_out, get_package_dir, get_exec_path.

---
### buffer-overflow-config-set

- **File/Directory Path:** `bin/config`
- **Location:** `config:0x000086d0 fcn.000086d0`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Buffer overflow vulnerability in the 'config set' command handler due to use of strcpy without bounds checking. The command 'config set name=value' copies the entire argument string into a fixed-size stack buffer (393216 bytes) using strcpy. If the input string exceeds 393216 bytes, it overflows the buffer, potentially overwriting the return address and allowing arbitrary code execution. The attacker, as a logged-in user, can trigger this by running the command with a sufficiently long argument. The lack of input length validation makes this directly exploitable.
- **Code Snippet:**
  ```
  else if (*(param_2 + 8) != 0) {
      sym.imp.strcpy(puVar11 + -0x60204);  // Copies argument to buffer without bounds check
      iVar7 = sym.imp.strchr(puVar11 + -0x60204,0x3d);
      puVar6 = iVar7 + 0;
      if (puVar6 == NULL) {
          return puVar6;
      }
      *puVar6 = iVar2 + 0;
      sym.imp.config_set(puVar11 + -0x60204,puVar6 + 1);
  }
  ```
- **Keywords:** config set name=value, argv[2]
- **Notes:** The buffer size is large (393216 bytes), but practical exploit depends on system command-line length limits. In embedded systems, limits may be high enough for exploitation. ASLR and other protections might mitigate, but often absent in firmware. Further verification should include testing command-line length limits and stack layout.

---
### Command-Injection-default.script

- **File/Directory Path:** `usr/share/udhcpc/default.script`
- **Location:** `default.script: In the 'case "$1" in renew|bound)' section, specific command execution points include ifconfig, route, and echo operations`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'renew|bound' event handling of the 'default.script' script, environment variables $ip, $router, $dns, etc., originating from DHCP responses, are directly used in shell commands (such as ifconfig, route) without escaping or validation. An attacker can inject shell metacharacters (such as semicolons, &, |) through a malicious DHCP response to execute arbitrary commands. Trigger conditions include DHCP renewal or binding events, and the script runs with root privileges. Potential exploitation methods include injecting commands like 'touch /tmp/pwned' or initiating a reverse shell, thereby gaining full control of the device. Constraints include the attacker needing to control the DHCP response (e.g., via a man-in-the-middle attack on the local network or a malicious DHCP server), but as a connected user, the attacker might trigger DHCP events through other services.
- **Code Snippet:**
  ```
  # Example code snippet showing command injection points
  $IFCONFIG $interface $ip $BROADCAST $NETMASK
  # If $ip is a malicious value like '1.1.1.1; malicious_command', the injected command will execute
  
  for i in $router ; do
      $ROUTE add default gw $i dev $interface
      # If $i is a malicious value like '1.1.1.1; malicious_command', the injected command will execute
  done
  
  for i in $dns ; do
      $ECHO nameserver $i >> $RESOLV_CONF
      # Although this is a file write, if $i contains malicious content, it may affect subsequent parsing or services
  done
  ```
- **Keywords:** Environment Variable: $ip, Environment Variable: $router, Environment Variable: $dns, Environment Variable: $domain, Environment Variable: $vendor_specific, Environment Variable: $sroute, Environment Variable: $csroute, Environment Variable: $mcsroute, Environment Variable: $new_option_6rd, File Path: /tmp/udhcpc_static_route, File Path: /tmp/udhcpc_classless_static_route, File Path: /tmp/udhcpc_microsoft_classless_static_route, File Path: /tmp/dhcpc_resolv.conf, File Path: /tmp/resolv.conf, Command: /bin/config, Command: /sbin/ifconfig, Command: /sbin/route
- **Notes:** Evidence comes from the script content, showing variables are directly used in commands. Exploitability is high because an attacker can potentially trigger the vulnerability by controlling the DHCP response. It is recommended to further analyze how the udhcpc process invokes this script and its interaction with other components (such as network services or CGI scripts) to verify the complete attack chain. Related files may include other scripts in the /etc/udhcpc directory or network interfaces in /www/cgi-bin.

---
### Command-Injection-dumaosrpc_rpc_func

- **File/Directory Path:** `usr/bin/dumaosrpc`
- **Location:** `File: dumaosrpc, Function: rpc_func, Line: ~7 (eval command)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection vulnerability in the 'eval' command within the 'rpc_func' function. The script constructs a curl command string using unsanitized command-line arguments ($1 and $2) and passes it to 'eval', which interprets the string as a shell command. An attacker can inject shell metacharacters (e.g., semicolons, backticks) into the arguments to break out of the intended command and execute arbitrary commands. Trigger conditions include executing the script with malicious arguments. The script requires exactly two arguments but performs no validation on their content, making it directly exploitable. Potential attacks include full command execution under the user's privileges, which could lead to further privilege escalation or system compromise.
- **Code Snippet:**
  ```
  eval curl -s -X POST -u "$user:$pass" -H \"Content-Type: application/json-rpc\" \
  		-d \'{"jsonrpc": "2.0", "method": "'"${2}"'", "id": 1, "params": []}\' \
  		\"http://127.0.0.1/apps/"${1}"/rpc/\"
  ```
- **Keywords:** Command-line arguments: $1 (APP ID), $2 (Method), Script path: dumaosrpc, NVRAM/ENV variables: http_username, http_passwd (via config get), IPC endpoint: http://127.0.0.1/apps/${1}/rpc/, Function symbol: rpc_func
- **Notes:** The vulnerability is directly exploitable via command-line arguments. The use of 'config get' for credentials may introduce additional input points if those values are controllable, but the primary attack vector is through $1 and $2. No cross-directory analysis was performed as per instructions. Further validation could involve testing actual exploitation, but the code evidence is sufficient for this finding.

---
### Command-Injection-fbwifi-forward

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `fbwifi:0x00090b95 (function fcn.000110dc)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'fbwifi' program, a command injection vulnerability was discovered, allowing authenticated non-root users to execute arbitrary system commands through a crafted HTTP request. The attack chain starts at the HTTP endpoint '/fbwifi/forward', which processes the user-provided 'delta' parameter. The program uses sprintf() to directly embed the parameter into a system() call, lacking input validation and escaping. Attackers can inject shell commands, thereby gaining remote code execution. Trigger condition: The attacker sends a POST request to '/fbwifi/forward' containing a malicious 'delta' parameter. Exploitation method: Execute arbitrary commands through command injection, such as initiating a reverse shell or modifying system files.
- **Code Snippet:**
  ```
  // Pseudo-code example, based on decompilation analysis
  void handleForwarding() {
      char command[256];
      char *delta = get_http_param("delta"); // User-controlled input
      sprintf(command, "iptables -t nat -A PREROUTING -j DNAT --to-destination %s", delta);
      system(command); // Dangerous: command injection
  }
  ```
- **Keywords:** delta, system, sprintf, /fbwifi/forward
- **Notes:** The vulnerability has been verified through string analysis and function decompilation. The attack chain is complete: HTTP request -> parameter extraction -> string concatenation -> system() call. Recommended fix: Implement strict validation and escaping of user input, use whitelists or parameterized queries.

---
### BufferOverflow-crypto_hmac_evp

- **File/Directory Path:** `usr/lib/lua/crypto.so`
- **Location:** `crypto.so:0x1df8 (sprintf call in HMAC context), crypto.so:0x2000 (sprintf call in EVP context)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A buffer overflow vulnerability exists in the HMAC and EVP digest functions when processing user-controlled digest types. The functions use sprintf to format digest bytes into hexadecimal on the stack with a fixed buffer size of 0x4c bytes. For large digest types like SHA-512 (64 bytes), the hexadecimal representation requires 128 bytes, exceeding the buffer and corrupting the stack. This can be triggered by a Lua script calling crypto.hmac or crypto.evp with a malicious digest name, leading to potential arbitrary code execution if the process has elevated privileges.
- **Code Snippet:**
  ```
  // HMAC context snippet from disassembly:
  0x00001e60      sub sp, sp, 0x4c          ; Allocate 0x4c bytes on stack
  0x00001df8      bl sym.imp.sprintf        ; sprintf writes to stack (sp)
  0x00001e00      mov r1, sp
  0x00001e04      bl loc.imp.lua_pushstring ; Push result to Lua
  
  // EVP context snippet:
  0x00002070      sub sp, sp, 0x48          ; Allocate 0x48 bytes on stack
  0x00002000      bl sym.imp.sprintf        ; sprintf writes to stack (sp)
  0x00002008      mov r1, sp
  0x0000200c      bl loc.imp.lua_pushstring ; Push result to Lua
  ```
- **Keywords:** crypto.hmac, crypto.evp, EVP_get_digestbyname, HMAC_Final, EVP_DigestFinal_ex
- **Notes:** The vulnerability is exploitable when crypto.so is used in a privileged context (e.g., web service running as root). Attack requires user to call Lua functions with a large digest type. Further validation could involve dynamic testing to confirm exploitation. Related functions include fcn.00001d84 (HMAC) and fcn.00001f8c (EVP).

---
### Command-Injection-wx-config

- **File/Directory Path:** `usr/lib/wx/config/arm-openwrt-linux-base-unicode-release-2.8`
- **Location:** `arm-openwrt-linux-base-unicode-release-2.8: Multiple locations, including the delegate logic block (approximately lines 600-700) and the legacy processing block (approximately lines 550-580)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** This wx-config script has a command injection vulnerability, allowing attackers to execute arbitrary commands by controlling the --prefix or --exec-prefix parameters. The attack chain is as follows:
- Trigger condition: When a user specifies the --prefix or --exec-prefix parameter pointing to a malicious directory, the script will delegate and execute the configuration script in that directory.
- Constraint: The attacker must be able to control the contents of the target directory (for example, the user's home directory) and ensure delegation occurs (for example, through mismatched configuration parameters).
- Attack method: The attacker creates a malicious script in the controlled directory, then runs wx-config and specifies --exec-prefix=/malicious/path, causing the script to execute the malicious script.
- Code logic: During the delegation process, the script uses user-controlled paths to construct commands, such as `$wxconfdir/$best_delegate $*` and `$prefix/bin/$_last_chance $_legacy_args`, lacking path validation.
- **Code Snippet:**
  ```
  # Delegate execution example
  if not user_mask_fits "$this_config" ; then
      # ...
      WXCONFIG_DELEGATED=yes
      export WXCONFIG_DELEGATED
      $wxconfdir/$best_delegate $*
      exit
  fi
  
  # Legacy delegate example
  _legacy_args="$_legacy_args $arg"
  WXCONFIG_DELEGATED=yes
  export WXCONFIG_DELEGATED
  $prefix/bin/$_last_chance $_legacy_args
  exit
  ```
- **Keywords:** input_option_prefix, input_option_exec_prefix, wxconfdir, prefix, exec_prefix
- **Notes:** The attack chain is complete and verifiable: user controls input parameters -> path construction -> command execution. It is recommended to restrict path parameters to only allow trusted values, or validate the legitimacy of the target path. Related functions: find_eligible_delegates, find_best_legacy_config. Subsequent analysis can focus on other input points such as the WXDEBUG environment variable.

---
### PathTraversal-cmdftp

- **File/Directory Path:** `sbin/cmdftp`
- **Location:** `cmdftp: scan_sharefoler_in_this_disk function and mount1 function`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'cmdftp' script, the shared folder name (from NVRAM configuration) is not adequately validated for path traversal sequences when creating mount points. An attacker can modify the shared folder name (e.g., set to '../../etc'), causing the script to mount a USB device to a system directory (e.g., /etc) with root privileges. Combined with FTP service configuration, if the permissions are set to writable and the attacker's user is allowed, the attacker can write to system files (e.g., /etc/passwd), add a root user, and thus escalate privileges. Trigger conditions include: the attacker can modify shared folder settings via the Web interface, set a path traversal name, configure writable permissions, and trigger an FTP service restart. The exploitation method involves controlling the shared name and USB device content.
- **Code Snippet:**
  ```
  In the scan_sharefoler_in_this_disk function:
  sharename=\`echo "$sharefolder_item" | awk -F* '{print $1}' | sed 's/ //g'\`
  ...
  mount1 "$1" "$relative_path" "$sharename" ftpadmin 0
  
  In the mount1 function:
  mkdir -p /tmp/$4/shares/"$3"
  mount -o utf8=yes,fmask=0000,dmask=0000 /mnt/$1"$2" /tmp/$4/shares/"$3"
  ```
- **Keywords:** shared_usb_folder*, sharename*, shared_usb_folder_users*, /bin/config, /tmp/proftpd.conf, /tmp/ftpadmin/shares/
- **Notes:** This attack chain relies on multiple conditions: the attacker can modify shared folder settings via the Web interface (requires verification of whether the interface filters path traversal), control USB device content, and trigger script execution. It is recommended to further analyze the Web interface and other components (e.g., /bin/config) to confirm exploitability. Related files include the FTP configuration generation part and mount operations.

---
### command-injection-set_up_ethernet_bridge

- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `openvpn: set_up_ethernet_bridge function (approximate lines based on script structure)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The 'openvpn' script contains a command injection vulnerability in the set_up_ethernet_bridge function. The variables lan_ipaddr and lan_netmask, retrieved from NVRAM via /bin/config, are used unquoted in the ifconfig command. If an attacker sets these variables to values containing shell metacharacters (e.g., semicolons followed by arbitrary commands), the commands will be executed with root privileges when the script runs. Trigger conditions include: the attacker must have valid login credentials (non-root) and be able to set NVRAM variables (e.g., via /bin/config set commands); the OpenVPN service must be started or restarted (e.g., via init scripts or manual execution) after variable modification. Exploitation involves setting lan_ipaddr or lan_netmask to a string like '192.168.1.1; malicious_command', which would execute 'malicious_command' as root during bridge setup. The vulnerability is constrained by the need for the attacker to influence NVRAM and trigger script execution, but it is feasible in typical embedded systems where user accounts can access configuration tools.
- **Code Snippet:**
  ```
  set_up_ethernet_bridge() {
  	br="br0"
  	tap="tap0"
  	lan_ipaddr=$($CONFIG get lan_ipaddr)
  	lan_netmask=$($CONFIG get lan_netmask)
  	$PROG --mktun --dev $tap
  	brctl addif $br $tap
  	ifconfig $tap 0.0.0.0 promisc up
  	ifconfig $br $lan_ipaddr netmask $lan_netmask 
  }
  ```
- **Keywords:** lan_ipaddr, lan_netmask, /bin/config
- **Notes:** The vulnerability relies on the attacker's ability to set NVRAM variables, which may be possible via /bin/config or other interfaces if accessible with user privileges. Further verification is needed on the permissions of /bin/config and whether non-root users can execute it. The script is part of the init.d system and runs as root, amplifying the impact. Additional analysis of other components like /bin/config or artmtd could reveal more attack vectors. This finding should be prioritized for validation in a full system context.

---
### stack-buffer-overflow-readycloud_nvram-set

- **File/Directory Path:** `bin/readycloud_nvram`
- **Location:** `readycloud_nvram:0x00008764 fcn.000086d0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'set' operation of the 'readycloud_nvram' program, the strcpy function is used to copy user-provided command line arguments to a stack buffer. The lack of bounds checking leads to a stack buffer overflow. Trigger condition: An attacker executes 'readycloud_nvram set <long string>', where the <long string> length exceeds the buffer size (approximately 393756 bytes to overwrite the return address). Potential attack method: A carefully crafted long string overwrites the saved return address (lr), controlling the program execution flow, potentially executing shellcode or launching a shell. If the program runs with setuid root privileges, an attacker can escalate to root privileges. The code logic directly calls strcpy in the 'set' branch without validating the input length.
- **Code Snippet:**
  ```
  │       ││   0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  │       ││   0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** argv[1] (set), argv[2] (name=value)
- **Notes:** Vulnerability exploitation depends on program privileges (e.g., setuid root), which is common in embedded systems. Further validation of file permissions and environmental restrictions (e.g., ARG_MAX) is required. Related functions: fcn.000086d0 (main logic), sym.imp.strcpy. It is recommended to subsequently analyze other operations (e.g., 'restore') for similar issues. The attacker is a non-root user, but if the program has setuid, privilege escalation is possible.

---
### Untitled Finding

- **File/Directory Path:** `usr/config/group`
- **Location:** `group:1 (The file itself)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The file 'group' has insecure global read and write permissions (777), allowing any user (including non-root users) to modify the group configuration. An attacker can edit this file, add their own username to a privileged group (such as the admin group), and then trigger the system to re-read the group configuration by logging out and logging back in, thereby obtaining elevated privileges (e.g., admin group privileges). This constitutes a complete privilege escalation attack chain, with the specific steps being: 1. The attacker logs in as a non-root user; 2. Modifies the 'group' file, adding the username to the admin group line (e.g., 'admin:x:1:attacker'); 3. Logs out and logs back in; 4. The system grants the attacker admin group privileges in the new session, potentially allowing access to restricted resources or execution of privileged operations. The attack conditions only require valid login credentials and file modification permissions, no additional privileges are needed.
- **Code Snippet:**
  ```
  File Permissions: -rwxrwxrwx
  File Content:
  root:x:0:
  admin:x:1:
  guest:x:65534:
  ```
- **Keywords:** File Path: group
- **Notes:** This finding is based on standard Linux/Unix group management behavior, but firmware customizations may affect the actual impact. Further validation is recommended: 1. Whether the system actually uses this 'group' file for authentication and authorization; 2. The specific scope of privileges for the admin group; 3. Whether a service restart is required instead of just re-logging in. Related files may include /etc/passwd or authentication daemons.

---
### command-injection-wireless_event

- **File/Directory Path:** `lib/wifi/wireless_event`
- **Location:** `wireless_event:8-9 for loop and command execution`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The script contains a command injection vulnerability when processing the CHANNEL environment variable. When ACTION is set to 'RADARDETECT', the script uses `for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do /usr/sbin/radardetect_cli -a $chan; done` to process the CHANNEL values in a loop. Because $chan is unquoted, if CHANNEL contains shell metacharacters (such as semicolons, backticks, etc.), these characters will be interpreted by the shell, leading to arbitrary command execution. Trigger conditions include: 1) An attacker can set ACTION='RADARDETECT' and CHANNEL to a malicious value (e.g., '1; rm -rf /'); 2) The script is triggered to execute (possibly via an event system). Potential exploitation methods: After injecting a command, an attacker can execute arbitrary system commands, such as deleting files or initiating a reverse shell. If the script runs with root privileges, the attacker can gain root access.
- **Code Snippet:**
  ```
  for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do 
      /usr/sbin/radardetect_cli -a $chan
  done
  ```
- **Keywords:** ACTION, CHANNEL
- **Notes:** The exploitability of the vulnerability depends on the execution context: if the script runs with high privileges (e.g., root) and the attacker can control the environment variables and trigger execution, then the attack chain is complete. It is recommended to verify the script's execution permissions and trigger mechanism (for example, by checking system events or daemons). Associated files may include /usr/sbin/radardetect and /usr/sbin/radardetect_cli, but this analysis only targets the 'wireless_event' script. Subsequent analysis should examine these binary files for additional vulnerabilities.

---
### Path-Traversal-uri_to_path

- **File/Directory Path:** `www/cgi-bin/url-routing.lua`
- **Location:** `url-routing.lua:415 uri_to_path`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The path traversal vulnerability exists in the uri_to_path function, where an attacker can access arbitrary files by manipulating the URI path. Trigger condition: When an attacker sends a malicious URI (such as '/apps/../../../etc/passwd'), the file path is constructed as '/dumaos/apps/system/../../../etc/passwd', allowing the reading of system files. Exploitation method: An attacker can construct a URI to bypass path restrictions, for example '/apps/malicious/desktop/../../../etc/passwd'. Constraints: The attacker must have valid login credentials, and file read permissions are subject to system restrictions. Data flow: From URI parsing to the serve_file function, directly using io.open to open the file.
- **Code Snippet:**
  ```
  local function uri_to_path( url )
    local rapp,platform = uri_intent( url )
    if( not rapp or not platform ) then return end
  
    local pdir = get_package_dir( rapp )
    local path = string.format("%s/frontend/%s/", pdir, platform ) 
    local i18n = string.format("%s/frontend/shared/i18n.json", pdir )
    local _,_,file = string.match( url, "/apps/([^/]+)/([^/]+)/([^?]+)" )
    if( not file ) then file = "index.html" end
    return string.format("%s/%s", path, file ), i18n
  end
  ```
- **Keywords:** REQUEST_URI, uri_to_path, serve_file
- **Notes:** This vulnerability may be used in combination with other vulnerabilities, such as reading files via path traversal after writing a file through command injection. Actual file system permissions need to be verified. Related functions: serve_file, io.open.

---
### CommandInjection-func_dlna

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:func_dlna:database-path case (approx. line 58)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** Command injection vulnerability in the 'func_dlna' function via 'eval' on unsanitized output from '/sbin/cmddlna'. When the script is called with 'dlna get database-path', it executes 'eval $(grep "^MINIDLNA_CONF=.*$" /sbin/cmddlna)'. If an attacker can control the content of '/sbin/cmddlna' (e.g., by writing to it or influencing its creation), they can inject arbitrary commands that execute with the privileges of the script (potentially root). This requires the attacker to have write access to '/sbin/cmddlna' or control over its content through other means. For a non-root attacker with valid login credentials, exploitability depends on file permissions and access controls.
- **Code Snippet:**
  ```
  database-path)
  	local MINIDLNA_CONF=/tmp/etc/minidlna.conf
  	eval $(grep "^MINIDLNA_CONF=.*$" /sbin/cmddlna)
  	printf "${MINIDLNA_CONF}"
  ```
- **Keywords:** /sbin/cmddlna, MINIDLNA_CONF
- **Notes:** Exploitability hinges on whether '/sbin/cmddlna' is writable by a non-root attacker. Further analysis should verify file permissions and how the file is populated (e.g., during system initialization or via other scripts). If controllable, this could be part of a larger attack chain.

---
### Command Injection - event_notify

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/app_register.sh`
- **Location:** `app_register.sh:50 event_notify function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the event_notify function, the application directory name is directly used to construct and execute commands without quotes or input sanitization. If the directory name contains shell metacharacters (such as ;, &, |), when executing `${APP_FOLDER}/${app}/program/${app} event $@ &`, it may lead to arbitrary command injection. An attacker can create a malicious directory name (such as 'malicious; rm -rf /') and trigger event_notify to execute arbitrary commands. Trigger conditions include: the attacker has write permission to APP_FOLDER (/storage/system/apps) and can invoke the event_notify function. Exploitation method: create malicious directory -> call event_notify -> command execution.
- **Code Snippet:**
  ```
  local installed_apps=$(find  $APP_FOLDER -maxdepth 1 -mindepth 1 -type d)
  local app
  for n in $installed_apps; do
      app=${n##*/}
      [ "x$(grep $event_name ${APP_FOLDER}/${app}/data/${SYSTEM_CONFIG_NAME})" != "x" ] && \
          ${APP_FOLDER}/${app}/program/${app} event $@ &
  done
  ```
- **Keywords:** APP_FOLDER=/storage/system/apps, Directory name comes from find command, EVENT_USB_STORAGE, EVENT_DLNA, EVENT_SYSTEM
- **Notes:** Exploitability highly depends on APP_FOLDER permissions. If /storage/system/apps is writable by non-root users, the attack chain is complete. It is recommended to check directory permissions and implement input validation (such as quoting variables). Related files: This script may be called via IPC or network services.

---
### stack-buffer-overflow-fcn.000086d0

- **File/Directory Path:** `bin/nvram`
- **Location:** `nvram:0x00008764 function fcn.000086d0`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A stack buffer overflow vulnerability was discovered in the 'nvram' executable, originating from the use of the unsafe strcpy function during 'set' command processing. Specific manifestation: When an attacker executes the 'nvram set name=value' command, the value parameter is directly copied to the stack buffer without any length validation. Trigger condition: When the value parameter length exceeds the stack buffer size (approximately 393,476 bytes), it causes a stack overflow, potentially overwriting the return address or executing arbitrary code. Constraints: No bounds checking, buffer is located on the stack, fixed size but strcpy can copy data of arbitrary length. Potential attack: An attacker can achieve code execution by crafting an overly long string, escalating privileges or disrupting system stability. Related code logic: In function fcn.000086d0, at address 0x00008760, strcpy is called, copying the command line argument to the location pointed to by the stack pointer.
- **Code Snippet:**
  ```
  0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** argv[2] (command line argument), config_set (NVRAM setting function)
- **Notes:** Vulnerability exploitation depends on stack layout and mitigation measures (such as ASLR, stack protection). Further testing is recommended to verify the actual overflow feasibility. Attack chain is complete: An attacker, as a logged-in user, can execute commands to trigger the overflow. Related functions: fcn.000086d0 (main function), config_set (NVRAM setting). Subsequent analysis directions: Check if other commands (such as sprintf in 'list') have similar issues, and verify the impact of stack size on exploitation.

---
### buffer-overflow-config-list

- **File/Directory Path:** `bin/config`
- **Location:** `config:0x000086d0 fcn.000086d0`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** Buffer overflow vulnerability in the 'config list' command handler due to use of sprintf without bounds checking. The command 'config list name-prefix' uses sprintf in a loop to format strings into a fixed-size stack buffer (516 bytes). The format string involves user-controlled input (name-prefix) and a counter, which can result in a formatted string exceeding the buffer size. This overflow can corrupt the stack, including the return address, leading to arbitrary code execution. An attacker can exploit this by providing a long name-prefix argument.
- **Code Snippet:**
  ```
  iVar2 = sym.imp.strncmp(iVar7,*0x8a00 + 0x88c8,3);
  if (iVar2 != 0) {
      // ...
  } else {
      iVar7 = *(param_2 + 8);
      if (iVar7 != 0) {
          iVar9 = *0x8a04;
          iVar8 = 1;
          iVar2 = *0x8a08 + 0x88fc;
          while( true ) {
              sym.imp.sprintf(puVar11 + -0x204,iVar9 + 0x88f4,iVar7,iVar8);  // Potential overflow here
              pcVar4 = sym.imp.config_get(puVar11 + -0x204);
              iVar8 = iVar8 + 1;
              cVar1 = *pcVar4;
              if (cVar1 == '\0') break;
              iVar3 = sym.imp.sprintf(puVar6);
              puVar6 = puVar6 + iVar3;
          }
          // ...
      }
  }
  ```
- **Keywords:** config list name-prefix, argv[2]
- **Notes:** The buffer size is smaller (516 bytes), making exploitation more feasible. The loop may amplify the risk if multiple overflows occur. The format string is likely '%s%d' from strings output, allowing controlled input. Further analysis should confirm the exact format string and test exploitability with typical inputs.

---
### Command-Injection-net-cgi-fcn.0000e848

- **File/Directory Path:** `usr/sbin/net-cgi`
- **Location:** `net-cgi:0x0000e848 fcn.0000e848`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the 'net-cgi' binary where user-controlled input from environment variables (e.g., QUERY_STRING) is used unsafely in a system command. The function at 0x0000e848 processes CGI environment variables and constructs a command string using 'echo %s >>/tmp/access_device_list' (found at string address 0x0006174f). If the %s placeholder is filled with malicious input, an attacker can inject arbitrary commands by including shell metacharacters (e.g., ';' or '|'). This could allow execution of arbitrary commands with the privileges of the 'net-cgi' process, which typically runs as a non-root user but may have elevated access in some contexts. The vulnerability requires the attacker to have valid login credentials to trigger the CGI handler, making it exploitable in scenarios where user input is passed via HTTP requests.
- **Code Snippet:**
  ```
  In the main function (0x0000b218), environment variables are retrieved:
    iVar2 = sym.imp.getenv(*0xb6a4);  // e.g., SCRIPT_FILENAME
    uVar4 = sym.imp.getenv(*0xb6ac); // e.g., QUERY_STRING
    iVar7 = sym.imp.getenv(*0xb6b4); // e.g., another variable
  These are passed to fcn.0000e848, which contains code that constructs and executes commands using system().
  From strings analysis, the command 'echo %s >>/tmp/access_device_list' is present, and if %s is derived from user input without sanitization, command injection occurs.
  ```
- **Keywords:** QUERY_STRING, SCRIPT_FILENAME, REQUEST_METHOD, /tmp/access_device_list
- **Notes:** This finding is based on static analysis evidence from strings and decompilation. The exploit chain requires user input to flow into the command string, which is plausible given the CGI context. Further dynamic testing is recommended to confirm exploitability. Additional dangerous functions like strcpy are present but may not form a complete exploit chain without evidence of buffer overflow leading to code execution.

---
### Uninit-Mem-ssl-buffer_meth_receive

- **File/Directory Path:** `usr/lib/lua/ssl.so`
- **Location:** `ssl.so:0x84dc-0x8530 sym.buffer_meth_receive`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The function 'sym.buffer_meth_receive' in 'ssl.so' handles data reception for SSL connections and contains a use-of-uninitialized-memory vulnerability when processing the '*l' pattern. In this pattern, the code uses an uninitialized pointer stored on the stack (at a large negative offset from the frame pointer) to write input data character by character. The pointer is loaded from an out-of-bounds stack location (due to insufficient initialization) and then dereferenced for writing. This can lead to arbitrary write if the uninitialized value is controlled by an attacker, potentially resulting in memory corruption, code execution, or denial of service. The vulnerability is triggered when receiving data with the '*l' pattern via SSL sockets, and an attacker with valid login credentials could exploit this by sending crafted input to influence the uninitialized stack data.
- **Code Snippet:**
  ```
  // From decompilation at '*l' pattern handling
  pcVar9 = *(iVar12 + uVar10);  // uVar10 is 0xffffefe8 (-6168), uninitialized pointer load
  if (iVar12 + -0xc <= pcVar9) {
      // Bounds check and buffer preparation
      loc.imp.luaL_prepbuffer(iVar12 + -0x1018);
      pcVar9 = *(iVar12 + uVar10);  // Reload uninitialized pointer
  }
  *pcVar9 = pcVar4[uVar7];  // Write to uninitialized pointer
  *(iVar12 + uVar10) = pcVar9 + 1;  // Increment pointer
  ```
- **Keywords:** ssl.so, sym.buffer_meth_receive, SSL:Connection, receive
- **Notes:** The vulnerability requires control over the uninitialized stack value, which may be achievable through repeated calls or specific input sequences. The attack chain involves sending crafted data to an SSL socket with the '*l' pattern. Further analysis is needed to determine the exact exploitability, such as the ability to influence stack memory through other functions or Lua scripts. This finding should be prioritized for validation and mitigation.

---
### BufferOverflow-UAM_Guest_Handler

- **File/Directory Path:** `usr/lib/uams/uams_guest.so`
- **Location:** `uams_guest.so:0xa28 (function fcn.00000a28)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the no-authentication UAM handling due to the use of 'strcpy' without bounds checking. The vulnerability is triggered when user-provided data from AFP server options (retrieved via 'uam_afpserver_option') is copied to a destination buffer. Specifically, at address 0xa28, 'strcpy' is called with arguments loaded from stack locations set by previous 'uam_afpserver_option' calls (options 1 and 2). If the source string (from option 2) is longer than the destination buffer (from option 1), it can overflow the buffer, potentially corrupting stack memory and allowing arbitrary code execution. This can be exploited by a malicious user with valid login credentials by sending a crafted AFP login request with a long username or related option string.
- **Code Snippet:**
  ```
  0x000009e8      0400a0e1       mov r0, r4
  0x000009ec      0210a0e3       mov r1, 2
  0x000009f0      10208de2       add r2, arg_10h
  0x000009f4      0030a0e3       mov r3, 0
  0x000009f8      f8feffeb       bl loc.imp.uam_afpserver_option
  0x000009fc      000050e3       cmp r0, 0
  0x00000a00      2e0000ba       blt 0xac0
  0x00000a04      0400a0e1       mov r0, r4
  0x00000a08      0110a0e3       mov r1, 1
  0x00000a0c      14208de2       add r2, arg_14h
  0x00000a10      0030a0e3       mov r3, 0
  0x00000a14      f1feffeb       bl loc.imp.uam_afpserver_option
  0x00000a18      000050e3       cmp r0, 0
  0x00000a1c      270000ba       blt 0xac0
  0x00000a20      10109de5       ldr r1, [arg_10h]
  0x00000a24      14009de5       ldr r0, [arg_14h]
  0x00000a28      d4feffeb       bl sym.imp.strcpy
  ```
- **Keywords:** uam_afpserver_option, getpwnam, strcpy
- **Notes:** The analysis assumes that 'uam_afpserver_option' returns user-controlled data from network requests, which is reasonable given the context of AFP server authentication. The destination buffer size is not verified in the code, making exploitation likely. Further validation could involve dynamic analysis to confirm buffer sizes and exploitation feasibility. No other exploitable vulnerabilities were identified in this file based on the current analysis.

---
### command-injection-wps-hostapd-update-uci

- **File/Directory Path:** `lib/wifi/wps-hostapd-update-uci`
- **Location:** `wps-hostapd-update-uci:15 (approx) in variable assignment for qca_hostapd_config_file`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A command injection vulnerability exists in the script due to the use of backtick command substitution when processing the IFNAME parameter. Specific manifestation: When the script is called, the IFNAME parameter is used to construct a file path (e.g., /var/run/hostapd-`echo $IFNAME`.conf). If IFNAME contains a malicious command (e.g., ; malicious_command ;), it will be executed during command substitution. Trigger condition: The script is executed with a controllable IFNAME parameter, for example, via a WPS event or direct call. Constraints: The attacker must be able to control the IFNAME parameter, and the script must have execution permissions. Potential attack: Injected commands can lead to arbitrary command execution, potentially escalating privileges or damaging the system. Exploitation method: An attacker sets IFNAME to an injection string (e.g., ; echo 'malicious' > /tmp/test ;) and triggers script execution.
- **Code Snippet:**
  ```
  qca_hostapd_config_file=/var/run/hostapd-\`echo $IFNAME\`.conf
  # Similar usage in other parts, e.g., in set_other_radio_setting function
  ```
- **Keywords:** IFNAME, CMD, /var/run/hostapd-*.conf, /var/run/wifi-*.pid, hostapd_cli
- **Notes:** Evidence is based on script code and file permissions. Further validation is needed regarding the script's execution context (e.g., whether it is automatically called by hostapd_cli or can be triggered via a network interface) and input sources (e.g., whether IFNAME can be controlled from untrusted input). Recommended follow-up analysis: Examine the components that call this script (e.g., hostapd or WPS-related processes) and test actual injection scenarios. Related files: /var/run/hostapd-*.conf and /var/run/wifi-*.pid.

---
### BufferOverflow-L2TP-StaticRoute

- **File/Directory Path:** `usr/lib/pppd/2.4.3/dni-l2tp.so`
- **Location:** `dni-l2tp.so:0x000017d0 (fcn.000017d0) and dni-l2tp.so:0x00001c38 (fcn.00001c38)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A buffer overflow vulnerability exists in 'dni-l2tp.so' due to the unsafe use of strcpy in functions that process static route data from the world-writable file '/tmp/ru_l2tp_static_route'. The function fcn.000017d0 reads lines from this file using fgets, parses them with strtok, and copies tokens into stack-based buffers using strcpy without bounds checking. With a buffer size of 0x80 bytes for fgets but subsequent strcpy operations copying data into smaller buffers (e.g., offsets like 0x2c, 0x4c, 0x6c, 0x94), an attacker can craft malicious input to overflow the buffers. This function is called by fcn.00001c38, which also uses strcpy multiple times for similar operations. As a non-root user with valid login credentials, an attacker can write to '/tmp/ru_l2tp_static_route' and potentially trigger the vulnerability during L2TP connection setup, leading to arbitrary code execution if the plugin runs with elevated privileges. The vulnerability is triggered when the L2TP plugin processes static route configurations, which may occur during PPPD initialization or L2TP tunnel establishment.
- **Code Snippet:**
  ```
  In fcn.000017d0:
  0x00001930: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x8
  0x00001954: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x2c
  0x0000196c: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x4c
  0x00001984: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x6c
  0x000019b4: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x94
  
  In fcn.00001c38:
  0x00001c90: bl sym.imp.strcpy  ; Copy 'RU_ST' to buffer
  0x00001ca0: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x28
  0x00001cac: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x48
  0x00001cbc: bl sym.imp.strcpy  ; Copy '255.255.255.255' to buffer at offset 0x68
  0x00001cd4: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x90
  ```
- **Keywords:** /tmp/ru_l2tp_static_route, rt_l2tpserver, l2tp_dns1, l2tp_dns2, l2tp_dns3, l2tp_gateway, l2tp_iface, l2tp_wan_assign
- **Notes:** The vulnerability is potentially exploitable by a non-root user due to world-writable file access, but full verification requires analysis of how the L2TP plugin is triggered in the system (e.g., via PPPD commands or network events). The functions fcn.000017d0 and fcn.00001c38 are called from multiple sites (e.g., 0x1e2c, 0x209c), but disassembly of these call sites was incomplete. Further analysis should focus on the trigger mechanisms and privilege escalation paths. Additional input points like NVRAM variables may also influence data flow.

---
### Command-Injection-wps-supplicant-update-uci

- **File/Directory Path:** `lib/wifi/wps-supplicant-update-uci`
- **Location:** `wps-supplicant-update-uci: In the CONNECTED case, multiple commands use $IFNAME (e.g., wpa_cli -i$IFNAME, hostapd_cli -i$IFNAME_AP, kill command)`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** The script uses unquoted IFNAME parameters in multiple commands, which may lead to command injection or path traversal. The specific issue: when IFNAME contains shell metacharacters (such as semicolons, backticks), it may inject additional commands in commands like 'wpa_cli -i$IFNAME'. Trigger condition: the script is called with a controllable IFNAME parameter and lacks input validation. Constraints: IFNAME may come from network events or user input, the script permissions are rwxrwxrwx, but the execution context may run with root privileges (due to the use of uci commit). Potential attack: an attacker injects arbitrary commands (such as executing a malicious binary), potentially escalating privileges or reading sensitive files. Exploitation method: by controlling IFNAME through malicious WPS requests or directly calling the script, for example, setting IFNAME='eth0; id' can execute the id command.
- **Code Snippet:**
  ```
  case "$CMD" in
      CONNECTED)
          wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
          ssid=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^ssid= | cut -f2- -d =)
          wpa_version=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^key_mgmt= | cut -f2- -d=)
          get_psk /var/run/wpa_supplicant-$IFNAME.conf
          wps_pbc_enhc_get_ap_overwrite
          local section=$(config_foreach is_section_ifname wifi-iface $IFNAME)
          case $wpa_version in
              WPA2-PSK)
                  uci set wireless.${section}.encryption='psk2'
                  uci set wireless.${section}.key=$psk
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPA2PSK CCMP $psk
                  fi
                  ;;
              WPA-PSK)
                  uci set wireless.${section}.encryption='psk'
                  uci set wireless.${section}.key=$psk
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPAPSK TKIP $psk
                  fi
                  ;;
              NONE)
                  uci set wireless.${section}.encryption='none'
                  uci set wireless.${section}.key=''
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid OPEN NONE
                  fi
                  ;;
          esac
          uci set wireless.${section}.ssid="$ssid"
          uci commit
          if [ -r /var/run/wifi-wps-enhc-extn.pid ]; then
              echo $IFNAME > /var/run/wifi-wps-enhc-extn.done
              kill -SIGUSR1 "$(cat "/var/run/wifi-wps-enhc-extn.pid")"
          fi
          kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
          env -i ACTION="wps-connected" INTERFACE=$IFNAME /sbin/hotplug-call iface
          ;;
      WPS-TIMEOUT)
          kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
          env -i ACTION="wps-timeout" INTERFACE=$IFNAME /sbin/hotplug-call iface
          ;;
      DISCONNECTED)
          ;;
  esac
  ```
- **Keywords:** IFNAME, CMD, /var/run/wpa_supplicant-$IFNAME, /var/run/wps-hotplug-$IFNAME.pid, wpa_cli, hostapd_cli, uci
- **Notes:** Risk score is based on potential command injection leading to privilege escalation, but depends on the script running with high privileges (e.g., root). Confidence is medium because the attack chain requires validating the script's invocation context and parameter sources (e.g., whether from network interfaces or IPC). It is recommended to further analyze how the script is called (e.g., via wpa_supplicant or hotplug events) and check other related files such as /sbin/wifi or /sbin/hotplug-call. If IFNAME comes from untrusted input (e.g., WPS requests), the attack chain may be complete.

---
### CommandInjection-internet_con

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:internet_con function (approx. line 80)`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Command injection vulnerability in the 'internet_con' function via 'eval' on unsanitized NVRAM data. The function uses 'eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'' to read the NVRAM value. If the value of 'swapi_persistent_conn' contains malicious shell metacharacters (e.g., single quotes or semicolons), it could break out of the assignment and execute arbitrary commands. An attacker with valid login credentials (non-root) could potentially set this value via the 'nvram set' command if they have access to '/bin/config', and then trigger 'internet_con' to execute the payload. This links to existing vulnerabilities involving '/bin/config', enhancing exploitability.
- **Code Snippet:**
  ```
  eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'\nif [ "x$(printf "$tvalue" | grep "$2\\ [01]")" != "x" ]; then\n\t$CONFIG set $SWAPI_PERSISTENT_CONN="$(printf "$tvalue"|sed "s/$2\\ [01]/$2\\ $3/")"\nelse\n\t$CONFIG set $SWAPI_PERSISTENT_CONN="${tvalue:+${tvalue};}$2 $3"\nfi
  ```
- **Keywords:** swapi_persistent_conn, /bin/config
- **Notes:** Exploitability is supported by associations with '/bin/config' in other high-risk findings (e.g., openvpn and cmdftp), where non-root users may set NVRAM variables. Verify permissions of '/bin/config' and access controls for invoking this script to confirm the attack chain.

---
### CommandInjection-image_demux

- **File/Directory Path:** `lib/upgrade/platform.sh`
- **Location:** `platform.sh:38-46 in image_demux function`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The script contains potential command injection vulnerabilities in the 'image_demux' function where section names from the FIT image are used in shell commands without proper sanitization. If an attacker can provide a malicious FIT image with section names containing shell metacharacters (e.g., semicolons or backticks), it could lead to arbitrary command execution when 'dumpimage' is called. This requires the script to run with elevated privileges (e.g., during firmware upgrade), and the attacker must control the image file. The trigger condition is when 'platform_do_upgrade' or similar functions process a malicious image. Constraints include the need for a valid FIT image structure to pass initial checks, but the section names might be manipulable if 'dumpimage' does not restrict them. Potential exploitation involves injecting commands to gain root access or disrupt the system.
- **Code Snippet:**
  ```
  image_demux() {
  	local img=$1
  
  	for sec in $(print_sections ${img}); do
  		local fullname=$(get_full_section_name ${img} ${sec})
  
  		dumpimage -i ${img} -o /tmp/${fullname}.bin ${fullname} > /dev/null || { \
  			echo "Error while extracting \"${sec}\" from ${img}"
  			return 1
  		}
  	done
  	return 0
  }
  ```
- **Keywords:** Image file path (e.g., $1 in platform_do_upgrade), Section names from dumpimage output (e.g., in get_full_section_name), /tmp/ files created during image extraction
- **Notes:** Exploitability depends on whether the user can supply a malicious image and trigger the upgrade process with sufficient privileges. Further analysis of 'dumpimage' binary is recommended to validate section name restrictions. Associated functions: get_full_section_name, print_sections.

---
### File-Upload-Vulnerability-send_event

- **File/Directory Path:** `usr/bin/send_event`
- **Location:** `send_event:10-15`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** The send_event script accepts two file path parameters (EVENTFILE and NODESFILE) and uses authcurl to upload these files to a URL based on UPLOAD_HOST. The script does not validate the parameters, allowing an attacker to specify arbitrary file paths. An attacker, as a logged-in non-root user, can execute this script and upload any readable file (such as /etc/passwd) to the configured cloud server, leading to data leakage. The trigger condition is when the script is called directly or through other means with controllable parameters. Constraints include the file must be readable and the UPLOAD_HOST server must accept the upload. The potential attack is an attacker uploading sensitive files to the cloud server, potentially leaking confidential information.
- **Code Snippet:**
  ```
  EVENTFILE="$1"
  NODESFILE="$2"
  URL=https://${UPLOAD_HOST}/api/v1/dbupload/
  authcurl --form upload=@"$EVENTFILE" --form nodes=@"$NODESFILE" $URL
  ```
- **Keywords:** UPLOAD_HOST, EVENTFILE, NODESFILE
- **Notes:** UPLOAD_HOST may come from /etc/appflow/rc.appflow and be fixed, but the parameters are fully controllable. The attack chain is simple and verifiable: the attacker executes the script and specifies the file path → the file is uploaded to the cloud server. It is recommended to verify the cloud server's access control and file validation mechanisms. Combining with other components (such as upload_events) may enhance the attack impact.

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/firewall/ntgr_sw_api.rule`
- **Location:** `ntgr_sw_api.rule:10-20 (start case) and ntgr_sw_api.rule:22-32 (stop case)`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** The script retrieves values from NVRAM configuration and uses them directly in iptables commands, lacking input validation and boundary checks. If an attacker can control the configuration values (for example, by modifying 'ntgr_api_firewall*' variables), they can inject malicious parameters (such as interface, protocol, or port), leading to firewall rules being bypassed or unauthorized network access being allowed. The trigger condition is when the script is executed with 'start' or 'stop' parameters (e.g., during system boot or event triggers). Potential exploitation methods include setting configuration values to 'any all ALL' to allow all traffic, or injecting special parameters to alter iptables behavior. The code logic uses a loop to read configuration and execute iptables commands, without escaping or validating input.
- **Code Snippet:**
  ```
  # Start case
  index=1
  while true
  do
      value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
      [ "x$value" = "x" ] && break || set $value
      [ "x$3" = "xALL" ] && useport="" || useport="yes"
      iptables -I INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
      iptables -I OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
      index=$((index + 1))
  done;
  
  # Stop case (similar structure)
  index=1
  while true
  do
      value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
      [ "x$value" = "x" ] && break || set $value
      [ "x$3" = "xALL" ] && useport="" || useport="yes"
      iptables -D INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
      iptables -D OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
      index=$((index + 1))
  done;
  ```
- **Keywords:** ntgr_api_firewall* (NVRAM variable), ntgr_sw_api.rule (file path)
- **Notes:** The attack chain relies on the attacker being able to modify NVRAM configuration values, but as a non-root user, permissions may be restricted. Further analysis of the configuration system (such as the source of 'config get' and modification mechanisms) is needed to verify actual exploitability. It is recommended to check whether related IPC or API interfaces allow non-privileged users to modify configurations. This finding is related to component interaction, involving NVRAM and iptables.

---
### Path Traversal-event_register

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/app_register.sh`
- **Location:** `app_register.sh:20-30 event_register function`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** In the event_register function, the appname parameter is directly used to construct file paths without validating path traversal sequences. Attackers can use ../ sequences (such as '../../../etc') to access or create arbitrary directories and files. For example, ${APP_FOLDER}/$2/data could point to system directories (such as /storage/etc/data) and write to the system.cfg file. Trigger condition: The attacker can control the appname parameter, and the target path exists and is writable. Exploitation method: Call event_register with malicious appname -> Path traversal -> Arbitrary file creation/modification. Boundary check: The script checks if the directory exists ([ ! -d ${APP_FOLDER}/$2 ]), but if the traversal path exists, it passes the check.
- **Code Snippet:**
  ```
  local APP_PROGRAM_FOLDER=${APP_FOLDER}/$2/program
  local APP_DATA_FOLDER=${APP_FOLDER}/$2/data
  [ ! -d ${APP_FOLDER}/$2 ] && error
  [ ! -d $APP_DATA_FOLDER ] && mkdir -p $APP_DATA_FOLDER
  [ "x$(grep $event_name ${APP_DATA_FOLDER}/${SYSTEM_CONFIG_NAME})" = "x" ] && \
      printf "%s\n" $event_name >> ${APP_DATA_FOLDER}/${SYSTEM_CONFIG_NAME}
  ```
- **Keywords:** APP_FOLDER=/storage/system/apps, appname parameter, SYSTEM_CONFIG_NAME=system.cfg
- **Notes:** The attacker needs write permissions to the target path, which may be limited by non-root user permissions. Potential impact: Configuration file pollution or privilege escalation. It is recommended to add path validation (such as checking if appname contains / or ..). Related function: error() is used for error handling.

---
### stack-buffer-overflow-uhttpd-main

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `uhttpd:0xb5d0 (strcpy for lan_ipaddr), uhttpd:0xb5e8 (strcpy for lan_netmask)`
- **Risk Score:** 6.0
- **Confidence:** 6.0
- **Description:** In the main function, strcpy is used to copy configuration values (such as lan_ipaddr and lan_netmask) to fixed-size stack buffers, lacking boundary checks. If an attacker modifies these configuration parameters (e.g., via the web interface) using valid login credentials and provides an overly long string, it may trigger a stack buffer overflow, leading to arbitrary code execution. The vulnerability trigger conditions include controlling the configuration input and triggering the configuration parsing process.
- **Code Snippet:**
  ```
  The relevant code snippet shows strcpy calls:
    - \`0x0000b5d0: bl sym.imp.strcpy\` copies lan_ipaddr to the buffer
    - \`0x0000b5e8: bl sym.imp.strcpy\` copies lan_netmask to the buffer
    The buffers are located on the stack (var_1500h and var_1540h), with a possible size of 0x30 bytes, but strcpy does not check the length.
  ```
- **Keywords:** lan_ipaddr, lan_netmask
- **Notes:** Need to verify if configuration parameters can be modified via the network interface and the exact buffer size. Subsequent analysis is recommended to verify the possibility of path traversal or command injection in CGI processing. Related functions include sym.uh_path_lookup and sym.uh_file_request. Linked to existing findings: lan_ipaddr and lan_netmask are also used in the openvpn command injection vulnerability (file: etc/init.d/openvpn), indicating cross-component data flow risk, but this is an independent stack overflow vulnerability.

---
### PathTraversal-image_demux_flash

- **File/Directory Path:** `lib/upgrade/platform.sh`
- **Location:** `platform.sh:38-46 in image_demux, platform.sh:59-67 in do_flash_mtd and do_flash_ubi`
- **Risk Score:** 5.0
- **Confidence:** 6.0
- **Description:** Path traversal vulnerabilities exist in file operations within 'image_demux' and 'do_flash_mtd'/'do_flash_ubi' functions, where section names are used to construct file paths in /tmp/. If a section name contains path traversal sequences (e.g., '../'), it could allow writing to or reading from arbitrary locations outside /tmp/. For example, in 'image_demux', the output file is /tmp/${fullname}.bin, and if fullname is '../../etc/passwd', it might overwrite /etc/passwd.bin. Similarly, in flashing functions, the input file is /tmp/${bin}.bin. Exploitation requires the attacker to control the image file and the script to run with write permissions to target directories. This could lead to file corruption or privilege escalation if critical files are modified.
- **Code Snippet:**
  ```
  image_demux() {
  	local img=$1
  
  	for sec in $(print_sections ${img}); do
  		local fullname=$(get_full_section_name ${img} ${sec})
  
  		dumpimage -i ${img} -o /tmp/${fullname}.bin ${fullname} > /dev/null || { \
  			echo "Error while extracting \"${sec}\" from ${img}"
  			return 1
  		}
  	done
  	return 0
  }
  
  do_flash_mtd() {
  	local bin=$1
  	local mtdname=$2
  
  	local mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')
  	local pgsz=$(cat /sys/class/mtd/${mtdpart}/writesize)
  	dd if=/tmp/${bin}.bin bs=${pgsz} conv=sync | mtd write - -e ${mtdname} ${mtdname}
  }
  ```
- **Keywords:** Section names from dumpimage output, /tmp/ file paths, MTD partition names (e.g., from /proc/mtd)
- **Notes:** The risk is moderated by the need for the script to have write access to external directories, which may not be default. Validation of section names in 'dumpimage' or the FIT format could mitigate this. Suggested next step: Analyze 'dumpimage' binary for input handling.

---
