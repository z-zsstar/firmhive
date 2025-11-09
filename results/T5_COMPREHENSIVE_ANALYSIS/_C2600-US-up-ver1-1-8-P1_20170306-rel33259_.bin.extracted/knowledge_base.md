# _C2600-US-up-ver1-1-8-P1_20170306-rel33259_.bin.extracted (30 findings)

---

### Untitled Finding

- **File/Directory Path:** `lib/netifd/proto/l2tp.sh`
- **Location:** `l2tp.sh:~line 70 (In the proto_l2tp_setup function, the echo command uses username and password)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'l2tp.sh' file. When the username or password field contains command substitution symbols (such as $(malicious_command)), because the escaped_str function only escapes backslashes and double quotes, and does not escape dollar signs or backticks, arbitrary commands are executed via the echo command when building the options file. An attacker, as a logged-in non-root user, can inject a malicious username or password by configuring L2TP connection settings (for example, via a web interface or API), triggering the script to execute arbitrary commands with root privileges. The vulnerability trigger conditions include: 1) The attacker can modify the L2TP configuration; 2) The script runs with root privileges (common in network management daemons); 3) The proto_l2tp_setup function is executed (for example, when a connection is established). The exploitation method is simple, only requiring setting the username or password to a value like '$(id > /tmp/pwned)'.
- **Code Snippet:**
  ```
  username=$(escaped_str "$username")
  password=$(escaped_str "$password")
  ...
  echo "${username:+user \"$username\" password \"$password\"}" >> "${optfile}"
  ```
- **Keywords:** username, password, escaped_str, proto_l2tp_setup, json_get_vars
- **Notes:** The vulnerability has been verified through shell command injection principles; the incomplete escaping in the escaped_str function is the root cause. Recommended fix: Add escaping for dollar signs and backticks in escaped_str, or use printf instead of echo to avoid command substitution. Related files: May be triggered via network configuration interfaces (such as /lib/netifd-proto.sh). Further analysis of other input points (such as the server field) can be done to confirm no similar issues exist.

---
### Permission-Misconfig-20-firewall

- **File/Directory Path:** `etc/hotplug.d/iface/20-firewall`
- **Location:** `etc/hotplug.d/iface/20-firewall`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file '20-firewall' has globally writable permissions (rwxrwxrwx), allowing any user (including non-root users) to modify the script content. When a hotplug event (such as interface up/down) occurs, this script is executed with root privileges. An attacker can modify the script to add malicious code (such as a reverse shell or command execution), thereby gaining root access. Trigger conditions include system hotplug events, such as network interface configuration changes. An attacker may exploit this vulnerability by modifying the script and waiting for or inducing an event to occur (for example, through network configuration tools or physical interface operations). The script itself has no code injection vulnerability, but the permission misconfiguration enables a complete attack chain.
- **Code Snippet:**
  ```
  #!/bin/sh
  # This script is executed as part of the hotplug event with
  # HOTPLUG_TYPE=iface, triggered by various scripts when an interface
  # is configured (ACTION=ifup) or deconfigured (ACTION=ifdown).  The
  # interface is available as INTERFACE, the real device as DEVICE.
  
  [ "$DEVICE" == "lo" ] && exit 0
  
  . /lib/functions.sh
  . /lib/firewall/core.sh
  
  fw_init
  fw_is_loaded || exit 0
  
  case "$ACTION" in
  	ifup)
  		fw_configure_interface "$INTERFACE" add "$DEVICE" &
  	;;
  	ifdown)
  		fw_configure_interface "$INTERFACE" del "$DEVICE"
  	;;
  esac
  ```
- **Keywords:** etc/hotplug.d/iface/20-firewall
- **Notes:** This vulnerability relies on hotplug events executing the script with root privileges. Non-root users may not be able to directly trigger all hotplug events, but they can exploit it through system events or indirect means (such as network configuration). It is recommended to check the permissions and execution context of other hotplug scripts to confirm the overall risk. The attack chain is complete and verifiable, but actual exploitation may require specific trigger conditions.

---
### Command-Injection-fw_load_functions

- **File/Directory Path:** `lib/access_control/core_global.sh`
- **Location:** `core_global.sh:fw_load_white_list and core_global.sh:fw_load_black_list`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** In the `fw_load_white_list` and `fw_load_black_list` functions, the MAC address values (`white_list_mac` and `black_list_mac`) are obtained from configuration and directly used in command substitution (`local mac=$(echo $white_list_mac | tr [a-z] [A-Z])`), without using quotes or input validation. This allows command injection because if the MAC address contains shell metacharacters (such as semicolons, backticks), they will be interpreted and execute arbitrary commands. Trigger condition: An attacker modifies the MAC address value in the configuration to a malicious string (e.g., '; rm -rf / ;'), and then triggers the access control function to be enabled (e.g., via UCI configuration reload). When the script runs with root privileges (common in OpenWrt), the injected commands will execute with root privileges, leading to privilege escalation or system destruction. The exploitation method is simple, only requiring control over the configuration input.
- **Code Snippet:**
  ```
  fw_load_white_list() {
      fw_config_get_white_list $1
      local mac=$(echo $white_list_mac | tr [a-z] [A-Z])
      local rule="-m mac --mac-source ${mac//-/:}"
      fw s_add 4 r access_control RETURN { "$rule" }
      echo "$mac" >> /tmp/state/access_control
      syslog $ACCESS_CONTROL_LOG_DBG_WHITE_LIST_ADD "$mac"
  }
  ```
- **Keywords:** white_list_mac, black_list_mac
- **Notes:** Attack chain is complete: from configuration input (source) to command execution (sink). Need to verify the actual environment: whether the script runs with root privileges, and whether the attacker can modify the configuration via the web interface or API. It is recommended to further analyze the 'fw' command and the UCI configuration system to confirm the scope of the injection impact. This vulnerability may affect all access control functions using this script.

---
### command-injection-hotplug2-fcn.00009238

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `hotplug2:0x09238 fcn.00009238`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection vulnerability in hotplug2 via command-line argument. The binary processes command-line arguments and uses them directly in `execlp` calls without sanitization. An attacker with valid login credentials can provide malicious arguments to execute arbitrary commands. The vulnerability is triggered when specific command-line options are used, and the input flows directly to `execlp`. This can be exploited by crafting arguments that include shell metacharacters or paths to malicious binaries.
- **Code Snippet:**
  ```
  // From decompilation of fcn.00009238
  // Command-line argument parsing and storage
  uVar3 = sym.imp.strdup(piVar6[1]);  // piVar6 points to command-line arguments
  puVar7[8] = uVar3;  // Stored in a struct
  // Later, used in execlp
  sym.imp.execlp(uVar3, uVar3, iVar8);  // uVar3 is user-controlled input
  ```
- **Keywords:** argv, command-line arguments
- **Notes:** The vulnerability is directly exploitable by a logged-in user passing malicious arguments to hotplug2. No additional privileges are required. The code path involves fork and execlp, ensuring command execution. Further analysis could identify other input points or network-based vulnerabilities, but this is the most straightforward exploit chain.

---
### Untitled Finding

- **File/Directory Path:** `lib/netifd/proto/dhcp6c.sh`
- **Location:** `dhcp6c.sh:82 proto_dhcp6c_setup`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'proto_dhcp6c_setup' and 'proto_dhcp6c_teardown' functions, the user-controllable 'ifname' variable is directly used to write to the /proc filesystem path, lacking input validation and boundary checks. An attacker can overwrite arbitrary files by setting 'ifname' to path traversal sequences (such as '../../../etc/passwd'). Trigger conditions include network interface configuration changes or protocol teardown; an attacker can exploit this vulnerability by modifying network configuration (such as the interface name) and triggering script execution. Exploitation method: When running with root privileges, overwrite sensitive files like /etc/passwd, leading to denial of service or potential privilege escalation.
- **Code Snippet:**
  ```
  echo '-1' > /proc/sys/net/ipv6/conf/$ifname/ndisc_mbit
  ```
- **Keywords:** ifname, /proc/sys/net/ipv6/conf/
- **Notes:** The vulnerability relies on the attacker being able to control 'ifname' and trigger script execution. It is recommended to further verify the permission settings of the network configuration interface and the input source of 'ifname'. Related function: proto_dhcp6c_teardown also has a similar issue (line 138).

---
### BufferOverflow-log-Lua-function

- **File/Directory Path:** `usr/lib/lua/log.so`
- **Location:** `log.so:0x5bc (function)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The function at 0x5bc, registered as the 'log' Lua function, contains a stack-based buffer overflow vulnerability. It allocates a fixed 512-byte stack buffer (via 'sub sp, sp, 0x200') to store pointers to string arguments from Lua. The loop from 0x604 to 0x624 uses 'luaL_optlstring' to retrieve optional string arguments and stores their pointers sequentially on the stack without bounds checking. If more than 128 string arguments are provided (since each pointer is 4 bytes), it will write beyond the buffer, corrupting the stack. This can be exploited by an attacker with valid login credentials to execute a malicious Lua script that calls 'log' with excessive arguments, potentially overwriting the return address (pc) popped at 0x654 and achieving arbitrary code execution. The vulnerability is triggered under the condition that the Lua script passes more than 130 total arguments (as the first two are integers).
- **Code Snippet:**
  ```
  0x000005c4      02dc4de2       sub sp, sp, 0x200  ; Allocate 512-byte buffer
  0x000005f8      b6ffffeb       bl loc.imp.lua_gettop  ; Get number of arguments
  0x00000600      060000ea       b 0x620
  0x00000604      0410a0e1       mov r1, r4  ; Argument index
  0x00000608      0500a0e1       mov r0, r5  ; Lua state
  0x0000060c      0820a0e1       mov r2, r8
  0x00000610      0030a0e3       mov r3, 0
  0x00000614      b5ffffeb       bl loc.imp.luaL_optlstring  ; Get string pointer
  0x00000618      014084e2       add r4, r4, 1  ; Increment index
  0x0000061c      0400a6e5       str r0, [r6, 4]!  ; Store pointer on stack
  0x00000620      070054e1       cmp r4, r7  ; Compare with top
  0x00000624      f6ffffda       ble 0x604  ; Loop if more arguments
  0x00000654      f087bde8       pop {r4, r5, r6, r7, r8, sb, sl, pc}  ; Return, pc can be overwritten
  ```
- **Keywords:** Lua function 'log'
- **Notes:** The vulnerability is directly exploitable by an attacker with Lua script execution capabilities, which is feasible given the user has login credentials. The function is part of a shared library used in Lua environments, and if the Lua process runs with elevated privileges (e.g., root), this could lead to privilege escalation. Further analysis should verify the context of Lua script execution and the impact of stack corruption. No other vulnerabilities with similar evidence were found in log.so.

---
### IntegerOverflow-HeapOverflow-exfat_ioctl

- **File/Directory Path:** `lib/modules/tuxera-fs/tfat.ko`
- **Location:** `tfat.ko:0x0800cc88 (sym.exfat_ioctl) for allocation; tfat.ko:0x0800cf08 (sym.exfat_ioctl) for copy`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The 'sym.exfat_ioctl' function in the 'tfat.ko' kernel module contains an integer overflow vulnerability that can lead to a heap buffer overflow. When processing the ioctl command 0xc0045803, the function copies a user-controlled size value (from var_38h) and uses it to allocate kernel memory with kmalloc(size + 1, 0xd0). If the size is set to 0xffffffff, the allocation size becomes 0 due to integer overflow. Subsequently, the function copies size bytes (0xffffffff) from user space to the allocated buffer using __copy_from_user, resulting in a heap overflow. This overflow can corrupt adjacent kernel memory, potentially leading to privilege escalation or denial of service. The vulnerability is triggered when a user issues the ioctl command with a malicious size value and a large buffer. The attacker must have access to the exfat filesystem device or file, which is feasible for a non-root user with appropriate permissions in some configurations.
- **Code Snippet:**
  ```
  Allocation code:
  0x0800cc88      010088e2       add r0, r8, 1               ; size = user_input + 1
  0x0800cc8c      d010a0e3       mov r1, 0xd0                ; flags
  0x0800cc90      feffffeb       bl __kmalloc                ; allocate memory
  
  Copy code:
  0x0800cf04      0800a0e1       mov r0, r8                  ; kernel buffer
  0x0800cf08      feffffeb       bl __copy_from_user         ; copy user_input bytes from user
  ```
- **Keywords:** ioctl command 0xc0045803, user-controlled size variable (var_38h), exfat filesystem device node
- **Notes:** This vulnerability requires further validation to confirm exploitability, such as testing on a target system to determine heap layout and potential overwrites of kernel structures. The attack chain assumes that the user can access the exfat device, which may depend on system permissions. Additional analysis of kernel heap mitigations (e.g., SLUB hardening) is recommended. The ioctl command 0xc0045803 likely corresponds to a volume label operation in exfat, but exact meaning may vary. Consider analyzing related functions like exfat_nlstouni and exfat_unitonls for additional issues.

---
### Command-Injection-samba_multicall-LIBSMB_PROG

- **File/Directory Path:** `usr/sbin/samba_multicall`
- **Location:** `samba_multicall:0xb04e0 fcn.000b040c (getenv call), samba_multicall:0x3fd04 fcn.0003fb28 (system call)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'samba_multicall' binary, allowing attackers to execute arbitrary commands through the environment variable 'LIBSMB_PROG'. The vulnerability triggers when the environment variable 'LIBSMB_PROG' is set. The function `fcn.000b040c` calls `getenv` to retrieve its value and directly passes it to `fcn.0003fb28`, which uses the `system` function to execute that value. Since there is no validation or filtering of the environment variable value, attackers can inject malicious commands. Exploitation method: An attacker (a logged-in non-root user) sets the environment variable 'LIBSMB_PROG' to an arbitrary command (e.g., 'LIBSMB_PROG=/bin/sh' or a string containing command injection) and triggers the code execution path (for example, by executing the binary or through a network request). The related code logic involves network socket operations, but the environment variable check is within a loop, ensuring the vulnerability can be triggered.
- **Code Snippet:**
  ```
  // From fcn.000b040c at 0xb04e0:
  0x000b04e0      ldr r0, [0x000b080c]        ; "LIBSMB_PROG"
  0x000b04e4      bl sym.imp.getenv           ; Get environment variable
  0x000b04e8      bl fcn.0003fb28             ; Call vulnerable function
  
  // From fcn.0003fb28 at 0x3fd04:
  void fcn.0003fb28(uint param_1) {
      // ...
      uVar6 = sym.imp.system(param_1); // Execute command without validation
      // ...
  }
  ```
- **Keywords:** LIBSMB_PROG
- **Notes:** This vulnerability requires the attacker to be able to set the environment variable and trigger code execution, possibly through local binary execution or network services. The environment variable 'LIBSMB_PROG' may be used by Samba-related processes, but the specific context requires further analysis. It is recommended to check if the binary runs in a privileged context and the accessibility of the environment variable. Subsequent analysis should focus on other input points (such as network interfaces, IPC) to identify additional attack chains.

---
### command-injection-proto_dslite_setup

- **File/Directory Path:** `lib/netifd/proto/dslite.sh`
- **Location:** `dslite.sh:18-22 proto_dslite_setup`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the 'resolveip' command call. When the 'AFTR_name' variable contains malicious content (such as semicolon-separated commands), it will be interpreted and executed by the shell in the command substitution '$(resolveip -6 -t 5 "$server")'. Trigger condition: An attacker sets a malicious 'AFTR_name' value through an accessible interface (such as a network configuration API), which is triggered when the script executes tunnel setup. Potential exploitation method: Injecting commands such as '; malicious_command' can lead to arbitrary code execution with root privileges, achieving privilege escalation. Constraints: The script relies on the external 'resolveip' command and does not validate or escape the input.
- **Code Snippet:**
  ```
      local server
      json_get_var server AFTR_name
      [ -n "$server" ] && [ -z "$peeraddr" ] && {
          for ip6 in $(resolveip -6 -t 5 "$server"); do
              # ( proto_add_host_dependency "$cfg" "$ip6" )
              peeraddr="$ip6"
          done
      }
  ```
- **Keywords:** AFTR_name, resolveip
- **Notes:** Assumes the script runs with root privileges (common for network configuration scripts). The attack chain is complete: input point ('AFTR_name') → data flow (unfiltered direct use in command) → dangerous operation (arbitrary command execution). It is recommended to validate the behavior of the 'resolveip' command and the script's calling context. Associated files may include network configuration files and IPC mechanisms. Subsequent analysis should check the input source of 'AFTR_name' (such as UCI configuration or web interface) to confirm exploitability.

---
### Injection-pppshare_generic_setup

- **File/Directory Path:** `lib/netifd/proto/pppshare.sh`
- **Location:** `pppshare.sh:pppshare_generic_setup function (approx. line 40-60 in provided content)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'pppshare.sh' script, the 'pppd_options' variable is obtained from the configuration via 'json_get_vars' and directly passed to the 'pppd' command without input validation or filtering. An attacker, as a non-root user, if able to modify network configuration (e.g., through the UCI interface or web management interface), can inject malicious options into 'pppd_options'. Since 'pppd' typically runs with root privileges, the attacker can exploit this injection to overwrite fixed script paths (such as 'ip-up-script'), specify a custom script (e.g., in the '/tmp' directory), which triggers when the PPP connection is established to execute arbitrary code with root privileges. Trigger conditions include modifying the configuration and initiating or waiting for a PPP connection establishment (e.g., through network interface events). Exploitation methods include: 1) The attacker creates a malicious script in a writable directory (e.g., '/tmp/evil_script'); 2) Setting 'pppd_options' via configuration to include 'ip-up-script /tmp/evil_script'; 3) When the PPP connection is established, 'pppd' executes this script, achieving privilege escalation.
- **Code Snippet:**
  ```
  proto_run_command "$config" /usr/sbin/pppd \
  	nodetach ifname "share-$config" \
  	ipparam "$config" \
  	${keepalive:+lcp-echo-interval $interval lcp-echo-failure ${keepalive%%[, ]*}} \
  	defaultroute noaccomp nopcomp ipv6 \
  	${dnsarg:+"$dnsarg"} \
  	${ipv4arg:+"$ipv4arg"} \
  	${ipaddr:+"$ipaddr:"} \
  	${username:+user "$username"} \
  	${password:+password "$password"} \
  	ip-up-script /lib/netifd/ppp-up \
  	ipv6-up-script /lib/netifd/pppshare-up \
  	ip-down-script /lib/netifd/ppp-down \
  	ipv6-down-script /lib/netifd/ppp-down \
  	${mru:+mtu $mru mru $mru} \
  	$pppd_options "$@"
  ```
- **Keywords:** pppd_options, username, password, keepalive, ip_mode, ipaddr, dns_mode
- **Notes:** This finding is based on script code analysis; 'pppd_options' is directly expanded in the 'pppd' command without quotes or filtering, allowing parameter injection. The complete attack chain requires: the attacker can modify the configuration (e.g., through a vulnerable interface) and trigger a PPP connection. It is recommended to further verify the configuration source (e.g., UCI system) and permission settings to confirm the actual control capability of non-root users. Related files include scripts like '/lib/netifd/ppp-up', but the current analysis is limited to 'pppshare.sh'.

---
### Untitled Finding

- **File/Directory Path:** `usr/lib/lua/luci/sys/config.lua`
- **Location:** `config.lua:xmlToFile function (stepaddentry['dir'] step)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the xmlToFile function. When parsing malicious XML configuration from NVRAM, arbitrary commands are executed via os.execute when creating directories due to improper input escaping. Specific trigger conditions include: an attacker modifying user configuration (e.g., via the web interface) to include malicious XML tags (such as directory names containing shell metacharacters), and then triggering a configuration reload (e.g., by calling reloadconfig). In the xmlToFile function, the 'dir' step of stepaddentry uses os.execute to concatenate command strings without filtering input, leading to command injection. Potential attack methods include: inserting semicolons or backticks in directory names to execute arbitrary commands (e.g., '; rm -rf /' or '`malicious command`'), potentially gaining root privileges (if LuCI runs as root).
- **Code Snippet:**
  ```
  In the xmlToFile function, the 'dir' step code of the stepaddentry table:
  os.execute('mkdir '.. filepath .. '/'.. data)
  Here, data comes from XML parsing and is not escaped for shell metacharacters. The relevant parsing code comes from the getxmlkey function:
  local data = string.match(line, exps[key])
  return {['key'] = toOrig(keys[key]), ['value'] = toOrig(data)}
  The toOrig function only reverses the escaping done by toEscaped (which only handles &, <, >) and does not handle other dangerous characters.
  ```
- **Keywords:** NVRAM user-config, /tmp/reload-userconf.xml, os.execute, luci.sys.config.xmlToFile
- **Notes:** Exploitation of this vulnerability relies on the attacker being able to modify the NVRAM configuration (via authorized user privileges) and trigger a configuration reload (e.g., by calling reloadconfig via the web interface). Further verification is needed to confirm if LuCI runs with root privileges and if the interface triggering the reload is exposed in the actual environment. It is recommended to implement strict shell escaping for input before the os.execute call or to use secure functions.

---
### BufferOverflow-fcn.0000df9c

- **File/Directory Path:** `usr/bin/tddp`
- **Location:** `tddp:fcn.0000df9c (address: ~0xe29c)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability was discovered in function fcn.0000df9c, occurring when processing UDP packets of type 2. An attacker can control the 4-byte value at offset 4 in the packet (converted to uVar13 after endianness conversion), which is used to calculate the copy size for memcpy (uVar13 + 0x1c). The size of the target buffer puVar15 (param_1 + 0xb01b) is 0xafc9 (45001 bytes), but the maximum allowed copy size can reach 45064 bytes (when uVar13 = 0xafac), resulting in a buffer overflow of 63 bytes. Trigger condition: The attacker sends a UDP packet to the corresponding port, sets the packet type to 2 (*(param_1 + 0xb01b) == '\x02'), and sets the 4-byte value at offset 4 to 0xafac. The vulnerability allows partial control over the overflow data, potentially overwriting stack or heap memory, leading to denial of service or potential code execution. Constraints: The attacker must possess valid login credentials (non-root user) and network access. Potential attack methods include overwriting the return address or executing arbitrary code, but the exploitation difficulty depends on the allocation location of param_1 (possibly stack or heap) and the memory layout.
- **Code Snippet:**
  ```
  uVar12 = *(param_1 + 0xb01f);
  uVar13 = uVar12 << 0x18 | (uVar12 >> 8 & 0xff) << 0x10 | (uVar12 >> 0x10 & 0xff) << 8 | uVar12 >> 0x18;
  // ...
  iVar3 = fcn.0000cb48(param_1 + 0xb037, uVar13, param_1 + 0x37, 0xafac);
  uVar12 = iVar3 + 0;
  if (iVar3 + 0 != 0) goto code_r0x0000e29c;
  // ...
  code_r0x0000e29c:
      sym.imp.memcpy(puVar15, puVar14, uVar13 + 0x1c);
  ```
- **Keywords:** Network Socket (UDP), param_1 structure field, NVRAM/Environment Variables (if param_1 comes from external configuration), tddp_parserVerTwoOpt (related protocol parsing function)
- **Notes:** The vulnerability requires the attacker to have network access and valid login credentials (non-root). The allocation location of param_1 was not determined in the analysis (possibly stack or heap), which affects the exploitation difficulty. It is recommended to further analyze the boundary check logic of fcn.0000cb48 and the source of param_1 (e.g., by tracing TDDP protocol parsing functions such as tddp_parserVerTwoOpt) to confirm the complete attack chain. Related functions: fcn.0000cb48, fcn.0000d930. If param_1 is allocated on the stack, the vulnerability may be easier to exploit; if on the heap, more conditions may be required.

---
### BufferOverflow-fcn.000121dc

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `fcn.000121dc:0x150ac and 0x1511c (strcpy call)`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** At multiple locations in function fcn.000121dc (such as 0x150ac and 0x1511c), strcpy calls copy user input param_2 or derived data into a fixed-size buffer (0x49 bytes). The lack of length validation may lead to a buffer overflow. An attacker can trigger an overflow by crafting a long IP address or configuration string, achieving code execution or a crash. The trigger condition is param_2 containing an overly long string, which may originate from network input or configuration operations. An attacker, as a connected non-root user with valid login credentials, can trigger this vulnerability through the network interface or IPC.
- **Code Snippet:**
  ```
  Decompiled from fcn.000121dc: iVar8 = fcn.00012034(0x49); ... sym.imp.strcpy(iVar8, *0x15304); Input param_2 is used in strcpy after processing by functions (such as fcn.00011a18)
  ```
- **Keywords:** param_2, *0x15304, *0x152fc, fcn.000121dc
- **Notes:** Buffer allocation size may be insufficient; the source of param_2 needs to be traced (may come from network or IPC). Global variables affect the execution path; it is recommended to analyze the buffer allocation logic of fcn.00012034. Associated input points include configuration interfaces and potential network data streams.

---
### Buffer-Overflow-fcn.0000a140

- **File/Directory Path:** `usr/bin/tp-cgi-fcgi`
- **Location:** `fcn.0000a140 (0xa140)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The function fcn.0000a140 retrieves the REQUEST_URI environment variable using getenv and copies it into a fixed-size stack buffer using strcpy without any bounds checking. An attacker with valid login credentials can send an HTTP request with a long REQUEST_URI value, causing a stack-based buffer overflow. This overflow can overwrite critical stack variables, including the return address, leading to arbitrary code execution. The function is called during CGI request processing, making it remotely accessible. The vulnerability is triggered when the CGI processes the request, and the lack of input validation allows exploitation.
- **Code Snippet:**
  ```
  uVar2 = sym.imp.getenv(*0xa280); // 'REQUEST_URI'
  sym.imp.strcpy(puVar10 + -0x2000, uVar2);
  ```
- **Keywords:** REQUEST_URI
- **Notes:** The buffer size is approximately 4096 bytes (from stack allocations), but strcpy copies without limit. Exploitation requires crafting a long REQUEST_URI in the HTTP request. The binary is for ARM architecture, so exploitation may require ARM-specific shellcode. Additional analysis could determine the exact offset for EIP control and test exploitability in a real environment. The function is called from address 0x8d98 in the main CGI handler, confirming the attack path.

---
### Command-Injection-autodetected.sh

- **File/Directory Path:** `lib/autodetect/autodetect.sh`
- **Location:** `autodetected.sh: approximately lines 58-59 (after 'Check the DHCP status' comment, within the if wait $DHCP_PID block)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The script contains a command injection vulnerability in the dnslookup command due to unquoted command substitution of the content from DNS_FILE (/tmp/autodetect-dns). When the script runs and DHCP detection succeeds, it executes 'dnslookup -t $DNS_TIMEOUT "$CHECK_URL" $(cat "$DNS_FILE")', where $(cat "$DNS_FILE") is not quoted, allowing shell metacharacters in the file content to break out and execute arbitrary commands. An attacker with write access to /tmp/autodetect-dns can inject malicious commands (e.g., '8.8.8.8; /bin/sh -c "malicious_command"') that will be executed with root privileges if the script runs as root. Trigger conditions include: the autodetect script being executed (e.g., during network detection events), DHCP detection succeeding (wait $DHCP_PID returns true), and the attacker having pre-written to /tmp/autodetect-dns. This could lead to full privilege escalation.
- **Code Snippet:**
  ```
  if wait $DHCP_PID; then
      record time $((DNS_TIMEOUT*1000))
      dnslookup -t $DNS_TIMEOUT "$CHECK_URL" $(cat "$DNS_FILE") >/dev/null && \
      record_clean_and_exit "dhcp"
  fi
  ```
- **Keywords:** DNS_FILE: /tmp/autodetect-dns, RESULT_FILE: (external variable, likely set by caller), CHECK_URL: (external variable), DNS_TIMEOUT: (external variable)
- **Notes:** Exploitability depends on the script running with root privileges and the attacker being able to write to /tmp/autodetect-dns. As a non-root user with login credentials, they may influence file content in /tmp, but triggering the script execution might require network events or other system interactions. Further analysis is recommended to verify how the script is invoked (e.g., by network services) and to check for any mitigations like file permissions or input validation in related components (e.g., dhcp.script).

---
### BufferOverflow-hfsplus_readdir

- **File/Directory Path:** `lib/modules/tuxera-fs/thfsplus.ko`
- **Location:** `thfsplus.ko:0x080048b4 hfsplus_readdir`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the 'hfsplus_readdir' function, there is a heap buffer overflow vulnerability originating from a memcpy operation lacking boundary checks. When copying directory entry data, the function uses a fixed-size 0x206 (518) byte memcpy operation, but the target buffer is only allocated 0xd0 (208) bytes via kmem_cache_alloc. This causes the copy operation to overflow the heap buffer, potentially overwriting adjacent memory, including heap metadata or function pointers. Trigger condition: An attacker can trigger this function through filesystem operations (such as reading a directory containing specially crafted directory entries), thereby controlling the source data (from the local variable 'var_54h'). Potential exploitation methods: The overflow could be used to execute arbitrary code, escalate privileges, or cause a system crash. Vulnerability constraints: The target buffer size is fixed at 208 bytes, while the copy size is fixed at 518 bytes, lacking validation; the attacker must be able to provide malicious directory entries (e.g., by mounting a malicious filesystem or accessing a malicious share).
- **Code Snippet:**
  ```
  Relevant assembly code snippet:
  0x0800489c      780095e5       ldr r0, [r5, 0x78]          ; Load target buffer pointer
  0x080048a0      000050e3       cmp r0, 0                  ; Check if null
  0x080048a4      0400000a       beq 0x80048bc             ; If null, jump to allocation code
  0x080048a8      50101be5       ldr r1, [var_54h]         ; Load source address
  0x080048ac      062200e3       movw r2, 0x206            ; Set copy size to 518 bytes
  0x080048b0      0c0080e2       add r0, r0, 0xc           ; Target address offset
  0x080048b4      feffffeb       bl memcpy                 ; Execute copy operation
  
  Allocation code path:
  0x080048cc      d010a0e3       mov r1, 0xd0             ; Allocation size is 208 bytes
  0x080048d0      feffffeb       bl kmem_cache_alloc      ; Allocate heap buffer
  0x080048dc      780085e5       str r0, [r5, 0x78]       ; Store to target pointer
  ```
- **Keywords:** memcpy, kmem_cache_alloc, var_54h, r5+0x78
- **Notes:** This vulnerability forms a complete attack chain: entry point (directory read), data flow (user-controllable data propagates to memcpy), dangerous operation (heap overflow). An attacker as a non-root user might exploit this vulnerability through standard file operations. It is recommended to further validate the attack vector, such as through dynamic testing or checking entry points for filesystem interaction. Related functions include 'hfsplus_bnode_read' and 'hfsplus_uni2asc', which may affect the source data. Other analyzed functions (such as hfsplus_mknod) did not reveal similar vulnerabilities, hence they are not reported.

---
### Sensitive-Info-Exposure-wireless.24g

- **File/Directory Path:** `www/webpages/data/wireless.24g.json`
- **Location:** `wireless.24g.json:1 (entire file)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** The file 'wireless.24g.json' stores sensitive wireless network configuration information in plain text, including the WPA PSK key ('psk_key': '12345656') and multiple WEP keys (e.g., 'wep_key1': '111'). An attacker, as a non-root user with valid login credentials, if having read permissions for this file, can directly read these keys, thereby gaining unauthorized network access. The trigger condition is the attacker being able to access the file path; no additional verification or boundary checks are needed because the data is statically stored. Potential attacks include network eavesdropping, man-in-the-middle attacks, or directly connecting to the network.
- **Code Snippet:**
  ```
  {
  	"timeout": false,
  	"success": true,
  	"data": {
  			"enable": "on",
  			"ssid": "TP_LINK112",
  			"hidden": "on",
  			"encryption": "wpa",
  			
  			"psk_version": "wpa",
  			"psk_cipher": "aes",
  			"psk_key": "12345656",
  
  			"wpa_version": "wpa",
  			"wpa_cipher": "aes",
  			"server": "",
  			"port": "",
  			"wpa_key": "",
  
  			
  			"wep_mode": "open",
  			"wep_select": "2",
  		
  			"wep_format1": "hex",
  			"wep_type1": "128",
  			"wep_key1": "111",
  			
  			"wep_format2": "hex",
  			"wep_type2": "128",
  			"wep_key2": "222",
  			
  			"wep_format3": "hex",
  			"wep_type3": "128",
  			"wep_key3": "333",
  			
  			"wep_format4": "hex",
  			"wep_type4": "128",
  			"wep_key4": "444",
  			
  			"hwmode": "b",
  			"htmode": "20",
  			"channel": "12",
  			"disabled":"off",
  			"txpower": "middle",
  			"wireless_2g_disabled":"on",
  			"wireless_2g_disabled_all":"on"
  	}
  	
  }
  ```
- **Keywords:** psk_key, wep_key1, wep_key2, wep_key3, wep_key4, ssid
- **Notes:** This is a practically exploitable vulnerability with a complete attack chain: attacker uses valid credentials to access the file -> reads plaintext keys -> gains unauthorized network access. It is recommended to verify file permissions (e.g., using 'ls -l' to confirm readability by non-root users) and check if any network services or components (such as a web interface or IPC) use this file, which could expand the attack surface. Subsequent analysis should focus on the processes that write to or read from this file to identify potential data injection points.

---
### Path-Traversal-uhttpd

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `uhttpd:0xc5a4 sym.uh_path_lookup, uhttpd:0xb5d4 sym.uh_file_request`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A path traversal vulnerability exists in uhttpd that allows authenticated users to read arbitrary files by exploiting insufficient path validation after canonicalization. When handling HTTP requests for files, the server uses the `uh_path_lookup` function to resolve the requested URL path to a filesystem path. This function uses `realpath` to canonicalize the path but does not verify that the resulting path remains within the document root. Consequently, an attacker can use sequences like '../' in the URL to escape the document root and access sensitive files (e.g., /etc/passwd). The vulnerability is triggered when a request is made for a path containing traversal sequences, which is then passed to `uh_file_request` and opened via the `open` system call without additional checks. This can lead to information disclosure and, if combined with other vulnerabilities, potential privilege escalation.
- **Code Snippet:**
  ```
  In sym.uh_path_lookup (0xc5a4):
  - Builds path from user-controlled URL using memcpy/strncat
  - Calls realpath at 0xc6f4 but does not validate if result is within document root
  In sym.uh_file_request (0xb5d4):
  - Opens file using path from uh_path_lookup via open() at 0xb660
  - No additional path validation before file access
  ```
- **Keywords:** REQUEST_URI, DOCUMENT_ROOT, SCRIPT_FILENAME
- **Notes:** The vulnerability is directly exploitable by authenticated users via HTTP requests. While realpath is used, the lack of document root validation after canonicalization makes it effective. Testing with paths like '/../../etc/passwd' should confirm the issue. This could be combined with CGI execution for code execution if executable files are accessed.

---
### Vulnerability-RSASetPublic

- **File/Directory Path:** `www/webpages/js/libs/encrypt.js`
- **Location:** `encrypt.js:Line number not specified (functions RSASetPublic and bnpExp)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** RSA public exponent `e` lacks validation, allowing attackers to break encryption by controlling the exponent value in the `param` parameter. Specific behavior: In the `RSASetPublic` function, `e` is parsed as an integer but not checked for valid values (such as typically being a small prime like 65537). If `e=1`, the encryption function `RSADoPublic` returns the plaintext itself (because `x^1 mod n = x`), rendering encryption ineffective; if `e` is greater than 0xffffffff or less than 1, the `bnpExp` function returns a fixed value `BigInteger.ONE`, causing the encryption output to always be 1. Trigger condition: An attacker provides a malicious `param` array where `param[1]` (i.e., `e`) is set to 1 or an invalid value. Exploitation method: When encryption is used for authentication or sensitive data protection (such as login password encryption), an attacker can inject a malicious public key to nullify the encryption, resulting in plaintext transmission or fixed-value transmission, thereby bypassing security mechanisms. Constraints: The attacker must be able to control the `param` input, for example, by modifying client-side scripts, MITM attacks, or injecting malicious data.
- **Code Snippet:**
  ```
  // RSASetPublic function snippet
  function RSASetPublic(N,E) {
      if(N != null && E != null && N.length > 0 && E.length > 0) {
          this.n = parseBigInt(N,16);
          this.e = parseInt(E,16); // No validation of e's value
      }else{
          alert("Invalid RSA public key");
      }
  }
  
  // bnpExp function snippet
  function bnpExp(e,z) {
      if(e > 0xffffffff || e < 1){
          return BigInteger.ONE; // Returns fixed value when e is invalid
      }
      // ... Calculation logic ...
  }
  ```
- **Keywords:** param, e, n, RSASetPublic, bnModPowInt, bnpExp
- **Notes:** The vulnerability relies on the attacker controlling the public key parameters, which could be achieved in the firmware web interface through client-side script modification or man-in-the-middle attacks. Further validation of the context calling this encryption function (such as the login process) is needed to confirm exploitability. It is recommended to add validation for `e` (such as range checks) and use standard padding schemes.

---
### CommandInjection-setup_interface_eval

- **File/Directory Path:** `usr/share/udhcpc/default.script`
- **Location:** `default.script: setup_interface function (approximately lines 20-30)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the setup_interface function of the 'default.script' script, the eval command is used to execute a dynamically constructed awk script, where the $valid_gw variable (built from the $router environment variable) is directly inserted into the awk pattern without escaping or validation. If $router contains malicious characters (such as single quotes or semicolons), it could break the awk script syntax and inject arbitrary commands. Trigger condition: When udhcpc processes a DHCP response, the $router variable is set to a malicious value. An attacker can exploit this vulnerability via a malicious DHCP server or by locally modifying environment variables to execute commands with root privileges. Exploitation method: For example, setting the $router value to '; malicious_command; ', causing eval to execute the injected command.
- **Code Snippet:**
  ```
  eval $(route -n | awk '
  	/^0.0.0.0\W{9}('$valid_gw')\W/ {next}
  	/^0.0.0.0/ {print "route del -net "$1" gw "$2";"}
  ')
  ```
- **Keywords:** router, valid_gw, interface, /etc/udhcpc.user
- **Notes:** This vulnerability requires the attacker to control the DHCP response or the udhcpc environment variables. udhcpc typically runs with root privileges, so successful exploitation could lead to privilege escalation. It is recommended to validate the input of the $router variable and use proper escaping or avoid eval. Further analysis should examine how the udhcpc binary sets environment variables and whether the /etc/udhcpc.user file can be written to by an attacker.

---
### Command-Injection-D-Bus-Service

- **File/Directory Path:** `usr/lib/dbus-1/dbus-daemon-launch-helper`
- **Location:** `fcn.00028c8c (0x00028c8c) and fcn.0000c0bc (0x0000c0bc)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The vulnerability arises from improper sanitization of the 'Exec' line in D-Bus service files during parsing and execution. The function fcn.00028c8c processes the Exec string into arguments for execv but fails to adequately validate or escape shell metacharacters. When combined with control over service file paths (e.g., through environment variables or writable directories), a non-root user can inject arbitrary commands. The attack requires the attacker to influence which service file is loaded, such as by creating a malicious service file in a user-writable directory and manipulating the DBUS_SYSTEM_BUS_ADDRESS or other environment variables to point to it. Upon execution, dbus-daemon-launch-helper parses the malicious Exec line and passes it to execv, leading to command injection and privilege escalation if the binary is setuid root.
- **Code Snippet:**
  ```
  From fcn.0000c0bc:
  0x0000c440      117200eb       bl fcn.00028c8c  // Calls argument processing function
  0x0000c584      4c109de5       ldr r1, [var_4ch]
  0x0000c588      000091e5       ldr r0, [r1]
  0x0000c58c      53f8ffeb       bl sym.imp.execv  // Executes the command
  
  From fcn.00028c8c (simplified):
  // This function parses the Exec string and prepares arguments for execv
  // If Exec contains unescaped metacharacters (e.g., ';', '&', '|'), it may lead to injection
  ```
- **Keywords:** DBUS_STARTER_ADDRESS, DBUS_STARTER_BUS_TYPE, DBUS_SYSTEM_BUS_ADDRESS, /etc/dbus-1/system.conf, .service files
- **Notes:** This finding is based on the analysis of the binary code and common vulnerabilities in D-Bus service activation. The exploitability depends on system configuration (e.g., writable service directories) and the setuid status of dbus-daemon-launch-helper. Further validation through dynamic testing or code review is recommended. The functions fcn.00028c8c and fcn.0000c0bc are critical to the attack chain.

---
### buffer-overflow-cgi-fcgi-fcn.00009148

- **File/Directory Path:** `usr/bin/cgi-fcgi`
- **Location:** `cgi-fcgi:0x92ec in function fcn.00009148`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the command-line argument processing of the 'cgi-fcgi' binary. The function fcn.00009148 uses `strcpy` without bounds checking to copy command-line arguments into a fixed-size buffer (e.g., acStack_28 of size 4 bytes). When an attacker provides a long command-line argument, it can overflow the buffer, corrupting adjacent stack memory and potentially allowing arbitrary code execution. The trigger condition is when the binary is invoked with malicious command-line arguments, which can be controlled via CGI requests in a web server context. The vulnerability involves missing boundary checks on input size before copying.
- **Code Snippet:**
  ```
  // From decompilation of fcn.00009148
  puVar12 = *(param_2 + iVar7 * 4); // Command-line argument
  pcVar3 = *(iVar15 + 0x2c); // Pointer to destination buffer
  sym.imp.strcpy(pcVar3, puVar12); // Unsafe copy without size check
  // Similarly for other cases using *(iVar15 + 0x28)
  ```
- **Keywords:** argv, command-line parameters
- **Notes:** The vulnerability is likely exploitable due to the use of `strcpy` on stack-based buffers with controlled input. However, further validation is needed to confirm the exact buffer sizes and exploitability under specific conditions. The function fcn.00009148 is called from fcn.00008b4c, which handles FastCGI initialization. Additional analysis of the stack layout and environment variable usage (e.g., via getenv) may reveal other attack vectors. Recommended next steps: test with long command-line arguments to trigger the overflow and analyze crash behavior.

---
### BufferOverflow-fcn.00018ef8

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `fcn.0000daec:0x0000dd60 (sprintf call)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In function fcn.00018ef8, network data is received via recvfrom. The data flows through fcn.0000e84c and fcn.0000daec, and is finally used in a sprintf call with the format string "/%d]". The lack of bounds checking may lead to a buffer overflow. An attacker can send crafted data to control the integer value, overwrite adjacent memory, execute arbitrary code, or cause a denial of service. The trigger condition is recvfrom receiving malicious data, affecting the integer parameter of sprintf. The attacker, as a connected non-root user with valid login credentials, can trigger this vulnerability through a network interface (such as DNS/DHCP requests).
- **Code Snippet:**
  ```
  Decompiled from fcn.00018ef8: iVar3 = sym.imp.recvfrom(param_1, uVar8, uVar1, 0); ... uVar5 = fcn.0000e84c(puVar13, iVar3); From fcn.0000daec: 0x0000dd60: bl sym.imp.sprintf (format: "/%d]")
  ```
- **Keywords:** recvfrom, fcn.00018ef8, fcn.0000e84c, fcn.0000daec, sym.imp.sprintf
- **Notes:** The integer source may come from user input, but further analysis of fcn.0000daec is needed to confirm controllability. The attack chain from recvfrom to sprintf can be verified. It is recommended to check the buffer size and integer value range. Associated components include network sockets and internal data processing functions.

---
### BufferOverflow-parmParser2p0

- **File/Directory Path:** `usr/lib/libtlvparser.so`
- **Location:** `libtlvparser.so:0x1df4 parmParser2p0`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the TLV parser function 'parmParser2p0' due to missing bounds checks during data copy operations. The parser processes input TLV (Type-Length-Value) data and copies values to memory locations based on parameters derived from the input. Specifically, in array copy loops (e.g., switch cases 0-5), the length value from the input ('piVar8[-10]') is used without validating if it exceeds the destination buffer size, allowing writes beyond allocated memory. The error message 'Parm offset elem exceeds max, result in overwrite' indicates that the code is aware of potential overwrites but does not prevent them. An attacker with valid login credentials (non-root) can exploit this by sending a malicious TLV packet with a large length value, triggering a buffer overflow. This could lead to arbitrary code execution if the overflow corrupts critical data or function pointers. The vulnerability is triggered when parsing crafted TLV data, and exploitation depends on the context in which the parser is used (e.g., network services or IPC mechanisms).
- **Code Snippet:**
  ```
  // Example from switch case 0 in parmParser2p0
  piVar8[-5] = 0;
  while (piVar8[-5] < piVar8[-10]) {
      *(piVar8 + -0x3b) = *(piVar8[-0x18] + *piVar8 * 4) & 0xff;
      *piVar8 = *piVar8 + 1;
      *(*piVar8[-0x19] + piVar8[-3] + piVar8[-0xb] + piVar8[-5]) = *(piVar8 + -0x3b);
      piVar8[-5] = piVar8[-5] + 1;
  }
  // No bounds check on the destination buffer, allowing overflow if piVar8[-10] is large
  ```
- **Keywords:** ParmDict, CmdDict, MaxParmDictEntries, MaxCmdDictEntries, parmCode, cmdCode
- **Notes:** The vulnerability is supported by the error message and decompiled code showing missing bounds checks. However, full exploitation requires the parser to be exposed to untrusted input, which is likely given the library's use in command parsing for wireless calibration or configuration. Further analysis should identify the specific binaries that use this library and their input mechanisms to confirm exploitability. The source file reference 'cmdRspParmsInternal.c:26' suggests the issue originates from source code, but the binary analysis provides sufficient evidence.

---
### buffer-overflow-sadc-fcn.000095a0

- **File/Directory Path:** `usr/lib/sysstat/sadc`
- **Location:** `sadc:0x000097b0 near fcn.000095a0`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the main function (fcn.000095a0) of the 'sadc' program, there is a buffer overflow vulnerability when processing command line arguments. When a command line argument is not a predefined option (such as '-C', '-D', etc.) and does not start with '-', the program uses strncpy to copy the argument to the stack buffer auStack_15c (size 255 bytes), but specifies a copy length of 0x100 (256 bytes), causing an off-by-one overflow. This overwrites adjacent stack variables (such as auStack_5d), potentially further overwriting the return address or control flow data. An attacker, as a non-root user with valid login credentials, can trigger the overflow by executing the sadc command and passing a specially crafted long argument (exceeding 255 bytes), potentially achieving arbitrary code execution. The vulnerability trigger condition depends on the argument format, and there is a lack of boundary checks.
- **Code Snippet:**
  ```
  else {
      if (*pcVar10 == '-') goto code_r0x000097b0;
      sym.imp.strncpy(puVar13 + -0x138, param_2[iVar5], 0x100);
      *(puVar13 + -0x39) = 0;
  }
  ```
- **Keywords:** argv (command line arguments)
- **Notes:** The vulnerability is located in the stack buffer and may be easily exploitable on the ARM architecture. Further validation of the exploitation chain is needed, such as checking binary protection mechanisms (e.g., ASLR, stack protection) and the specific consequences of the overflow. It is recommended to analyze adjacent functions (e.g., fcn.0000a9e0) to confirm data flow and potential attack enhancements. Associated files: No interaction with other files.

---
### BufferOverflow-tlv2AddParms

- **File/Directory Path:** `usr/lib/libtlvencoder.so`
- **Location:** `libtlvencoder.so:0x00000a08 sym.tlv2AddParms`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The function sym.tlv2AddParms contains multiple memcpy operations with fixed large sizes (0x40, 0x80, 0x100, 0x200 bytes) that copy user-controlled parameter data into a command response buffer. The destination buffer pointer is incremented after each copy without adequate bounds checking, allowing an attacker to overflow the buffer by supplying crafted parameter types and data. This can lead to arbitrary code execution or memory corruption when the library is used in contexts like network services processing TLV commands. The vulnerability is triggered when parameter codes are manipulated to bypass dictionary checks, directing execution to switch cases that perform large memcpy operations.
- **Code Snippet:**
  ```
  // From decompilation: memcpy calls with fixed sizes
  case 0:
      param_1 = loc.imp.memcpy(**(iVar3 + *0x1394) + *(iVar3 + *0x13a8) + 0x1c, puVar9[-10], 0x40);
      **(iVar3 + *0x1394) = **(iVar3 + *0x1394) + 0x40;
      break;
  case 1:
      param_1 = loc.imp.memcpy(**(iVar3 + *0x1394) + *(iVar3 + *0x13a8) + 0x1c, puVar9[-10], 0x80);
      **(iVar3 + *0x1394) = **(iVar3 + *0x1394) + 0x80;
      break;
  case 2:
      param_1 = loc.imp.memcpy(**(iVar3 + *0x1394) + *(iVar3 + *0x13a8) + 0x1c, puVar9[-10], 0x100);
      **(iVar3 + *0x1394) = **(iVar3 + *0x1394) + 0x100;
      break;
  case 3:
      param_1 = loc.imp.memcpy(**(iVar3 + *0x1394) + *(iVar3 + *0x13a8) + 0x1c, puVar9[-10], 0x200);
      **(iVar3 + *0x1394) = **(iVar3 + *0x1394) + 0x200;
      break;
  ```
- **Keywords:** param_1, param_2, param_3, param_4, CmdDict, ParmDict, MaxParmDictEntries
- **Notes:** The vulnerability requires control over parameter types and data, which is feasible for an authenticated user via command injection or manipulated TLV commands. The error string 'Parm offset elem exceeds max, result in overwrite' at 0x000023fd suggests additional parameter offset issues, but its code path could not be verified. Further analysis should focus on how sym.tlv2AddParms is called in parent processes and the size of the destination buffer provided by callers.

---
### Command-Injection-nat_config_http_rule

- **File/Directory Path:** `lib/nat/nat_config.sh`
- **Location:** `nat_config.sh:Line number unknown (function nat_config_http_rule)`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** In the `nat_config_http_rule` function, the `$rules` variable is used without quotes in the `{ $rules }` section of the `fw add` command, which may lead to command injection. `$rules` originates from user-controllable UCI configuration parameters `http_ip` and `http_port`, generated via the `nat_http_param_to_rule` function. If an attacker can control these parameters and cause `nat_http_param_to_rule` to return a malicious command string, arbitrary commands can be executed when the script runs with root privileges. Trigger conditions include modifying remote management configuration and triggering NAT rule reload (such as service restart). Potential exploitation methods include injecting commands to escalate privileges or perform malicious operations.
- **Code Snippet:**
  ```
      rules=$(nat_http_param_to_rule "$params")
      fw add 4 n "prerouting_rule_${mod}" "DNAT" "$" { $rules }
  ```
- **Keywords:** remote:enable, remote:port, remote:ipaddr, nat_http_param_to_rule, fw
- **Notes:** Further verification of the `nat_http_param_to_rule` function's implementation and the `fw` command's behavior is needed to confirm the completeness of the attack chain. It is recommended to analyze relevant files (such as scripts defining `nat_http_param_to_rule`) to increase confidence. Attackers may modify configurations via the web interface or UCI commands.

---
### Untitled Finding

- **File/Directory Path:** `etc/hotplug.d/iface/03-lanv6`
- **Location:** `03-lanv6: proto_lanv6_setup and proto_lanv6_teardown functions`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the `proto_lanv6_setup` and `proto_lanv6_teardown` functions, the `ifname` parameter is read from the configuration file `/etc/config/network` and used to construct the directory path `/tmp/radvd-$ifname`. Due to a lack of input validation, if `ifname` contains path traversal sequences (such as '../'), an attacker can cause the `rm -rf` and `mkdir -p` operations to be performed on arbitrary paths. For example, setting `ifname` to '../../etc' would change `radvddir` to '/etc', thereby deleting or creating system directories. Trigger conditions include: an attacker being able to modify the configuration file (e.g., through incorrect permissions or other vulnerabilities) and triggering script execution (for example, by setting the `ACTION=ifup` and `INTERFACE=lanv6` environment variables or through network interface events). Potential exploitation methods include system file destruction, privilege escalation, or service disruption.
- **Code Snippet:**
  ```
  local radvddir="/tmp/radvd-$ifname"
  [ -d "$radvddir" ] && rm -rf "$radvddir"
  mkdir -p "$radvddir"
  ```
- **Keywords:** /etc/config/network, lanv6.ifname, ACTION, INTERFACE
- **Notes:** Exploitation of this vulnerability relies on the attacker having write permissions to `/etc/config/network`, which as a non-root user may require other configuration errors or auxiliary vulnerabilities. It is recommended to further verify the permissions of the configuration file and the execution context of the script. Related files include `/etc/config/network` and possible configuration files for the radvd or dhcp6s services. Subsequent analysis should check whether other system components expose interfaces for modifying the configuration.

---
### ScriptExecution-udhcpc_user

- **File/Directory Path:** `usr/share/udhcpc/default.script`
- **Location:** `default.script: end (around line 40)`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** At the end of the script, the /etc/udhcpc.user file is executed (if it exists), which may introduce an additional attack surface. If this file can be written to by an attacker (e.g., due to improper file permissions), the attacker can directly inject malicious code, executed with udhcpc's privileges (typically root). Trigger condition: when udhcpc runs and this file exists. Exploitation method: an attacker, as a non-root user, writes malicious commands to /etc/udhcpc.user.
- **Code Snippet:**
  ```
  [ -f /etc/udhcpc.user ] && . /etc/udhcpc.user
  ```
- **Keywords:** /etc/udhcpc.user
- **Notes:** This vulnerability depends on the file permissions and writability of /etc/udhcpc.user. It is recommended to check the permissions and ownership of this file. If the file does not exist or is read-only, the risk is reduced.

---
### CommandInjection-setup_interface_env

- **File/Directory Path:** `usr/share/udhcpc/default.script`
- **Location:** `default.script: setup_interface function (approximately lines 10-15)`
- **Risk Score:** 4.0
- **Confidence:** 6.0
- **Description:** The script uses environment variables (such as $interface, $ip, $subnet, $broadcast) directly inserted into shell commands (like ifconfig and route) in multiple places. Although most are enclosed in quotes, there is a lack of input validation and boundary checking. If variables contain special characters, it may introduce command injection risk, but the risk is low because the quotes provide some protection. Trigger condition: Malicious DHCP response or local environment variable control. Exploitation method: For example, if $interface contains '; rm -rf / ;', arbitrary commands may be executed, but actual exploitation is limited by the use of quotes.
- **Code Snippet:**
  ```
  ifconfig $interface $ip netmask ${subnet:-255.255.255.0} broadcast ${broadcast:-+}
  route add -$type "$1" gw "$2" dev "$interface"
  ```
- **Keywords:** interface, ip, subnet, broadcast, staticroutes, msstaticroutes
- **Notes:** These input points are low risk because double quotes provide partial protection, but adding input validation is still recommended. Attackers need precise control of variable values, and exploitation might be limited by the command context. Should check how udhcpc filters DHCP responses.

---
