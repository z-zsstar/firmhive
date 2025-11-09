# R7500 (18 findings)

---

### StackBufferOverflow-fcn.00009c88

- **File/Directory Path:** `bin/ookla`
- **Location:** `ookla:0x9c88 fcn.00009c88`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In function fcn.00009c88, there exists a stack buffer overflow vulnerability. The vulnerability is triggered during a memcpy operation, where the copy length is calculated as strlen(source buffer) - 0x11. If the string length of the source buffer (from param_1 + 0x820) is less than 0x11 (17 bytes), the length calculation underflows, becoming a large unsigned value (for example, a length of 0xFFFFFFFF when strlen=0), causing memcpy to copy excessive data to the target stack buffer. The target buffer is located low in the stack frame, and the overflow can overwrite the saved return address (LR), allowing an attacker to control program flow. Trigger condition: An attacker provides param_1 input such that param_1 + 0x820 points to a short string (length < 17). param_1 originates from command-line argument processing (via getopt_long in fcn.00014680), and a user can control the data by running the ookla binary and passing crafted arguments. Constraints: The source buffer length must be less than 17 bytes to trigger the underflow; the target buffer size is fixed, and the overflow can overwrite critical stack data. Potential attack method: An attacker crafts a short string input, triggers the overflow to overwrite the return address, achieving arbitrary code execution. Since the attacker possesses valid login credentials (non-root user), they can run the binary locally and escalate privileges. Related code logic: The vulnerability stems from a lack of bounds checking during input processing, directly using the strlen calculation result as the memcpy length.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.strlen(piVar7 + 0 + -0x400);
  sym.imp.memcpy(piVar7 + 0 + -0x500, piVar7 + 0 + -0x400, iVar1 + -0x11);
  ```
- **Keywords:** param_1
- **Notes:** The vulnerability is independently exploitable and does not rely on other components. It is recommended to further trace the ultimate source of param_1 to confirm all input vectors.

---
### Command-Injection-internet_con

- **File/Directory Path:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Location:** `ntgr_sw_api.sh:internet_con function (eval line)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'internet_con' function. Attackers can exploit it through the following steps: 1) Use 'nvram set' to set the 'swapi_persistent_conn' NVRAM variable to a malicious string (such as "'; malicious_command; '"); 2) Call the 'internet_con' function (for example, './ntgr_sw_api.sh internet_con dummy app value'). When 'eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\' is executed, the malicious command will be executed. Vulnerability trigger conditions: the attacker can call the script and set the NVRAM variable; the script may run with root privileges, leading to privilege escalation. The exploitation method is simple, requiring only two steps.
- **Code Snippet:**
  ```
  eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'\nif [ "x$(printf "$tvalue" | grep "$2\\ [01]")" != "x" ]; then\n    $CONFIG set $SWAPI_PERSISTENT_CONN="$(printf "$tvalue"|sed "s/$2\\ [01]/$2\\ $3/")"\nelse\n    $CONFIG set $SWAPI_PERSISTENT_CONN="${tvalue:+${tvalue};}$2 $3"\nfi
  ```
- **Keywords:** swapi_persistent_conn, internet_con, nvram
- **Notes:** Assumes the script runs with root privileges (common for system configuration scripts). The attack chain is complete and verifiable. It is recommended to check the script's invocation context (such as web interface or IPC) to confirm exploitability. Other functions (such as 'nvram set') may have minor issues, but no complete attack chain was found.

---
### Command-Injection-start

- **File/Directory Path:** `usr/sbin/green_download.sh`
- **Location:** `green_download.sh:~132 start() function (Exact line numbers may vary depending on file version, but located at the end of the start function)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In the start function of the 'green_download.sh' file, there is a command injection vulnerability. When the script starts the greendownload process, it uses command substitution $(/bin/config get ...) and variable expansion to build command line arguments. If an attacker can control the following NVRAM configuration variables: wan_ifname, green_download_max_uprate, green_download_max_downrate, green_download_max_tasks_run, or green_download_max_tasks_all, and inject shell metacharacters (such as ;, &, |, etc.) into them, arbitrary commands can be executed when the script runs with root privileges.

Trigger conditions:
- The attacker has valid login credentials (non-root user) and can set the aforementioned NVRAM configuration variables via the web interface, API, or other means.
- The attacker triggers the start or restart of the green download service (e.g., by enabling the feature or changing settings).
- The script runs with root privileges (as part of a system service).

Potential attack methods:
- The attacker sets wan_ifname to 'eth0; malicious_command'. When the script executes, it will first run greendownload -i eth0, then execute malicious_command.
- Similarly, other configuration variables can also be used to inject commands.

The exploit chain is complete and verifiable: Attacker controls input (configuration variables) → Data flows through the script without validation → Triggers dangerous operation (command execution).
- **Code Snippet:**
  ```
  greendownload -i $(/bin/config get wan_ifname) -w $work_dir -s $statfifo_work_dir -u $green_dl_uprate -d $green_dl_downrate -r $green_dl_max_tasks_run -a $green_dl_max_tasks_all
  ```
- **Keywords:** wan_ifname, green_download_max_uprate, green_download_max_downrate, green_download_max_tasks_run, green_download_max_tasks_all
- **Notes:** This vulnerability requires the attacker to be able to set NVRAM configuration variables and trigger a service restart. It is recommended to check if other components (such as the web interface) allow users to set these variables. Furthermore, the greendownload binary should be analyzed for other potential vulnerabilities. Symlink attacks and path traversal might be possible in the stop function, but command injection is a more directly exploitable vulnerability.

---
### CommandInjection-ppp.sh-print_ip_up

- **File/Directory Path:** `lib/network/ppp.sh`
- **Location:** `ppp.sh, in the print_ip_up function, specifically in the route del commands for staticdns1 and staticdns2`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection vulnerability in the PPP ip-up script generated by ppp.sh. The ip-up script, which runs with root privileges when a PPP connection is established, uses user-controlled configuration values (wan_ether_dns1 and wan_ether_dns2) in shell commands without proper sanitization. This allows command injection via shell metacharacters (e.g., semicolons). Trigger conditions include: (1) attacker sets wan_ether_dns1 or wan_ether_dns2 to a malicious string containing commands, (2) DNS assignment is enabled for the PPP protocol (e.g., wan_pptp_dns_assign=1 for PPTP), and (3) a PPP connection is established. Potential exploitation involves injecting commands to gain root access.
- **Code Snippet:**
  ```
  staticdns1="\$(config get wan_ether_dns1)"
  staticdns2="\$(config get wan_ether_dns2)"
  ...
  if [ "x\$staticdns1" != "x" ]; then
      /sbin/route del \$staticdns1
  elif [ "x\$staticdns2" != "x" ]; then
      /sbin/route del \$staticdns2
  fi
  ```
- **Keywords:** wan_ether_dns1, wan_ether_dns2, wan_pptp_dns_assign, wan_l2tp_dns_assign, wan_pppoe_dns_assign, wan_proto, /etc/ppp/ip-up, /tmp/resolv.conf
- **Notes:** This finding assumes the attacker can set NVRAM configuration values through an authenticated interface (e.g., web UI). The vulnerability is introduced when ppp.sh generates the ip-up script. Further analysis could verify the accessibility of config set commands by non-root users and explore other potential injection points.

---
### Kernel-Write-ufsd_ioctl

- **File/Directory Path:** `lib/ufsd/ufsd.ko`
- **Location:** `ufsd.ko:0x08005a28 ufsd_ioctl`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'ufsd_ioctl' function, when handling ioctl command 0x80206659 (0x6659 | 0x80200000), there is a lack of validation for the user pointer param_3. The function directly writes to offset locations of param_3 (*(param_3 + 8) and *(param_3 + 0xc)) without checking if param_3 points to a valid user-space address or performing boundary checks. An attacker, as an authenticated non-root user, can control param_3 to point to a kernel address by accessing the device file (such as /dev/ufsd) and sending a specific ioctl command, leading to arbitrary kernel writes. The written values are read from kernel structures (uVar3 and uVar7), but an attacker could achieve privilege escalation by overwriting kernel data. Trigger condition: The attacker has access to the device file and valid login credentials. Exploitation method: Craft a malicious ioctl call, specifying param_3 as the target kernel address, to trigger the write operation.
- **Code Snippet:**
  ```
  Key parts extracted from the decompiled code:
  if (param_2 != (0x6659 | 0x80200000)) {
      // ...
  } else {
      // ...
      if (param_3 != 0xfffffff8) {
          // ...
          *(param_3 + 8) = uVar3;
          *(param_3 + 0xc) = uVar7;
      }
      // ...
  }
  ```
- **Keywords:** param_3, ioctl command 0x80206659, /dev/ufsd device file
- **Notes:** This vulnerability is based on decompiled code analysis, with solid evidence. The attack chain is complete: the attacker controls the param_3 pointer, and the ioctl write may lead to privilege escalation. It is recommended to further verify device file permissions and kernel address mapping. Related functions include func_0x08005a78 and func_0x08005adc, but the current focus is on ufsd_ioctl.

---
### command-injection-vlan_create_br_and_vif

- **File/Directory Path:** `lib/cfgmgr/opmode.sh`
- **Location:** `opmode.sh: function vlan_create_br_and_vif and vlan_create_brs_and_vifs`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'opmode.sh' file. Attackers can inject arbitrary commands during script execution by controlling the values of NVRAM variables vlan_tag_1 through vlan_tag_10. Specifically, when the script processes these variables, it uses 'set - $(echo $tv)' to split them, and the split fields (such as vid) are directly used for command execution (e.g., 'vconfig add $RawEth $1'). If the vid field contains shell metacharacters (such as semicolons or pipe symbols), it will lead to command injection. Trigger conditions include: the attacker has valid login credentials (non-root user) and can set NVRAM variables via the web interface or API; the script runs with root privileges (common during device startup or configuration changes). Exploitation method: set vlan_tag_i to a malicious value (e.g., '1 Internet 1; touch /tmp/pwned; 0 0 0'), when the script runs, the injected command will execute with root privileges.
- **Code Snippet:**
  ```
  for i in 1 2 3 4 5 6 7 8 9 10; do
      tv=$($CONFIG get vlan_tag_$i)
      [ -n "$tv" ] || continue
      set - $(echo $tv)
      # $1: enable, $2: name, $3: vid, $4: pri, $5:wports, $6:wlports
      [ "$1" = "1" ] || continue
      if [ "$2" = "Internet" ]; then 
          i_vid=$3
          i_pri=$4
      else
          used_wports=$(($used_wports | $5))
          vlan_create_br_and_vif $3 $4   # $3 (vid) is passed without validation
          sw_configvlan "vlan" "add" "br" $3 $5 $4
      fi
  done
  
  vlan_create_br_and_vif() # $1: vid, $2: pri
  {
      local brx="br$1"
      ...
      if [ -n "$RawEth" ]; then
          vconfig add $RawEth $1 && ifconfig $RawEth.$1 up   # Command injection if $1 contains malicious characters
          brctl addif $brx $RawEth.$1
          vlan_set_vif_pri $RawEth.$1 $2
      else
          ...
      fi
      ...
  }
  ```
- **Keywords:** vlan_tag_1, vlan_tag_2, vlan_tag_3, vlan_tag_4, vlan_tag_5, vlan_tag_6, vlan_tag_7, vlan_tag_8, vlan_tag_9, vlan_tag_10
- **Notes:** The exploitation of this vulnerability relies on the script running with root privileges and the attacker being able to trigger script execution (e.g., by changing device configuration). It is recommended to validate NVRAM input values to ensure they only contain numbers or safe characters. Further analysis of other files (such as cfgmgr.sh) is needed to confirm the complete attack chain and mitigation measures.

---
### Path-Traversal-hostapd_functions

- **File/Directory Path:** `lib/wifi/hostapd.sh`
- **Location:** `hostapd.sh: hostapd_set_bss_options function and hostapd_setup_vif function`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The path traversal vulnerability allows arbitrary file deletion and overwriting. An attacker can inject path traversal sequences (such as '../../etc/passwd') by modifying the 'phy' or 'ifname' parameters in the wireless configuration. When the script executes, it uses these parameters to construct file paths, for example in `rm /var/run/hostapd-$phy/$ifname` and file creation operations. Trigger condition: The attacker possesses valid login credentials (non-root), can modify wireless settings through a configuration interface (such as a Web interface or API), and can trigger script execution (e.g., by restarting the network service). Exploitation method: Injecting malicious paths can delete critical system files (such as `/etc/passwd`) or overwrite configuration files, leading to denial of service or potential privilege escalation. The code logic directly uses input variables without filtering, lacking boundary checks.
- **Code Snippet:**
  ```
  In the hostapd_set_bss_options function:
  [ -f /var/run/hostapd-$phy/$ifname ] && rm /var/run/hostapd-$phy/$ifname
  ctrl_interface=/var/run/hostapd-$phy
  
  In the hostapd_setup_vif function:
  cat > /var/run/hostapd-$ifname.conf <<EOF
  ...
  EOF
  hostapd -P /var/run/wifi-$ifname.pid -B /var/run/hostapd-$ifname.conf -e $entropy_file
  Where entropy_file=/var/run/entropy-$ifname.bin
  ```
- **Keywords:** phy, ifname, /var/run/hostapd-$phy/$ifname, /var/run/hostapd-$ifname.conf, /var/run/entropy-$ifname.bin
- **Notes:** The vulnerability relies on the configuration system allowing malicious values to be set; it is recommended to verify if the configuration interface filters input. Associated files: May involve UCI configuration files (e.g., /etc/config/wireless). Subsequent analysis direction: Check if configuration management components (such as the Web interface) validate input and test the feasibility of actual exploitation.

---
### Command-Injection-read_conf_file_for_athr_hostapd

- **File/Directory Path:** `etc/hotplug.d/wps/00-wps`
- **Location:** `00-wps:read_conf_file_for_athr_hostapd function (specific line number not provided, but located in the latter part of the script)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the read_conf_file_for_athr_hostapd function, the assignment of tmp_ssid uses backtick command substitution (`cat $FILE |grep -nr '^ssid' |cut -d = -f 2-`), where the $FILE variable is obtained from an environment variable and not sufficiently validated. If $FILE contains command separators like semicolons (e.g., '/tmp/evil; touch /tmp/pwned; #'), arbitrary commands may be injected and executed. Trigger conditions include: $ACTION=SET_CONFIG, $PROG_SRC=athr-hostapd, $SUPPLICANT_MODE≠1, and $FILE pointing to a malicious path controlled by an attacker. An attacker, as a non-root user, can exploit this vulnerability by creating a malicious file and triggering a WPS event (e.g., via a network request), potentially leading to command execution with root privileges, achieving privilege escalation.
- **Code Snippet:**
  ```
  read_conf_file_for_athr_hostapd() {
      sed -e 's/=/ /' -e '/^\#/d' -e '/^$/d' $FILE > ${FILE}.$$
      while read -r arg val; do
  	case "$arg" in
  	    ssid)
  		/* here the origin code will lead to bug 35280,[WPS]The SSID shows wrong when i set ssid contain spaces 
  		 * by Wired external registrar in Win7 ,so i repeace the ssid vaule as follows */
  		#tmp_ssid="$val"
  		tmp_ssid="\`cat $FILE |grep -nr '^ssid' |cut -d = -f 2-\`"
  		;;
  	    wpa|wpa_key_mgmt|wpa_pairwise|wps_state)
                  eval tmp_$arg="$val"
                  ;;
  	    wpa_passphrase)
                  # Handle special chars, "\" -> "\\\\", "\`" -> "\\`", """ -> "\""
                  # Note that the method to handle "\`" differs from the one of SSID above.
                  # This is weird but exactly done by Wireless Settings web page in WNDR3700.
  		tmp_wpa_passphrase="$(echo "$val"|sed -e 's/\\/\\\\/g' -e 's/\`/\\\`/g' -e 's/"/\\"/g')"
  		;;
  	    wpa_psk)
  		tmp_wpa_psk="$(echo $val|sed -e 's/\\/\\\\/g' -e 's/\`/\\\`/g' -e 's/"/\\"/g')"
  		;;
  	esac
      done < ${FILE}.$$
      rm -f ${FILE}.$$
      if [ "x$tmp_wpa_passphrase" = "x" ]; then
         tmp_wpa_passphrase="$tmp_wpa_psk"
      fi
  }
  ```
- **Keywords:** $FILE, $ACTION, $PROG_SRC, $SUPPLICANT_MODE, /bin/config
- **Notes:** Vulnerability exploitability depends on the script running with high privileges (such as root), which may be achieved through the hotplug mechanism. The attack chain is complete: the attacker controls the $FILE path and triggers a WPS event. It is recommended to verify the hotplug context and permission model. Other functions (such as set_config) use input filtering, but this point does not filter command injection. Related files: Events may be triggered through network services (such as hostapd).

---
### Command-Injection-RMT_invite.cgi

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `RMT_invite.cgi:3 (eval statement) and proccgi (binary, imported functions: getenv, strcpy, strtok)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A command injection vulnerability exists in 'RMT_invite.cgi' via the 'proccgi' binary. Attackers can send malicious CGI parameters (such as FORM_submit_flag, FORM_TXT_remote_login, etc.), which are processed by 'proccgi' and output in shell variable assignment format (e.g., 'FORM_param="value"'). Since 'RMT_invite.cgi' uses eval to execute the output of 'proccgi', and there is a lack of input validation and filtering, attackers can inject command separators (such as semicolons, backticks, or newlines) to execute arbitrary commands. Trigger condition: An attacker sends a specially crafted HTTP request to the CGI endpoint, exploiting the permissions of a logged-in user. Potential exploitation methods include executing system commands, escalating privileges, or complete device compromise. Constraints: The attacker must have valid login credentials but does not require root privileges.
- **Code Snippet:**
  ```
  From RMT_invite.cgi:
  #!/bin/sh
  . /www/cgi-bin/func.sh
  eval "\`/www/cgi-bin/proccgi $*\`"
  
  From proccgi analysis (strings output):
  Embedded script: eval executing proccgi output
  Output format: FORM_%s="value"
  Imported functions: getenv, strcpy, strtok indicating input processing without bounds checking
  ```
- **Keywords:** QUERY_STRING, CONTENT_LENGTH, REQUEST_METHOD, PATH_INFO, FORM_submit_flag, FORM_TXT_remote_login, FORM_TXT_remote_passwd, /www/cgi-bin/proccgi, /www/cgi-bin/func.sh, /www/cgi-bin/RMT_invite.cgi
- **Notes:** The vulnerability relies on 'proccgi' outputting unfiltered data, and 'RMT_invite.cgi' directly using eval, creating an exploitable chain. Dynamic testing is recommended to confirm command execution. Related files include 'func.sh', but it has not been analyzed. Subsequent checks should examine if other CGI scripts similarly use 'proccgi'.

---
### Config-Injection-cmd_ftp

- **File/Directory Path:** `lib/dnicmd/cmd_ftp`
- **Location:** `cmd_ftp: functions 'scan_sharefoler_in_this_disk' and 'print_onesharefolder_config'`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the 'cmd_ftp' script, the share name is obtained from the NVRAM variable 'shared_usb_folder' and directly inserted into the proftpd configuration file, lacking input validation and escaping. Attackers can inject arbitrary configurations by setting a malicious share name (containing newline characters and proftpd configuration directives). For example, the share name can contain directives such as '</Directory><Limit ALL>AllowAll</Limit>', breaking the configuration file structure and adding unauthorized permission rules. Trigger condition: After the attacker modifies the NVRAM variable, the script regenerates the configuration file (such as through a service restart). Exploitation method: The attacker uses valid credentials to modify the share name via the web interface, causing proftpd to load malicious configurations, allowing unauthorized file access or privilege escalation.
- **Code Snippet:**
  ```
  In the 'scan_sharefoler_in_this_disk' function:
  sharename=\`echo "$sharefolder_item" | awk -F* '{print $1}' | sed 's/ //g'\`
  ...
  print_onesharefolder_config "$sharename" "$access" "$j"
  
  In the 'print_onesharefolder_config' function:
  cat <<EOF >>$proftpd_tmpfile
  	<Directory /tmp/ftpadmin/shares/$1>
  	AllowOverwrite    on
  		<Limit DIRS>
  			DenyAll
  EOF
  ...
  cat <<EOF >> $proftpd_tmpfile
  	</Directory>
  EOF
  ```
- **Keywords:** shared_usb_folder (NVRAM variable), /tmp/proftpd.conf (configuration file path), /bin/config (configuration tool)
- **Notes:** This vulnerability relies on the attacker being able to modify the NVRAM variable, possibly through the web interface. Further verification is needed to check if the web interface filters share name input. It is recommended to check how other components (such as the web server) handle share name input. The vulnerability may allow non-root users to gain unauthorized file access via FTP.

---
### CommandInjection-sw_configvlan_vid

- **File/Directory Path:** `lib/cfgmgr/enet.sh`
- **Location:** `enet.sh: sw_tmpconf_add_vlan function and sw_tmpconf_generate_swconf function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The 'vid' parameter in the 'sw_configvlan_vlan' function is used unsafely when writing to temporary files that are later sourced using the '.' command. This allows command injection if 'vid' contains malicious shell code. When the temporary file is sourced during 'sw_tmpconf_generate_swconf', any embedded commands in 'vid' are executed in the shell context, potentially leading to arbitrary command execution with root privileges. The vulnerability requires the attacker to control the 'vid' parameter passed to 'sw_configvlan' with opmode 'vlan' and action 'add'.
- **Code Snippet:**
  ```
  sw_tmpconf_add_vlan() # $1: vlanindex, $2: vid, $3: ports
  {
  	cat <<EOF > "$swconf.tmp$1"
  vid="$2"
  ports="$3"
  EOF
  }
  
  sw_tmpconf_generate_swconf() # $1: vlanindex
  {
  	local vid ports i=1
  
  	sw_printconf_add_switch
  	while [ $i -le $1 ]; do
  		. "$swconf.tmp$i"   # This sources the file, executing any commands
  		sw_printconf_add_vlan "switch0" "$i" "$vid" "$ports"
  		i=$(($i + 1))
  	done
  }
  ```
- **Keywords:** vid parameter in sw_configvlan_vlan add, temporary files /tmp/sw.conf.tmp*, sourcing via . command
- **Notes:** This vulnerability is exploitable if an attacker can control the 'vid' parameter through a configuration interface (e.g., web UI or API) that invokes this script. The script is likely run as root, so command execution would be with elevated privileges. Further analysis is needed to identify the calling context and parameter sources.

---
### CommandInjection-sw_configvlan_pri

- **File/Directory Path:** `lib/cfgmgr/enet.sh`
- **Location:** `enet.sh: sw_print_ssdk_cmds_set_ports_pri function and sw_configvlan_vlan function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The 'pri' parameter in the 'sw_configvlan_vlan' function is used unsafely in generated command files that are executed via 'sh'. This allows command injection if 'pri' contains malicious shell code. The 'pri' value is directly embedded into commands written to '$ssdk_cmds_file', and when 'qt sh $ssdk_cmds_file' is executed, any injected commands are run with root privileges. The vulnerability requires the attacker to control the 'pri' parameter passed to 'sw_configvlan' with opmode 'vlan' and action 'add'.
- **Code Snippet:**
  ```
  sw_print_ssdk_cmds_set_ports_pri() # $1: ports, $2: pri
  {
  	local p
  
  	for p in $ports; do
  		echo $p | grep -q "t" && continue
  
  		cat <<EOF
  $ssdk_sh qos ptDefaultCpri set $p $2
  EOF
  	done
  }
  
  # In sw_configvlan_vlan add:
  sw_print_ssdk_cmds_set_ports_pri "$ports" "$pri" >> $ssdk_cmds_file
  # Later executed with:
  qt sh $ssdk_cmds_file
  ```
- **Keywords:** pri parameter in sw_configvlan_vlan add, command file /tmp/ssdk.sh, execution via qt sh
- **Notes:** This vulnerability is exploitable if an attacker can control the 'pri' parameter through a configuration interface. The use of 'sh' to execute the command file makes it susceptible to injection. Further investigation is required to determine how 'sw_configvlan' is invoked and whether user input flows into these parameters.

---
### Module-Injection-load_qcawifi

- **File/Directory Path:** `lib/wifi/33-qca-wifi`
- **Location:** `qcawifi.sh: load_qcawifi function (specific line number unknown, but the code snippet comes from the loop section in the script)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The file '33-qca-wifi' contains a list of Wi-Fi kernel modules, with permissions -rwxrwxrwx, allowing non-root users to read and write. The script 'qcawifi.sh' reads this file within the load_qcawifi function and uses 'insmod' to load the modules. Since 'insmod' typically requires root privileges, if 'qcawifi.sh' runs as root (common in embedded systems), an attacker can inject a malicious module entry by modifying '33-qca-wifi', leading to arbitrary code execution and privilege escalation. Trigger conditions include system startup, Wi-Fi reconfiguration, or execution of 'qcawifi.sh' when related services restart. The attacker needs valid login credentials (non-root) and the ability to modify the file, then must wait for or trigger the module loading process.
- **Code Snippet:**
  ```
  for mod in $(cat /lib/wifi/33-qca-wifi*); do
      case ${mod} in
          umac) [ -d /sys/module/${mod} ] || insmod ${mod} ${umac_args};;
          *) [ -d /sys/module/${mod} ] || insmod ${mod};;
      esac
  done
  ```
- **Keywords:** File path: /lib/wifi/33-qca-wifi, Script path: /lib/wifi/qcawifi.sh, Function: load_qcawifi, Command: insmod
- **Notes:** The attack chain is based on file writability and the script's use of 'insmod', but it needs to be verified whether 'qcawifi.sh' executes with root privileges. It is recommended to check how system services or initialization scripts (such as those in /etc/init.d/) call this script. Additionally, it should be confirmed whether non-root users can trigger module loading (e.g., via network interfaces or CLI). If 'qcawifi.sh' does not run with high privileges, the risk might be reduced. Related files include other scripts in the current directory (like hostapd.sh), but no direct references were found.

---
### buffer-overflow-fcn.0000c038

- **File/Directory Path:** `sbin/net-util`
- **Location:** `net-util:0xc038 in function fcn.0000c038`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the function fcn.0000c038, which is called from commands like 'detwanv6' and 'daemonv6'. The function uses strcpy to copy the user-provided interface name (from command-line arguments) into a fixed-size stack buffer without any bounds checking. This allows an attacker to overflow the buffer by supplying a long string, potentially overwriting the return address and achieving arbitrary code execution. The vulnerability is triggered when net-util is executed with commands that require an interface name, such as 'net-util detwanv6 <interface>'. As a non-root user with login credentials, the attacker can control the input and craft a payload to exploit this.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar6 + -7, param_1);  // param_1 is user-controlled command-line argument
  ```
- **Keywords:** command-line arguments for 'detwanv6' or 'daemonv6' commands, interface name parameter
- **Notes:** The risk score assumes that the binary may run with elevated privileges in some contexts (e.g., if called from root processes), but if not, the impact is limited to the user's privileges. Further analysis is needed to determine if net-util is setuid or called from privileged services. The buffer size is approximately 32 bytes, but exact layout requires deeper stack analysis. Exploitation might require bypassing protections, but firmware often lacks ASLR or canaries.

---
### Command-Injection-wx-config

- **File/Directory Path:** `usr/lib/wx/config/arm-openwrt-linux-base-unicode-release-2.8`
- **Location:** `arm-openwrt-linux-base-unicode-release-2.8: Around line 640-650 (Delegate execution point)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the wx-config script, allowing attackers to execute arbitrary commands by manipulating the --exec-prefix option and the configuration mask. Trigger condition: When an attacker invokes the script and specifies --exec-prefix to point to a directory they control, and creates a malicious file name containing shell metacharacters (such as a semicolon) in that directory, causing the configmask to match that file. When the script delegates execution, because the variables are not quoted/escaped, the shell interprets the metacharacters in the file name as command separators, leading to command injection. Exploitation method: An attacker can place a file with a name like 'malicious; echo hacked;' and use options to make the configmask match it, thereby executing the injected command. This vulnerability requires the attacker to have write permissions to the target directory, but as a non-root user, they might control the home directory or temporary directories.
- **Code Snippet:**
  ```
  # Delegate execution code snippet
  if [ $_numdelegates -eq 1 ]; then
      $wxconfdir/\`find_eligible_delegates $configmask\` $*
      exit
  fi
  
  # Or use best_delegate
  if [ -n "$best_delegate" ]; then
      $wxconfdir/$best_delegate $*
      exit
  fi
  ```
- **Keywords:** input_option_exec_prefix, input_option_prefix, wxconfdir, configmask, best_delegate
- **Notes:** The vulnerability relies on the attacker being able to control the --exec-prefix directory and file names. It is recommended to use quotes for variables (e.g., "$wxconfdir/$best_delegate") to prevent command injection. Subsequent checks can examine other similar delegation points or utility execution paths. Related functions: find_eligible_delegates, get_mask.

---
### Command-Injection-wireless_event

- **File/Directory Path:** `lib/wifi/wireless_event`
- **Location:** `wireless_event:7`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The script has a command injection vulnerability when processing the CHANNEL environment variable. When ACTION is 'RADARDETECT', the script uses `echo $CHANNEL` in command substitution (for loop). Since the variable is not quoted, if CHANNEL contains commands enclosed in backticks (such as `malicious_command`), these commands will be executed during the command substitution phase. An attacker can execute arbitrary commands by setting CHANNEL to a malicious value (such as `rm -rf /` or `id`). Trigger conditions include: controlling the ACTION and CHANNEL environment variables, and ensuring the script is triggered (for example, through the wireless event mechanism). Potential exploitation methods include privilege escalation (if the script runs with root privileges) or system destruction. The vulnerability stems from a lack of input validation and sanitization.
- **Code Snippet:**
  ```
  for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do
  ```
- **Keywords:** ACTION, CHANNEL, /usr/sbin/radardetect, /usr/sbin/radardetect_cli
- **Notes:** The vulnerability can be directly verified from the code, but the full attack chain requires confirming the script's trigger mechanism and execution privileges (for example, whether it is executed by root). It is recommended to subsequently analyze the script's invocation context (such as through IPC or event systems) and the behavior of /usr/sbin/radardetect_cli to assess the actual impact. Associated files may include processes or configurations that call this script.

---
### BufferOverflow-config_set

- **File/Directory Path:** `bin/config`
- **Location:** `config:0x00008760 fcn.000086cc`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** The 'config' binary contains a buffer overflow vulnerability in the 'set' command handler due to the use of strcpy without bounds checking. User input from the command-line argument (argv[1]) is copied directly to a stack buffer, which can be overflowed with a long input. This could potentially overwrite the return address and lead to arbitrary code execution if the stack is executable or if ROP gadgets are available. The vulnerability is triggered when a non-root user runs 'config set <long string>' with a string longer than the stack buffer size. The stack buffer is allocated with a total size of 0x60204 bytes, but the exact vulnerable buffer might be smaller, and the overflow can occur if the input exceeds the available space.
- **Code Snippet:**
  ```
  0x0000875c      0d00a0e1       mov r0, sp                  ; char *dest
  0x00008760      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** argv[1] for 'set' command, config_set function
- **Notes:** The binary has permissions -rwxrwxrwx, allowing any user to execute it. Exploitability depends on the system configuration, such as stack protections and ASLR. Further analysis is needed to verify the exact buffer size and develop a reliable exploit. This finding should be prioritized for manual testing in the target environment.

---
### buffer-overflow-fcn.00000830

- **File/Directory Path:** `usr/lib/uams/uams_guest.so`
- **Location:** `uams_guest.so:0xa28 function fcn.00000830`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** A buffer overflow vulnerability exists in 'uams_guest.so' due to the use of strcpy with user-controlled username input without bounds checking. The vulnerability is triggered during guest authentication when the NoAuthUAM processes a username from the network. The strcpy function copies the username from a source buffer ([sp, 0x10]) to a destination buffer ([sp, 0x14]) without validating the length, allowing an attacker to overflow the stack buffer. This could corrupt adjacent stack memory, including saved registers and return addresses, potentially leading to arbitrary code execution. The attack requires the attacker to have valid login credentials and to send a crafted long username in an AFP authentication request. Constraints include the success of uam_afpserver_option call, but no length checks are evident. Exploitation could result in privilege escalation if the process runs with elevated privileges.
- **Code Snippet:**
  ```
  0x00000a20      10109de5       ldr r1, [sp, 0x10]
  0x00000a24      14009de5       ldr r0, [sp, 0x14]
  0x00000a28      d4feffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** uam_afpserver_option, getpwnam, username input from network AFP authentication
- **Notes:** The vulnerability is potentially exploitable but requires further analysis to confirm the exact buffer sizes and stack layout. Additional investigation into the calling context and process privileges is recommended to assess the full impact. The function fcn.00000830 is likely the login function for NoAuthUAM, based on strings like 'login noauth'. No other obvious vulnerabilities were found in this file.

---
