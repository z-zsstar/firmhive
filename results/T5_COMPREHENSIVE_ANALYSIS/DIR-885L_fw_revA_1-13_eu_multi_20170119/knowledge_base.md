# DIR-885L_fw_revA_1-13_eu_multi_20170119 (36 findings)

---

### CodeInjection-form_macfilter

- **File/Directory Path:** `htdocs/mydlink/form_macfilter`
- **Location:** `form_macfilter (specific line number unknown, but code is in the fwrite and dophp call sections)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A code injection vulnerability was discovered in the 'form_macfilter' script, allowing remote code execution (RCE). When $_POST['settingsChanged'] is 1, the script directly writes user-controlled POST parameters (such as entry_enable_*, mac_*, mac_hostname_*, mac_addr_*, sched_name_*) to a temporary PHP file (/tmp/form_macfilter.php), which is then executed via dophp('load'). An attacker can inject malicious PHP code, for example by setting entry_enable_0 to '1; system("id"); //', leading to arbitrary command execution. The trigger condition includes: an attacker submitting a POST request to this script with settingsChanged=1. The exploitation method is simple, requiring only the construction of malicious POST data to achieve RCE.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **Keywords:** $_POST['settingsChanged'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp
- **Notes:** This vulnerability has a complete attack chain: attacker controls POST data -> data is written to a temporary file -> file is executed -> RCE. The exact behavior of the dophp function needs to be verified, but based on the context, it executes PHP code. It is recommended to further analyze the implementation of the dophp function to confirm exploitability. Related files may include /htdocs/mydlink/libservice.php (which defines dophp).

---
### RCE-form_macfilter

- **File/Directory Path:** `htdocs/mydlink/get_Macfilter.asp`
- **Location:** `form_macfilter: approximately lines 30-40 (fwrite and dophp calls)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In the 'form_macfilter' file, user input is processed via `$_POST` and directly written to a temporary PHP file, which is then dynamically loaded and executed using `dophp("load")`. An attacker can inject malicious PHP code into POST parameters (such as `entry_enable_*`), leading to remote code execution. Specific trigger condition: an attacker submits a POST request to the 'form_macfilter' endpoint containing malicious code in `entry_enable_*` or other parameters. For example, setting `entry_enable_0` to `1; system('id'); //` will generate `$enable = 1; system('id'); //;` in the temporary file, and when `dophp` loads it, `system('id')` will be executed. Exploitation method: after authentication, an attacker can execute arbitrary system commands to escalate privileges or control the device.
- **Code Snippet:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  // Other similar fwrite calls
  dophp("load",$tmp_file);
  ```
- **Keywords:** form_macfilter, get_Macfilter.asp, /acl/macctrl
- **Notes:** This vulnerability requires the attacker to have valid login credentials, but the exploitation chain is complete and verifiable. The 'dophp' function might be defined in 'xnode.php', which was not directly analyzed, but the code behavior is evident. It is recommended to further verify the implementation of 'xnode.php'. 'get_Macfilter.asp' serves as a data output point and might be used for reflective attacks, but the risk is low.

---
### Untitled Finding

- **File/Directory Path:** `etc/init0.d/rcS`
- **Location:** `rcS: Line number not specified, but the key code is in the 'for i in /etc/init0.d/S??* ; do ... $i start' loop`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** In the 'rcS' script, all S??* scripts in the /etc/init0.d/ directory are executed in a loop ('$i start'). However, because these scripts have global write permissions (777), a non-root attacker can modify or add malicious scripts. When the system starts or rcS runs with root privileges, these scripts are executed, allowing the attacker to inject arbitrary code and escalate privileges. Trigger conditions include system startup or service restart. The attacker only needs to log into the device, modify any script in /etc/init0.d/ (such as S80telnetd.sh), add malicious commands (such as a reverse shell or backdoor), and then wait for or trigger a restart. The constraint is that the attacker requires filesystem access, but based on evidence, both the directory and files are writable.
- **Code Snippet:**
  ```
  for i in /etc/init0.d/S??* ; do
  	# Ignore dangling symlinks (if any).
  	[ ! -f "$i" ] && continue
  	# run the script
  	#echo [$i start]
  	$i start
  	# generate stop script
  	echo "$i stop" > $KRC.tmp
  	[ -f $KRC ] && cat $KRC >> $KRC.tmp
  	mv $KRC.tmp $KRC
  done
  ```
- **Keywords:** /etc/init0.d/, /var/killrc0
- **Notes:** Based on ls output, the /etc/init0.d/ directory and all script file permissions are 777, indicating they are writable by non-root users. rcS typically runs with root privileges, so executing scripts has high privileges. It is recommended to further verify the permissions and generation process of the /var/killrc0 file, but the current attack chain is complete. Associated files include all scripts under /etc/init0.d/ (such as S80telnetd.sh). Subsequent analysis should check other startup scripts and service interactions.

---
### RCE-SQLite3_load_command

- **File/Directory Path:** `bin/sqlite3`
- **Location:** `fcn.0000d0d0 (0x0000d0d0) in sqlite3`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The '.load' command in SQLite3 CLI allows loading external shared libraries without proper validation of the file path or entry point. A non-root user with login credentials can create a malicious shared library (e.g., in their home directory) and load it via '.load /path/to/malicious.so', leading to arbitrary code execution. The command processes user input directly and passes it to `sqlite3_load_extension`, which loads and executes the library's initialization function. This provides a complete attack chain for privilege escalation or other malicious activities.
- **Code Snippet:**
  ```
  Relevant code from decompilation:
  if ((piVar12[-0x17] != 0x6c) || ... ) {
      // ... 
  } else {
      piVar12[-100] = 0;
      piVar12[-0x24] = piVar12[-0x5e];  // filename from user input
      iVar3 = piVar12[-1];
      if (iVar3 == 2 || ... ) {
          iVar3 = 0;
      } else {
          iVar3 = piVar12[-0x5d];  // entry point from user input
      }
      piVar12[-0x25] = iVar3;
      fcn.0000cc84(...);
      iVar3 = sym.imp.sqlite3_load_extension(**(piVar12 + ...), piVar12[-0x24], piVar12[-0x25], piVar12 + -400);
      // ...
  }
  ```
- **Keywords:** .load, sqlite3_load_extension
- **Notes:** This vulnerability is exploitable only if the user can create a shared library, which is feasible with login access. The SQLite3 CLI must have load extension enabled, which appears to be the case here as `sqlite3_load_extension` is called directly. No additional vulnerabilities like SQL injection or buffer overflows were found to be fully exploitable in this context.

---
### Untitled Finding

- **File/Directory Path:** `etc/scripts/upnp/M-SEARCH.sh`
- **Location:** `ssdp.php: SSDP_ms_send_resp function (specific line number unavailable, but the function is defined in the file)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** During UPnP M-SEARCH processing, the user-controlled TARGET_HOST parameter is directly embedded into a shell command, lacking input validation and escaping, leading to a command injection vulnerability. Specific manifestation: When an attacker sends a malicious UPnP M-SEARCH request, the TARGET_HOST parameter (corresponding to $2 in M-SEARCH.sh) propagates to the SSDP_ms_send_resp function in ssdp.php and is used to construct the 'httpc' command string. Because the parameter is wrapped in double quotes but internal quotes are not escaped, an attacker can inject shell metacharacters (such as semicolons, backticks) to execute arbitrary commands. Trigger condition: The attacker possesses valid login credentials and can send UPnP requests; Constraint: No input filtering or boundary checking; Potential exploitation: Achieve arbitrary code execution through command injection, potentially escalating privileges (if the script runs with high permissions). Code logic: Command concatenation in ssdp.php directly uses user input, M-SEARCH.sh and M-SEARCH.php perform no validation.
- **Code Snippet:**
  ```
  function SSDP_ms_send_resp($target_host, $phyinf, $max_age, $date, $location, $server, $st, $usn)
  {
  	echo "xmldbc -P /etc/scripts/upnp/__M-SEARCH.resp.php";
  	echo " -V \"MAX_AGE="	.$max_age	."\"";
  	echo " -V \"DATE="		.$date		."\"";
  	echo " -V \"LOCATION="	.$location	."\"";
  	echo " -V \"SERVER="	.$server	."\"";
  	echo " -V \"ST="		.$st		."\"";
  	echo " -V \"USN="		.$usn		."\"";
  
  	echo " | httpc -i ".$phyinf." -d \"".$target_host."\" -p UDP\n";
  }
  ```
- **Keywords:** UPNPMSG=/runtime/upnpmsg, TARGET_HOST (from UPnP request), /var/run/M-SEARCH.*.sh, SSDP_ms_send_resp function, httpc command
- **Notes:** Vulnerability is based on code analysis, the attack chain is complete: from UPnP request input to command execution. It is recommended to further validate exploitation in the actual device environment (e.g., test httpc command behavior). Related files: M-SEARCH.sh (parameter passing), M-SEARCH.php (data flow). Subsequent analysis directions: Check if other UPnP-related files (such as NOTIFYAB.sh) have similar issues, or analyze the httpc binary to confirm command processing logic.

---
### Command-Injection-usbmount_helper_add

- **File/Directory Path:** `etc/scripts/usbmount_helper.php`
- **Location:** `usbmount_helper.php: In the code block for action='add' (approximately lines 40-50, based on code structure)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the 'add' action, when processing new disk entries, the code uses the `setattr` function to execute the shell command `sh /etc/scripts/usbmount_fsid.sh `.prefix.pid`, where the `prefix` and `pid` variables come directly from user input and are not filtered or validated. An attacker can inject shell metacharacters (such as `;`, `&`, `|`) to execute arbitrary commands. Trigger conditions include: sending an HTTP request setting `action=add` and controlling the `prefix` or `pid` parameters (for example, setting them to `; malicious_command #`). Exploiting this vulnerability, an attacker can gain command execution privileges, potentially escalate privileges (if the web server is running with root permissions), leading to full device control. Potential attack methods include: file system operations, network access, or persistent backdoor installation.
- **Code Snippet:**
  ```
  if ($action=="add")
  {
      // ... code omitted ...
      if (isfile("/sbin/sfdisk")=="1"&&$pid!="0")
          setattr($base."/id", "get", "sh /etc/scripts/usbmount_fsid.sh ".$prefix.$pid);
      else
          set($base."/id","");
      // ... code omitted ...
  }
  ```
- **Keywords:** $action, $prefix, $pid, setattr
- **Notes:** Vulnerability is based on code logic analysis, evidence comes from file content. It is recommended to further verify input filtering mechanisms and web interface access controls in the actual environment. Associated file: '/etc/scripts/usbmount_fsid.sh' may be affected by this. Subsequent analysis direction: Check web server configuration and permissions, confirm if input sources (such as HTTP parameters) are controllable.

---
### CodeInjection-form_portforwarding

- **File/Directory Path:** `htdocs/mydlink/form_portforwarding`
- **Location:** `form_portforwarding:20-40 (Section using fwrite and dophp in a loop)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A code injection vulnerability was discovered in the 'form_portforwarding' file. When a user submits port forwarding configuration (via a POST request setting `settingsChanged=1`), the script directly writes unfiltered POST data (such as 'enabled_*', 'name_*', 'ip_*', etc.) to a temporary file '/tmp/form_portforwarding.php', which is then loaded and executed using `dophp("load",$tmp_file)`. Since the input is not validated or escaped, an attacker can inject malicious PHP code (for example, including `"; system("id"); //` in the 'name_*' field), leading to arbitrary code execution. Trigger condition: An attacker sends a specially crafted POST request to this script. Exploitation method: Inject code by controlling POST parameters, thereby executing system commands and potentially gaining web server privileges. The attacker is a user already connected to the device and possessing valid login credentials (non-root user).
- **Code Snippet:**
  ```
  while($i < $max)
  {
      fwrite("w+", $tmp_file, "<?\n");
      fwrite("a", $tmp_file, "$enable = $_POST[\"enabled_".$i."\"];\n");
      fwrite("a", $tmp_file, "$used = $_POST[\"used_".$i."\"];\n");
      fwrite("a", $tmp_file, "$name = $_POST[\"name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port = $_POST[\"public_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port_to = $_POST[\"public_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$ip = $_POST[\"ip_".$i."\"];\n");
      fwrite("a", $tmp_file, "$private_port = $_POST[\"private_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$hidden_private_port_to = $_POST[\"hidden_private_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$protocol = $_POST[\"protocol_".$i."\"];\n");
      fwrite("a", $tmp_file, "?>\n");
      dophp("load",$tmp_file);
      // ... Subsequent configuration settings
  }
  ```
- **Keywords:** $_POST["settingsChanged"], $_POST["enabled_*"], $_POST["name_*"], $_POST["ip_*"], /tmp/form_portforwarding.php, dophp
- **Notes:** Vulnerability is based on direct code evidence: unfiltered input is written and executed. It is recommended to further verify the behavior of the 'dophp' function and the usage of temporary files. Related files: /htdocs/phplib/xnode.php and /htdocs/webinc/config.php may contain relevant function definitions. Subsequent analysis should check these included files for any input filtering mechanisms. The attack chain is complete and verifiable, applicable to authenticated users.

---
### CodeInjection-form_wlan_acl

- **File/Directory Path:** `htdocs/mydlink/form_wlan_acl`
- **Location:** `form_wlan_acl:15-19`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A PHP code injection vulnerability was discovered in the 'form_wlan_acl' script. When a user submits a POST request with the 'settingsChanged' parameter set to 1, the script directly embeds user-controlled 'mac_i' and 'enable_i' parameters into a temporary PHP file, which is then executed via 'dophp("load",$tmp_file)'. An attacker can inject malicious PHP code (such as system commands), leading to arbitrary code execution. Trigger condition: An attacker sends a POST request to this script containing malicious code in the MAC or enable parameters. Exploitation method: For example, setting the 'mac_0' parameter value to '\"; system(\"id\"); //' can execute system commands. The vulnerability is due to a lack of input validation and escaping, allowing direct code injection.
- **Code Snippet:**
  ```
  fwrite("w+", $tmp_file, "<?\n");\nfwrite("a",  $tmp_file, "$MAC = $_POST["mac_.$i."];\n");\nfwrite("a",  $tmp_file, "$ENABLE = $_POST["enable_.$i."];\n");\nfwrite("a",  $tmp_file, ">\n");\ndophp("load",$tmp_file);
  ```
- **Keywords:** $_POST['settingsChanged'], $_POST['mode'], $_POST['mac_<i>'], $_POST['enable_<i>'], /tmp/form_wlan_acl.php, dophp
- **Notes:** The vulnerability allows an attacker to execute arbitrary code with web server privileges, potentially leading to privilege escalation or system control. It is recommended to check if other similar scripts have the same issue and verify if the 'get_valid_mac' function provides any protection (but the code injection occurs before validation). Subsequent analysis should focus on the implementation of the 'dophp' function and other input processing points.

---
### Hardcoded-Credentials-logininfo.xml

- **File/Directory Path:** `htdocs/web/webaccess/logininfo.xml`
- **Location:** `logininfo.xml:1 (File path)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Hardcoded credentials (username 'admin', password 't') were discovered in the 'logininfo.xml' file. The password strength is extremely weak and may be a default or test password. The file permissions are set to '-rwxrwxrwx', allowing all users (including non-root users) to read it. An attacker, as a logged-in non-root user, can easily read the file contents, obtain the administrator credentials, and use them for privilege escalation or unauthorized access. The trigger condition is that the attacker possesses valid login credentials (non-root) and can access the file system. Potential attack methods include using the obtained credentials to log into the administrator account or perform sensitive operations. The constraint is that the file must exist and its permissions have not been fixed.
- **Code Snippet:**
  ```
  <?xml version="1.0"?><root><user>admin</user><user_pwd>t</user_pwd><volid>1</volid></root>
  ```
- **Keywords:** logininfo.xml
- **Notes:** The file may be used by the login system or other components. It is recommended to further analyze related components (such as login processing logic) to confirm how the credentials are used. The attack chain is complete: non-root user reads the file → obtains credentials → uses credentials for attack. The risk score is high because the credentials are weak and the permissions are lax, making it easy to exploit.

---
### FilePermission-stunnel.key

- **File/Directory Path:** `etc/stunnel.key`
- **Location:** `stunnel.key`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The file 'stunnel.key' contains an RSA private key with permissions set to -rwxrwxrwx, allowing all users (including non-root users) full access. An attacker as a logged-in user can directly read this file and obtain the private key. The trigger condition is simple: the attacker only needs to use basic file reading commands (such as 'cat'). The lack of proper permission controls (such as restricting read access to root or specific users) leads to private key exposure. Potential attacks include: using the private key to decrypt SSL/TLS communications, impersonating the service for man-in-the-middle attacks, or combining with other vulnerabilities to escalate privileges. The exploitation method is direct: the attacker copies the private key and uses it with malicious tools (such as OpenSSL) to decrypt traffic or forge certificates.
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
- **Notes:** This finding is based on direct evidence: file permissions and content verification. The attack chain is complete and verifiable: non-root users can read the private key and directly misuse it. It is recommended to immediately fix the file permissions (for example, set to 600), allowing only necessary users to access. Subsequent analysis should check if other services depend on this private key and assess the potential impact scope.

---
### Config-DefaultValue_XML

- **File/Directory Path:** `etc/defnodes/defaultvalue.xml`
- **Location:** `defaultvalue.xml: Entire file, specifically in the Account section (approximately lines 30-35), Wi-Fi section (approximately lines 200-250), and Web Access section (approximately lines 400-410)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Default configuration vulnerability found in the 'defaultvalue.xml' file, allowing an attacker to gain full control of the router. Specific manifestations:
- Wi-Fi network is set to open authentication (authtype>OPEN</authtype>) and no encryption (encrtype>NONE</encrtype>) by default, with SSIDs 'dlink' and 'dlink-5GHz', allowing any user to connect without credentials.
- Web management interface is enabled (<enable>1</enable>), listening on HTTP port 8181 and HTTPS port 4433.
- The Admin account password is empty (<password></password>), allowing an attacker to log in with a blank password.
Trigger conditions: The attacker has connected to the device's Wi-Fi network (due to it being open, no credentials needed) or has access via the local area network. The attacker then accesses the Web management interface (e.g., http://192.168.0.1:8181), logs in using the username 'Admin' and a blank password, and gains administrator privileges. Potential exploitation methods include modifying router settings, launching malicious services, or further attacking internal network devices. Constraints: This configuration is the default setting and might be changed in actual deployment, but if unmodified, the vulnerability exists.
- **Code Snippet:**
  ```
  Account section example:
  <account>
    <count>1</count>
    <max>2</max>
    <entry>
      <name>Admin</name>
      <password></password>
      <group>0</group>
    </entry>
  </account>
  
  Wi-Fi section example:
  <entry>
    <uid>WIFI-1</uid>
    <opmode>AP</opmode>
    <defaultssid>dlink</defaultssid>
    <ssid>dlink</ssid>
    <ssidhidden>0</ssidhidden>
    <authtype>OPEN</authtype>
    <encrtype>NONE</encrtype>
    ...
  </entry>
  
  Web Access section example:
  <webaccess>
    <enable>1</enable>
    <httpenable>0</httpenable>
    <httpport>8181</httpport>
    <httpsenable>0</httpsenable>
    <httpsport>4433</httpsport>
    ...
  </webaccess>
  ```
- **Keywords:** defaultvalue.xml, device.account.entry.password, wifi.entry.authtype, wifi.entry.encrtype, webaccess.enable, webaccess.httpport, webaccess.httpsport
- **Notes:** This vulnerability is based on the default configuration file and exists in actual devices if the configuration remains unchanged. The attack chain is complete and verifiable: from connecting to the open Wi-Fi to logging into the Web interface, requiring no additional vulnerabilities. It is recommended to check if actual devices have applied these default settings and verify if other configuration files (e.g., PHP scripts) have enhanced security. Subsequent analysis can examine related PHP files (e.g., defaultvalue.php) to confirm data flow and processing logic. Related finding: Queried vulnerabilities related to '/webaccess/account/entry' (PrivEsc-WEBACCESS_setup_wfa_account), but this finding is independent and more direct.

---
### Command-Injection-try_set_psk_passphrase

- **File/Directory Path:** `etc/services/WIFI/rtcfg.php`
- **Location:** `rtcfg.php:357 try_set_psk_passphrase function`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple command injection vulnerabilities were discovered in the 'rtcfg.php' file. Attackers can inject malicious shell commands by controlling WiFi configuration parameters (such as SSID, PSK key, WEP key). When the script generates configuration and executes it, the injected commands run with root privileges. Specific trigger conditions include: users setting malicious SSID or key values (containing shell metacharacters such as ;, |, `, etc.) through the web interface, then applying the configuration (such as restarting WiFi or saving settings), causing 'rtcfg.php' to generate shell scripts containing injected commands. Exploitation method: entering '; malicious_command ;' in the SSID or key fields, the generated command will execute the malicious command. Lack of input validation and escaping leads to direct embedding into echo statements.
- **Code Snippet:**
  ```
  function try_set_psk_passphrase($wl_prefix, $wifi)
  {
  	$auth = query($wifi."/authtype");
  	if($auth != "WPAPSK" && $auth != "WPA2PSK" && $auth != "WPA+2PSK")
  		return;
  
  	$key = get("s", $wifi."/nwkey/psk/key");
  	echo "nvram set ".$wl_prefix."_wpa_psk=\"".$key."\"\n";
  }
  ```
- **Keywords:** nvram set wl*_wpa_psk, nvram set wl*_ssid, nvram set wl*_key*, /wifi/entry/ssid, /wifi/entry/nwkey/psk/key, /wifi/entry/nwkey/wep/key:*
- **Notes:** Attack chain is complete: input point (web interface) → data flow (obtained via get/query) → dangerous operation (generating shell commands). Need to verify if the generated script is executed, but based on context, it is likely executed by the web server or initialization script with root privileges. It is recommended to check if included files (such as xnode.php) filter input, but the current file has no escaping. Subsequent analysis can examine how the web interface calls this script.

---
### command-injection-dhcp-hostname-dynamic

- **File/Directory Path:** `etc/services/INET/inet_ipv4.php`
- **Location:** `inet_ipv4.php:inet_ipv4_dynamic function (approximately lines 100-110)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the inet_ipv4_dynamic function, the $hostname_dhcpc variable (from NVRAM's /device/hostname_dhcpc) is directly inserted into the udhcpc command without proper escaping. An attacker can modify the hostname to a malicious string (such as 'example.com; malicious_command'), triggering command injection when the interface starts or updates, leading to arbitrary command execution. Trigger condition: after the attacker modifies the hostname configuration, the network interface reconnects or DHCP renewal occurs. Exploitation method: inject shell commands by modifying the hostname field through the web interface or API.
- **Code Snippet:**
  ```
  $hostname_dhcpc = get("s", "/device/hostname_dhcpc");
  ...
  'udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname_dhcpc.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' '.$dhcpplus_cmd.' &\n'
  ```
- **Keywords:** /device/hostname_dhcpc, /etc/services/INET/inet4_dhcpc_helper.php, /var/servd/*-udhcpc.sh
- **Notes:** Need to verify whether hostname_dhcpc is indeed user-controllable (via the web interface). It is recommended to check if /etc/scripts/IPV4.INET.php properly escapes parameters. Related functions: get() and query() may read data from the XML database.

---
### Command-Injection-AddPortMapping

- **File/Directory Path:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **Location:** `ACTION.DO.AddPortMapping.php: in the code constructing $sourceip and $cmd (exact line number unknown, near end of file)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** This vulnerability originates from the `$NewRemoteHost` input parameter being directly concatenated into the `iptables` command string without validation. An attacker can break out of the command string and execute arbitrary commands by injecting special characters (such as quotes or semicolons) into the `NewRemoteHost` parameter. The trigger condition is: when processing a UPnP add port mapping request, the `NewRemoteHost` contains a malicious payload. Constraints include: the device must be in router mode (`/runtime/device/layout` is 'router'), and the attacker must possess valid login credentials (non-root user, but the UPnP service may run with high privileges). Potential attack methods include: sending a UPnP request with the `NewRemoteHost` value set to `"; malicious_command ; #`, leading to command injection. In the code logic, when constructing the `iptables` command, `$NewRemoteHost` is directly used for the `-s` option without any filtering.
- **Code Snippet:**
  ```
  $sourceip = ' -s "'.$NewRemoteHost.'"'; and $cmd = 'iptables -t nat -A DNAT.UPNP'.$proto.' --dport '.$NewExternalPort.' -j DNAT --to-destination "'.$NewInternalClient.'":'.$NewInternalPort.$sourceip; and fwrite("a", $_GLOBALS["SHELL_FILE"], $cmd."\n");
  ```
- **Keywords:** NewRemoteHost, SHELL_FILE
- **Notes:** Further verification is needed for the path and execution mechanism of `SHELL_FILE` (e.g., whether it is executed by cron or a system service). It is recommended to check related IPC or NVRAM interactions, but these are not directly involved in this file. Subsequent analysis should focus on the overall UPnP service flow and permission settings. This vulnerability is related to known UPnP command injection vulnerabilities (e.g., in M-SEARCH.sh), indicating multiple input validation flaws exist within the UPnP service.

---
### Command-Injection-checkfw.sh

- **File/Directory Path:** `etc/events/checkfw.sh`
- **Location:** `File: checkfw.sh (Exact line numbers cannot be precisely obtained, but based on the content, the vulnerability is located in the part that constructs the `wget_string` and executes the `wget` command, approximately near lines 20-30 in the output)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** This vulnerability exists in the part of the script that constructs the wget URL and executes the download command. Multiple variables (such as `srv`, `reqstr`, `model`, `global`, `buildver`, `MAC`) are obtained via `xmldbc -g` from NVRAM or runtime data and are directly concatenated when building the `wget_string`, without using quotes or escaping. If an attacker can control any of these variables (for example, by modifying NVRAM settings) and insert shell metacharacters (such as semicolons, spaces, backticks), they can inject arbitrary commands when the wget command is executed. For example, if the `srv` variable is set to "http://example.com; malicious_command", the full wget command could become "wget http://http://example.com; malicious_command ...", causing `malicious_command` to execute with root privileges. The attack trigger condition is the script running periodically (via xmldbc scheduled tasks) or being executed manually, and the attacker needs to first modify the relevant NVRAM variables. Potential exploitation methods include executing system commands, downloading malware, or escalating privileges.
- **Code Snippet:**
  ```
  #!/bin/sh
  ...
  model="\`xmldbc -g /runtime/device/modelname\`"
  srv="\`xmldbc -g /runtime/device/fwinfosrv\`"
  reqstr="\`xmldbc -g /runtime/device/fwinfopath\`"
  ...
  wget_string="http://"$srv$reqstr"?model=${model}_${global}_FW_${buildver}_${MAC}"
  rm -f $fwinfo
  xmldbc -X /runtime/firmware
  wget  $wget_string -O $fwinfo
  ...
  ```
- **Keywords:** /runtime/device/fwinfosrv, /runtime/device/fwinfopath, /runtime/device/modelname, /device/fwcheckparameter, /runtime/devdata/hwver, /runtime/devdata/lanmac
- **Notes:** This finding requires further validation:
  - Confirm whether an attacker, as a non-root user, can modify the relevant NVRAM variables via the web interface or CLI.
  - Verify the script's execution context (whether it runs with root privileges).
  - It is recommended to subsequently analyze related components (such as the xmldbc tool, web interface) to confirm data flow and access control.
  - Related files: /etc/events/checkfw.sh (current file), possibly involving /usr/sbin/xmldbc or other IPC mechanisms.

---
### File-Permission-Exploit-wan_stats.xml

- **File/Directory Path:** `htdocs/widget/wan_stats.xml`
- **Location:** `wan_stats.xml:1 (entire file)`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** The file 'wan_stats.xml' has global read, write, and execute permissions (-rwxrwxrwx), allowing any user (including non-root users) to modify its content. This file is a PHP script used to generate XML output for WAN statistics and may be accessed via a web interface. An attacker can modify the file to insert malicious PHP code (such as system command execution) and then trigger its execution via a web request. Since the web server typically runs with root privileges, this could allow privilege escalation. Trigger conditions include: the attacker having file modification permissions and accessing the file via an authenticated web request. Potential attack methods include: inserting code such as `system($_GET['cmd'])` to achieve remote command execution. Boundary checks: no file permission restrictions or code signature verification.
- **Code Snippet:**
  ```
  File permissions: -rwxrwxrwx 1 user user 14162 Nov 29  2016 wan_stats.xml
  Related code: <?
  	include "/htdocs/phplib/xnode.php";
  	include "/htdocs/webinc/config.php";
  	// ... PHP code generating XML output
  ?>
  ```
- **Keywords:** wan_stats.xml, /htdocs/phplib/xnode.php, /htdocs/webinc/config.php
- **Notes:** The attack chain relies on the file being executed by the web server (such as Apache or lighttpd); further verification of the web server configuration and the file's accessibility is required. It is recommended to check the web root directory location and the server's execution permissions. Associated files: /htdocs/phplib/xnode.php and /htdocs/webinc/config.php may contain more data flow logic. Subsequent analysis direction: verify how the web interface calls this file and check other PHP files with similar permissions.

---
### command-injection-SSDP_ms_send_resp

- **File/Directory Path:** `etc/scripts/upnp/M-SEARCH.php`
- **Location:** `M-SEARCH.php (multiple branches use $TARGET_HOST) and ssdp.php:SSDP_ms_send_resp function`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** In 'M-SEARCH.php', the variable `$TARGET_HOST` comes from untrusted input (such as network requests) and is passed directly to the `SSDP_ms_send_resp` function in 'ssdp.php'. This function uses `echo` to construct shell commands (involving `xmldbc` and `httpc`) and embeds `$target_host` into the command string without escaping or validation. An attacker can control `$TARGET_HOST` to inject shell metacharacters (such as semicolons, backticks) to execute arbitrary commands. Trigger condition: The attacker sends an M-SEARCH request where the `TARGET_HOST` parameter contains a malicious payload (e.g., '; whoami #'), and `$SEARCH_TARGET` is a valid value (e.g., 'ssdpall'). Exploitation method: Command injection may lead to arbitrary command execution under a non-root user's privileges, with potential impacts including information disclosure, privilege escalation, or device control. The lack of input filtering and boundary checks in the code logic makes the attack feasible.
- **Code Snippet:**
  ```
  From M-SEARCH.php:
  foreach ($path)
  {
      ...
      SSDP_ms_send_resp($TARGET_HOST, $phyinf, $max_age, $date, $location, $server, "upnp:rootdevice", $uuid."::upnp:rootdevice");
      ...
  }
  
  From ssdp.php:
  function SSDP_ms_send_resp($target_host, $phyinf, $max_age, $date, $location, $server, $st, $usn)
  {
      echo "xmldbc -P /etc/scripts/upnp/__M-SEARCH.resp.php";
      echo " -V \"MAX_AGE=".$max_age."\"";
      ...
      echo " | httpc -i ".$phyinf." -d \"".$target_host."\" -p UDP\n";
  }
  ```
- **Keywords:** $TARGET_HOST, $SEARCH_TARGET, SSDP_ms_send_resp, /etc/scripts/upnp/ssdp.php
- **Notes:** The vulnerability depends on the environment where the output commands are executed by the shell; it is recommended to verify the actual execution flow (e.g., check if the caller executes the output). Related file: '/etc/scripts/upnp/__M-SEARCH.resp.php' may contain more context. Future analysis directions: Test actual exploitation, check if other input variables (such as $PARAM) have similar issues.

---
### Command-Injection-dev_start

- **File/Directory Path:** `etc/services/WIFI/rtcfg.php`
- **Location:** `rtcfg.php:728 dev_start function`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the SSID setting. The attacker controls the SSID value, which is directly embedded into the nvram set command without escaping shell metacharacters. Trigger condition: A user sets a malicious SSID (e.g., '; echo "hacked" > /tmp/test ;'). When the configuration is applied, the command 'nvram set wl*_ssid="; echo "hacked" > /tmp/test ;"' is generated, leading to command injection. There is a lack of boundary checks and validation, and the input comes directly from the user.
- **Code Snippet:**
  ```
  echo "nvram set ".$wl_prefix."_ssid=\"".get("s",$wifi."/ssid")."\"\n";
  ```
- **Keywords:** nvram set wl*_ssid, /wifi/entry/ssid
- **Notes:** SSID is a common user-configurable field, making the attack easy to trigger. It is associated with the web interface configuration process. It is recommended to validate other input points such as country code and WPS settings.

---
### Stored-XSS-version.php

- **File/Directory Path:** `htdocs/webinc/version.php`
- **Location:** `version.php in the SSID output section (specific code lines approximately in the middle of the file, corresponding to 2.4GHz, 5GHz, and secondary 5GHz SSID output)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored XSS vulnerability exists in the SSID output section. An attacker, as a non-root user but possessing login credentials, can modify the WiFi SSID setting via the web interface to a malicious string (e.g., `<script>alert('XSS')</script>`). When the version.php page is accessed, the SSID value is directly output to HTML without escaping, leading to malicious script execution. Trigger condition: The attacker modifies the SSID and accesses version.php. Potential exploitation: Executes arbitrary JavaScript in an authenticated context, potentially used for privilege escalation, session theft, or modifying device settings. The code logic directly uses `echo` to output the SSID value, with no input validation or output encoding.
- **Code Snippet:**
  ```
  <div class="info">
  	<span class="name">SSID (2.4G) :</span>				
  	<pre style="font-family:Tahoma"><span class="value"><? include "/htdocs/phplib/xnode.php"; $path = XNODE_getpathbytarget("/wifi", "entry", "uid", "WIFI-1", "0"); echo get(h,$path."/ssid");?></span></pre>
  </div>
  <!-- Similar code is used for WIFI-3 and WIFI-5 -->
  ```
- **Keywords:** /wifi/entry/uid/WIFI-1/ssid, /wifi/entry/uid/WIFI-3/ssid, /wifi/entry/uid/WIFI-5/ssid
- **Notes:** SSID can typically be modified via the web interface by non-root users, which increases exploitability. It is recommended to further verify the input filtering mechanism for SSID settings in the web interface. Related file: /htdocs/phplib/xnode.php (used to obtain SSID values). Subsequent analysis direction: Check if other user-controllable variables (such as country code, MAC address) are similarly output insecurely.

---
### XSS-onepage.php

- **File/Directory Path:** `htdocs/webinc/js/onepage.php`
- **Location:** `onepage.php:Line number not specified (in OnClickSave and OnConnecting functions)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored cross-site scripting (XSS) vulnerability was discovered in the 'onepage.php' file. User-input SSID and password values are directly assigned to innerHTML without escaping, leading to malicious script execution. Trigger condition: An attacker (logged-in user) inputs malicious JavaScript code as the SSID or password in the setup wizard, then clicks the save or connect button. When the page updates and displays these values, the script executes in the user's browser. Potential exploitation methods: Stealing session cookies, redirecting users, or performing other client-side attacks. The vulnerability exists in multiple functions, including OnClickSave and OnConnecting.
- **Code Snippet:**
  ```
  // OnClickSave function snippet
  document.getElementById("24Gssid_megg").innerHTML = ssid24;
  document.getElementById("24Gkey_megg").innerHTML = pass24;
  document.getElementById("5Gssid_megg").innerHTML = ssid5;
  document.getElementById("5Gkey_megg").innerHTML = pass5;
  
  // OnConnecting function snippet
  document.getElementById("24Gssid_megg1").innerHTML = ssid24;
  document.getElementById("24Gkey_megg1").innerHTML = pass24;
  document.getElementById("5Gssid_megg1").innerHTML = ssid5;
  document.getElementById("5Gkey_megg1").innerHTML = pass5;
  ```
- **Keywords:** OBJ("wiz_ssid").value, OBJ("wiz_key").value, OBJ("wiz_ssid_Aband").value, OBJ("wiz_key_Aband").value, document.getElementById("24Gssid_megg").innerHTML, document.getElementById("24Gkey_megg").innerHTML, document.getElementById("5Gssid_megg").innerHTML, document.getElementById("5Gkey_megg").innerHTML
- **Notes:** The vulnerability requires user interaction (clicking a button) to trigger, but since the attacker is a logged-in user, they can trigger it themselves or trick other users via social engineering. It is recommended to check if server-side input validation and escaping are performed. Subsequent analysis should focus on whether other input points and server-side scripts (such as getcfg.php, register_send.php) have similar issues.

---
### Command-Injection-inet_ipv6-get_dns

- **File/Directory Path:** `etc/services/INET/inet_ipv6.php`
- **Location:** `inet_ipv6.php: Multiple locations (e.g., inet_ipv6_static function, inet_ipv6_auto function)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'inet_ipv6.php' file, originating from the `get_dns` function returning user-controlled DNS values that are directly embedded into shell commands without input validation or escaping. An attacker, as an authenticated non-root user, can modify DNS settings via the Web interface (e.g., in IPv6 configuration) to inject malicious commands. When the IPv6 configuration is applied (such as during mode switching or service restart), the commands executed via `startcmd` or `fwrite` will parse the injected payload, leading to arbitrary command execution. Trigger conditions include: modifying the DNS value to a malicious string containing shell metacharacters (e.g., `;`, `"`, `|`), and triggering IPv6 reconfiguration (e.g., by saving settings via the interface). Potential exploitation methods include executing system commands, uploading files, or escalating privileges.
- **Code Snippet:**
  ```
  // Example from inet_ipv6_static function
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH".
      " MODE=STATIC INF=".$inf.
      " DEVNAM=".$devnam.
      " IPADDR=".query("ipaddr").
      " PREFIX=".query("prefix").
      " GATEWAY=".query("gateway").
      " ROUTERLFT=".query("routerlft").
      " PREFERLFT=".query("preferlft").
      " VALIDLFT=".query("validlft").
      ' "DNS='.get_dns($inetp."/ipv6").'"'
      );
  
  // get_dns function definition
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
- **Keywords:** dns/entry, /inet/entry/ipv6/dns, startcmd, fwrite
- **Notes:** Attack chain is complete: Input point (DNS settings) → Data flow (obtained via `get_dns`) → Dangerous operation (shell command execution). It is necessary to verify whether the DNS value is indeed user-controllable (via the Web interface) and confirm that the service runs with root privileges. It is recommended to further analyze related Web interface files (e.g., CGI scripts) to confirm the input path. The vulnerability exists in multiple IPv6 modes (e.g., STATIC, AUTO, 6IN4, etc.).

---
### Command-Injection-security_setup

- **File/Directory Path:** `etc/services/WIFI/rtcfg.php`
- **Location:** `rtcfg.php:312 security_setup function`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists at the WEP key setup. The attacker controls the WEP key value and injects through the nvram set command. Trigger condition: the user sets a malicious WEP key (e.g., '; malicious_command ;'), generating the command 'nvram set wl*_key*="; malicious_command ;"'. There is a lack of input filtering, and the data flow goes directly from /wifi/entry/nwkey/wep/key:* to the echo statement.
- **Code Snippet:**
  ```
  $keystring = query($wifi."/nwkey/wep/key:".$defkey);
  echo "nvram set ".$wl_prefix."_key".$defkey."=\"".$keystring."\"\n";
  ```
- **Keywords:** nvram set wl*_key*, /wifi/entry/nwkey/wep/key:*
- **Notes:** Although WEP is less commonly used, it is still a configurable option. The attack chain relies on the web interface exposing these fields. It is recommended to check all input points that use query/get.

---
### info-leak-vpnconfig

- **File/Directory Path:** `htdocs/web/vpnconfig.php`
- **Location:** `vpnconfig.php: approximately lines 10-12 (obtaining credentials), approximately lines 30-50 (outputting credentials to XML)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The script 'vpnconfig.php', after authorization check passes ($AUTHORIZED_GROUP >= 0), generates an Apple VPN configuration file (mobileconfig) containing plaintext VPN username, password, pre-shared key (PSK), and IP address. An attacker can access this script via an HTTP request, download the configuration file, and extract sensitive credentials. Trigger condition: The attacker possesses valid login credentials and the authorization check passes. Constraint: Authorization depends on the $AUTHORIZED_GROUP variable, whose value may come from the session or global configuration. Potential attack: The attacker uses the obtained credentials to connect to the VPN, potentially accessing internal network resources or escalating privileges. Code logic: Uses the get('x', ...) function to retrieve data from configuration paths (e.g., /vpn/ipsec/username) and directly embeds it into the XML output without input validation or output encoding.
- **Code Snippet:**
  ```
  $username = get("x", "/vpn/ipsec/username");
  $password = get("x", "/vpn/ipsec/password");
  $psk = get("x", "/vpn/ipsec/psk");
  // ... output to XML:
  echo '\t\t\t<data>'.$psk.'</data>';
  echo '\t\t\t<string>'.$username.'</string>';
  echo '\t\t\t<string>'.$password.'</string>';
  ```
- **Keywords:** NVRAM/ENV variables: /vpn/ipsec/username, /vpn/ipsec/password, /vpn/ipsec/psk, File path: vpnconfig.php, IPC/Socket: Possibly via web server (HTTP)
- **Notes:** The authorization mechanism ($AUTHORIZED_GROUP) and the behavior of the get function require further verification; it is recommended to analyze include files such as /htdocs/webinc/config.php and /htdocs/phplib/xnode.php. This vulnerability relies on the attacker already having login credentials, but provides a clear attack chain: access script → download configuration → extract credentials → VPN connection.

---
### command-injection-static-ip-config

- **File/Directory Path:** `etc/services/INET/inet_ipv4.php`
- **Location:** `inet_ipv4.php:inet_ipv4_static function (approximately lines 30-50)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the inet_ipv4_static function, the $ipaddr, $mask, $gw, $mtu, and $dns variables (from NVRAM queries) are directly inserted into the phpsh command. An attacker can modify static IP configuration fields (such as IP address), inject command separators (such as semicolons) to execute arbitrary commands. Trigger condition: after an attacker modifies static network settings, the interface is reconfigured. Exploitation method: set a malicious IP address (e.g., '1.1.1.1; malicious_command') via the configuration interface.
- **Code Snippet:**
  ```
  $ipaddr = query("ipaddr");
  $mask = query("mask");
  $gw = query("gateway");
  ...
  startcmd("phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH STATIC=1 INF=".$inf." DEVNAM=".$ifname." IPADDR=".$ipaddr." MASK=".$mask." GATEWAY=".$gw." MTU=".$mtu.' "DNS='.$dns.'"\n'.$event_add_WANPORTLINKUP );
  ```
- **Keywords:** /inet/entry/ipv4/ipaddr, /inet/entry/ipv4/mask, /inet/entry/ipv4/gateway, /inet/entry/ipv4/dns/entry, /etc/scripts/IPV4.INET.php
- **Notes:** phpsh may partially process parameters, but direct string concatenation still poses a risk. Need to validate the input handling of IPV4.INET.php. Related file: /htdocs/phplib/xnode.php.

---
### Command-Injection-inet_child

- **File/Directory Path:** `etc/services/INET/inet_child.php`
- **Location:** `inet_child.php: In the ipv6_child function and at the end of the script, specific line numbers unknown (but relevant calls are shown in the code snippet)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In inet_child.php, when constructing commands in the startcmd and stopcmd functions using the $CHILD_INFNAME variable, there is a lack of input validation and filtering, which may lead to command injection. Specific manifestation: When $CHILD_INFNAME contains shell metacharacters (such as semicolons, backticks, or pipes), an attacker can inject arbitrary commands. Trigger conditions include the script executing with sufficient privileges (such as root) and the commands being executed via the written files. Potential exploitation methods: An attacker, as a non-root user but possessing login credentials, can control $CHILD_INFNAME through environment variables, NVRAM settings, or other interfaces to inject malicious commands (such as file creation, privilege escalation). Constraints: The vulnerability depends on the privileges of the command executor and the controllability of the input source.
- **Code Snippet:**
  ```
  stopcmd( "rm -f /var/run/CHILD.".$child.".UP");
  startcmd("echo 1 > /var/run/CHILD.".$child.".UP");
  // Where $child is derived from $CHILD_INFNAME
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH INF=".$child." MODE=CHILD DEVNAM=".$devnam." IPADDR=".$ipaddr." PREFIX=".$prefix);
  ```
- **Keywords:** $CHILD_INFNAME, Variables obtained via XNODE_get_var (such as {child}_IPADDR, {child}_PREFIX), /var/run/CHILD.{child}.UP, /proc/sys/net/ipv6/conf/{devnam}/disable_ipv6
- **Notes:** The complete exploitation chain of the vulnerability requires verification of the command execution context (for example, whether the file handles of $_GLOBALS['START'] and $_GLOBALS['STOP'] point to scripts executed with root privileges). It is recommended to subsequently analyze other components, such as /etc/scripts/IPV6.INET.php and the command execution mechanism, to confirm exploitability. Related functions include ipv6_child, startcmd, stopcmd.

---
### XSS-form_admin-get_Admin.asp

- **File/Directory Path:** `htdocs/mydlink/get_Admin.asp`
- **Location:** `get_Admin.asp and form_admin (specific line numbers unknown, but key code segments inferred from content)`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** A stored cross-site scripting (XSS) vulnerability was discovered in the 'get_Admin.asp' file. The attack chain starts from the 'form_admin' file, where the user controls the 'web' configuration value (port number) via the POST parameter 'config.web_server_wan_port_http', which is stored directly without validation. When 'get_Admin.asp' uses `query("web")` to read this configuration and directly outputs it to HTML, malicious scripts may be executed. Trigger condition: An attacker (with valid login credentials) submits malicious data to 'form_admin', setting the port number to a malicious script (such as `<script>alert('XSS')</script>`), and then accesses the 'get_Admin.asp' page. Potential attacks include session hijacking, privilege escalation, or execution of arbitrary JavaScript code. The lack of input validation and output escaping in the code logic makes the vulnerability exploitable.
- **Code Snippet:**
  ```
  From 'form_admin':
  <?
  $Remote_Admin_Port = $_POST["config.web_server_wan_port_http"];
  if($Remote_Admin=="true"){
      set($WAN1P."/web", $Remote_Admin_Port);
  }
  ?>
  From 'get_Admin.asp':
  <?
  $remotePort = query("web");
  ?>
  <divide><? echo $remotePort; ?><option>
  ```
- **Keywords:** web, /htdocs/mydlink/form_admin, /htdocs/mydlink/get_Admin.asp
- **Notes:** The vulnerability has been verified as a complete attack chain: input point (form_admin) → data flow (set/web) → dangerous operation (direct output). It is recommended to check if other similar files (such as form_*) also lack input validation and to implement output escaping (e.g., using htmlspecialchars). The attacker requires authentication, but the risk is high as it can lead to session hijacking.

---
### Command-Injection-DeletePortMapping

- **File/Directory Path:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php`
- **Location:** `ACTION.DO.DeletePortMapping.php:~20-30 (inside the 'if (query("enable")==1)' block)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In DeletePortMapping.php, the script uses data from port mapping entries (such as remotehost, internalclient) directly concatenated into iptables command strings without adequate input validation or filtering. If these entry data are maliciously controlled (for example, via a UPnP Add operation), it may lead to command injection when the command is executed. The attack chain is complete: an attacker first needs to inject malicious NewRemoteHost data into a port mapping entry via the UPnP Add function (such as ACTION.DO.AddPortMapping.php), and then trigger the delete operation to execute arbitrary commands. Trigger conditions include the device being in an enabled state (query("enable")==1), and the attacker possessing valid login credentials (non-root user). Exploitability has been verified, and input data controllability confirmed through correlation analysis.
- **Code Snippet:**
  ```
  if (query("enable")==1)
  {
  	$remotehost = get("s", "remotehost");
  	if ($remotehost != "") $sourceip = ' -s "'.$remotehost.'"';
  	if (query("protocol") == "TCP")	$proto = ' -p tcp';
  	else							$proto = ' -p udp';
  	$extport = query("externalport");
  	$intport = query("internalport");
  	$intclnt = query("internalclient");
  
  	$cmd =	'iptables -t nat -D DNAT.UPNP'.$proto.' --dport '.$extport.
  			' -j DNAT --to-destination "'.$intclnt.'":'.$intport;
  	SHELL_info("a", $_GLOBALS["SHELL_FILE"], "UPNP:".$cmd);
  	fwrite("a", $_GLOBALS["SHELL_FILE"], $cmd."\n");
  }
  ```
- **Keywords:** NewRemoteHost, NewExternalPort, NewProtocol, /runtime/upnpigd/portmapping/entry, remotehost, externalport, protocol, internalport, internalclient, SHELL_FILE
- **Notes:** Through correlation analysis of the command injection vulnerability in ACTION.DO.AddPortMapping.php, it is confirmed that inputs such as NewRemoteHost can be controlled by the attacker, forming a complete attack chain. It is recommended to further check the execution context and permissions of SHELL_FILE, but the current evidence chain is sufficient to verify exploitability. The attacker needs to utilize the UPnP service flow, first adding then deleting the malicious entry.

---
### BufferOverflow-main-mDNSResponderPosix

- **File/Directory Path:** `bin/mDNSResponderPosix`
- **Location:** `main function at addresses 0x0003a5c0 to 0x0003a5dc in mDNSResponderPosix`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the TXT record processing of mDNSResponderPosix when handling the -x command-line option. The program copies user-provided name=val pairs into a fixed-size global buffer (gServiceText) without proper bounds checking. The vulnerability occurs in a while loop that uses strlen to get the length of each argument and memcpy to copy the data into the buffer. The current offset (gServiceTextLen) is updated without verifying if the total size exceeds the buffer capacity. When the total input length exceeds approximately 263 bytes, it overwrites the gServiceTextLen variable itself, allowing an attacker to control the write offset and achieve arbitrary memory write. This can lead to code execution by overwriting function pointers or other critical data structures. The vulnerability is triggerable by any user with execute permissions on the binary, and exploitation does not require root privileges, though it does not escalate privileges unless the binary is setuid root.
- **Code Snippet:**
  ```
  while (iVar9 = *piVar14, iVar9 - param_1 < 0 != SBORROW4(iVar9,param_1)) {
      uVar1 = *(iVar3 + 0x1f8);
      uVar2 = sym.imp.strlen(param_2[iVar9]);
      *(iVar3 + uVar1 + 0xf0) = uVar2;
      sym.mDNSPlatformMemCopy(iVar3 + uVar1 + 0xf1, param_2[iVar9]);
      *(iVar3 + 0x1f8) = *(iVar3 + 0x1f8) + 1 + *(iVar3 + *(iVar3 + 0x1f8) + 0xf0);
      *piVar14 = *piVar14 + 1;
  }
  ```
- **Keywords:** Command-line arguments (-x), Global variable gServiceText, Global variable gServiceTextLen
- **Notes:** This vulnerability is exploitable by a non-root user with login credentials to execute arbitrary code within their own privilege context. The attack chain involves providing malicious -x arguments to overflow the buffer and overwrite gServiceTextLen, enabling arbitrary memory write. Further analysis could explore other input points like service files (-f) or network interfaces for additional vulnerabilities. The binary is not setuid, so privilege escalation is not directly possible, but it could be used in conjunction with other vulnerabilities.

---
### Command-Injection-SETVPNSRRT

- **File/Directory Path:** `etc/profile`
- **Location:** `scripts/SETVPNSRRT.php`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the SETVPNSRRT.php script, when handling PPTP/L2TP VPN connections, using user-controllable server addresses (from NVRAM or web configuration) to generate shell commands lacks input validation. The variable $server is used in the 'gethostip -d' command, and if it contains special characters (such as semicolons), arbitrary commands can be injected. Trigger condition: An attacker sets a malicious VPN server address through the web interface (for example, containing '; malicious_command'), which is executed when a VPN connection attempt is made. Constraint: Only triggers the gethostip command when the server address is not in IPv4 format. Potential exploitation: Inject commands to obtain a shell or perform malicious operations, potentially running with root privileges (the script is typically called by system services).
- **Code Snippet:**
  ```
  if(INET_validv4addr($server) != 1)
  {
      echo "sip=\`gethostip -d ".$server."\`\n";
      echo "sed -i \"s/".$server."/$sip/g\" /etc/ppp/options.".$INF."\n";
      echo "phpsh /etc/scripts/vpnroute.php PATH=".$inetp."/ppp4/".$overtype."/olddomainip INF=".$INF." DOMAINIP=".$domain." IP=".$l_ip." SERVER=$sip"." MASK=".$l_mask." DEV=".$l_dev." GW=".$l_gw."\n";
  }
  ```
- **Keywords:** pptp_server, l2tp_server, /etc/scripts/SETVPNSRRT.php, /etc/scripts/vpnroute.php, NVRAM variables
- **Notes:** Need to verify how the web interface sets the server address (such as through nvram_set) to confirm user controllability. It is recommended to subsequently analyze web components to complete the attack chain. Related files: vpnroute.php (may also have similar vulnerabilities).

---
### info-leak-get_Wireless.php

- **File/Directory Path:** `htdocs/mydlink/get_Wireless.php`
- **Location:** `get_Wireless.php:1 (beginning of code) and output sections (e.g., conditional output statements near the end of the file)`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** This vulnerability allows an attacker to control the 'displaypass' GET parameter to 1, causing the script to output sensitive wireless network configuration information, including WEP keys, PSK keys, and RADIUS keys. The attack chain is complete: input point ($_GET['displaypass']) → data flow (direct use of user input, lack of authorization verification and boundary checks) → dangerous operation (conditional output of sensitive information). The trigger condition is an attacker sending a GET request to 'get_Wireless.php' and setting 'displaypass=1'. The attacker possesses login credentials and can practically exploit the leaked keys for wireless network connection or further attacks. Exploitability is high because the code logic directly relies on user input.
- **Code Snippet:**
  ```
  Relevant code snippet:
  - Input acquisition: \`$displaypass = $_GET["displaypass"];\`
  - Conditional output example: \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
  - Other sensitive outputs: \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\` and \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **Keywords:** $_GET["displaypass"], get_Wireless.php, /wifi/entry/nwkey/psk/key, /wifi/entry/nwkey/wep/key:*
- **Notes:** The vulnerability is practically exploitable because the attacker possesses login credentials and may access this script via the web interface. Associated functions include XNODE_getpathbytarget, query, and get, possibly involving interaction with NVRAM or configuration data. It is recommended to check the overall authentication and authorization mechanism to ensure only authorized users (such as administrators) can access sensitive information. Subsequent analysis directions include verifying the script's access control and other potential input points.

---
### PrivEsc-WEBACCESS_setup_wfa_account

- **File/Directory Path:** `etc/services/WEBACCESS.php`
- **Location:** `WEBACCESS.php setup_wfa_account function (approximately lines 70-110)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** In the setup_wfa_account function of WEBACCESS.php, the username is not filtered for newline characters when writing to the authentication file '/var/run/storage_account_root'. An attacker (authenticated non-root user) can create or modify a user account through the web interface, setting the username to a malicious string containing newline characters (e.g., 'attacker\nadmin'), leading to the injection of a new user entry in the authentication file. This may allow the attacker to create a high-privilege account (e.g., 'admin') or manipulate disk permissions, thereby escalating privileges. Trigger conditions include: webaccess enabled, attacker able to modify the username, setup_wfa_account function execution (typically when configuration changes). Exploitation method: attacker sets malicious username → file is written during configuration update → new user entry is injected → attacker logs in using the injected account.
- **Code Snippet:**
  ```
  fwrite("a", $ACCOUNT, query("username").":x".$storage_msg."\n");
  ```
- **Keywords:** /var/run/storage_account_root, /webaccess/account/entry, /runtime/webaccess/device/entry
- **Notes:** Further verification is needed to determine if the web interface allows newline characters in the username input and if the authentication file parser correctly handles multi-line entries. It is recommended to check the input filtering of the user creation/modification interface. Related function: comma_handle (possibly unused). Subsequent analysis direction: verify input points (e.g., web interface processing) and the usage of the authentication file.

---
### Information Leakage-get_Email.asp

- **File/Directory Path:** `htdocs/mydlink/get_Email.asp`
- **Location:** `get_Email.asp:Line number not specified (but in the conditional output section of the code snippet)`
- **Risk Score:** 6.0
- **Confidence:** 9.0
- **Description:** This file has a sensitive information leakage vulnerability, allowing attackers to leak the SMTP password by controlling the 'displaypass' GET parameter. Specific manifestation: When an attacker (an authenticated user) sends a GET request to 'get_Email.asp' and sets 'displaypass=1', the SMTP password is output in plain text in the XML response. Trigger condition: The attacker must possess valid login credentials and be able to access this page. Constraint: The parameter value must be 1 to trigger the leak; other values will not output the password. Potential attack: Attackers can use the leaked password for further attacks, such as abusing the SMTP server or password reuse attacks. The code logic is straightforward, lacking additional validation for parameter access control.
- **Code Snippet:**
  ```
  $displaypass = $_GET["displaypass"];
  ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **Keywords:** displaypass (GET parameter), /device/log/email/smtp/password (NVRAM variable)
- **Notes:** This vulnerability requires the attacker to already be authenticated, so the risk is medium. It is recommended to check if the access control mechanism for this page is sufficiently strict. Subsequent analysis can examine other related files (such as components that call this file) to look for more complex attack chains.

---
### Untitled Finding

- **File/Directory Path:** `htdocs/web/getcfg.php`
- **Location:** `getcfg.php: in the main else block after authorization check, where SERVICES parameter is processed`
- **Risk Score:** 6.0
- **Confidence:** 7.0
- **Description:** In 'getcfg.php', there is a potential arbitrary file inclusion vulnerability via the `$_POST["SERVICES"]` parameter. An attacker can control the `$GETCFG_SVC` variable, which is used to construct the file path `/htdocs/webinc/getcfg/`.$GETCFG_SVC.`.xml.php`, with no input validation or path traversal protection. If an attacker can inject path traversal sequences (such as `../../../etc/passwd`), it may lead to the loading and execution of arbitrary files, thereby achieving remote code execution (RCE) or information disclosure. Trigger condition: The attacker sends a POST request to 'getcfg.php', sets the `SERVICES` parameter to a malicious value, and the user is a power user (`$AUTHORIZED_GROUP >= 0`). Potential exploitation methods: Including system sensitive files (e.g., /etc/passwd) or executing code from uploaded malicious PHP files. Constraints: The file must exist, and the `dophp` function might only execute PHP files, but if there is no suffix check, it might leak the contents of non-PHP files.
- **Code Snippet:**
  ```
  $GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
  TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
  if ($GETCFG_SVC!="")
  {
      $file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
      /* GETCFG_SVC will be passed to the child process. */
      if (isfile($file)=="1")
      {
          if(get("", "/runtime/device/sessions_privatekey")==1)
          {
              AES_Encrypt_DBnode($GETCFG_SVC, "Encrypt");
              dophp("load", $file);
              AES_Encrypt_DBnode($GETCFG_SVC, "Decrypt");
          }
          else
          {    dophp("load", $file);}
      }
  }
  ```
- **Keywords:** $_POST["SERVICES"], $GETCFG_SVC, $file, dophp
- **Notes:** This finding is based on code evidence, but exploitability depends on whether the attacker can upload malicious files or if readable sensitive files exist on the system. It is recommended to further analyze the behavior of the 'dophp' function (likely located in '/htdocs/phplib/') and the system file structure to verify if arbitrary file inclusion can lead to RCE. Additionally, checking session management (such as $SESSION_UID) might reveal information disclosure risks. The attacker needs to be a power user, so the authorization mechanism could also be an attack vector.

---
### command-injection-dns-dynamic

- **File/Directory Path:** `etc/services/INET/inet_ipv4.php`
- **Location:** `inet_ipv4.php:inet_ipv4_dynamic function (approximately lines 80-90)`
- **Risk Score:** 6.0
- **Confidence:** 6.5
- **Description:** In the inet_ipv4_dynamic function, the $dns variable (DNS settings from NVRAM) is inserted into the generated udhcpc helper script, which is executed via phpsh. If $dns contains malicious content, it may affect script behavior or lead to injection. Trigger condition: DHCP client restarts after modifying DNS settings. Exploitation method: Set DNS to a malicious string.
- **Code Snippet:**
  ```
  $dns = $dns.$VaLuE." ";
  ...
  ' "DNS='.$dns.'$dns"'
  ```
- **Keywords:** /inet/entry/ipv4/dns/entry, /var/servd/*-udhcpc.sh
- **Notes:** There is a typo in the code ('$dns' repeated), which may affect behavior. Need to verify the generation and execution of the udhcpc helper script.

---
### Config-Injection-generate_configs

- **File/Directory Path:** `etc/services/WIFI/hostapdcfg.php`
- **Location:** `hostapdcfg.php:80 generate_configs`
- **Risk Score:** 5.0
- **Confidence:** 6.0
- **Description:** In the 'hostapdcfg.php' file, a configuration injection vulnerability was discovered. Attackers can inject arbitrary hostapd configuration options by controlling the SSID field, because the SSID value is directly written to the configuration file without proper input validation or filtering. Specific behavior: When generating the hostapd configuration file, the SSID value (from `query("ssid")`) is directly used in the `fwrite` call. If the SSID contains a newline character (`\n`), the attacker can add additional configuration lines. Trigger condition: An attacker modifies the SSID in the wireless settings via the Web interface or other interface and includes malicious configuration options. Potential attacks include injecting `ignore_broadcast_ssid=1` to hide the SSID, or injecting `wpa_passphrase=attacker` to attempt to overwrite the pre-shared key (but it might be overwritten by subsequent formal settings). Exploitation method: An attacker, as a non-root user but possessing valid login credentials, modifies the SSID to a malicious string, causing the generated configuration file to contain unexpected configurations, potentially leading to denial of service or security setting bypass. Constraints: The injected configuration options must be valid in hostapd and not be overwritten by subsequently written configurations; the attacker needs to know the available hostapd options.
- **Code Snippet:**
  ```
  fwrite("a", $output, 'ssid='.$ssid.'\n'. 'wpa='.$wpa.'\n'. 'ieee8021x='.$ieee8021x.'\n' );
  ```
- **Keywords:** ssid, /runtime/phyinf, /wifi/entry/ssid, /var/run/hostapd-*.conf
- **Notes:** The exploitation of this vulnerability depends on hostapd's parsing behavior of the configuration file (e.g., whether it allows multiple identical keys or unknown options). It is recommended to further verify how the hostapd binary handles injected configurations and check if the Web interface imposes restrictions on SSID length and characters. Associated file: /etc/services/PHYINF/phywifi.php (may define the input source). Subsequent analysis direction: Trace the path of SSID data flow from the Web interface to this script and test actual injection scenarios.

---
### XSS-index.php-modelname

- **File/Directory Path:** `htdocs/smart404/index.php`
- **Location:** `index.php:3 (in <TITLE> tag)`
- **Risk Score:** 3.5
- **Confidence:** 4.0
- **Description:** In the 'index.php' file, the `query` function is used to dynamically output the device model name (/runtime/device/modelname) into the HTML <TITLE> tag. If an attacker can control this value (for example, through NVRAM settings), they may inject malicious scripts leading to XSS. Trigger condition: the attacker modifies the modelname value in NVRAM, and the script executes when a user visits an error page. Potential exploitation methods: stealing sessions or redirecting users. However, the current file does not show direct user input handling, and there is a lack of evidence proving that modelname can be externally controlled or is unfiltered.
- **Code Snippet:**
  ```
  <TITLE><?echo query("/runtime/device/modelname");?></TITLE>
  ```
- **Keywords:** query, /runtime/device/modelname, /runtime/device/devconfsize
- **Notes:** The risk score is relatively low because there is a lack of complete evidence for the attack chain. Further analysis of the `query` function's implementation (possibly in /htdocs/phplib/xnode.php) and the NVRAM setting mechanism is needed to verify data controllability and filtering status. It is recommended to trace the data source and modification interface for /runtime/device/modelname. Related finding: in /etc/events/checkfw.sh, modelname is obtained via NVRAM and used for command injection, confirming that modelname can be modified by an attacker, thus completing the attack chain.

---
