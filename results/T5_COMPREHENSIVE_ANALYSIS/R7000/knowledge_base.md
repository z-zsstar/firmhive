# R7000 (9 findings)

---

### Untitled Finding

- **File/Directory Path:** `bin/startcircle`
- **Location:** `startcircle: multiple lines (e.g., line for export TZ, line for $DIR/timetracker -p)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Attack Chain: Non-root users exploit the global write permissions (rwxrwxrwx) of the /mnt/shares/usr/bin directory to replace script-executed binary files (e.g., get_tz, timetracker). When the startcircle script runs with root privileges, it executes these malicious binaries, leading to privilege escalation. Trigger Condition: The attacker is logged into the device and possesses valid credentials (non-root), allowing them to modify files in /mnt/shares/usr/bin. Exploitation Method: The user replaces any binary with malicious code, which is automatically executed with root privileges during system startup or script execution.
- **Code Snippet:**
  ```
  export TZ=\`$DIR/get_tz\`
  [ "x$TZ" = "x" ] && export TZ='GMT8DST,M03.02.00,M11.01.00'
  $DIR/timetracker -p
  $DIR/mdnsd $ip "$ipv6" &
  $DIR/ipsetload circleservers /tmp/circleservers
  ```
- **Keywords:** /mnt/shares/usr/bin/get_tz, /mnt/shares/usr/bin/timetracker, /mnt/shares/usr/bin/mdnsd, /mnt/shares/usr/bin/ipsetload, LD_LIBRARY_PATH, PATH
- **Notes:** Evidence Support: Script content shows execution of multiple binary files; ls -la output shows current directory file permissions are rwxrwxrwx, allowing modification by non-root users. It is recommended to immediately fix directory permissions (e.g., change to root write-only) and verify binary integrity. Subsequent analysis can be performed on specific binaries (e.g., circled, timetracker) to identify other vulnerabilities.

---
### Command-Injection-circled-NVRAM

- **File/Directory Path:** `bin/circled`
- **Location:** `bin/circled: fcn.00011308 and fcn.0000f14c`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'circled' binary due to improper sanitization of the 'circle_download_server' NVRAM variable. The variable is read using popen in function fcn.00011308, trimmed of whitespace (spaces, newlines, tabs) only via fcn.0000eab0, and then passed directly into a wget command executed via system in fcn.0000f14c. This allows a non-root user with login credentials to set the NVRAM variable to include arbitrary commands (e.g., using semicolons or backticks), which are executed with the privileges of the 'circled' process (likely root). The vulnerability is triggered during the firmware update check process when circled attempts to download a loader using the user-controlled URL.
- **Code Snippet:**
  ```
  // From fcn.00011308:
  sym.imp.popen("nvram get circle_download_server", "r");
  sym.imp.fgets(buffer, size, pipe);
  fcn.0000eab0(buffer); // Only trims whitespace
  // Later, call to fcn.0000f14c with buffer as argument
  
  // From fcn.0000f14c:
  sym.imp.snprintf(command_buffer, 0x400, "wget -q -T 10 -O %s %sget_loader.php?DEVID=%s", "/tmp/loader.bin", "http://download.meetcircle.co/dev/firmware/netgear/", buffer);
  sym.imp.system(command_buffer); // Command injection here if buffer contains malicious content
  ```
- **Keywords:** circle_download_server (NVRAM variable), /tmp/loader.bin (file path), /tmp/circled (file path), /mnt/shares/usr/bin/ (directory path)
- **Notes:** The vulnerability requires that the non-root user can set NVRAM variables (which is often possible via web interfaces or CLI commands in similar embedded systems). The 'circled' daemon likely runs with root privileges, so successful exploitation leads to root command execution. Further analysis could verify the exact permissions for NVRAM setting and the privilege level of circled. This finding is based on static analysis; dynamic testing would confirm exploitability.

---
### command-injection-amule-sh-start-restart

- **File/Directory Path:** `etc/aMule/amule.sh`
- **Location:** `amule.sh:start function (specific line number unknown, but inferred from content to be at the points of copying, modifying configuration, and executing commands)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the start and restart functions of the 'amule.sh' script, the user-provided working directory path parameter `$2` is assigned to the `emule_work_dir` variable and is used unquoted in multiple commands, leading to a command injection vulnerability. Specific trigger condition: when the script is called with the 'start' or 'restart' action, an attacker providing a path containing shell metacharacters (such as semicolons, backticks) can inject arbitrary commands. For example, if `emule_work_dir` is set to '/tmp; malicious_command', then a command like 'amuled -c $emule_work_dir &' would be parsed as 'amuled -c /tmp; malicious_command &', executing the malicious command. The vulnerability allows an attacker to execute arbitrary code, potentially escalating privileges (if the script runs with high permissions). Exploitation is simple: the attacker only needs to call the script and provide a malicious parameter.
- **Code Snippet:**
  ```
  start() {
  	emule_work_dir=$1
  	...
  	cp /etc/aMule/amule.conf $emule_work_dir
  	cp /etc/aMule/remote.conf $emule_work_dir
  	cp /etc/aMule/config/*  $emule_work_dir
  	...
  	amuled -c $emule_work_dir &
  }
  restart() {
  	stop
  	start $1
  }
  [ $1 = "start" ] && start $2
  [ $1 = "restart" ] && restart $2
  ```
- **Keywords:** Command line argument $2, Environment variable emule_work_dir
- **Notes:** The vulnerability is practically exploitable with a complete attack chain: input (command line argument) → data flow (variable propagation) → dangerous operation (command execution). It is necessary to verify the script execution context (e.g., whether it runs with root privileges). Subsequent analysis of the script invocation method (e.g., via a service or direct user execution) is recommended to confirm the possibility of privilege escalation. Associated files may include configuration files under /etc/aMule/.

---
### XSS-edit_devicename_sAlert

- **File/Directory Path:** `www/script/opmode.js`
- **Location:** `opmode.js: sAlert function and edit_devicename function`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A stored XSS vulnerability was discovered in the 'opmode.js' file. Attackers can inject malicious scripts by controlling the device name parameter. When a user calls the `edit_devicename` function (for example, through the device name editing interface), the `sAlert` function directly inserts unescaped input using `innerHTML`, leading to arbitrary JavaScript execution. Trigger condition: An attacker sets a malicious device name (containing an XSS payload), which is then triggered when the user views or edits the device name. Exploitation method: Inject scripts such as `<script>alert('XSS')</script>` or more complex malicious code, potentially stealing session cookies or performing unauthorized actions.
- **Code Snippet:**
  ```
  function sAlert(str, callback_ok, callback_cancel, dwidth, anc){
      // ...
      var div1=document.createElement("div");
      div1.innerHTML=str; // Unescaped user input
      // ...
  }
  
  function edit_devicename(name){
      sAlert('<table>...<input type="text" name="new_devname" value="'+name+'" ...>...</table>', check_dev, function(){return false;}, 600, 1);
  }
  ```
- **Keywords:** sAlert function, edit_devicename function, new_devname form field
- **Notes:** This is a client-side XSS vulnerability, but the attacker is logged in and can set stored malicious input. It is recommended to perform HTML escaping on user input. Further verification is needed to determine if the backend also lacks input filtering. Related files may include other pages that use `sAlert`.

---
### BufferOverflow-wps_monitor

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `bin/wps_monitor:0xcc60 (fcn.0000c9d8 strcpy call), bin/wps_monitor:0xc658 (fcn.0000c5b0 sprintf call), bin/wps_monitor:0xdb10 (fcn.0000d4b0 strcpy call)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the wps_monitor binary, multiple buffer overflow vulnerabilities were discovered, primarily due to the use of strcpy and sprintf functions lacking input validation and boundary checks. An attacker, as an authenticated non-root user, can inject overly long strings by controlling NVRAM variables (such as wps_config_command, wps_ifname, lan_hwaddr) or passing malicious parameters to the wps_monitor program. When the program processes these inputs, data is obtained via nvram_get and directly copied to fixed-size stack buffers (e.g., 100 bytes), causing stack buffer overflow. This can overwrite the return address or critical stack data, allowing the attacker to execute arbitrary code. Trigger conditions include: the attacker setting malicious NVRAM values (using nvram_set) or invoking wps_monitor with long parameters; the exploitation method involves crafting carefully designed input strings to control program flow and execute shellcode. The vulnerabilities exist in multiple functions, including fcn.0000c9d8, fcn.0000c5b0, and fcn.0000d4b0, forming a complete attack chain from input points to dangerous operations.
- **Code Snippet:**
  ```
  Decompiled code example from fcn.0000c9d8:
    sym.imp.strcpy(iVar13, puVar12);  // iVar13 points to stack buffer, puVar12 from param_2 or nvram_get
  Decompiled code example from fcn.0000c5b0:
    sym.imp.sprintf(iVar7, *0xc6ac, puVar6, param_3);  // iVar7 is stack buffer, puVar6 and param_3 contain tainted data
  Decompiled code example from fcn.0000d4b0:
    sym.imp.strcpy(fp, src);  // src from lan_ifnames or similar NVRAM variable
  ```
- **Keywords:** NVRAM variables: wps_config_command, wps_ifname, lan_hwaddr, wps_uuid, lan_ifnames, wan_ifnames, Function symbols: nvram_get, nvram_set, strcpy, sprintf, IPC/Network interface: Indirect control via NVRAM settings
- **Notes:** Vulnerabilities are based on decompiled code analysis; evidence shows external inputs flow into dangerous functions via NVRAM or parameters. Complete attack chain: input point (NVRAM variables) -> data flow (nvram_get) -> dangerous operation (strcpy/sprintf without boundary checks) -> potential exploitation (stack overflow). Further validation is needed for exact stack buffer sizes and exploit feasibility, but code patterns indicate high risk. Recommend subsequent testing for actual exploitation and checking other related files such as NVRAM configuration files or startup scripts. No command injection or format string vulnerabilities were found.

---
### XSS-buildText

- **File/Directory Path:** `www/script/highcharts.js`
- **Location:** `highcharts.js:97 function buildText`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** During the text rendering process in Highcharts.js, there exists an XSS vulnerability originating from insufficient validation of user-provided href values when dynamically setting the 'onclick' attribute. When user-controlled text content (such as chart data labels, tooltips, or axis labels) contains a malicious href attribute, this attribute value is extracted and directly concatenated into the 'onclick' handler in the form 'location.href="<user_input>"'. If the user input contains a 'javascript:' URL, arbitrary JavaScript code will be executed when the user clicks the affected element. Attackers can exploit this vulnerability by constructing malicious chart configurations (for example, returning '<a href="javascript:alert('XSS')">Click</a>' in a data label formatter) to trigger XSS, steal session cookies, modify page content, or perform other malicious actions. The vulnerability trigger conditions include: the attacker can provide or modify chart configuration data, and the victim interacts with the chart (such as clicking an element).
- **Code Snippet:**
  ```
  za(R,"style",X.match(e)[1].replace(/(;| |^)color([ :])/,"$1fill$2"));
  if(f.test(X)){za(R,"onclick",'location.href="'+X.match(f)[1]+'"');Ia(R,{cursor:"pointer"})}
  X=X.replace(/<(.|\n)*?>/g,"")||" ";
  ```
- **Keywords:** Text content, href attribute, onclick event, Data label formatter, Tooltip formatter
- **Notes:** This vulnerability requires user interaction (click) to trigger, but the probability of exploitation may be increased through social engineering or automatic triggering (such as event simulation). It is recommended to perform strict validation and escaping of user input, avoiding direct string concatenation into event handlers. Further verification is needed to determine if other input points (such as tooltip formatters) are also affected. In the firmware context, an attacker as a logged-in user might exploit this vulnerability by modifying chart configurations through the web interface.

---
### Buffer Overflow-parseServers

- **File/Directory Path:** `bin/ookla`
- **Location:** `ookla:0x0000ace4 sym.parseServers`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the parseServers function, there is a buffer overflow vulnerability when parsing server configuration. The function uses rindex to find a colon (':') in the input string to separate the host and port parts, but if the input string contains no colon, rindex returns NULL, and the code does not check for this case. This causes the copy length parameter in the strncpy operation to be calculated as an invalid large positive number (because the NULL address is 0, and the stack address is higher), potentially copying a large amount of data into the target stack buffer, resulting in a stack overflow. Trigger condition: An attacker provides an overly long string without a colon by modifying the 'servers.%d.host' field in the configuration file 'settings.txt'. Constraint: The attacker must have permission to modify the configuration file (as a logged-in user, possibly via the web interface or API). Potential attack method: Through carefully crafted input, the overflow can overwrite the return address or critical variables, enabling arbitrary code execution or denial of service. The vulnerability affects all server entries because it is located within a parsing loop. The code logic shows that tainted data read from the configuration file is directly used in string operations, lacking boundary checks and NULL pointer validation.
- **Code Snippet:**
  ```
  uVar2 = sym.imp.rindex(puVar10 + 8 + -0x448, 0x3a); // Find colon, returns NULL if not present
  *(puVar10 + -0xc) = uVar2;
  // ... No check if uVar2 is NULL
  sym.imp.strncpy(*(*(0x6838 | 0x20000) + 0x24), puVar10 + 8 + -0x448, *(puVar10 + -0xc) - (puVar10 + 8 + -0x448)); // If uVar2 is NULL, length calculation is invalid, causing massive data copy
  ```
- **Keywords:** settings.txt, servers.%d.host, servers.%d.serverid, servers.%d.url
- **Notes:** Attack chain is complete: Input point (configuration file) → Data flow (parse_config to parseServers) → Dangerous operation (stack overflow). It is recommended to verify the target buffer size and memory layout to optimize exploitation. Subsequent analysis can examine the modification mechanism of the configuration file (e.g., via network interface) to confirm the attack vector. The use of strcpy in other functions (like parseEngineSettings) carries lower risk, as the buffer size might be large, and there is no evidence it can lead to code execution.

---
### command-injection-minidlna-R-option

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `minidlna.exe:0xc6c4 (fcn.0000c028 case 6)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was identified in the minidlna.exe binary when the `-R` (force rescan) option is used. The vulnerability occurs in the main function where user-controlled data from command-line arguments or configuration files is incorporated into a `system` call without proper sanitization. Specifically, the code constructs a command string using `snprintf` with the format `rm -rf %s/files.db %s/art_cache` and passes it to `system`. If an attacker can control the paths (e.g., through a malicious configuration file or command-line argument), they can inject arbitrary commands. This could lead to remote code execution if the minidlna process is running with elevated privileges or if the attacker has write access to configuration files.

- **Trigger Condition**: The vulnerability is triggered when the `-R` option is passed to minidlna, typically during a forced rescan of the media library.
- **Constraints and Boundary Checks**: The `snprintf` uses a buffer of 4096 bytes, but no validation is performed on the path inputs, allowing command injection if paths contain shell metacharacters.
- **Potential Exploitation**: An attacker with the ability to modify command-line arguments or configuration files (e.g., via a compromised script or weak file permissions) can inject commands to execute arbitrary code.
- **Code Logic**: The dangerous code is located in the main function's command-line parsing switch statement, case 6, where `system` is called with a user-influenced string.
- **Code Snippet:**
  ```
  case 6:
      *(puVar28 + -0x21b4) = *(puVar28 + -0x2194);
      sym.imp.snprintf(puVar28 + -0x1184, 0x1000, *0xd06c);  // Format: "rm -rf %s/files.db %s/art_cache"
      sym.imp.system(puVar28 + -0x1184);  // Command injection here
      break;
  ```
- **Keywords:** minidlna.conf, media_dir, db_dir, log_dir
- **Notes:** This vulnerability requires the attacker to control the command-line arguments or configuration file paths, which may be feasible if the minidlna process is started with user-influenced parameters or if configuration files are writable by the user. However, exploitation depends on the specific deployment scenario. Additional analysis of HTTP request handling and SQL queries is recommended to identify other potential attack vectors, such as SQL injection or buffer overflows in network-facing code.

---
### command-injection-fcn.000290a4

- **File/Directory Path:** `bin/wget`
- **Location:** `File: wget Function: fcn.000290a4 Address: 0x29138`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In function fcn.000290a4, parameter param_1 is used to construct a command string and executed via the system function, creating a command injection vulnerability. Specific attack chain: param_1 may originate from user-controllable input (such as command line arguments or environment variables), is formatted into a buffer via sprintf and embedded into another string, and finally executed via a call to system. An attacker (as a connected non-root user) can execute arbitrary commands by injecting malicious characters (e.g., ;, |, backticks). The trigger condition is a user providing malicious input, leading to command injection and thus arbitrary code execution on the system. This is a complete and verifiable attack path, based on code analysis and the call chain (fcn.000101f0 and fcn.0001a3ac).
- **Code Snippet:**
  ```
  if (param_1 != 0) { iVar1 = sym.imp.fopen64(*0x29158, *0x2915c); if (iVar1 != 0) { sym.imp.fprintf(iVar1, *0x29160, param_1); sym.imp.fclose(iVar1); sym.imp.sprintf(puVar2 + -0x40, *0x29164, param_1); sym.imp.sprintf(puVar2 + -0x80, *0x29168, puVar2 + -0x40); sym.imp.system(puVar2 + -0x80); return 0; } sym.imp.puts(*0x2916c); }
  ```
- **Keywords:** sym.imp.system, fcn.000290a4, fcn.000101f0, fcn.0001a3ac
- **Notes:** Further validation is needed for the specific source of param_1 (such as command line argument processing), but based on the call chain (fcn.000101f0 and fcn.0001a3ac), it is likely user-controllable. It is recommended to fix this by using safe functions (like execve) or strictly validating input. The attacker is a non-root user, but could exploit this vulnerability to escalate privileges or perform malicious actions.

---
