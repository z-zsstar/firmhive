# R9000 (9 alerts)

---

### script-transbt-poptsk-env-torrentdir

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/transbt-poptsk.sh:24`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The script directly uses the $TORRENT_DIR environment variable to construct command parameters (line 24), posing significant risks:
1. Command injection (via $TRANS_REMOTE -a parameter)
2. Path traversal (via rm $TORRENT_DIR/$3)
3. Lack of validation for the $3 parameter
- **Code Snippet:**
  ```
  $TRANS_REMOTE -a $TORRENT_DIR/$3 | grep success && ret=1 && rm $TORRENT_DIR/$3 && return
  ```
- **Keywords:** TORRENT_DIR, TRANS_REMOTE, rm
- **Notes:** Highest Risk Item: Environment Variables Directly Enter Command Execution Context

---
### libconfig-CONFIG_SECRET-env

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libconfig.so:0x18a20`
- **Risk Score:** 9.0
- **Confidence:** 6.75
- **Description:** The function fcn.00018a20 accesses the environment variable 'CONFIG_SECRET' for encryption REDACTED_PASSWORD_PLACEHOLDER initialization. Security concerns:  
- REDACTED_PASSWORD_PLACEHOLDER source relies on environment variables  
- Uses hardcoded default values when not set  
- Violates REDACTED_PASSWORD_PLACEHOLDER management best practices
- **Keywords:** CONFIG_SECRET, fcn.00018a20, AES_init_ctx
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER risk: REDACTED_PASSWORD_PLACEHOLDER management mechanism needs to be refactored

---
### script-transbt-poptsk-env-sed

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/transbt-poptsk.sh:21,26,35,46`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** The script repeatedly uses the sed command to modify the QUEUEN_FILE file (lines 21, 26, 35, 46), whose path is derived from the environment variable $GREEN_DOWNLOAD_QUEUEN_BT. This may lead to:
1. Arbitrary file modification (via sed -i)
2. Privilege escalation attacks (if modifying critical system files)
- **Code Snippet:**
  ```
  sed -i ''$ln's/^queuen/adding/' $QUEUEN_FILE
  ```
- **Keywords:** sed, QUEUEN_FILE, GREEN_DOWNLOAD_QUEUEN_BT
- **Notes:** env_get → file path → sed in-place modification complete attack chain

---
### script-transbt-poptsk-env-checkfile

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/transbt-poptsk.sh:14-15`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The script uses the $GREEN_DOWNLOAD_CHECK_FILE environment variable as the error output redirection target (line 14) and grep input (line 15). Failure to validate file path security may lead to:  
1. Arbitrary file writing (via 2> redirection)  
2. Arbitrary file reading (via grep)
- **Code Snippet:**
  ```
  /usr/sbin/dni_dcheck /tmp/admin_home/.mldonkey/$1 1>/dev/null 2>$GREEN_DOWNLOAD_CHECK_FILE
  grep "overall_size_bigger_than_usb:1" $GREEN_DOWNLOAD_CHECK_FILE && mem_full=1
  ```
- **Keywords:** GREEN_DOWNLOAD_CHECK_FILE, grep, dni_dcheck
- **Notes:** dual risk: serving as both an output target and an input source

---
### binary-ntgr_sw_api-nvram-access

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ntgr_sw_api -> etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** The ntgr_sw_api system implements NVRAM operations through external scripts, presenting the following security issues:
1. Supports four operation types: REDACTED_PASSWORD_PLACEHOLDER
2. Discovered NVRAM variables include critical network configurations (wan_ifname, wan_proto, etc.)
3. Main risk points:
   - Inadequate validation of input parameters (command injection risk)
   - NVRAM values directly used to construct system commands (e.g., restarting WAN interface)
   - Persistent connection settings could be abused to cause DoS
- **Code Snippet:**
  ```
  HIDDEN/bin/configHIDDENNVRAMHIDDEN
  HIDDEN：/etc/init.d/net-wan restart $wan_ifname
  ```
- **Keywords:** nvram, config, swapi_persistent_conn, wan_ifname, Device_name, wan_proto, wan_endis_dod
- **Notes:** The complete NVRAM operation chain: binary file → external script → /binconfig utility → actual NVRAM operation

---
### script-transbt-poptsk-env-queue

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/transbt-poptsk.sh:6,21,26,35,38,40,46`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script directly assigns the value of the environment variable `$GREEN_DOWNLOAD_QUEUEN_BT` to the `QUEUEN_FILE` variable (line 6), which is subsequently used for multiple file operations (lines 21, 26, 35, 38, 40, 46). The lack of input validation and path sanitization could allow attackers to perform path traversal attacks by controlling this environment variable.
- **Code Snippet:**
  ```
  QUEUEN_FILE=$GREEN_DOWNLOAD_QUEUEN_BT
  ...
  sed -i ''$ln's/^queuen/adding/' $QUEUEN_FILE
  ```
- **Keywords:** GREEN_DOWNLOAD_QUEUEN_BT, QUEUEN_FILE, sed
- **Notes:** The complete chain from environment variable to file operation: GREEN_DOWNLOAD_QUEUEN_BT → QUEUEN_FILE → sed operation target

---
### libconfig-CONFIG_PATH-env

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libconfig.so:0x15680`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The function fcn.REDACTED_PASSWORD_PLACEHOLDER accesses the environment variable 'CONFIG_PATH' directly for file path concatenation. Security issues:
- No path normalization is performed
- Potential path traversal vulnerability
- Could be exploited to overwrite critical configuration files
- **Keywords:** CONFIG_PATH, fcn.REDACTED_PASSWORD_PLACEHOLDER, strcat
- **Notes:** Suggestions:
1. Implement a path whitelist
2. Use realpath for normalization

---
### nvram-wan_ifname

- **File/Directory Path:** `N/A`
- **Location:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The `wan_ifname` NVRAM variable stores the WAN interface name and is used for:
1. Network interface configuration
2. Command construction (e.g., interface restart)
Risk: Malicious modification may lead to network configuration errors or command injection
- **Keywords:** wan_ifname, net-wan, restart

---
### nvram-wan_proto

- **File/Directory Path:** `N/A`
- **Location:** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** wan_proto stores the WAN protocol type, REDACTED_PASSWORD_PLACEHOLDER risks:
1. Protocol type is directly used for network service configuration
2. Incorrect values may cause service interruption
- **Keywords:** wan_proto, network, config

---
