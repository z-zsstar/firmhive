# R9000 (23 alerts)

---

### envvar-wl_psk_phrase

- **File/Directory Path:** `sbin/update-wifi`
- **Location:** `sbin/update-wifi:441,449-453`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Accessing the WiFi REDACTED_PASSWORD_PLACEHOLDER environment variable 'wl_psk_phrase' in the '/sbin/update-wifi' script, directly processing and using it for configuration, poses a high risk.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** wl_psk_phrase
- **Notes:** WiFi passwords are directly processed and used for configuration, high risk

---
### system-traffic_meter-invalid_cmd

- **File/Directory Path:** `sbin/traffic_meter`
- **Location:** `sbin/traffic_meter:*0xd7b4, *0xd7b8, *0xd7bc`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The 'system' function call uses an invalid command string, posing a serious security risk.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** system
- **Notes:** May lead to undefined behavior or crashes, requires fixing.

---
### env-get-CONTENT_LENGTH-netmsg

- **File/Directory Path:** `bin/netmsg`
- **Location:** `bin/netmsg:0x3e0f8`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The CONTENT_LENGTH environment variable is directly converted by atoi and used for memory allocation without boundary checks, which may lead to integer overflow. Direct usage for memory allocation may cause integer overflow.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** CONTENT_LENGTH, getenv, atoi, malloc
- **Notes:** It is recommended to add boundary checks for CONTENT_LENGTH to prevent integer overflow.

---
### wifi-config-dniconfig_multiple

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Multiple "dniconfig get" values were read to obtain various WiFi configuration parameters (endis_wl_radio, wl_sectype, wps_status, etc.). These values directly controlled security settings and radio operations without proper validation, posing a high risk.
- **Keywords:** dniconfig get endis_wl_radio, dniconfig get wl_sectype, dniconfig get wps_status, dniconfig get endis_ssid_broadcast, dniconfig get wl_access_ctrl_on, dniconfig get wl_country
- **Notes:** configuration_load

---
### nvram-get-lan_ipaddr

- **File/Directory Path:** `sbin/cmddlna`
- **Location:** `sbin/cmddlna:86`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Retrieve the LAN IP address configuration variable. High risk: This variable is used to set the IP address of the DLNA server. If maliciously tampered with, it may cause the server to bind to an incorrect IP address, leading to security issues.
- **Code Snippet:**
  ```
  print_dlna_conf "$($config get lan_ipaddr)" "$($config get lan_netmask)" "$name" "$($config get upnp_enable_tivo)" "$($config get Device_name)" > $MINIDLNA_CONF
  ```
- **Keywords:** lan_ipaddr, cmddlna
- **Notes:** nvram_get

---
### nvram-get-lan_netmask

- **File/Directory Path:** `sbin/cmddlna`
- **Location:** `sbin/cmddlna:86`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Retrieve the LAN subnet mask configuration variable. High risk: This variable is used to set the subnet mask for the DLNA server. If maliciously tampered with, it may cause the server to bind to an incorrect network range, leading to security issues.
- **Code Snippet:**
  ```
  print_dlna_conf "$($config get lan_ipaddr)" "$($config get lan_netmask)" "$name" "$($config get upnp_enable_tivo)" "$($config get Device_name)" > $MINIDLNA_CONF
  ```
- **Keywords:** lan_netmask, cmddlna
- **Notes:** nvram_get

---
### env-get-SHELL-netmsg

- **File/Directory Path:** `bin/netmsg`
- **Location:** `bin/netmsg:0x21b28`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The SHELL environment variable is directly passed to execvp for execution, which could be hijacked leading to arbitrary command execution. There is a risk of command injection.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** SHELL, getenv, execvp
- **Notes:** It is recommended to avoid directly using SHELL environment variables for command execution and instead use fixed paths.

---
### wifi-config-wla_channel

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The variable 'wla_channel' is used in multiple case statements for channel configuration. Directly affects radio operation and could be used for channel jamming, presenting a high risk.
- **Keywords:** wla_channel
- **Notes:** configuration_load

---
### wifi-config-wla_country

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The variable 'wla_country' is used for country-specific channel restrictions. Affects regulatory compliance and presents a high risk.
- **Keywords:** wla_country
- **Notes:** Affects regulatory compliance

---
### envvar-hotplug2.mount-fs_type

- **File/Directory Path:** `sbin/hotplug2.mount`
- **Location:** `sbin/hotplug2.mount:123`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The environment variable fs_type is used to retrieve the file system type, and its value is directly utilized in the mount command. This poses a high risk, as it could be maliciously manipulated to mount inappropriate file systems.
- **Code Snippet:**
  ```
  fs_type=$(vol_id /dev/$1 | grep ID_FS_TYPE | awk -F= '{print $2}')
  ```
- **Keywords:** fs_type, hotplug2.mount
- **Notes:** Further analysis is required on the definition and configuration location of the fs_type variable.

---
### envvar-hotplug2.mount-mount_part

- **File/Directory Path:** `sbin/hotplug2.mount`
- **Location:** `sbin/hotplug2.mount:136`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The environment variable `mount_part` is used to specify the mount point, and its value is directly utilized in the mount command. This poses a high risk, as it could be maliciously manipulated to result in improper filesystem mounting.
- **Code Snippet:**
  ```
  mount -t ufsd -o nls=utf8,rw,nodev,noatime,uid=0,gid=0,fmask=0,dmask=0 --force /dev/$1 /mnt/$mount_part
  ```
- **Keywords:** mount_part, hotplug2.mount
- **Notes:** Further analysis is required on the definition and configuration location of the mount_part variable.

---
### envvar-mac_addresses

- **File/Directory Path:** `sbin/update-wifi`
- **Location:** `sbin/update-wifi:80,86,92`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the 'sbin/update-wifi' script, accessing MAC address environment variables (mac_2g/mac_5g/mac_60g) directly for configuration may be susceptible to forgery.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** mac_2g, mac_5g, mac_60g
- **Notes:** The MAC address is directly used for configuration and may be forged.

---
### nvram-traffic_meter-config_get

- **File/Directory Path:** `sbin/traffic_meter`
- **Location:** `sbin/traffic_meter:fcn.0000d7c0 @ 0xd7e8, 0xd808`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The NVRAM variables accessed via the 'config_get' function are primarily used for traffic statistics and control functions. While most accesses are secure, the direct usage of the 'traffic_block_all' configuration value carries command injection risks.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** config_get, traffic_block_all, system, /sbin/ledcontrol
- **Notes:** It is recommended to strictly validate the 'traffic_block_all' configuration value, or refactor the code to avoid directly using configuration values to construct commands.

---
### nvram-config_get-0x8988

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER (config_get)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** High-risk security issue: The return value of the config_get function call at 0x8988 is used directly without NULL check, which may lead to memory corruption or code execution. This value is used in sprintf operation, posing a risk of format string vulnerability.
- **Code Snippet:**
  ```
  Not provided in original data
  ```
- **Keywords:** config_get, sprintf, 0x8988, pcVar2
- **Notes:** Further analysis of the libconfig.so library is required to obtain complete implementation details of NVRAM operations and conduct security assessments.

---
### nvram-config_get-0x8988

- **File/Directory Path:** `sbin/cpuutil`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER (config_get)`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** High-risk security issue: The return value of the config_get function call at 0x8988 is used directly without NULL checking, which may lead to memory corruption or code execution. This value is used in a sprintf operation, posing a risk of format string vulnerability.
- **Keywords:** config_get, sprintf, 0x8988, pcVar2
- **Notes:** Further analysis of the libconfig.so library is required to obtain complete implementation details of NVRAM operations and conduct security assessments.

---
### env-get-PATH-netmsg

- **File/Directory Path:** `bin/netmsg`
- **Location:** `bin/netmsg:0x12df8,0x3f10c`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The PATH environment variable is used for file path searches and command execution, and the lack of validation may lead to path hijacking or command injection. The value is used for file path searches and command execution, posing a risk of path hijacking.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** PATH, getenv, strdup, setenv, execvp
- **Notes:** Review all code paths that use the PATH environment variable

---
### env_access-check_board_parameter-environment_variables

- **File/Directory Path:** `sbin/check_board_parameter`
- **Location:** `check_board_parameter: shell script`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script 'sbin/check_board_parameter' was found accessing environment variables $BAKMTD, $ARTMTD, and $validlen. These variables are used to construct device paths (e.g., /dev/$ARTMTD) and temporary file paths (e.g., /tmp/$ARTMTD), which are directly passed to nanddump and nandwrite commands. This usage pattern poses potential security risks, as malicious control of these variables could lead to arbitrary file read/write or command injection.
- **Code Snippet:**
  ```
  nanddump /dev/$ARTMTD -l $validlen -f /tmp/$ARTMTD 2>/dev/null
  nandwrite -p -m -q /dev/$BAKMTD /tmp/$ARTMTD
  ```
- **Keywords:** $BAKMTD, $ARTMTD, $validlen, nanddump, nandwrite
- **Notes:** It is recommended to further verify the sources of these environment variables and check whether there is sufficient input validation and sanitization. If these variables originate from untrusted sources (such as user input or network), the risk is higher.

---
### config-access-netutil-config_get

- **File/Directory Path:** `sbin/net-util`
- **Location:** `net-util:0x95b8 (fcn.000095b8)`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** In the 'sbin/net-util' file, the function `fcn.000095b8` was found to retrieve configuration values via `config_get` and use `sprintf` to construct strings without proper validation. Specific risks include:
1. Configuration values obtained through `config_get` are directly used for string construction without validation
2. The use of `sprintf` may lead to buffer overflow risks
3. The constructed strings are subsequently written back to the configuration system via `config_set`
Potential impact: May result in configuration system pollution or command injection risks
- **Code Snippet:**
  ```
  pcVar1 = sym.imp.config_get();
  if (*pcVar1 != '\0') {
      sym.imp.sprintf(auStack_50,"%s%s",param_2,pcVar1 + param_3);
      sym.imp.config_set(param_1,auStack_50);
  }
  ```
- **Keywords:** config_get, config_set, sprintf, auStack_50, sym.imp.config_get
- **Notes:** It is recommended to further analyze other call points of `config_get` and verify whether the constructed strings could be used for command execution. The implementation of `config_get`/`config_set` should be checked to determine if it involves access to NVRAM or similar configuration systems.

---
### nvram_get-usb_enableFTP-cmdftp

- **File/Directory Path:** `sbin/cmdftp`
- **Location:** `sbin/cmdftp`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the '/sbin/cmdftp' script, the NVRAM variable 'usb_enableFTP' is accessed indirectly via the '/bin/config' tool, which controls whether the FTP service is enabled. Improper configuration may lead to unauthorized FTP access.
- **Code Snippet:**
  ```
  N/A (shell script analysis)
  ```
- **Keywords:** usb_enableFTP, cmdftp, config
- **Notes:** It is recommended to further analyze the implementation of the '/bin/config' tool to verify how it accesses and stores these configuration variables.

---
### file-permission-ssdk_sh_id

- **File/Directory Path:** `sbin/ssdk_sh_id`
- **Location:** `ssdk_sh_id`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The file 'sbin/ssdk_sh_id' is a POSIX shell script with permissions set to 777 (REDACTED_PASSWORD_PLACEHOLDER by all users), posing a security risk. The script itself does not directly access NVRAM or environment variables, but it calls the '/usr/sbin/ssdk_sh' program, which may potentially access environment variables. Due to security restrictions, further analysis of the called program is not possible.
- **Keywords:** ssdk_sh_id, SSDK_SH, SSDK_ID, sw_index
- **Notes:** It is recommended to modify the file permissions to a more restrictive setting (such as 755) and further analyze whether the '/usr/sbin/ssdk_sh' program accesses environment variables in an environment with full filesystem access.

---
### env-get-HTTP_COOKIE-netmsg

- **File/Directory Path:** `bin/netmsg`
- **Location:** `bin/netmsg:0x3e058,0x3e068,0x3e17c`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The HTTP_COOKIE environment variable is processed via strdup and strtok without validation, potentially leading to injection attacks. The values are inadequately validated during processing, posing injection risks.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** HTTP_COOKIE, getenv, strdup, strtok
- **Notes:** Implement strict input validation for all user-provided environment variables

---
### nvram_get-shared_usb_folder_users-cmdftp

- **File/Directory Path:** `sbin/cmdftp`
- **Location:** `sbin/cmdftp`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the '/sbin/cmdftp' script, the NVRAM variable 'shared_usb_folder_users' is indirectly accessed via the '/bin/config' utility. This variable controls user permissions for shared folders. Improper permission configuration may lead to information disclosure or unauthorized write access.
- **Code Snippet:**
  ```
  N/A (shell script analysis)
  ```
- **Keywords:** shared_usb_folder_users, cmdftp, config
- **Notes:** It is recommended to check whether the usage of these variables in the script poses security risks, such as unvalidated input or improper permission control.

---
### command_injection-mul_pppoe_dns-ip_addr_dname

- **File/Directory Path:** `sbin/mul_pppoe_dns`
- **Location:** `sbin/mul_pppoe_dns`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the file 'sbin/mul_pppoe_dns', access to the command-line parameters '$ip_addr' and '$dname' was detected. These parameters are directly used in routing commands and file operations without adequate validation, posing risks of command injection and file path injection.
- **Code Snippet:**
  ```
  Not provided in the input
  ```
- **Keywords:** mulpppoe_ifname, RECORD_FILE, PPP1_DNS_FILE, ip_addr, dname
- **Notes:** It is recommended to further verify the source of command-line parameter inputs and the runtime environment of the script to ensure security.

---
