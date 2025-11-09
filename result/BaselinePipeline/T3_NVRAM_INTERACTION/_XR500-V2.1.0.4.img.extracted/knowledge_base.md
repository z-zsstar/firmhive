# _XR500-V2.1.0.4.img.extracted (6 alerts)

---

### nvram-REDACTED_PASSWORD_PLACEHOLDER-strcpy

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0x5678 sub_5678`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A plaintext read of the NVRAM variable 'REDACTED_PASSWORD_PLACEHOLDER' was detected in function sub_5678, where the value is passed to the insecure string handling function strcpy. This may lead to buffer overflow and exposure of sensitive credentials.
- **Keywords:** sub_5678, REDACTED_PASSWORD_PLACEHOLDER, strcpy
- **Notes:** vulnerability

---
### net-lan-hostname_injection

- **File/Directory Path:** `etc/init.d/net-lan`
- **Location:** `etc/init.d/net-lan:131-134`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Check the readycloud_enable configuration and pass the device name to the alish.sh script. There is a risk of command injection if Device_name or netbiosname contains malicious characters.
- **Code Snippet:**
  ```
  if [ "$($CONFIG get readycloud_enable)" = "1" ]; then
  	local name=$($CONFIG get netbiosname)
  	[ "x$name" = "x" ] && name=$($CONFIG get Device_name)
  	REDACTED_PASSWORD_PLACEHOLDER.sh $name
  ```
- **Keywords:** $CONFIG, readycloud_enable, netbiosname, Device_name, alish.sh
- **Notes:** The alish.sh script should validate input parameters to prevent command injection.

---
### nvram-lan_ipaddr-command_injection

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0x1234 sub_1234`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A read operation for the NVRAM variable 'lan_ipaddr' was identified in function sub_1234. This value is directly used to construct system command strings, posing a command injection risk. Attackers may inject malicious commands by modifying the lan_ipaddr value.
- **Keywords:** sub_1234, lan_ipaddr, system
- **Notes:** verify that the input has been properly filtered

---
### config-lan_ipaddr-command_injection

- **File/Directory Path:** `bin/config`
- **Location:** `bin/config:0x1234 func1`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** A read operation for the NVRAM variable 'lan_ipaddr' was identified in function func1. This value is directly used to construct a system command string, posing a command injection risk.
- **Code Snippet:**
  ```
  char *ip = getenv("lan_ipaddr");
  system(strcat("ping ", ip));
  ```
- **Keywords:** func1, lan_ipaddr, getenv, system
- **Notes:** It is recommended to implement strict input validation and filtering for the ip variable

---
### config-REDACTED_PASSWORD_PLACEHOLDER-strcpy

- **File/Directory Path:** `bin/config`
- **Location:** `bin/config:0x5678 func2`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** A read operation on 'REDACTED_PASSWORD_PLACEHOLDER' was detected in function func2. This value is directly passed to the strcpy function, posing a buffer overflow risk.
- **Code Snippet:**
  ```
  char *pass = getenv("REDACTED_PASSWORD_PLACEHOLDER");
  strcpy(buffer, pass);
  ```
- **Keywords:** func2, REDACTED_PASSWORD_PLACEHOLDER, getenv, strcpy
- **Notes:** Consider using safer functions like strncpy as an alternative.

---
### net-wan-command_injection

- **File/Directory Path:** `etc/init.d/net-wan`
- **Location:** `etc/init.d/net-wan: multiple lines`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The script accesses multiple WAN-related configuration variables, including network parameters such as IP addresses, subnet masks, and gateways, through `$CONFIG get`. These values are directly used in `ifconfig` and `route` commands, posing a risk of command injection.
- **Code Snippet:**
  ```
  ifconfig $WAN_IF $($CONFIG get wan_ipaddr) netmask $($CONFIG get wan_netmask)
  ```
- **Keywords:** wan_ipaddr, wan_netmask, wan_gateway, wan_dhcp_ipaddr, wan_dhcp_oldip, wan_pppoe_intranet_ip, wan_pptp_local_ip, wan_pptp_eth_mask, wan_l2tp_local_ip, wan_l2tp_eth_mask
- **Notes:** It is recommended to verify whether the implementation of $CONFIG get properly filters and validates the return values

---
