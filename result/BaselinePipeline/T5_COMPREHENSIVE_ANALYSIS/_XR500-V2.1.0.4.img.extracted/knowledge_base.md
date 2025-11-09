# _XR500-V2.1.0.4.img.extracted (7 alerts)

---

### uhttpd-command-injection

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `usr/sbin/uhttpd:0x0000eff0`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** A command injection vulnerability was identified in the uh_cgi_auth_check function of usr/sbin/uhttpd, where popen is used to execute external commands. Attackers could potentially inject malicious commands by manipulating input parameters. This vulnerability resides in the critical authentication path, potentially allowing authentication bypass or arbitrary system command execution.
- **Keywords:** uh_cgi_auth_check, popen, snprintf, authentication
- **Notes:** Check the input filtering and escaping mechanisms. This vulnerability can be triggered through the web interface.

---
### proccgi-heap-overflow

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x87f0 fcn.000087c8`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A critical heap buffer overflow vulnerability was discovered in www/cgi-bin/proccgi. The function fcn.000087c8 calculates input length using strlen but only allocates a buffer of length+1 bytes, then directly copies using strcpy. Attackers can exploit this vulnerability by injecting overly long strings through environment variables or CGI parameters.
- **Code Snippet:**
  ```
  0x000087d8      a3ffffeb       bl sym.imp.strlen
  0x000087dc      010080e2       add r0, r0, 1
  0x000087e0      80ffffeb       bl sym.imp.malloc
  0x000087ec      0510a0e1       mov r1, r5
  0x000087f0      76ffffeb       bl sym.imp.strcpy
  ```
- **Keywords:** sym.imp.strcpy, fcn.000087c8, sym.imp.getenv, sym.imp.malloc
- **Notes:** Verify which input parameters are passed to the function and whether mitigation measures (such as ASLR) exist.

---
### weak-wireless-config

- **File/Directory Path:** `etc/config/wireless`
- **Location:** `etc/config/wireless:3-5, 11-13`
- **Risk Score:** 9.0
- **Confidence:** 5.75
- **Description:** The wireless network configuration is disabled by default, but the settings indicate that if enabled, it would use an OpenWrt SSID with no encryption (encryption none). If activated, this would allow any device to connect to the internal network, creating a serious risk of network boundary breach.
- **Keywords:** wireless, wifi-device, disabled, ssid, encryption
- **Notes:** If wireless is enabled without encryption configured, it will allow any device to connect to the network. The actual status of the wireless interface needs to be checked.

---
### nvram-strcpy-buffer-overflow

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0xREDACTED_PASSWORD_PLACEHOLDER fcn.000086d0`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** An unvalidated strcpy usage was found in the config_set function of bin/nvram, which may lead to stack buffer overflow when processing user-supplied configuration values. Attackers can exploit this vulnerability by providing overly long strings, potentially enabling arbitrary code execution. The vulnerability resides in the critical path handling name=value format input, directly exposed to external input.
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER      0d00a0e1       mov r0, sp
  0xREDACTED_PASSWORD_PLACEHOLDER      a0ffffeb       bl sym.imp.strcpy
  ```
- **Keywords:** strcpy, config_set, fcn.000086d0, name=value
- **Notes:** Verify the stack buffer size and actual input limits. This vulnerability may be triggered through web interfaces or network services.

---
### dns-hijack-via-config

- **File/Directory Path:** `etc/init.d/dnsmasq`
- **Location:** `etc/init.d/dnsmasq:5-10,60-61`
- **Risk Score:** 8.5
- **Confidence:** 6.75
- **Description:** dnsmasq has a DNS hijacking feature upon startup. When the configuration item 'dns_hijack'=1 is set, it sends a SIGUSR1 signal to force dnsmasq to reload its configuration. Combined with a configuration injection vulnerability, attackers could potentially exploit this functionality to conduct DNS cache poisoning attacks.
- **Code Snippet:**
  ```
  set_hijack() {
  	sleep 2
  	killall -SIGUSR1 dnsmasq
  	sleep 1
  	killall -SIGUSR1 dnsmasq
  }
  ```
- **Keywords:** set_hijack, dns_hijack, killall -SIGUSR1 dnsmasq
- **Notes:** Check the configuration method of the dns_hijacking setting to confirm whether it can be modified through the network interface.

---
### factory-mode-telnet-activation

- **File/Directory Path:** `etc/init.d/telnet`
- **Location:** `etc/init.d/telnet:6`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The /etc/init.d/telnet service startup depends on the 'factory_mode' configuration, which directly listens on the br0 interface in factory mode. If an attacker can spoof factory mode (e.g., via NVRAM injection), they could activate the insecure telnet service. Combined with NVRAM injection vulnerabilities, this could form a complete attack chain.
- **Keywords:** factory_mode, utelnetd, telnetenable, /bin/config get
- **Notes:** Check if the implementation of /config/get has vulnerabilities such as command injection.

---
### uhttpd-path-traversal

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `usr/sbin/uhttpd:0x0000dad0`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The uh_path_lookup function in uHTTPd is vulnerable to path traversal attacks, where attackers could potentially access sensitive system files by crafting specially designed URLs. This vulnerability stems from insecure usage of realpath, which may lead to exposure of confidential information such as configuration files or passwords.
- **Keywords:** uh_path_lookup, realpath, DOCUMENT_ROOT
- **Notes:** Path normalization needs to be validated. This vulnerability can be triggered through the web interface.

---
