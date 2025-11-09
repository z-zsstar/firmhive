# R6200v2-V1.0.3.12_10.1.11 (5 alerts)

---

### command-injection-http-param-b268

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xb268 main`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** High-risk command injection vulnerability. Attackers can inject malicious commands by controlling the param_2[1] parameter. When this parameter matches a specific string (*0xc2cc), the program constructs and executes a system command via sprintf. Verification is required to determine whether the param_2 parameter originates from GET/POST parameters in HTTP requests.
- **Code Snippet:**
  ```
  iVar14 = sym.imp.strcmp(iVar6,*0xc2cc);
  if (iVar14 == 0) {
      sym.imp.sprintf(puVar19 + -0x18c,*0xc3c0,*0xc3bc);
      sym.imp.system(puVar19 + -0x18c);
  ```
- **Keywords:** param_2, strcmp, sprintf, system, *0xc2cc, puVar19 + -0x18c, http_param
- **Notes:** Verify whether the param_2 parameter originates from the GET/POST parameters of the HTTP request.

---
### command-injection-http-param-b268

- **File/Directory Path:** `sbin/htmlget`
- **Location:** `acos_service:0xb268 main`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** High-risk command injection vulnerability. An attacker can inject malicious commands by controlling the param_2[1] parameter. When this parameter matches a specific string (*0xc2cc), the program constructs and executes system commands via sprintf. It is necessary to verify whether the param_2 parameter originates from GET/POST parameters in HTTP requests.
- **Code Snippet:**
  ```
  iVar14 = sym.imp.strcmp(iVar6,*0xc2cc);
  if (iVar14 == 0) {
      sym.imp.sprintf(puVar19 + -0x18c,*0xc3c0,*0xc3bc);
      sym.imp.system(puVar19 + -0x18c);
  ```
- **Keywords:** param_2, strcmp, sprintf, system, *0xc2cc, puVar19 + -0x18c, http_param, command_execution
- **Notes:** Verify whether the param_2 parameter originates from the GET/POST parameters of the HTTP request.

---
### buffer-overflow-nvram-config

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `fcn.0000a600:0xa878, fcn.0000d35c:0xd3e0, main:0xb5a4`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Multiple buffer overflow risks. The return value of 'acosNvramConfig_get' is directly passed to 'strcpy' without length checking, potentially causing stack overflow. These configuration parameters may originate from the web interface, requiring input source validation.
- **Code Snippet:**
  ```
  uVar4 = sym.imp.acosNvramConfig_get(*0xaf0c);
  sym.imp.strcpy(puVar9,uVar4);
  ```
- **Keywords:** strcpy, acosNvramConfig_get, fcn.0000a600, fcn.0000d35c, main, web_config
- **Notes:** These configuration parameters may originate from the web interface, requiring validation of the input source.

---
### mac-command-injection-b3fc

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xb3fc main`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Network configuration command injection vulnerability. The program reads the Ethernet MAC address and directly concatenates it into a command string for execution without validation, which could be exploited by forged MAC addresses. The MAC address may originate from either the network interface or web configuration.
- **Code Snippet:**
  ```
  sym.imp.bd_read_eth_mac(puVar19 + -0xc,puVar17);
  sym.imp.sprintf(iVar6,*0xc364,uVar4,uVar5);
  sym.imp.system(iVar6);
  ```
- **Keywords:** bd_read_eth_mac, sprintf, system, puVar19 + -0xc, *0xc364, mac_config
- **Notes:** MAC addresses may originate from network interfaces or web configurations

---
### network_input-htmlget-sprintf_overflow

- **File/Directory Path:** `sbin/htmlget`
- **Location:** `htmlget: fcn.000087f0 (0x8924)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** An unsafe 'sprintf' call (address 0x8924) was detected in function 'fcn.000087f0' of file 'sbin/htmlget', used for formatting HTTP request strings. The target buffer is allocated via 'malloc(0x46)', but there is no explicit length check during string formatting. The format string contains two variable parameters (hostname and user agent), which may cause buffer overflow if these inputs are excessively long.

Security Impact:
- May lead to buffer overflow, with risk depending on whether the hostname or user agent strings can be controlled by an attacker.
- Although it does not directly process HTTP parameters, it involves HTTP request formatting and is part of a web service component.

Recommendations:
- Replace with 'snprintf' and provide buffer size limitation.
- Verify that the length of hostname and user agent strings does not exceed buffer limits.
- **Code Snippet:**
  ```
  sprintf(buffer, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", hostname, user_agent);
  ```
- **Keywords:** fcn.000087f0, sprintf, 0x8924, GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n, www.netgear.com, HTMLGET 1.0, HTTP response parsing, network_input
- **Notes:** Further verification is needed to determine whether the hostname and user-agent string can be controlled by an attacker. The buffer size (0x46 bytes) appears sufficient for default values, but may be inadequate if longer strings are used.

---
