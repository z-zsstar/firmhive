# _AC1450-V1.0.0.36_10.0.17.chk.extracted (11 alerts)

---

### command-injection-acos_service-system

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** The code contains multiple instances where the system() function is directly called to execute commands, with some command strings potentially incorporating user-controllable inputs. This may lead to command injection vulnerabilities. The risky calls are concentrated across multiple branches within the main function, particularly when handling specific string matches. Further verification is required to determine whether the inputs originate from HTTP request parameters.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** system, main, acos_service, strstr, http_input
- **Notes:** Further verification is required to determine which parameters may originate from HTTP requests and to confirm whether the command injection point can be triggered through the web interface.

---
### nvram-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:0x4f98,0x4fb8`
- **Risk Score:** 9.0
- **Confidence:** 7.0
- **Description:** The nvram_loaddefault function (0x4f98, 0x4fb8) contains a system() call that executes shell commands. If the command string includes any user-controllable input, there exists a risk of command injection.
- **Keywords:** nvram_loaddefault, system, web_reset
- **Notes:** May be invoked during a factory reset operation. Verification is required to determine if any web-accessible functionality triggers this operation.

---
### upnpd-http-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/upnpd:0x22fcc,0x22fdc,0x22fec`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Multiple unverified strcpy calls were found in function fcn.000229e4, directly processing HTTP request parameters (file=, host=, etc.). These calls may lead to buffer overflow vulnerabilities, which attackers could exploit by crafting specially designed HTTP requests.
- **Keywords:** fcn.000229e4, strcpy, file=, host=, http_request
- **Notes:** Further verification is needed to confirm whether these parameters indeed originate from HTTP requests, as well as the actual size of the target buffer.

---
### nvram-buffer-overflow

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:0x4d00,0x4d90`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The library contains multiple unsafe strcpy calls in the nvram_set(0x4d00) and nvram_get(0x4d90) functions. When processing untrusted input from the web interface, there is a typical buffer overflow risk. These functions may serve as core NVRAM parameter handlers invoked by web components.
- **Keywords:** nvram_set, nvram_get, strcpy, web_parameter
- **Notes:** These functions may be called when processing web form submissions that modify NVRAM parameters. Attackers could potentially overflow the buffer by submitting parameter values that exceed the maximum length.

---
### command-injection-nvram-system

- **File/Directory Path:** `N/A`
- **Location:** `0x12314-0x129d4`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The function at 0x12314 contains multiple calls to `system()` with dynamically constructed command strings. The commands are built using NVRAM configuration values (such as 'ipv6_proto', 'lan_ifname') without proper sanitization, which could lead to command injection if these values are controlled by an attacker.
- **Code Snippet:**
  ```
  system("radvd -d 1 -C %s &");
  ```
- **Keywords:** system, ipv6_proto, lan_ifname, radvd -d 1 -C %s &, fprintf, sprintf, web_config
- **Notes:** The command execution utilizes multiple NVRAM values that may be controlled via the web interface. It is necessary to verify whether these values are properly sanitized in the web interface.

---
### parameter-injection-acos_service-strstr

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The program uses strstr to check command-line arguments for executing different functions, but it does not adequately validate the arguments. Attackers may trigger dangerous operations by crafting malicious parameters. These parameters could originate from web interface calls.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** strstr, main, param_2, argv, http_parameter
- **Notes:** The parameters may originate from web interface calls, requiring reverse analysis of the HTTP request processing flow for confirmation.

---
### nvram-to-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `0x12314-0x129d4`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The function at 0x12314 contains multiple NVRAM configuration reads (acosNvramConfig_get), where these values are directly used for command construction without proper validation. This pattern recurs throughout the function for various IPv6-related configurations.
- **Code Snippet:**
  ```
  acosNvramConfig_get("ipv6_lan_ipaddr");
  ...
  fprintf(config_file, " prefix %s {\n", ip_addr);
  ```
- **Keywords:** acosNvramConfig_get, ipv6_proto, ipv6_lan_ipaddr, RA_REDACTED_SECRET_KEY_PLACEHOLDER, system, web_nvram
- **Notes:** All NVRAM configuration parameters used for command construction should be treated as potentially malicious input.

---
### buffer-overflow-acos_service-sprintf

- **File/Directory Path:** `N/A`
- **Location:** `sbin/acos_service:main`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** Multiple instances of unsafe string manipulation functions such as sprintf and strcpy were found, which may lead to buffer overflow vulnerabilities. Particularly when handling configuration parameters and network interface information, there is no apparent length validation. Verification is required to determine whether these inputs originate from HTTP request parameters.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** sprintf, strcpy, acosNvramConfig_get, bd_read_eth_mac, http_input
- **Notes:** Need to verify the input source and buffer size, especially whether it can be triggered via HTTP requests

---
### nvram-format-string

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libnvram.so:0x5dac-0x5e60`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** Multiple instances of sprintf calls (e.g., sync_essential_values 0x5dac-0x5e60) were found in the code without visible length checks, indicating potential format string vulnerabilities.
- **Keywords:** sync_essential_values, sprintf, web_config
- **Notes:** These calls appear to be used for configuration value formatting. It could be dangerous if the format string contains user input.

---
### temp-file-race-condition

- **File/Directory Path:** `N/A`
- **Location:** `0x1236c-0x126b8`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** Binary files use `fopen()` and file operations to create and write configuration files (/tmp/radvd.conf) before executing related commands. If proper file permissions are not maintained, attackers may manipulate these files or their contents.
- **Code Snippet:**
  ```
  fopen("/tmp/radvd.conf", "w");
  ...
  system("radvd -d 1 -C /tmp/radvd.conf &");
  ```
- **Keywords:** fopen, /tmp/radvd.conf, fprintf, fwrite, system, web_tmpfile
- **Notes:** Verify whether temporary file handling has race conditions and correct permissions.

---
### upnpd-multiple-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/upnpd`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The program contains numerous strcpy call sites, many of which may process user-controllable input. Further analysis of these call contexts is required to determine whether additional vulnerabilities exist.
- **Keywords:** strcpy, fcn.0000b2a4, fcn.000246f4, fcn.00027f28, http_parameter
- **Notes:** Conduct an in-depth analysis of the marked function

---
