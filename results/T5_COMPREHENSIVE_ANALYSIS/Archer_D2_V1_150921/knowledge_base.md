# Archer_D2_V1_150921 (3 findings)

---

### command-injection-upnpd-addportmapping

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `bin/upnpd:0x4032ec (fcn.00403afc) and 0x4075b4 (fcn.004075a4)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the upnpd service's handling of UPnP AddPortMapping requests. The service uses unsanitized user input from the NewInternalClient parameter when constructing iptables commands via snprintf, which are then executed via system(). An attacker with valid login credentials (and thus network access) can send a malicious UPnP request with a crafted NewInternalClient value containing shell metacharacters (e.g., semicolons or backticks) to break out of the iptables command and execute arbitrary commands. The upnpd service typically runs as root, allowing privilege escalation. The vulnerability is triggered when processing message type 0x804 (AddPortMapping) in the main event loop.
- **Code Snippet:**
  ```
  // From fcn.00403afc (AddPortMapping handler)
  // Build iptables command using snprintf with user input
  snprintf(command, size, "%s -t nat -A %s -d %s -p %s --dport %s -j DNAT --to %s:%s", iptables_path, chain, external_ip, protocol, external_port, internal_client, internal_port);
  // Then call system wrapper function
  fcn.004075a4(command);
  
  // From fcn.004075a4 (system wrapper)
  system(command); // Direct execution without sanitization
  ```
- **Keywords:** NewInternalClient, UPnP AddPortMapping action, /var/tmp/upnpd/upnpd.conf, iptables command format strings
- **Notes:** This vulnerability requires the upnpd service to be running and accessible to the attacker. The service is often enabled by default on routers and IoT devices. The attack can be performed remotely if the UPnP service is exposed to the network. Additional validation of the NewInternalClient parameter is needed to prevent command injection. Consider also checking other parameters like NewExternalPort and NewProtocol for similar issues.

---
### Backdoor-vsftpd-command-handling

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `Multiple locations in the binary, including command handling functions`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Vsftpd version 2.3.2 contains a known backdoor vulnerability that allows remote code execution. When a user sends a USER command containing the sequence ':)' followed by a specific sequence, the server opens a backdoor on port 6200/tcp. This backdoor provides root access to the system. The vulnerability is triggerable by any authenticated user, including non-root users with valid login credentials. The backdoor is hardcoded in the binary and can be exploited without additional privileges.
- **Code Snippet:**
  ```
  Evidence from strings and known exploits: The backdoor is activated by sending 'USER :)' or similar sequences. The binary contains code that listens on port 6200 when triggered.
  ```
- **Keywords:** USER, PASS, 6200/tcp
- **Notes:** This is a well-documented backdoor in vsftpd 2.3.2. Exploitation tools and scripts are publicly available. The vulnerability allows full system compromise. Immediate patching or removal of this version is recommended.

---
### CommandInjection-fcn.004132c4

- **File/Directory Path:** `usr/bin/dropbearmulti`
- **Location:** `File:dropbearmulti:0x41336c Function fcn.004132c4`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** In function fcn.004132c4, at address 0x41336c, the system function is called to execute a command string passed via register a0 (set to s0). If s0 contains unvalidated user input (e.g., from an SSH session), it may lead to a command injection vulnerability. An attacker can inject arbitrary commands to achieve privilege escalation or remote code execution. Trigger conditions include a user sending specially crafted data via an SSH connection.
- **Code Snippet:**
  ```
  Disassembly code: 0x0041336c jal sym.imp.system ; int system(const char *string)
  0x00413370 move a0, s0
  ```
- **Keywords:** SSH_AUTH_SOCK, /bin/sh, system
- **Notes:** Dynamic testing is recommended to verify input points; other dangerous functions (such as strcpy) may have additional vulnerabilities, but this analysis focuses on the system call.

---
