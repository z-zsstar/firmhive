# _AC1450-V1.0.0.36_10.0.17.chk.extracted (6 alerts)

---

### hotplug2-command-injection

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0x0000a8d0`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** The sbin/hotplug2 contains an unvalidated command execution vulnerability. Attackers can execute arbitrary commands by modifying rule files or injecting malicious device events. Combined with dangerous rules in /etc/hotplug2.rules, attackers can control the DEVICENAME or MODALIAS environment variables to trigger command execution or kernel module loading. This forms a complete attack chain from environment variable control to privileged command execution.
- **Code Snippet:**
  ```
  case 0:
    uVar5 = sym.imp.strdup(**(iVar12 + 4));
    uVar9 = fcn.0000a73c(uVar5,param_1);
    iVar11 = sym.imp.system();
  ```
- **Keywords:** system, fcn.0000a8d0, execvp, fork, waitpid, DEVPATH, DEVICENAME, MODALIAS, makedev, modprobe
- **Notes:** Check whether the /etc/hotplug2.rules file can be modified by non-privileged users. If an attacker can modify the rules file or control environment variables, this constitutes a high-risk complete attack chain.

---
### utelnetd-buffer-overflow

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd:0x95c0-0x95cc`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** bin/utelnetd uses strcpy for buffer copying, posing a buffer overflow risk. When handling the pseudo-terminal device path returned by ptsname, it directly copies without checking the destination buffer size. An attacker could potentially trigger an overflow by controlling the length of the pseudo-terminal device name. Combined with network access permissions, this constitutes a remotely exploitable vulnerability.
- **Keywords:** strcpy, ptsname
- **Notes:** The buffer size limit needs to be validated in conjunction with the specific environment. If the utelnetd service is exposed to external networks, this constitutes a high-risk vulnerability.

---
### hotplug2-mknod-vulnerability

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0x0000a8d0`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The sbin/hotplug2 utility allows device node creation through rule files, with permission settings potentially controllable by attackers. This may lead to excessively permissive device file permissions or the creation of hazardous device nodes. Combined with environment variable manipulation, this constitutes a complete attack vector.
- **Code Snippet:**
  ```
  uVar13 = sym.imp.mknod(uVar9,uVar13,*(puVar14 + -0x34) | *(puVar14 + -0x3c) | uVar2 & 0xff | (uVar1 << 0x14) >> 0xc,*(puVar14 + -0x30) | *(puVar14 + -0x38));
  ```
- **Keywords:** mknod, fcn.0000a8d0, chmod, chown, DEVPATH, DEVICENAME
- **Notes:** Check whether the device node permissions are correctly restricted.

---
### hotplug2-env-injection

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0x0000a8d0`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** There is an environment variable injection vulnerability in sbin/hotplug2. When the function sets environment variables via setenv(), it fails to adequately filter variable names and values. Attackers can inject environment variables by crafting malicious device events, affecting subsequently executed child processes.
- **Code Snippet:**
  ```
  sym.imp.setenv(**(iVar12 + 4),(*(iVar12 + 4))[1],1);
  ```
- **Keywords:** setenv, fcn.0000a8d0, execvp, fork
- **Notes:** env_set may be combined with other vulnerabilities to form more complex attack chains.

---
### cgi-authentication-bypass

- **File/Directory Path:** `www/cgi-bin/RMT_invite_reg.htm`
- **Location:** `www/cgi-bin/RMT_invite_reg.htm`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The file www/cgi-bin/RMT_invite_reg.htm contains sensitive form fields (TXT_remote_login and TXT_remote_password) which could be tampered with, potentially leading to authentication bypass. Although the corresponding CGI script does not exist, similar implementations might be present in other CGI scripts.
- **Keywords:** RMT_invite.cgi, TXT_remote_login, TXT_remote_password, submit_flag, BTN_unreg
- **Notes:** Further inspection is required to determine whether the RMT_invite.cgi or its alternative components are dynamically generated during device operation.

---
### group-config-privilege-escalation

- **File/Directory Path:** `etc/group`
- **Location:** `etc/group`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Improper configuration in etc/group where all groups (including guest) have GID 0 (equivalent to REDACTED_PASSWORD_PLACEHOLDER). If the guest account can perform privileged operations, it may lead to privilege escalation. Combined with other vulnerabilities (such as command injection), attackers could exploit this configuration to gain REDACTED_PASSWORD_PLACEHOLDER privileges.
- **Keywords:** etc/group, REDACTED_PASSWORD_PLACEHOLDER::0:0:, guest::0:
- **Notes:** The exploitation requires combining with other vulnerabilities to achieve a complete privilege escalation attack chain.

---
