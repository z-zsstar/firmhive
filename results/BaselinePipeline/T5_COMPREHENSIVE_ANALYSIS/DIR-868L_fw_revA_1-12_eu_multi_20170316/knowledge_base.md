# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (8 alerts)

---

### mt-daapd-insecure-config

- **File/Directory Path:** `var/mt-daapd.conf`
- **Location:** `var/mt-daapd.conf:8-9`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Hardcoded REDACTED_PASSWORD_PLACEHOLDER credentials (REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER) in mt-daapd configuration and service running as REDACTED_PASSWORD_PLACEHOLDER. Combined with world-writable configuration files, this creates significant privilege escalation risks.
- **Keywords:** admin_pw, runas, port 3689
- **Notes:** configuration

---
### logd-command-injection

- **File/Directory Path:** `usr/sbin/logd`
- **Location:** `usr/sbin/logd: multiple locations`
- **Risk Score:** 9.0
- **Confidence:** 7.5
- **Description:** logd service calls system and popen to execute external scripts ('/var/run/logd_helper_%u.sh') without proper input validation. If attackers can control these scripts or parameters, it could lead to command injection.
- **Keywords:** system, popen, /var/run/logd_helper_%u.sh
- **Notes:** Scripts should be analyzed for input handling vulnerabilities. Implement strict input validation and sandboxing.

---
### httpd-buffer-overflow

- **File/Directory Path:** `sbin/httpd`
- **Location:** `sbin/httpd:0x135f4 fcn.000132e8`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  strcpy(puVar7 + iVar6 + -0x67c, *(puVar7 + -0x30));
  ```
- **Keywords:** fcn.000132e8, strcpy, puVar7, iVar6, -0x67c, -0x30
- **Notes:** vulnerability

---
### cgibin-command-injection

- **File/Directory Path:** `htdocs/cgibin`
- **Location:** `htdocs/cgibin:0xec8c fcn.0000e4f0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple instances of the system() function calls in the htdocs/cgibin directory execute auxiliary scripts without adequately validating input parameters. The most dangerous case involves executing the "/etc/scripts/dlcfg_hlper.sh" script, where user-controlled script parameters could potentially lead to command injection vulnerabilities.
- **Code Snippet:**
  ```
  system("/etc/scripts/dlcfg_hlper.sh");
  ```
- **Keywords:** system, /etc/scripts/dlcfg_hlper.sh, /etc/scripts/dongle_list_helper.sh, /etc/scripts/apn_list_helper.sh
- **Notes:** vulnerability

---
### adapter-cmd-injection

- **File/Directory Path:** `etc/scripts/adapter_cmd.php`
- **Location:** `etc/scripts/adapter_cmd.php`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** vulnerability
- **Code Snippet:**
  ```
  echo "chat -D ".$devname." OK-AT-OK\n";
  ```
- **Keywords:** query, /runtime/tty/entry:1/devname, /runtime/tty/entry:1/cmdport/devname, chat -D, chat -e -v -c -D
- **Notes:** It is necessary to verify whether the data in /runtime/tty/entry:1 can be corrupted through network interfaces or other input points.

---
### mt-daapd-buffer-overflow

- **File/Directory Path:** `usr/sbin/mt-daapd`
- **Location:** `sbin/mt-daapd:0x17c1c`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** vulnerability
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar8,iVar3);
  ```
- **Keywords:** fcn.00017c1c, strcpy, iVar8, iVar3, sym.imp.strlen
- **Notes:** It is necessary to verify whether the source of iVar3 is controllable and the buffer size of iVar8. Analyze the call path to determine the attack surface.

---
### devdata-command-injection

- **File/Directory Path:** `usr/sbin/devdata`
- **Location:** `usr/sbin/rgbin:0xd208 (fcn.0000ce98)`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** vulnerability
- **Keywords:** sym.imp.system, 0xb334, fcn.0000ce98
- **Notes:** vulnerability

---
### mtd-config-insecure

- **File/Directory Path:** `etc/init.d/S22mydlink.sh`
- **Location:** `etc/init.d/S22mydlink.sh:3-4`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** configuration
- **Keywords:** MYDLINK, REDACTED_PASSWORD_PLACEHOLDER, mount -t squashfs
- **Notes:** configuration

---
