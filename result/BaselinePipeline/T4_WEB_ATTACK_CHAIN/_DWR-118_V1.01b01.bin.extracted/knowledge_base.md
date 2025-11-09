# _DWR-118_V1.01b01.bin.extracted (6 alerts)

---

### httpd-system-command-injection

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x405050-0x405090 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Dangerous system() calls were found in multiple functions of the httpd binary, used to execute shell commands. These commands include process management (killall, rmmod) and system reboot (reboot) operations, with command strings directly concatenated, posing command injection risks. Attackers may potentially inject malicious commands by manipulating input parameters.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7db0))("echo \"             [ -e /var/run/web-rebinding.pid ] && kill \\\`cat /var/run/web-rebinding.pid\\\` ;             killall -9 wscd             ;             killall -9 watchdog-touch   ;             watchdog-touch -d           ;             rmmod -f ralink_wdt         ;         \" > /tmp/killall-wdt.sh ; sh /tmp/killall-wdt.sh & ");
  ```
- **Keywords:** system, killall, rmmod, reboot
- **Notes:** verify whether these commands accept user-controllable input from HTTP requests

---
### httpd-strcpy-buffer-overflow

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:HIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A large number of strcpy calls were found in httpd, posing buffer overflow risks. If these calls process user input from HTTP requests, attackers could exploit this vulnerability to execute arbitrary code.
- **Keywords:** strcpy
- **Notes:** Further analysis of the context of these strcpy calls is needed to determine whether HTTP request input is being processed.

---
### httpd-filesystem-command-injection

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x409838-0x409a10 (fcn.0040950c)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple file system operation commands (mkdir, cp) and process management commands (daemon) were identified in httpd, posing potential command injection risks. If these commands accept user input, they could be exploited to execute arbitrary commands.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7db0))("mkdir -p /ram/www");
  (**(loc._gp + -0x7db0))(auStack_168);
  ```
- **Keywords:** system, mkdir, cp, daemon
- **Notes:** verify whether these commands accept user input from HTTP requests

---
### httpd-sprintf-format-string

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:HIDDEN`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A large number of sprintf calls were found in httpd, posing a risk of format string vulnerabilities. If the format string contains user input, attackers could potentially exploit this vulnerability to read memory or execute arbitrary code.
- **Keywords:** sprintf
- **Notes:** Check if the format string contains user input from HTTP requests

---
### httpd-reboot-dos

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x405a68 (fcn.004058d4)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A direct call to system("reboot") was discovered in httpd, which could lead to a denial of service attack. If an attacker is able to trigger this function, it will cause the device to reboot.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7db0))("reboot");
  ```
- **Keywords:** system, reboot
- **Notes:** Check if the trigger condition can be controlled by external HTTP requests

---
### httpd-tar-command-injection

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x409db0-0x409e1c (fcn.00409d0c)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The execution of the tar command was detected in httpd, posing potential risks of path traversal or command injection. If the source or parameters of the archive are user-controlled, it could be exploited to access arbitrary files or execute commands.
- **Code Snippet:**
  ```
  (**(loc._gp + -0x7db0))(auStack_88);
  ```
- **Keywords:** system, tar, cp
- **Notes:** Verify the trustworthiness of the compressed file source and whether it accepts parameters from HTTP requests

---
