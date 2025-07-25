# R6200v2-V1.0.3.12_10.1.11 (6 alerts)

---

### upnp-command-injection

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `usr/sbin/upnpd:HIDDEN`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** Multiple critical vulnerabilities exist in /usr/sbin/upnpd, including command injection risks (system() calls), memory corruption risks (insecure string functions), and XML injection risks. Combined with the exposed UPnP control interface in the www directory, attackers can achieve remote code execution.
- **Keywords:** system, _eval, popen, strcpy, sprintf, strncpy, soap_getDeviceName, soap_REDACTED_SECRET_KEY_PLACEHOLDER, Public_UPNP_C3, WANIPConnection
- **Notes:** UPnP services are typically exposed within the local network, posing high risks.

---
### utelnetd-buffer-overflow

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `bin/utelnetd:0x95cc fcn.000090a4`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In bin/utelnetd, an insecure use of strcpy was found for copying the pseudo-terminal device path returned by ptsname into a fixed-size buffer. An attacker can trigger a buffer overflow by controlling the length of the pseudo-terminal device name, leading to arbitrary code execution. This vulnerability exists during the telnet service initialization phase and can be exploited remotely.
- **Code Snippet:**
  ```
  uVar4 = sym.imp.ptsname(puVar15);
  sym.imp.strcpy(ppuVar3 + 5,uVar4);
  ```
- **Keywords:** sym.imp.strcpy, sym.imp.ptsname, fcn.000090a4
- **Notes:** Further verification is required regarding the target buffer size and attack feasibility.

---
### eapd-wireless-config-overflow

- **File/Directory Path:** `bin/eapd`
- **Location:** `bin/eapd:0xceb0`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** Multiple instances of unvalidated strcpy/memcpy calls exist in bin/eapd, which may lead to buffer overflow when handling wireless network configurations. Attackers could achieve remote code execution or privilege escalation by crafting malicious network interface names or configuration data.
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar4,iVar6);
  iVar2 = sym.imp.strlen(iVar4);
  sym.imp.memcpy(iVar4 + iVar2,*0xd2c4,10);
  ```
- **Keywords:** fcn.0000ceb0, strcpy, iVar4, iVar6, wl_probe, wl_ioctl, nvifname_to_osifname
- **Notes:** Further verification is required regarding the buffer size and input source.

---
### netatalk-auth-bypass

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_REDACTED_PASSWORD_PLACEHOLDER.so`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER:sym.REDACTED_PASSWORD_PLACEHOLDER_login`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The Netatalk authentication module (REDACTED_PASSWORD_PLACEHOLDER) contains buffer operation vulnerabilities and logical flaws, which may lead to authentication bypass or remote code execution. Combined with improper configuration of the afpREDACTED_PASSWORD_PLACEHOLDER file (minimum REDACTED_PASSWORD_PLACEHOLDER length set to 0) and enabled guest accounts, attackers could potentially gain unauthorized access.
- **Code Snippet:**
  ```
  sym.imp.memcpy(puVar4[-1],puVar4[-6],*puVar4);
  ```
- **Keywords:** sym.REDACTED_PASSWORD_PLACEHOLDER_login, memcpy, puVar4[-1], puVar4[-6], *puVar4, afpREDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDERfile, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** The context of the call and the possibility of input control need to be analyzed

---
### init-script-tempfile-race

- **File/Directory Path:** `etc/init.d`
- **Location:** `etc/init.d/afpdHIDDENavahi-daemon`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The service scripts (afpd and avahi-daemon) in etc/init.d have temporary file race condition vulnerabilities, as they create configuration files in the /tmp directory in an insecure manner. Attackers could potentially manipulate service configurations through symlink attacks or race conditions.
- **Keywords:** AFP_CONF_DIR, mkdir -p, cp -f, AppleVolumes.default, AVAHI_SERVICES_CONF_DIR, /tmp/avahi/services
- **Notes:** Need to verify the implementation details of the update_afp function

---
### web-ui-xss

- **File/Directory Path:** `www/script/script.js`
- **Location:** `www/script/script.js:iframeResizeHIDDEN`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Multiple potential DOM-based XSS vulnerabilities exist in www/script/script.js, particularly in the iframeResize function which directly outputs unvalidated content. Combined with improper file permission settings (777) for PWD_REDACTED_PASSWORD_PLACEHOLDER_h.htm, this could form a complete attack chain.
- **Keywords:** iframeResize, iframe.contentDocument, iframe.Document, PWD_REDACTED_PASSWORD_PLACEHOLDER_h.htm, 777 permissions
- **Notes:** Verification of actual exploitation conditions and user interaction requirements is required

---
