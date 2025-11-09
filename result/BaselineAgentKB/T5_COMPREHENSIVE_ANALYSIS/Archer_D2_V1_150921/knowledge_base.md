# Archer_D2_V1_150921 (1 alerts)

---

### hotplug-command-injection

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hotplug:fcn.004013a0`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The sbin/hotplug program contains multiple unfiltered system calls for executing system commands (cp, rm, echo). These commands use parameters derived from device paths, which could potentially lead to command injection vulnerabilities if these paths can be externally controlled.
- **Code Snippet:**
  ```
  sym.imp.snprintf(auStack_1b0,0x100,"rm -rf /var/run/usb_device_host%d",auStack_b0[0]);
  sym.imp.system(auStack_1b0);
  ```
- **Keywords:** system, cp -pR, rm -rf, echo, /var/run/usb_device_host%d
- **Notes:** Further confirmation is required to determine whether the device path parameter could be externally controlled.

---
