# R6400v2-V1.0.2.46_1.0.36 (5 alerts)

---

### remote-nvram-leafp2p_remote_url

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:36-40`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The script reads the `leafp2p_remote_url` variable and sets the default web service URL. This URL is used for remote service communication, employing HTTP protocol instead of HTTPS, creating a risk of man-in-the-middle attacks.
- **Code Snippet:**
  ```
  leafp2p_remote_url=$(${nvram} get leafp2p_remote_url)
  [ -z $leafp2p_remote_url ] && {
      ${nvram} set leafp2p_remote_url="http://peernetwork.netgear.REDACTED_PASSWORD_PLACEHOLDER"
      ${nvram} commit
  }
  ```
- **Keywords:** leafp2p_remote_url, nvram get, nvram set, nvram commit
- **Notes:** The URL uses HTTP protocol instead of HTTPS, posing a risk of man-in-the-middle attacks.

---
### leafp2p-nvram-leafp2p_sys_prefix

- **File/Directory Path:** `etc/init.d/leafp2p.sh`
- **Location:** `etc/init.d/leafp2p.sh:5`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The script retrieves the environment variable `leafp2p_sys_prefix` using the `nvram get` command and uses it to construct the paths `SYS_PREFIX` and `PATH`. This value is directly utilized in subsequent script execution path construction, posing a potential security risk. If the variable is maliciously modified, it could lead to arbitrary command execution.
- **Code Snippet:**
  ```
  SYS_PREFIX=$(${nvram} get leafp2p_sys_prefix)
  CHECK_LEAFNETS=${SYS_PREFIX}/bin/checkleafnets.sh
  PATH=${SYS_PREFIX}/bin:${SYS_PREFIX}/usr/bin:/sbin:/usr/sbin:/bin:/usr/bin
  ```
- **Keywords:** leafp2p_sys_prefix, nvram, SYS_PREFIX, CHECK_LEAFNETS, PATH
- **Notes:** It is recommended to verify the source and integrity of the `leafp2p_sys_prefix` variable to prevent path injection attacks.

---
### busybox-getenv-PATH

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x51af0`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A getenv call was found in the busybox binary that reads the PATH environment variable. This value is used for path search during execution, posing a command injection risk. If PATH is maliciously modified, it could lead to execution of unintended programs.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, sym.imp.getenv, PATH, 0x521e0
- **Notes:** Modifying the PATH environment variable is a common attack vector that requires special attention.

---
### remote-nvram-leafp2p_replication_url

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:24-28`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The script reads the `leafp2p_replication_url` variable and sets a default value of 'https://readyshare.netgear.com/device/entry'. This URL is used for device replication services, and if tampered with, it could lead to data leakage or man-in-the-middle attacks.
- **Code Snippet:**
  ```
  leafp2p_replication_url=$(${nvram} get leafp2p_replication_url)
  [ -z $leafp2p_replication_url ] && {
      ${nvram} set leafp2p_replication_url="https://readyshare.netgear.com/device/entry"
      ${nvram} commit
  }
  ```
- **Keywords:** leafp2p_replication_url, nvram get, nvram set, nvram commit
- **Notes:** The URL is used for external communication, and if tampered with, it may lead to man-in-the-middle attacks or data leakage.

---
### remote-nvram-leafp2p_replication_hook_url

- **File/Directory Path:** `etc/init.d/remote.sh`
- **Location:** `etc/init.d/remote.sh:30-34`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The script reads the `leafp2p_replication_hook_url` variable and sets the default value to 'https://readyshare.netgear.com/device/hook'. This URL is used for hook services, with security risks similar to those of replication_url.
- **Code Snippet:**
  ```
  leafp2p_replication_hook_url=$(${nvram} get leafp2p_replication_hook_url)
  [ -z $leafp2p_replication_hook_url ] && {
      ${nvram} set leafp2p_replication_hook_url="https://readyshare.netgear.com/device/hook"
      ${nvram} commit
  }
  ```
- **Keywords:** leafp2p_replication_hook_url, nvram get, nvram set, nvram commit
- **Notes:** The URL is used for external communication, with security risks similar to those of replication_url.

---
