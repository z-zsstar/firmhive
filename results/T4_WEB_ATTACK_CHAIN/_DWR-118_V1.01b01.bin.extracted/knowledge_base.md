# _DWR-118_V1.01b01.bin.extracted (1 alerts)

---

### web-httpd-tar_execution

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `0x0002d390, 0x0002d3d4 (.rodata)`
- **Risk Score:** 7.0
- **Confidence:** 6.25
- **Description:** The tar extraction functionality was found to use hardcoded paths for executing system commands. The critical paths '/usr/lib/uilib.tar.gz' and '/tmp/uilib' appear to be hardcoded.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** /usr/lib/uilib.tar.gz, /tmp/uilib, system
- **Notes:** It is necessary to confirm whether these hardcoded paths can be controlled or influenced through the web interface.

---
