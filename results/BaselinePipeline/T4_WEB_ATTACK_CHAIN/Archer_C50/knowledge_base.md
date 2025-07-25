# Archer_C50 (4 alerts)

---

### httpd-strcpy-buffer-overflow

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x00408c64 (sym.http_parser_main)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  iVar6 = sym.http_stream_fgets(*(*param_1 + 8),*param_1 + 0x14,pcVar11,iStack_38);
  ```
- **Keywords:** sym.http_parser_main, strcpy, HTTPHIDDEN
- **Notes:** It is recommended to perform input length validation and use safer functions such as strncpy.

---
### bpalogin-strcpy-buffer-overflow

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `usr/sbin/bpalogin:0x004019b0 (sym.login)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** vulnerability
- **Code Snippet:**
  ```
  0x004028d8      4081828f       lw v0, -sym.imp.strcpy(gp)
  0x004028dc      REDACTED_PASSWORD_PLACEHOLDER       nop
  0x004028e0      21c84000       move t9, v0
  0x004028e4      09f82003       jalr t9
  ```
- **Keywords:** sym.login, sym.extract_valuestring, sym.add_field_string, strcpy, strncpy
- **Notes:** vulnerability

---
### httpd-file-upload-traversal

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x00407d64 (sym.http_rpm_update)`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** vulnerability
- **Code Snippet:**
  ```
  iVar6 = sym.http_stream_fgets(*(*param_1 + 8),*param_1 + 0x14,pcVar11,iStack_38);
  ```
- **Keywords:** sym.http_rpm_update, filename, strcmp
- **Notes:** vulnerability

---
### httpd-sscanf-format-string

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER (sym.http_cgi_main)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  iVar6 = sym.http_stream_fgets(*(*param_1 + 8),*param_1 + 0x14,pcVar11,iStack_38);
  ```
- **Keywords:** sym.http_cgi_main, sscanf, HTTP/1.1
- **Notes:** vulnerability

---
