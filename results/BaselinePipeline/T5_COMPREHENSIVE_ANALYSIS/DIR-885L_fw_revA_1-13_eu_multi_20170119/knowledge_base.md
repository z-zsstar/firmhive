# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (3 alerts)

---

### httpd-strcpy-buffer-overflow

- **File/Directory Path:** `sbin/httpd`
- **Location:** `sbin/httpd:0xa23c (fcn.0000a070)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** An unsafe `strcpy` usage was found in `sbin/httpd`, where the content of the source buffer `puVar4 + -0x90` is directly copied to the target buffer `puVar4[-0x48]` without checking its size. Attackers can overwrite adjacent memory by controlling input data, leading to a buffer overflow vulnerability.
- **Code Snippet:**
  ```
  if (puVar4[-0x48] != 0) {
      sym.imp.strcpy(puVar4[-0x48], puVar4 + -0x90);
  }
  ```
- **Keywords:** strcpy, puVar4[-0x48], puVar4 + -0x90, fcn.0000a070
- **Notes:** Further analysis is required to determine the origins of `puVar4[-0x48]` and `puVar4 + -0x90`, verifying whether attackers can control the input data. It is recommended to inspect all locations where `fcn.0000a070` is called.

---
### stunnel-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `etc/stunnel.conf`
- **Location:** `etc/stunnel.conf:4-5`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The `etc/stunnel.conf` configuration file has `setuid = 0` and `setgid = 0` set, which means the stunnel service will run with REDACTED_PASSWORD_PLACEHOLDER privileges. Any service vulnerability could potentially be exploited to gain REDACTED_PASSWORD_PLACEHOLDER access, increasing potential security risks.
- **Keywords:** setuid, setgid
- **Notes:** It is recommended to configure the service to run as a non-privileged user to reduce the potential attack surface.

---
### stunnel-certificate-security

- **File/Directory Path:** `etc/stunnel.conf`
- **Location:** `etc/stunnel.conf:1-2`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The paths for the certificate and REDACTED_PASSWORD_PLACEHOLDER files in `etc/stunnel.conf` are `/etc/stunnel_cert.pem` and `/etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER`. Improper permissions on these files may lead to private REDACTED_PASSWORD_PLACEHOLDER leakage. Additionally, the configuration file does not specify certificate verification options, which could allow insecure connections.
- **Keywords:** cert, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to check the permissions of the certificate and REDACTED_PASSWORD_PLACEHOLDER files and ensure that appropriate certificate verification options are configured.

---
