# _DWR-118_V1.01b01.bin.extracted (1 alerts)

---

### script-ppp-ip-up-dns-insert

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-up`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER-up`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The script uses the `sl_insert_dns_file` function to insert DNS information into the `/etc/resolv.conf` file, where the DNS information may come from environment variables or configuration files.
- **Keywords:** sl_insert_dns_file, /etc/resolv.conf
- **Notes:** DNS information may be tampered with, leading to DNS hijacking or man-in-the-middle attacks.

---
