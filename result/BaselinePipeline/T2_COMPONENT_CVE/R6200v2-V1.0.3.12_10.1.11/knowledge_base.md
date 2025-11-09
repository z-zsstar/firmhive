# R6200v2-V1.0.3.12_10.1.11 (2 alerts)

---

### dnsmasq-2.15-OpenDNS-1

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `usr/sbin/dnsmasq (binary strings)`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** The dnsmasq version information found in the file usr/sbin/dnsmasq is 2.15-OpenDNS-1. This version may contain multiple high-risk vulnerabilities, including CVE-2017-14492, CVE-2017-14493, and CVE-2017-14491, which allow remote attackers to cause heap or stack overflow through carefully crafted requests, leading to denial of service or arbitrary code execution.
- **Code Snippet:**
  ```
  Found version string: '2.15-OpenDNS-1'
  ```
- **Keywords:** dnsmasq, 2.15-OpenDNS-1, DNS, DHCPv6
- **Notes:** third_party_component

---
### avahi-daemon-0.6.25

- **File/Directory Path:** `usr/sbin/avahi-daemon`
- **Location:** `usr/sbin/avahi-daemon (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The version information of Avahi 0.6.25 was found in the file usr/sbin/avahi-daemon. This version has a known vulnerability CVE-2010-2244, where a remote attacker can cause a denial of service (assertion failure and daemon exit) by sending specially crafted DNS packets.
- **Code Snippet:**
  ```
  Found version string: '0.6.25'
  ```
- **Keywords:** avahi-daemon, 0.6.25, AvahiDnsPacket, avahi-core/socket.c
- **Notes:** It is recommended to upgrade to the latest version of Avahi to fix this vulnerability.

---
