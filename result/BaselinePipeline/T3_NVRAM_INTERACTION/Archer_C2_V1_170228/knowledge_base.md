# Archer_C2_V1_170228 (3 alerts)

---

### env-PATH-libc

- **File/Directory Path:** `lib/libc.so.0`
- **Location:** `lib/libc.so.0:0x55984-0x55988`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In lib/libc.so.0, the function sym.execvp accesses the PATH environment variable via getenv to locate executable files. This could potentially be exploited by attackers for path hijacking attacks.
- **Keywords:** sym.execvp, sym.getenv
- **Notes:** It is recommended to verify the security of the PATH environment variable before execution.

---
### env-PATH-arping

- **File/Directory Path:** `usr/bin/arping`
- **Location:** `usr/bin/arping:0x42f398`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In /usr/bin/arping, a read operation of the PATH environment variable (`getenv("PATH")` was detected. The return value is used for path processing, posing a potential command injection risk.
- **Code Snippet:**
  ```
  lw t9, -sym.imp.getenv(gp); lui a0, 0x44; addiu a0, a0, -0x2a30 ; "PATH"
  ```
- **Keywords:** getenv, PATH, 0x42f398, 0x43d5d0
- **Notes:** The PATH variable is used directly; it is necessary to check whether subsequent processing is secure.

---
### env-HOME-libc

- **File/Directory Path:** `lib/libc.so.0`
- **Location:** `lib/libc.so.0:0x3e120-0x3e124`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In lib/libc.so.0, the function sym.ruserpass accesses the HOME environment variable via getenv to construct the path to the .netrc file (~/.netrc). This could be exploited by attackers by setting a malicious HOME environment variable path to specify a malicious .netrc file containing sensitive authentication information.
- **Keywords:** sym.ruserpass, sym.getenv, str.HOME, str._.netrc
- **Notes:** It is recommended to verify the permissions and content of the .netrc file to prevent malicious path injection through environment variables.

---
