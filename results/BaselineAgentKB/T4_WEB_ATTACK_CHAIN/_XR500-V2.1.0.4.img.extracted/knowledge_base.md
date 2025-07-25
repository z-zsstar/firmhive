# _XR500-V2.1.0.4.img.extracted (1 alerts)

---

### proccgi-strcpy-vulnerability

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x87f0 (fcn.000087c8)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** In the fcn.000087c8 function of the proccgi binary, an insecure use of the strcpy function was found when processing the QUERY_STRING parameter. The function first obtains the length of the input string and allocates memory, then uses strcpy to copy the content, but fails to implement effective length restrictions or boundary checks on the input. This may lead to a buffer overflow vulnerability. Attackers could exploit this vulnerability by crafting an excessively long QUERY_STRING parameter.
- **Code Snippet:**
  ```
  0x000087ec      0510a0e1       mov r1, r5
  0x000087f0      76ffffeb       bl sym.imp.strcpy
  ```
- **Keywords:** strcpy, QUERY_STRING, malloc, proccgi, fcn.000087c8
- **Notes:** Further verification is needed to determine whether constructing an excessively long QUERY_STRING parameter could trigger a crash or execute arbitrary code.

---
