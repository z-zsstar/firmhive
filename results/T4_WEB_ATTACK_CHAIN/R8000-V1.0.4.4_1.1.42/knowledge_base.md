# R8000-V1.0.4.4_1.1.42 (1 alerts)

---

### web-querystring-snprintf

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `genie.cgi:0x999c (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.0
- **Confidence:** 8.25
- **Description:** In genie.cgi, it was found that the QUERY_STRING parameter obtained via getenv is passed to the snprintf function for URL string construction without sufficient validation. Attackers may perform injection attacks by carefully crafting query strings. The issue is located in function fcn.REDACTED_PASSWORD_PLACEHOLDER, involving addresses 0x999c, 0x9ac4, and 0x9b7c.
- **Code Snippet:**
  ```
  // HIDDEN
  char *query = getenv("QUERY_STRING");
  snprintf(url_buf, sizeof(url_buf), "http://example.com/%s", query);
  ```
- **Keywords:** QUERY_STRING, getenv, snprintf, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further verification is needed to determine whether the QUERY_STRING may contain special characters that could lead to injection, and whether the size of url_buf is sufficient.

---
