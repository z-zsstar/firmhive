# R8000-V1.0.4.4_1.1.42 (1 alerts)

---

### http-injection-genie.cgi-QUERY_STRING

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x9f74 (fcn.00009ef8)`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The HTTP QUERY_STRING parameter is obtained via getenv and directly used to construct URLs, which may be exploited for injection attacks. Attackers can influence program behavior by carefully crafted query parameters. The trigger condition occurs when QUERY_STRING parameters are passed through HTTP requests. Potential impacts include arbitrary URL construction and possible server-side request forgery (SSRF).
- **Code Snippet:**
  ```
  char *query = getenv("QUERY_STRING");
  snprintf(url, sizeof(url), "http://example.com/api?%s", query);
  ```
- **Keywords:** getenv, QUERY_STRING, snprintf
- **Notes:** It is necessary to check whether the format string of snprintf strictly restricts the input format. It is recommended to verify all code paths that use QUERY_STRING parameters.

---
