Security Hardening

- Response headers added for API and static files:
  - X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer, Cache-Control: no-store.
- Directory listings disabled to avoid exposing files.
- IDs and base64 inputs validated; malformed or oversized requests rejected.
- POST body size capped (~200 KB); oversized requests receive 413.
- .gitignore prevents committing encrypted identity exports and Tor runtime data.

If an oniondm-identity-*.json backup has been committed previously, create a new identity and remove the old backup from version control history.
