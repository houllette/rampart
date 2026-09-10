# Adapted cross-tenant cache predicate

This original, reduced fixture models the shared-cache isolation contract
disclosed as CVE-2026-82755 in
`ash_authentication_oauth2_server`. Two tenants request the same URL through a
small RFC-style shared-cache model while uncached `Plug.Conn` responses provide
the independent controls. The vulnerable response is public; the fixed response
is private. The oracle confirms only an exact replay of tenant A's varying
security projection to tenant B. It does not copy upstream code or execute the
full package.
