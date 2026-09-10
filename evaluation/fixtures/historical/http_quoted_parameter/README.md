# Adapted quoted HTTP parameter predicate

This original, reduced fixture models the authentication-parameter integrity
contract disclosed as CVE-2026-82756 in
`ash_authentication_oauth2_server`. It sends a real `Plug.Conn` response, parses
the emitted `WWW-Authenticate` challenge independently, and requires the
request-derived metadata value to remain one quoted `resource_metadata`
parameter. It does not copy upstream code or execute the full package.
