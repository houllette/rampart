# Reduced explicit-unit resource policy

This original model is informed by [CVE-2026-82752](https://cna.erlef.org/cves/CVE-2026-82752.html)
and the pinned Ash patch/first-parent pair in the capability catalog. A four-byte
output policy is incorrectly enforced using graphemes in the vulnerable model.
The fixed model checks bytes before emitting the value. The Havoc oracle counts
the actual emitted binary independently; ASCII below/equal/above the limit and
multibyte controls establish the fixed path's liveness and rejection behavior.

No Ash source is copied or executed. Literal versus atomic Ash paths, database
persistence and actual Ash configuration remain untested. This demonstrates the
generic unit-disparity primitive, not reproduction of the upstream CVE.
