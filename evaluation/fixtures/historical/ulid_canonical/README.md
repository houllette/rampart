# Adapted canonical-codec predicate

This original, reduced fixture models the identity-aliasing contract disclosed
as CVE-2026-81638 in `ash_double_entry`: every accepted textual identifier must
be its decoded identity's canonical re-encoding. It intentionally models only
the first-character overflow needed to exercise that reusable relation. It does
not copy upstream implementation code or claim to execute the full package. The
corpus pins the reviewed upstream vulnerable/fixed revisions.
