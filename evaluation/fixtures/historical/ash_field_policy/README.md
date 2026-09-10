# Adapted actor-paired Ash field-policy predicate

This original, reduced fixture models the alternate-path field-policy contract
disclosed as CVE-2026-78216 in `ash_lua` and shared by CVE-2026-78230 in
`ash_ai`. A privileged actor proves that the protected value and both paths are
live. The same record and aggregate paths are then exercised for a restricted
actor. The vulnerable aggregate returns the protected value while the fixed
aggregate applies field authorization. `static.ex` is parsed but never compiled;
it preserves a representative `Ash.aggregate/3` option difference for the
versioned SAST classifier. No upstream package code is copied or executed.
