# Adapted terminal-control predicate

This original, reduced fixture models the shared security contract behind
CVE-2026-82710 (`usage_rules`) and CVE-2026-82584 (`igniter`): package-controlled
text must not retain attacker-capable control bytes when rendered to a terminal.
It does not copy upstream implementation code or claim to execute either full
package. The evaluation corpus pins the reviewed upstream vulnerable/fixed
revisions and uses the same byte-level Havoc oracle for both fixture paths.
