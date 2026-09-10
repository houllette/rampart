# Reduced incremental buffer policy

This original model is informed by [CVE-2026-82728](https://cna.erlef.org/cves/CVE-2026-82728.html)
and the pinned Mint patch/first-parent pair in the capability catalog. The driver
delivers at most 128 bytes and 32 chunks to a reduced line accumulator. The
vulnerable model retains more than 16 bytes in an incomplete state; the fixed
model rejects and releases its buffer. Measurements are logical buffer bytes
after each step, not peak allocation or backing-binary/process memory.

Controls include a valid completed line, exact-budget incomplete input, and
whole versus one-byte over-budget deliveries. No Mint HTTP state machine,
network connection or upstream source is executed. Worker lifecycle/cleanup
and the actual HTTP status/chunk-metadata grammar remain upstream fixture work.
