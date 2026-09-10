# Reduced numeric conversion work policy

This original model is informed by [CVE-2026-82729](https://cna.erlef.org/cves/CVE-2026-82729.html)
and the pinned Mint patch/first-parent pair in the capability catalog. Both
models enforce a 64-byte buffer cap, preserving the distinction from the prior
buffer fix. The vulnerable model folds more than 16 hexadecimal digits into a
BEAM arbitrary-precision integer; the fixed model rejects before conversion.
Instrumentation counts actual digit-fold operations, and a separately declared
Havoc budget checks those measurements. Valid 1/16-digit controls and whole/
fragmented 17-digit cases are exercised within 128 bytes and 32 chunks.

This proves a finite operation-count budget violation in a reduced model. It
does not measure Mint CPU behavior, model the cost of each bignum operation,
prove asymptotic complexity, or execute upstream Mint source.
