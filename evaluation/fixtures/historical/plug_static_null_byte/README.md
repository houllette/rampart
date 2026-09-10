# Plug.Static null-byte regression fixture

This is a minimal, adapted excerpt of the path predicate changed by
`elixir-plug/plug` commit `cc583068e482e22bab33931fb4d5d36e7d889fa6` for
CVE-2017-1000052 / GHSA-2q6v-32mr-8p8x. The vulnerable parent is
`c30ffae4d221db68babb3c1513b094a7b0d413f2`.

`upstream_vulnerable_static.ex` and `upstream_fixed_static.ex` are exact copies
of `lib/plug/static.ex` at those revisions. Their SHA-256 digests are pinned by
the corpus. They are parsed as untrusted static inputs and are deliberately not
compiled because both define `Plug.Static` and target an older dependency stack.

The original predicate was private. `vulnerable.ex` and `fixed.ex` make only that
predicate public under distinct fixture module names so the evaluation can replay
the reviewed input without pretending to execute the full historical package.
The relevant rejection lists are otherwise preserved semantically.

The upstream files and adapted excerpts are derived from Plug, copyright 2013
Plataformatec, under the Apache License 2.0. They are evaluation data, not part of
a published Rampart package.
