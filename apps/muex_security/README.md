# MuexSecurity

MuexSecurity is a small operator pack for the actively maintained
[Muex](https://hex.pm/packages/muex) mutation-testing engine. It does not fork
or replace Muex: Muex owns AST traversal, mutant compilation, test selection,
optimization, and reporting. This package contributes focused mutations for
security controls.

```elixir
def deps do
  [
    {:muex, "~> 0.9", only: [:dev, :test], runtime: false},
    {:muex_security, "~> 0.1", only: [:dev, :test], runtime: false}
  ]
end
```

Run the pack through its adapter task. All normal Muex options are forwarded;
`--mutators` names a subset of security operators rather than Muex's built-ins:

```sh
mix muex.security --files lib/my_app --test-paths test/security
mix muex.security --mutators security_decision,sanitizer_bypass,secure_compare
```

`MuexSecurity.configure/1` and `run/1` provide the same integration
programmatically. `MuexSecurity.mutators/0` returns the stable name/module
registry.

Muex 0.9.1 documents a compile-time `config :muex, mutators: ...` map, but its
released resolver does not currently merge that map. Its `--mutator-paths`
workaround recompiles already-loaded dependency modules and emits redefinition
warnings. The adapter task injects the compiled mutator modules into
`%Muex.Config{}` instead, leaving Muex's execution/reporting path unchanged.
This compatibility shim can disappear when the upstream registry is honored.

The pack is deliberately not a new top-level Rampart analysis tool. It is an
extension package for an existing engine, matching Rampart's “extend muex,
don't rebuild it” boundary. It has no dependency on `security_core` and emits no
suite findings by itself; Muex remains the report authority.

A future Muex-to-Rampart adapter may observe surviving security mutants as
normalized candidates and validate them by rerunning one exact mutant/test
selection. That adapter—not this operator pack—must own the Core finding,
validation, and proof-seed contract. Keeping the boundary separate prevents AST
operators from depending on an agent or report transport.

See [OPERATORS.md](OPERATORS.md) for exact semantics and noise controls.
