# Dynamic target derivation

Havoc 0.2 adds conservative target descriptors and a `security_targets` macro.
Derivation describes *where to inject* and supplies default generators/oracles;
the test still owns execution and fixtures. This preserves Havoc's in-process
boundary and avoids guessing how to authenticate, construct a changeset, or
build a Phoenix connection.

## Function specifications

`Havoc.Target.Function.derive/2` reads public BEAM `@spec` metadata and emits one
target per direct `String.t()` or `binary()` argument. Unions containing those
types are supported. Opaque/local aliases and structured types are skipped.

```elixir
targets =
  Havoc.Target.Function.derive(MyApp.Parser,
    only: [{:parse, 2}],
    oracles: [:no_crash, :no_injection_signal]
  )

security_targets "specified parsers resist hostile text",
  targets: targets,
  runs: 200 do
  Havoc.Target.Function.invoke(target, payload,
    arguments: fn
      %{function: :parse} -> ["replaced by Havoc", [mode: :strict]]
    end
  )
end
```

Argument positions are one-based. For functions with arity greater than one,
`:arguments` is mandatory and can be a list or target-to-list callback. Havoc
replaces only the selected position. Explicit positions can supplement specs:

```elixir
Havoc.Target.Function.derive(MyModule,
  parameters: %{{:decode, 2} => [1], normalize: [1]}
)
```

This is not automatic `@spec` test-data generation. Havoc deliberately derives
only adversarial text injection points and requires fixtures for everything
else.

## Phoenix routes

When Phoenix is present in the consumer,
`Havoc.Target.Phoenix.derive(MyAppWeb.Router)` dynamically calls
`Phoenix.Router.routes/1`. No Phoenix dependency is added to Havoc.

```elixir
targets = Havoc.Target.Phoenix.derive(MyAppWeb.Router, methods: [:get, :post])

security_targets "dynamic routes reject hostile path segments",
  targets: targets do
  path = Havoc.Target.Phoenix.path(target, payload)
  get(build_conn(), path)
end
```

Only `:segment` and `*glob` path parameters can be inferred from router data.
Phoenix route metadata does not describe query/body parameters, authentication
fixtures, or request schemas. Those require explicit targets or a future OpenAPI
provider. Payloads are RFC 3986 encoded by default; `encode: false` is available
for a deliberately raw Plug-level test.

## Provider extension

A provider implements `Havoc.Target.Provider` and returns `%Havoc.Target{}`
values. Target IDs must be deterministic because they are appended to property
IDs and therefore bind durable corpus entries. A provider should fail closed by
skipping shapes it cannot instantiate rather than inventing invalid fixtures.
