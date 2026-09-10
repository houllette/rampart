[
  subdirectories: ["apps/*"],
  inputs: [
    "{mix,.formatter}.exs",
    "{config,lib,test}/**/*.{ex,exs}",
    "evaluation/*.exs",
    "evaluation/support/**/*.exs",
    "evaluation/fixtures/{composed,otp,plug,overhead}/**/*.{ex,exs}",
    "evaluation/fixtures/historical/**/vulnerable.ex",
    "evaluation/fixtures/historical/**/fixed.ex",
    "evaluation/fixtures/historical/{terminal_control,ulid_canonical,http_quoted_parameter,cache_tenancy,ash_field_policy}/**/*.{ex,exs}"
  ]
]
