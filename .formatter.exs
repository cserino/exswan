# Root formatter inputs for the monorepo.
# Each package also has its own .formatter.exs used when running mix format inside the package.
[
  inputs: [
    "{mix,.formatter}.exs",
    "packages/*/{mix,.formatter}.exs",
    "packages/*/{config,lib,test}/**/*.{ex,exs}"
  ]
]
