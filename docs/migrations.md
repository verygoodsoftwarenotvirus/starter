# Migrations

Migrations in the API are handled via [the Darwin library](https://go.pkg.dev/github.com/GuiaBolso/darwin). We keep the individual migration files in [the migrations directory](postgres/migrations/). They get embedded into the end Go binary by the compiler.

We employ the strategy of attempting to migrate the database when the server starts, every time. Darwin is smart enough to know when no migrations need to run, so the 99% case (where deploys are made with no schema changes) is very fast, migration is basically a single-query operation to check on the state of migrations.
