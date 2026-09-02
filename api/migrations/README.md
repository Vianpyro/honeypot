# PostgreSQL migrations

`0001_initial.sql` is the target HoneyLab schema. It is deliberately separate
from `cloudflare/schema.sql`: the latter remains the D1 source schema needed
for a later data migration and rollback.

The Rust API will execute these files through SQLx. SQLx records applied
migrations and refuses altered historical migration files; new schema changes
must therefore use a new, ordered migration file.

The first migration also uses `IF NOT EXISTS` for direct local validation, but
production schema evolution must always go through the migration runner.
