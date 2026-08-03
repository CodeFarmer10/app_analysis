# Traffic Logs Created Time Design

## Goal

Add a database-generated creation timestamp to each row in `traffic_logs`.

## Scope

- Add `created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP` to the
  `traffic_logs` definition used for new databases.
- Add an idempotent compatibility migration that adds the same column when an
  existing `traffic_logs` table does not have it.
- Keep traffic-log inserts unchanged so MySQL supplies the timestamp.
- Do not expose the field through repository queries, APIs, reports, or the
  frontend.

## Existing Data

When the compatibility migration adds the non-null column, MySQL assigns the
column default to existing rows. Those values represent migration time rather
than the original row insertion time, which is not available.

## Verification

- Verify the migration declares the column in the base table definition.
- Verify the compatibility migration is guarded by an information-schema check
  and can run repeatedly.
- Run the relevant backend test suite or migration checks available in the
  repository.
