# angel-store-audit
Angel Supermarket weekly store audit

## Setup notes

- `index.html` is the whole dashboard; `js/backend.js` connects it to Supabase (`config.js` holds the project URL and the publishable key, which is public by design).
- `supabase/schema.sql` is the database setup: tables, roles, row-level security, photo and document storage, and the edit-window lock. Run it in the Supabase SQL editor; it is safe to run again.
- People, emails and the store manager PIN are never stored in this repository.
