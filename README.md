# SupaScan

A command-line auditor for weak or missing Row Level Security (RLS) on Supabase projects.
It probes a target's PostgREST API with a given key (or session) and reports which tables
are readable, writable, or locked down.

## Features

- Automatic table discovery via four chained methods:
  1. PostgREST OpenAPI spec (`/rest/v1/`)
  2. `information_schema.tables`
  3. PostgREST "Perhaps you meant" 404 hints
  4. Common table-name enumeration (list in `config/tables.json`)
- Per-table RLS checks: SELECT, INSERT, UPDATE (no-op write on a real row), DELETE
- Risk rating per table: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`
- Full data extraction (`--backup`) with one CSV file per table, including a header row
- Optional authenticated session so RLS policies scoped to a user (`auth.uid()`) can be tested

## Requirements

- Python 3.9+
- `requests`, `pystyle`, `colorama`

```bash
pip install requests pystyle colorama
```

## Usage

```text
python supascan.py <subdomain> -a <anon_key> [options]
```

| Option | Description |
| --- | --- |
| `subdomain` | The Supabase subdomain (`example` for `example.supabase.co`) |
| `-a`, `--anon_key` | The Supabase API key (publishable/anon, or secret with `-s`) |
| `-s`, `--secret` | Treat the key as a secret key (bypasses RLS) |
| `-t`, `--tables` | Audit specific tables instead of auto-discovering |
| `--access_token` | Use an authenticated session JWT as the Bearer token |
| `--cookie` | Extract the session JWT from a `sb-<ref>-auth-token` cookie value |
| `--email`, `--password` | Log in via Supabase Auth (password grant) to get a session |
| `-o`, `--output` | Output directory for results |
| `-b`, `--backup` | Extract all accessible tables (requires `-o`) |

### Examples

Audit with an anon key:

```bash
python supascan.py myproject -a sb_publishable_xxxx
```

Audit as a logged-in user (policies using `auth.uid()` now apply):

```bash
python supascan.py myproject -a <anon_key> --email you@example.com --password '...'
python supascan.py myproject -a <anon_key> --access_token eyJhbGciOi...
python supascan.py myproject -a <anon_key> --cookie 'sb-<ref>-auth-token=...'
```

Audit only specific tables:

```bash
python supascan.py myproject -a <anon_key> -t profiles orders messages
```

Extract every readable table to CSV:

```bash
python supascan.py myproject -a <anon_key> -b -o ./out
```

## Session authentication

Supabase's REST API does not use cookies for authorization. The `apikey` header stays your
anon key, and the `Authorization: Bearer` value decides the role: the anon key runs as
`anon`, while a user's access token runs as `authenticated` with that user's `auth.uid()`.
Many projects only expose data to authenticated users, which is why the session options exist.

Ways to get a token:

1. **Network tab (most reliable):** log into the site, find a request to
   `*.supabase.co/rest/v1/...`, copy the `Authorization: Bearer ...` value minus `Bearer `.
2. **Cookie:** copy the `sb-<ref>-auth-token` cookie value — it is JSON (sometimes
   base64-encoded JSON) containing `access_token`. `--cookie` decodes it for you.
3. **Login:** pass `--email` and `--password` (the password is prompted for if omitted).

Access tokens expire (about an hour by default). If a long scan starts failing, grab a
fresh token and re-run.

## Output

- **Audit mode** prints a live report per table (risk level + probe details) and a summary.
  With `-o <dir>` it also writes `<dir>/audit_results.json`.
- **Backup mode** (`-b`) writes one `<dir>/<table>.csv` per accessible table with a header
  row of column names. JSON/array columns are embedded as JSON strings; tables with zero
  accessible rows are skipped with a note.

## Project structure

```text
SupaScan/
├── supascan.py          # entry point, CLI, session handling
├── discover.py          # table discovery + RLS status/policy checks
├── extraction.py        # table dumping, CSV/JSON export
├── config/
│   ├── banner.txt       # startup banner
│   └── tables.json      # candidate table names for enumeration
└── utility/
    ├── logger.py        # colored console logging
    ├── load_tables.py   # config loader
    └── get_time.py      # timestamp helper
```
