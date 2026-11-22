\set ON_ERROR_STOP on
\getenv next_writer_secret FILE_LEDGER_WRITER_NEXT_PASSWORD
BEGIN;
CREATE ROLE file_ledger_appenders NOLOGIN;
CREATE ROLE file_ledger_writer_next LOGIN PASSWORD :'next_writer_secret';
GRANT file_ledger_appenders TO file_ledger_writer, file_ledger_writer_next;
SELECT pg_catalog.format('GRANT CONNECT ON DATABASE %I TO file_ledger_appenders', current_database()) \gexec
COMMIT;