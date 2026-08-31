-- Bounds how fast a password can be guessed.
--
-- A table of its own rather than a count over `audit_log`, because the
-- throttle has to *reserve* an attempt before argon2 runs, not count the
-- failures that have already been written. Counting is a read: any number
-- of concurrent logins can all observe the same under-limit total, spend
-- argon2, and only then record their failures — which is precisely the
-- burst the limit exists to stop.
--
-- One upsert does the reservation atomically. `ON CONFLICT DO UPDATE`
-- takes a row lock, so concurrent attempts on one username serialize on
-- this row and each gets its own incremented value back, across every
-- replica.
--
-- `window_start` is when the current window opened. An attempt arriving
-- after it has elapsed resets the counter rather than extending it, so the
-- limit is self-healing and nobody stays locked out.
CREATE TABLE login_attempts (
    username     TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The primary key serves the reservation and the post-login clear, both of
-- which address a row by username. The periodic purge does not: it asks
-- for everything whose window has elapsed, and without this it reads the
-- whole table every five minutes.
--
-- That matters because the table's size is attacker-influenced — one row
-- per distinct username anybody guesses at — and the purge is precisely
-- what keeps it small, so it is the one query that must not degrade as the
-- table grows. In steady state it matches a handful of rows out of
-- however many are live, which is the shape an index is for.
--
-- Plain rather than CONCURRENTLY: the table is created empty three lines
-- up, so there is nothing to scan and no concurrent writer to block.
CREATE INDEX login_attempts_window_idx ON login_attempts (window_start);
