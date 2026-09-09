-- Which upstream answers for a given package, when a repo/channel has
-- more than one of the same format.
--
-- Without these two columns the only ordering is the name, alphabetically,
-- and every upstream is asked about every package. That is wrong the
-- moment the upstreams are not interchangeable mirrors — a vendor registry
-- holding one scope alongside a public one, say. It also fails quietly
-- rather than loudly: an upstream that answers for a name it has no
-- business serving (proxying it, or redirecting to the public registry)
-- simply wins, and every package ends up attributed to it.

-- Higher is tried first; ties fall back to the name, so an existing
-- deployment that has never set a priority keeps the order it has today.
ALTER TABLE upstreams ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- Globs the package name must match for this upstream to be consulted at
-- all. Empty means "no restriction", which is what every existing row
-- gets, so adding this changes nothing until an operator opts in.
ALTER TABLE upstreams ADD COLUMN package_patterns TEXT[] NOT NULL DEFAULT '{}';
