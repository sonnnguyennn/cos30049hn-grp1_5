"""Disk-backed candidate validation and deterministic diagnostic group allocation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable

PARTITIONS = ("TRAIN", "VALIDATION", "TEST")
WEIGHTS = (3, 1, 1)  # exact 60/20/20 rational targets, denominator 5


def tuple_bytes(values: Iterable[float | str]) -> bytes:
    """Equality authority: canonical ordered values, not a digest or a target."""
    return json.dumps(list(values), ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def duplicate_statistics(sizes: Iterable[int]) -> dict[str, int]:
    result = dict(total_observations=0, unique_X_groups=0, repeated_groups=0,
                  duplicate_excess_rows=0, rows_involved_in_duplicates=0)
    for n in sizes:
        result["total_observations"] += n
        result["unique_X_groups"] += 1
        result["repeated_groups"] += n > 1
        result["duplicate_excess_rows"] += n - 1
        result["rows_involved_in_duplicates"] += n if n > 1 else 0
    return result


def make_database(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        PRAGMA cache_size=-65536;
        PRAGMA temp_store=FILE;
        CREATE TABLE groups (
          gid INTEGER PRIMARY KEY, payload BLOB NOT NULL UNIQUE, sha TEXT NOT NULL,
          sortkey TEXT NOT NULL, n0 INTEGER NOT NULL, n1 INTEGER NOT NULL,
          partition INTEGER);
        CREATE TABLE observations (
          source INTEGER NOT NULL, rownum INTEGER NOT NULL, pk TEXT NOT NULL,
          y INTEGER NOT NULL, gid INTEGER NOT NULL, category TEXT, subcategory TEXT,
          PRIMARY KEY(source,rownum)) WITHOUT ROWID;
    """)


def allocation_choice(totals: tuple[int, int], assigned: list[list[int]],
                      counts: tuple[int, int]) -> int:
    """Exact integer deficits. Pure groups use one class; mixed use both, once."""
    active = [label for label in (0, 1) if counts[label]]
    deficits = [sum(WEIGHTS[p] * totals[y] - 5 * assigned[p][y] for y in active)
                for p in range(3)]
    return max(range(3), key=lambda p: (deficits[p], -p))


def allocate(connection: sqlite3.Connection, *, persist: bool) -> dict:
    """Mixed first, then pure benign, then pure malicious; groups never split by label."""
    totals = tuple(connection.execute("SELECT SUM(n0),SUM(n1) FROM groups").fetchone())
    assigned = [[0, 0] for _ in PARTITIONS]
    group_counts = [[0, 0] for _ in PARTITIONS]
    digest = hashlib.sha256()
    updates = []
    query = """SELECT gid,sha,payload,n0,n1 FROM groups
      ORDER BY CASE WHEN n0>0 AND n1>0 THEN 0 WHEN n0>0 THEN 1 ELSE 2 END,
      sortkey COLLATE BINARY,sha COLLATE BINARY,payload"""
    for gid, sha, payload, n0, n1 in connection.execute(query):
        p = allocation_choice(totals, assigned, (n0, n1))
        assigned[p][0] += n0
        assigned[p][1] += n1
        group_counts[p][0] += n0 > 0
        group_counts[p][1] += n1 > 0
        # Tuple included as a collision-safe identifier; no dependence on insertion gid.
        digest.update(tuple_bytes([sha, payload.decode("ascii"), PARTITIONS[p]]) + b"\n")
        if persist:
            updates.append((p, gid))
            if len(updates) >= 8192:
                connection.executemany("UPDATE groups SET partition=? WHERE gid=?", updates)
                updates.clear()
    if updates:
        connection.executemany("UPDATE groups SET partition=? WHERE gid=?", updates)
    if persist:
        connection.commit()
    return {"rows_by_class": assigned, "groups_by_class": group_counts,
            "ordered_group_assignment_sha256": digest.hexdigest()}
