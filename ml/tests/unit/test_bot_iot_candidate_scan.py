from __future__ import annotations

import hashlib
import sqlite3

from iotguard.data.bot_iot_candidate_scan import (
    allocate,
    allocation_choice,
    duplicate_statistics,
    make_database,
    tuple_bytes,
)


def test_duplicate_terms_reconcile():
    assert duplicate_statistics([1, 1, 3, 4]) == {
        "total_observations": 9, "unique_X_groups": 4, "repeated_groups": 2,
        "duplicate_excess_rows": 5, "rows_involved_in_duplicates": 7}


def test_integer_deficit_tie_and_mixed_labels():
    assert allocation_choice((10, 100), [[0, 0]]*3, (1, 0)) == 0
    assert allocation_choice((10, 100), [[6, 60], [2, 20], [2, 20]], (1, 1)) == 0
    assert allocation_choice((10, 100), [[6, 60], [0, 0], [0, 0]], (0, 2)) == 1


def build(order):
    db = sqlite3.connect(":memory:")
    make_database(db)
    fixtures = [(tuple_bytes([float(i), "tcp"]), (1, 1) if i == 0 else
                 ((1, 0) if i < 20 else (0, 3))) for i in range(100)]
    for i in order:
        payload, counts = fixtures[i]
        sha = hashlib.sha256(payload).hexdigest()
        db.execute("INSERT INTO groups(payload,sha,sortkey,n0,n1) VALUES(?,?,?,?,?)",
                   (payload, sha, hashlib.sha256(("1729:"+sha).encode()).hexdigest(), *counts))
    return db


def test_exact_equality_not_hash_and_deterministic_mixed_group_allocation():
    db = build(range(100))
    # Deliberately collide digest IDs: exact different tuples must remain different groups.
    db.execute("UPDATE groups SET sha='collision',sortkey='tie' WHERE gid IN (1,2)")
    assert db.execute("SELECT COUNT(*) FROM groups WHERE sha='collision'").fetchone()[0] == 2
    first = allocate(db, persist=True)
    assert first == allocate(db, persist=False)
    assert sum(map(sum, first["rows_by_class"])) == 261
    assert db.execute("SELECT COUNT(*) FROM groups WHERE partition IS NULL").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM groups WHERE n0>0 AND n1>0").fetchone()[0] == 1


def test_allocation_independent_of_insertion_order():
    first = allocate(build(range(100)), persist=True)
    reverse = allocate(build(reversed(range(100))), persist=True)
    assert first == reverse
