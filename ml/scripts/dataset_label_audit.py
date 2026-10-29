"""Build A3 label/taxonomy evidence without modifying source datasets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Decimal, getcontext
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
DEFAULT_NBAIOT_STRUCTURE = AUDIT_DIR / "n_baiot_csv_structure.csv"
DEFAULT_BOTIOT_STRUCTURE = AUDIT_DIR / "bot_iot_csv_structure.csv"
DEFAULT_SUMMARY = AUDIT_DIR / "label_audit_summary.json"

LABEL_FIELDS = ("attack", "category", "subcategory")
NBAIOT_TOTAL_ROWS = 7_062_606
BOTIOT_TOTAL_ROWS = 3_668_522
EXPECTED_NBAIOT_FINE_COUNTS = {
    "benign": 555_932,
    "gafgyt_combo": 515_156,
    "gafgyt_junk": 261_789,
    "gafgyt_scan": 255_111,
    "gafgyt_tcp": 859_850,
    "gafgyt_udp": 946_366,
    "mirai_ack": 643_821,
    "mirai_scan": 537_979,
    "mirai_syn": 733_299,
    "mirai_udp": 1_229_999,
    "mirai_udpplain": 523_304,
}
EXPECTED_FAMILY_MEMBERS = {
    "gafgyt": {"combo", "junk", "scan", "tcp", "udp"},
    "mirai": {"ack", "scan", "syn", "udp", "udpplain"},
}
FAMILY_HINTS = {"gafgyt_attacks": "gafgyt", "mirai_attacks": "mirai"}

NBAIOT_MAPPING_FIELDS = [
    "logical_id",
    "device",
    "source_kind",
    "raw_family_hint",
    "raw_parent_archive_relative_path",
    "raw_source_relative_path",
    "raw_extracted_relative_path",
    "raw_member_name",
    "canonical_binary",
    "canonical_family",
    "canonical_fine_class",
    "row_count",
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv_atomic(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentage(count: int, total: int) -> str:
    if not total:
        return ""
    getcontext().prec = 28
    return format(Decimal(count) * Decimal(100) / Decimal(total), "f")


def map_n_baiot_row(row: dict[str, str]) -> dict[str, Any]:
    logical_id = row.get("logical_id", "")
    source_kind = row.get("source_kind", "")
    family_hint = row.get("archive_family_hint", "")
    source_relative = row.get("source_relative_path", "")
    extracted_relative = row.get("extracted_relative_path", "")
    parent_archive = row.get("parent_archive_relative_path", "")

    if source_kind == "immutable_benign_source":
        benign_name_matches = PurePosixPath(source_relative).name == "benign_traffic.csv"
        if family_hint or parent_archive or not benign_name_matches:
            raise ValueError(f"Invalid benign provenance for {logical_id}")
        member_name = PurePosixPath(source_relative).name
        binary, family, fine = "benign", "benign", "benign"
    elif source_kind == "derived_extracted_attack":
        if family_hint not in FAMILY_HINTS:
            raise ValueError(f"Unexpected archive family {family_hint!r} for {logical_id}")
        family = FAMILY_HINTS[family_hint]
        member_name = PurePosixPath(extracted_relative).name
        member_path = PurePosixPath(member_name)
        if member_path.suffix != ".csv" or member_path.stem not in EXPECTED_FAMILY_MEMBERS[family]:
            raise ValueError(
                f"Unexpected {family} member {member_name!r} for {logical_id}"
            )
        if PurePosixPath(parent_archive).stem != family_hint:
            raise ValueError(f"Parent archive conflicts with family hint for {logical_id}")
        binary, fine = "malicious", f"{family}_{member_path.stem}"
    else:
        raise ValueError(f"Unexpected source_kind {source_kind!r} for {logical_id}")

    return {
        "logical_id": logical_id,
        "device": row.get("device", ""),
        "source_kind": source_kind,
        "raw_family_hint": family_hint,
        "raw_parent_archive_relative_path": parent_archive,
        "raw_source_relative_path": source_relative,
        "raw_extracted_relative_path": extracted_relative,
        "raw_member_name": member_name,
        "canonical_binary": binary,
        "canonical_family": family,
        "canonical_fine_class": fine,
        "row_count": int(row["row_count"]),
    }


def build_n_baiot_evidence(
    structure_rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    mapping = sorted(
        (map_n_baiot_row(row) for row in structure_rows), key=lambda row: row["logical_id"]
    )
    logical_ids = [row["logical_id"] for row in mapping]
    if len(mapping) != 89 or len(set(logical_ids)) != 89:
        raise ValueError("N-BaIoT must contain exactly 89 uniquely mapped logical CSVs")

    total = sum(row["row_count"] for row in mapping)
    if total != NBAIOT_TOTAL_ROWS:
        raise ValueError(f"N-BaIoT row reconciliation failed: {total}")

    level_fields = {
        "binary": "canonical_binary",
        "family": "canonical_family",
        "fine_class": "canonical_fine_class",
    }
    distributions: dict[str, Counter[str]] = {}
    distribution_rows: list[dict[str, Any]] = []
    for level, field in level_fields.items():
        counts: Counter[str] = Counter()
        for row in mapping:
            counts[row[field]] += row["row_count"]
        distributions[level] = counts
        if sum(counts.values()) != total:
            raise ValueError(f"N-BaIoT {level} distribution does not reconcile")
        for label in sorted(counts):
            distribution_rows.append(
                {
                    "distribution_level": level,
                    "label": label,
                    "count": counts[label],
                    "percentage_of_total": percentage(counts[label], total),
                }
            )

    if dict(distributions["fine_class"]) != EXPECTED_NBAIOT_FINE_COUNTS:
        raise ValueError(
            "N-BaIoT fine-class counts differ from the independently derived A2 targets"
        )
    expected_binary = {"benign": 555_932, "malicious": 6_506_674}
    if dict(distributions["binary"]) != expected_binary:
        raise ValueError("N-BaIoT binary counts differ from the A2-derived targets")

    device_totals: Counter[str] = Counter()
    for row in mapping:
        device_totals[row["device"]] += row["row_count"]
    device_rows: list[dict[str, Any]] = []
    for level, field in level_fields.items():
        device_counts: Counter[tuple[str, str]] = Counter()
        for row in mapping:
            device_counts[(row["device"], row[field])] += row["row_count"]
        if sum(device_counts.values()) != total:
            raise ValueError(f"N-BaIoT device x {level} distribution does not reconcile")
        for device, label in sorted(device_counts):
            count = device_counts[(device, label)]
            device_rows.append(
                {
                    "distribution_level": level,
                    "device": device,
                    "label": label,
                    "count": count,
                    "percentage_of_total": percentage(count, total),
                    "percentage_within_device": percentage(count, device_totals[device]),
                }
            )

    device_families: dict[str, set[str]] = defaultdict(set)
    for row in mapping:
        device_families[row["device"]].add(row["canonical_family"])
    missing_mirai = sorted(
        device for device, families in device_families.items() if "mirai" not in families
    )
    if missing_mirai != ["Ennio_Doorbell", "Samsung_SNH_1011_N_Webcam"]:
        raise ValueError(f"Unexpected N-BaIoT Mirai coverage: {missing_mirai}")

    summary = {
        "total_rows": total,
        "logical_csv_count": len(mapping),
        "binary_class_count": len(distributions["binary"]),
        "family_class_count": len(distributions["family"]),
        "fine_class_count": len(distributions["fine_class"]),
        "binary_distribution": dict(sorted(distributions["binary"].items())),
        "family_distribution": dict(sorted(distributions["family"].items())),
        "fine_class_distribution": dict(sorted(distributions["fine_class"].items())),
        "unmapped_logical_files": 0,
        "coverage_notes": [
            "Ennio_Doorbell and Samsung_SNH_1011_N_Webcam have no observed Mirai archive; "
            "this is recorded coverage, not inferred corruption."
        ],
        "devices_without_observed_mirai": missing_mirai,
    }
    return mapping, distribution_rows, device_rows, summary


def lexical_type(value: str | None) -> str:
    if value is None:
        return "null"
    if value == "":
        return "empty"
    if re.fullmatch(r"[+-]?\d+", value):
        return "integer_string"
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\d*\.\d+)", value):
        return "decimal_string"
    return "text"


def new_bot_profile() -> dict[str, Any]:
    return {
        "row_count": 0,
        "value_counts": {field: Counter() for field in LABEL_FIELDS},
        "attack_category": Counter(),
        "category_subcategory": Counter(),
        "joint": Counter(),
        "row_width_mismatches": 0,
        "invalid_or_missing_label_rows": 0,
    }


def profile_bot_csv(path: Path, delimiter: str) -> dict[str, Any]:
    profile = new_bot_profile()
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter, strict=True)
        header = next(reader, None)
        if header is None:
            raise ValueError(f"Bot-IoT CSV has no header: {path}")
        indices: dict[str, int] = {}
        for field in LABEL_FIELDS:
            positions = [index for index, name in enumerate(header) if name == field]
            if len(positions) != 1:
                raise ValueError(f"Required label column {field!r} is absent or duplicated: {path}")
            indices[field] = positions[0]

        for row in reader:
            profile["row_count"] += 1
            if len(row) != len(header):
                profile["row_width_mismatches"] += 1
            values = tuple(
                row[indices[field]] if indices[field] < len(row) else None
                for field in LABEL_FIELDS
            )
            attack, category, subcategory = values
            for field, value in zip(LABEL_FIELDS, values, strict=True):
                profile["value_counts"][field][value] += 1
            profile["attack_category"][(attack, category)] += 1
            profile["category_subcategory"][(category, subcategory)] += 1
            profile["joint"][(attack, category, subcategory)] += 1
            if any(value is None or value.strip() == "" for value in values):
                profile["invalid_or_missing_label_rows"] += 1
    return profile


def merge_bot_profiles(profiles: Iterable[dict[str, Any]]) -> dict[str, Any]:
    merged = new_bot_profile()
    for profile in profiles:
        merged["row_count"] += profile["row_count"]
        merged["row_width_mismatches"] += profile["row_width_mismatches"]
        merged["invalid_or_missing_label_rows"] += profile[
            "invalid_or_missing_label_rows"
        ]
        for field in LABEL_FIELDS:
            merged["value_counts"][field].update(profile["value_counts"][field])
        for key in ("attack_category", "category_subcategory", "joint"):
            merged[key].update(profile[key])
    return merged


def sortable_value(value: str | None) -> tuple[int, str]:
    return (0, "") if value is None else (1, value)


def display_value(value: str | None) -> str:
    return "<NULL>" if value is None else value


def normalize_canonical(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().casefold()).strip("_")
    if not normalized:
        raise ValueError(f"Cannot canonicalize empty label value {value!r}")
    return normalized


def counter_for_level(profile: dict[str, Any], level: str) -> Counter[Any]:
    if level in LABEL_FIELDS:
        return profile["value_counts"][level]
    if level == "attack_category":
        return profile["attack_category"]
    if level == "category_subcategory":
        return profile["category_subcategory"]
    if level == "attack_category_subcategory":
        return profile["joint"]
    if level == "total":
        return Counter({(): profile["row_count"]})
    raise ValueError(f"Unknown distribution level: {level}")


def key_columns(level: str, key: Any) -> tuple[str, str, str]:
    if level == "total":
        return "", "", ""
    if level == "attack":
        return display_value(key), "", ""
    if level == "category":
        return "", display_value(key), ""
    if level == "subcategory":
        return "", "", display_value(key)
    if level == "attack_category":
        return display_value(key[0]), display_value(key[1]), ""
    if level == "category_subcategory":
        return "", display_value(key[0]), display_value(key[1])
    return tuple(display_value(value) for value in key)


def distribution_sort_key(item: tuple[Any, int]) -> tuple[Any, ...]:
    key = item[0]
    values = key if isinstance(key, tuple) else (key,)
    return tuple(sortable_value(value) for value in values)


def analyze_primary_relationships(profile: dict[str, Any]) -> dict[str, Any]:
    attack_to_categories: dict[str | None, set[str | None]] = defaultdict(set)
    category_to_attacks: dict[str | None, set[str | None]] = defaultdict(set)
    category_to_subcategories: dict[str | None, set[str | None]] = defaultdict(set)
    subcategory_to_categories: dict[str | None, set[str | None]] = defaultdict(set)
    subcategory_to_attacks: dict[str | None, set[str | None]] = defaultdict(set)
    for (attack, category, subcategory), count in profile["joint"].items():
        if count <= 0:
            continue
        attack_to_categories[attack].add(category)
        category_to_attacks[category].add(attack)
        category_to_subcategories[category].add(subcategory)
        subcategory_to_categories[subcategory].add(category)
        subcategory_to_attacks[subcategory].add(attack)

    if any(value is None or value.strip() == "" for value in attack_to_categories):
        raise ValueError("Bot-IoT attack contains null/empty values")
    normal_categories = [
        value
        for value in category_to_attacks
        if value is not None and value.strip().casefold() == "normal"
    ]
    if len(normal_categories) != 1:
        raise ValueError(f"Expected one lexical Normal category, observed {normal_categories}")
    normal_category = normal_categories[0]
    benign_attacks = category_to_attacks[normal_category]
    non_normal_attacks = set().union(
        *(
            attacks
            for category, attacks in category_to_attacks.items()
            if category != normal_category
        )
    )
    if len(benign_attacks) != 1 or len(non_normal_attacks) != 1:
        raise ValueError("Observed attack/category relationships do not define binary semantics")
    benign_attack = next(iter(benign_attacks))
    malicious_attack = next(iter(non_normal_attacks))
    if benign_attack == malicious_attack:
        raise ValueError("Normal and non-Normal categories share the same attack value")

    category_deterministic = all(len(values) == 1 for values in category_to_attacks.values())
    subcategory_deterministic = all(
        len(values) == 1 for values in subcategory_to_attacks.values()
    )
    conflict_count = sum(
        count
        for (attack, category, _subcategory), count in profile["joint"].items()
        if (category == normal_category and attack != benign_attack)
        or (category != normal_category and attack != malicious_attack)
    )
    if not category_deterministic or not subcategory_deterministic or conflict_count:
        raise ValueError("Bot-IoT labels contain attack/category/subcategory semantic conflicts")

    return {
        "normal_category_raw_value": normal_category,
        "benign_attack_raw_value": benign_attack,
        "malicious_attack_raw_value": malicious_attack,
        "attack_to_categories": attack_to_categories,
        "category_to_attacks": category_to_attacks,
        "category_to_subcategories": category_to_subcategories,
        "subcategory_to_categories": subcategory_to_categories,
        "subcategory_to_attacks": subcategory_to_attacks,
        "attack_derivable_from_category": category_deterministic,
        "attack_derivable_from_subcategory": subcategory_deterministic,
        "semantic_conflict_rows": conflict_count,
    }


def build_bot_evidence(
    bot_root: Path, structure_rows: list[dict[str, str]]
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in structure_rows:
        grouped[row["representation"]].append(row)
    required_representations = {
        "all_features_5pct_shards",
        "ten_best_full",
        "ten_best_predefined_train",
        "ten_best_predefined_test",
    }
    if set(grouped) != required_representations:
        raise ValueError(f"Unexpected Bot-IoT representation set: {sorted(grouped)}")

    profiles: dict[str, dict[str, Any]] = {}
    for representation in sorted(grouped):
        file_profiles = []
        for row in sorted(grouped[representation], key=lambda item: item["logical_id"]):
            path = bot_root / Path(row["source_relative_path"])
            delimiter = {"comma": ",", "semicolon": ";"}.get(row["delimiter"])
            if delimiter is None:
                raise ValueError(f"Unsupported delimiter for {path}: {row['delimiter']}")
            profile = profile_bot_csv(path, delimiter)
            if profile["row_count"] != int(row["row_count"]):
                raise ValueError(f"Bot-IoT row-count mismatch for {path}")
            file_profiles.append(profile)
        profiles[representation] = merge_bot_profiles(file_profiles)

    expected_rows = {
        "all_features_5pct_shards": BOTIOT_TOTAL_ROWS,
        "ten_best_full": BOTIOT_TOTAL_ROWS,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    for representation, expected in expected_rows.items():
        profile = profiles[representation]
        if profile["row_count"] != expected:
            raise ValueError(f"Unexpected Bot-IoT row count for {representation}")
        for field in LABEL_FIELDS:
            if sum(profile["value_counts"][field].values()) != expected:
                raise ValueError(f"{representation} {field} counts do not reconcile")
        if sum(profile["joint"].values()) != expected:
            raise ValueError(f"{representation} joint label counts do not reconcile")
        if profile["row_width_mismatches"]:
            raise ValueError(f"{representation} contains row-width mismatches")
        if profile["invalid_or_missing_label_rows"]:
            raise ValueError(f"{representation} contains absent/empty label values")

    full = profiles["ten_best_full"]
    train = profiles["ten_best_predefined_train"]
    test = profiles["ten_best_predefined_test"]
    all_features = profiles["all_features_5pct_shards"]
    levels = (
        "attack",
        "category",
        "subcategory",
        "attack_category",
        "category_subcategory",
        "attack_category_subcategory",
    )
    aggregate_comparisons: dict[str, dict[str, bool]] = {}
    for level in levels:
        full_counter = counter_for_level(full, level)
        split_counter = counter_for_level(train, level) + counter_for_level(test, level)
        aggregate_comparisons[level] = {
            "all_features_matches_ten_best_full": (
                counter_for_level(all_features, level) == full_counter
            ),
            "train_plus_test_matches_ten_best_full": split_counter == full_counter,
        }
    if not all(
        result
        for comparison in aggregate_comparisons.values()
        for result in comparison.values()
    ):
        raise ValueError("Bot-IoT aggregate label distributions differ across representations")

    relationships = analyze_primary_relationships(all_features)
    return profiles, {
        "expected_rows": expected_rows,
        "aggregate_comparisons": aggregate_comparisons,
        "relationships": relationships,
    }


def build_bot_value_rows(profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for representation in sorted(profiles):
        profile = profiles[representation]
        for field in LABEL_FIELDS:
            counts = profile["value_counts"][field]
            groups: dict[str, set[str | None]] = defaultdict(set)
            for value in counts:
                key = "<NULL>" if value is None else value.strip().casefold()
                groups[key].add(value)
            for value, count in sorted(counts.items(), key=lambda item: sortable_value(item[0])):
                group_key = "<NULL>" if value is None else value.strip().casefold()
                rows.append(
                    {
                        "representation": representation,
                        "label_field": field,
                        "raw_value": display_value(value),
                        "value_state": "null" if value is None else "present",
                        "lexical_type": lexical_type(value),
                        "count": count,
                        "percentage_of_representation": percentage(count, profile["row_count"]),
                        "has_outer_whitespace": (
                            "" if value is None else str(value != value.strip()).lower()
                        ),
                        "casefold_group": group_key,
                        "casefold_variant_count": len(groups[group_key]),
                    }
                )
    return rows


def build_bot_distribution_rows(profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    levels = (
        "attack",
        "category",
        "subcategory",
        "attack_category",
        "category_subcategory",
        "attack_category_subcategory",
    )
    for representation in sorted(profiles):
        profile = profiles[representation]
        for level in levels:
            counter = counter_for_level(profile, level)
            for key, count in sorted(counter.items(), key=distribution_sort_key):
                attack, category, subcategory = key_columns(level, key)
                rows.append(
                    {
                        "representation": representation,
                        "distribution_level": level,
                        "raw_attack": attack,
                        "raw_category": category,
                        "raw_subcategory": subcategory,
                        "count": count,
                        "percentage_of_representation": percentage(
                            count, profile["row_count"]
                        ),
                    }
                )
    return rows


def build_relationship_rows(
    profile: dict[str, Any], analysis: dict[str, Any]
) -> list[dict[str, Any]]:
    specifications = (
        ("attack_to_category", "attack", "category", analysis["attack_to_categories"]),
        ("category_to_attack", "category", "attack", analysis["category_to_attacks"]),
        (
            "category_to_subcategory",
            "category",
            "subcategory",
            analysis["category_to_subcategories"],
        ),
        (
            "subcategory_to_category",
            "subcategory",
            "category",
            analysis["subcategory_to_categories"],
        ),
        (
            "subcategory_to_attack",
            "subcategory",
            "attack",
            analysis["subcategory_to_attacks"],
        ),
    )
    rows: list[dict[str, Any]] = []
    joint = profile["joint"]
    for relationship, left_field, right_field, mapping in specifications:
        for left_value in sorted(mapping, key=sortable_value):
            rights = mapping[left_value]
            for right_value in sorted(rights, key=sortable_value):
                count = 0
                for (attack, category, subcategory), joint_count in joint.items():
                    values = {
                        "attack": attack,
                        "category": category,
                        "subcategory": subcategory,
                    }
                    if values[left_field] == left_value and values[right_field] == right_value:
                        count += joint_count
                rows.append(
                    {
                        "representation": "all_features_5pct_shards",
                        "relationship": relationship,
                        "left_field": left_field,
                        "left_raw_value": display_value(left_value),
                        "right_field": right_field,
                        "right_raw_value": display_value(right_value),
                        "count": count,
                        "right_value_count_for_left": len(rights),
                        "deterministic_from_left": str(len(rights) == 1).lower(),
                    }
                )
    return rows


def build_comparison_rows(profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    all_features = profiles["all_features_5pct_shards"]
    full = profiles["ten_best_full"]
    train = profiles["ten_best_predefined_train"]
    test = profiles["ten_best_predefined_test"]
    levels = (
        "total",
        "attack",
        "category",
        "subcategory",
        "attack_category_subcategory",
    )
    rows: list[dict[str, Any]] = []
    for level in levels:
        counters = {
            "all": counter_for_level(all_features, level),
            "full": counter_for_level(full, level),
            "train": counter_for_level(train, level),
            "test": counter_for_level(test, level),
        }
        keys = set().union(*(counter.keys() for counter in counters.values()))
        for key in sorted(keys, key=lambda item: distribution_sort_key((item, 0))):
            attack, category, subcategory = key_columns(level, key)
            split_count = counters["train"][key] + counters["test"][key]
            rows.append(
                {
                    "distribution_level": level,
                    "raw_attack": attack,
                    "raw_category": category,
                    "raw_subcategory": subcategory,
                    "all_features_5pct_shards_count": counters["all"][key],
                    "ten_best_full_count": counters["full"][key],
                    "ten_best_predefined_train_count": counters["train"][key],
                    "ten_best_predefined_test_count": counters["test"][key],
                    "train_plus_test_count": split_count,
                    "all_features_matches_ten_best_full": str(
                        counters["all"][key] == counters["full"][key]
                    ).lower(),
                    "train_plus_test_matches_ten_best_full": str(
                        split_count == counters["full"][key]
                    ).lower(),
                }
            )
    return rows


def build_canonical_mapping_rows(
    primary: dict[str, Any], relationships: dict[str, Any]
) -> tuple[list[dict[str, str]], dict[str, dict[str, str]]]:
    mappings: dict[str, dict[str, str]] = {
        "attack": {
            relationships["benign_attack_raw_value"]: "benign",
            relationships["malicious_attack_raw_value"]: "malicious",
        },
        "category": {},
        "subcategory": {},
    }
    for field in ("category", "subcategory"):
        for raw_value in primary["value_counts"][field]:
            if raw_value is None:
                raise ValueError(f"Cannot canonicalize null {field}")
            mappings[field][raw_value] = normalize_canonical(raw_value)
        if len(set(mappings[field].values())) != len(mappings[field]):
            raise ValueError(f"Canonical {field} normalization would merge raw values")

    rows: list[dict[str, str]] = []
    for field in LABEL_FIELDS:
        canonical_field = "canonical_binary" if field == "attack" else f"canonical_{field}"
        for raw_value, canonical_value in sorted(mappings[field].items()):
            rows.append(
                {
                    "source_field": field,
                    "raw_value": raw_value,
                    "canonical_field": canonical_field,
                    "canonical_value": canonical_value,
                    "mapping_scope": "spelling/case normalization without source-label replacement",
                }
            )
    return rows, mappings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-structure", type=Path, default=DEFAULT_NBAIOT_STRUCTURE)
    parser.add_argument("--bot-iot-structure", type=Path, default=DEFAULT_BOTIOT_STRUCTURE)
    parser.add_argument("--output-dir", type=Path, default=AUDIT_DIR)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    bot_root = args.bot_iot_root.resolve()
    output_dir = args.output_dir.resolve()
    if not bot_root.is_dir():
        raise FileNotFoundError(f"Bot-IoT root does not exist: {bot_root}")
    if output_dir == bot_root or bot_root in output_dir.parents:
        raise ValueError("Audit output must not be written inside the Bot-IoT source root")

    n_mapping, n_distribution, n_device_distribution, n_summary = build_n_baiot_evidence(
        load_csv(args.n_baiot_structure.resolve())
    )
    bot_profiles, bot_analysis = build_bot_evidence(
        bot_root, load_csv(args.bot_iot_structure.resolve())
    )
    relationships = bot_analysis["relationships"]
    canonical_rows, canonical_mappings = build_canonical_mapping_rows(
        bot_profiles["all_features_5pct_shards"], relationships
    )

    output_paths = {
        "n_baiot_label_mapping": output_dir / "n_baiot_label_mapping.csv",
        "n_baiot_label_distribution": output_dir / "n_baiot_label_distribution.csv",
        "n_baiot_device_label_distribution": output_dir
        / "n_baiot_device_label_distribution.csv",
        "bot_iot_label_values": output_dir / "bot_iot_label_values.csv",
        "bot_iot_label_distribution": output_dir / "bot_iot_label_distribution.csv",
        "bot_iot_label_relationships": output_dir / "bot_iot_label_relationships.csv",
        "bot_iot_representation_label_comparison": output_dir
        / "bot_iot_representation_label_comparison.csv",
        "bot_iot_canonical_label_mapping": output_dir
        / "bot_iot_canonical_label_mapping.csv",
    }
    write_csv_atomic(output_paths["n_baiot_label_mapping"], NBAIOT_MAPPING_FIELDS, n_mapping)
    write_csv_atomic(
        output_paths["n_baiot_label_distribution"],
        ["distribution_level", "label", "count", "percentage_of_total"],
        n_distribution,
    )
    write_csv_atomic(
        output_paths["n_baiot_device_label_distribution"],
        [
            "distribution_level",
            "device",
            "label",
            "count",
            "percentage_of_total",
            "percentage_within_device",
        ],
        n_device_distribution,
    )
    write_csv_atomic(
        output_paths["bot_iot_label_values"],
        [
            "representation",
            "label_field",
            "raw_value",
            "value_state",
            "lexical_type",
            "count",
            "percentage_of_representation",
            "has_outer_whitespace",
            "casefold_group",
            "casefold_variant_count",
        ],
        build_bot_value_rows(bot_profiles),
    )
    write_csv_atomic(
        output_paths["bot_iot_label_distribution"],
        [
            "representation",
            "distribution_level",
            "raw_attack",
            "raw_category",
            "raw_subcategory",
            "count",
            "percentage_of_representation",
        ],
        build_bot_distribution_rows(bot_profiles),
    )
    write_csv_atomic(
        output_paths["bot_iot_label_relationships"],
        [
            "representation",
            "relationship",
            "left_field",
            "left_raw_value",
            "right_field",
            "right_raw_value",
            "count",
            "right_value_count_for_left",
            "deterministic_from_left",
        ],
        build_relationship_rows(bot_profiles["all_features_5pct_shards"], relationships),
    )
    write_csv_atomic(
        output_paths["bot_iot_representation_label_comparison"],
        [
            "distribution_level",
            "raw_attack",
            "raw_category",
            "raw_subcategory",
            "all_features_5pct_shards_count",
            "ten_best_full_count",
            "ten_best_predefined_train_count",
            "ten_best_predefined_test_count",
            "train_plus_test_count",
            "all_features_matches_ten_best_full",
            "train_plus_test_matches_ten_best_full",
        ],
        build_comparison_rows(bot_profiles),
    )
    write_csv_atomic(
        output_paths["bot_iot_canonical_label_mapping"],
        [
            "source_field",
            "raw_value",
            "canonical_field",
            "canonical_value",
            "mapping_scope",
        ],
        canonical_rows,
    )

    primary = bot_profiles["all_features_5pct_shards"]
    whitespace_variants = {
        field: sorted(
            value
            for value in primary["value_counts"][field]
            if value is not None and value != value.strip()
        )
        for field in LABEL_FIELDS
    }
    casefold_groups: dict[str, dict[str, list[str]]] = {}
    for field in LABEL_FIELDS:
        groups: dict[str, list[str]] = defaultdict(list)
        for value in primary["value_counts"][field]:
            if value is not None:
                groups[value.strip().casefold()].append(value)
        casefold_groups[field] = {
            key: sorted(values) for key, values in sorted(groups.items()) if len(values) > 1
        }

    hashes = {
        path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path)
        for path in output_paths.values()
    }
    summary = {
        "audit_batch": "A3",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "method": {
            "n_baiot": "derived from verified A2 logical-file provenance and row counts",
            "bot_iot": "streamed Python csv reads limited to attack/category/subcategory",
            "source_rows_modified": False,
        },
        "n_baiot": n_summary,
        "bot_iot": {
            "all_features_rows": primary["row_count"],
            "observed_column_terminology": "46 observed columns; predictor eligibility undecided",
            "attack_unique_count": len(primary["value_counts"]["attack"]),
            "category_unique_count": len(primary["value_counts"]["category"]),
            "subcategory_unique_count": len(primary["value_counts"]["subcategory"]),
            "all_features_raw_distributions": {
                field: {
                    display_value(value): count
                    for value, count in sorted(
                        primary["value_counts"][field].items(),
                        key=lambda item: sortable_value(item[0]),
                    )
                }
                for field in LABEL_FIELDS
            },
            "invalid_or_missing_label_rows": primary["invalid_or_missing_label_rows"],
            "row_width_mismatches": primary["row_width_mismatches"],
            "whitespace_variants": whitespace_variants,
            "casefold_variant_groups": casefold_groups,
            "proven_relationships": {
                "normal_category_raw_value": relationships["normal_category_raw_value"],
                "benign_attack_raw_value": relationships["benign_attack_raw_value"],
                "malicious_attack_raw_value": relationships["malicious_attack_raw_value"],
                "attack_derivable_from_category": relationships[
                    "attack_derivable_from_category"
                ],
                "attack_derivable_from_subcategory": relationships[
                    "attack_derivable_from_subcategory"
                ],
                "semantic_conflict_rows": relationships["semantic_conflict_rows"],
                "subcategories_under_multiple_categories": sorted(
                    display_value(value)
                    for value, categories in relationships[
                        "subcategory_to_categories"
                    ].items()
                    if len(categories) > 1
                ),
            },
            "canonical_mappings": canonical_mappings,
            "aggregate_distribution_comparisons": bot_analysis[
                "aggregate_comparisons"
            ],
            "representation_row_counts": {
                representation: profile["row_count"]
                for representation, profile in sorted(bot_profiles.items())
            },
            "record_identity_proven": False,
        },
        "label_target_metadata": ["attack", "category", "subcategory"],
        "artifact_sha256": hashes,
        "overall_status": "PASS",
    }
    write_json_atomic(args.output_dir.resolve() / DEFAULT_SUMMARY.name, summary)
    print(f"Wrote A3 evidence to: {output_dir}")
    print("Overall status: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, csv.Error, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
