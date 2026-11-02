# Bot-IoT candidate full validation — 2026-11-02

Status: **PROPOSED_FOR_REVIEW**. Targeted validation only; no classifier/clustering,
scaler or encoder fit, official training package, LR rerun or full G1/G2 rerun.

## Smoke terminology addendum (historical evidence unchanged)

| Statistic | Meaning | Smoke count |
| --- | --- | ---: |
| Total observations | All selected source rows | 10,328 |
| Unique X groups | All distinct normalized tuples | 4,164 |
| Repeated groups | Distinct tuples occurring at least twice | 1,365 |
| Singleton groups | Distinct tuples occurring once | 2,799 |
| Duplicate-excess rows | Sum(size-1) | 6,164 |
| Rows involved in duplicates | Sum(size) for repeated groups | 7,529 |

Thus 10,328 = 4,164 + 6,164 = 2,799 + 7,529 and 7,529 = 1,365 + 6,164.
The earlier “duplicate groups” label refers to **repeated groups**. It was not a
count of all unique groups, repeated observations or excess observations. The old
JSON/handoff remain unchanged. Full verification reconstructs the identical selected
rows and checks both historical sample membership and assembled-X hashes.

## Frozen policy

Policy/implementation were committed **before** the full scan at `18ddf59`.
The 13 predictors and seed1729 are unchanged. Exact normalized tuples are SQLite
UNIQUE BLOB keys, independent of labels; SHA256 collisions cannot merge different X.
Valid category text and valid-but-unseen TRAIN-relative values are separate concepts.
Frozen unseen policy remains error/blocker, without vocabulary learned from held-out data.
Full definitions and integer-deficit tie rules are in candidate JSON `scan_policy` and
the protocol pre-scan addendum. Mixed-label groups are retained intact in the frozen
diagnostic extension and independently block adoption; no labels or records are changed.

## Reproduction

From repository root, with a **new external working directory**:

```powershell
ml/.venv/Scripts/python.exe ml/scripts/verify_bot_iot_candidate_full.py --root E:/Document/Bot_IoT_Dataset --work-dir <fresh-external-directory>
ml/.venv/Scripts/python.exe -m pytest ml/tests/unit/test_bot_iot_candidate_scan.py ml/tests/unit/test_bot_iot_secondary.py ml/tests/unit/test_bot_iot_preprocessing.py -q
ml/.venv/Scripts/python.exe -m ruff check ml/src/iotguard/data/bot_iot_candidate_scan.py ml/scripts/verify_bot_iot_candidate_full.py ml/tests/unit/test_bot_iot_candidate_scan.py
```

External working storage contains SQLite exact groups and observations, diagnostic
membership JSONLs, all conflicting tuple/count records, group-size histogram and
verification JSON. These are validation evidence, not an official package; no scaler,
encoder, X matrices or models are exported. Database cache is capped at64MiB and
assembly batches at8,192 rows; SQLite sorting uses external temporary storage.


## VERIFIED — kết quả full scan và proposed split

- Bốn content hashes khớp raw manifest trước scan, trên bytes thực sự đọc, sau scan,
  sau allocation và được independent checker hash lại. Sizes/mtime giữ nguyên.
- Rows từng shard:1.000.000 /1.000.000 /1.000.000 /668.522. Tất cả3.668.522 rows
  validate thành công; invalid rows0, unassigned rows0, SHA256 collision buckets0,
  SQLite integrity_check=ok. Source/group/observation totals khớp.
- Full X:672.607 unique groups,497.259 repeated groups,2.995.915 excess rows,
  3.493.174 rows involved in duplicates,175.348 singleton groups.
- Binary support:477 benign thuộc406 groups;3.668.045 malicious thuộc672.202 groups.
  Hai group counts cộng lại lớn hơn unique X groups đúng1 vì có1 mixed-label group.
- Smoke được tái tạo cùng source membership/X hashes; toàn bộ số trong addendum đầu
  tài liệu đã được exact-confirm, không chỉ suy ra bằng số học. Evidence cũ không đổi.
- Exact-tuple partition overlap0 qua SQL group-by payload; allocation replay trong runner
  và checker độc lập đều khớp. Checker dùng Fraction, không import allocation implementation;
  kiểm tra từng672.607 group và tái tạo digests từ đủ3.668.522 observations.

| Partition | Total rows | Benign | Malicious | Unique X groups | Benign groups | Malicious groups |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TRAIN | 2.201.114 | 286 | 2.200.828 | 396.266 | 248 | 396.019 |
| VALIDATION | 733.704 | 96 | 733.608 | 138.060 | 77 | 137.983 |
| TEST | 733.704 | 95 | 733.609 | 138.281 | 81 | 138.200 |

Rows100/50/50 và groups20/10/10 **đều PASS cho cả hai classes**. Actual counts không
phải nominal286/95/96; không đổi membership để ép counts theo làm tròn dự kiến.

## BLOCKED — cần PM/Hiếu quyết định, chưa adopt phương án khác

**1. Exact-X cross-label conflict.** Có đúng1 group,3.744 rows:11 benign và3.733 malicious.
Tất cả ở shard4, labels Normal/Normal và Reconnaissance/Service_Scan. Exact tuple theo
ordered predictors:

`[1.0,60.0,0.0,1.0,0.0,60.0,0.0,0.0,0.0,0.0,"e","udp","INT"]`

Group SHA256 `413952c7fb9dc5b9ed4e85b5bd90fcf56ad147a666dacec19fd8ada49a90b844`.
Toàn group ở TRAIN;11 benign không bị drop/relabel. Source labels khác nhau không tự
chứng minh annotation sai: với13 features hiện tại, các observations này không phân biệt
được bằng X. Frozen policy chặn adoption. Mọi conflict tuples/counts lưu ngoài Git;
SQLite giữ lineage đầy đủ để review từng record.

**2. Valid-but-unseen categories.** TRAIN có4 protocols và10 states. TEST có thêm
`ipv6-icmp` và `NRS`, cùng8 observations; VALIDATION không có unseen category.
Flags coverage TRAIN/VALIDATION/TEST:9/6/7 values; protocols:4/4/5; states:10/10/11.
`handle_unknown=error` đã khóa trước diagnostics nên candidate preprocessing/split này
bị chặn; không học full vocabulary hoặc chuyển các dòng đó sang TRAIN.

**3. Concentration/uncertainty.** Largest benign group tại TRAIN/VALIDATION/TEST có
18/18/8 rows, chiếm6,29%/18,75%/8,42% benign partition. Largest malicious groups có
84.240/753/1.193 rows; group84.240 chiếm3,83% TRAIN. Support gates pass không biến
repeated rows thành các quan sát độc lập; review group-aware uncertainty và row/group
weighted reporting trước official experiment.

## PLANNED — phương án review có lý do, chưa triển khai/adopt

- Conflict: review source semantics/lineage của group; có thể đề xuất chấp nhận và báo rõ
  ambiguity/noise trong một protocol revision, hoặc candidate v2 có thêm transaction
  information được chứng minh semantics/availability. Không tự thêm IP/time/seq/aggregates,
  không gọi labels sai, không drop group, không lựa features theo model scores.
- Unseen: nếu muốn hỗ trợ categories mới, đề xuất một reserved UNKNOWN representation
  được định nghĩa trước, vocabulary vẫn fit TRAIN-only. Đây là policy khác cần review,
  không phải sửa ngầm encoder hiện tại; không thêm chính tên held-out categories vào vocab.
- Giữ proposed membership và seed hiện tại để PM/Hiếu đánh giá trade-off. Không reroll.
  Nếu đổi contract/encoding/features, tạo version/evidence mới và kiểm chứng lại có phạm vi.
- Chỉ sau review/adoption và package/runner/resource checks riêng mới chuẩn bị official
  package và classifier/Dummy trên Kaggle. Checkpoint này không READY_FOR_TRAINING.

## Evidence, hashes, resource usage và lệnh đã chạy

Git giữ ba JSON nhỏ (tổng khoảng29KB):

- [Full verification](../../artifacts/manifests/bot_iot_candidate_full_verification.json)
- [Independent replay](../../artifacts/manifests/bot_iot_candidate_full_independent_verification.json)
- [Proposed split summary](../../artifacts/manifests/bot_iot_candidate_proposed_split_summary.json)

External archive: `E:/Document/iotguard_secondary_candidate_reviews/20261102_full_v1`.
SQLite366.944.256 bytes; membership files tổng552.391.301 bytes. Tổng working artifacts
khoảng919MB; không đưa bulk files vào Git. Policy/protocol bytes dùng lúc scan được lưu
riêng dưới `frozen_candidate_contract.json` và `frozen_protocol.md` (được copy trước khi
xem diagnostics). Git revision đầy đủ: `18ddf599ce3d137e3d234b91349e3349023cc3f2`,
working tree sạch lúc scanner bắt đầu. Implementation hashes có trong verification JSON.

Frozen contract SHA256:
`fc5a44ef1a5ea13e12e2249c1243ec28b8747a08d65b3d3740f2e95cdfe1c64d`.
Frozen protocol SHA256:
`53b813a91bfebb1d2ed3baf1513e800a574e853a8ac2fc2761a0c4ef81d689c3`.
Verification JSON SHA256:
`4560b9bfbf12d96fd72161139b75738ae9437584c2d6e24150c266961094c045`.
Current contract/protocol chỉ thêm post-scan completion/blocker annotations; không nhận
chúng là exact bytes dùng trong scan. Policy, predictors, labels, seed và encoding không đổi.

Full scan:719,22s elapsed,714,67s process CPU, peak RSS323.428.352 bytes (~308,45MiB),
batch8.192, SQLite cache64MiB. Independent replay:67,34s; pass với0 mismatches.
Không chạy nhiều process nặng song song lúc scan; checker chỉ chạy sau scanner kết thúc.

Các lệnh chính thực sự đã chạy:

```powershell
git switch -c codex/bot-iot-full-candidate-validation
git commit -m "Freeze Bot-IoT exact-group scan and split policy before diagnostics"
ml/.venv/Scripts/python.exe ml/scripts/verify_bot_iot_candidate_full.py --root E:/Document/Bot_IoT_Dataset --work-dir E:/Document/iotguard_secondary_candidate_reviews/20261102_full_v1
ml/.venv/Scripts/python.exe ml/scripts/check_bot_iot_candidate_evidence.py --work-dir E:/Document/iotguard_secondary_candidate_reviews/20261102_full_v1 --output E:/Document/iotguard_secondary_candidate_reviews/20261102_full_v1/independent_verification.json
git fetch origin
```

Tests trước scan:87 passed (4,30s); final targeted rerun87 passed (3,06s), gồm canonical parser, candidate assembly và split
algorithm. Có test deliberate hash collision, insertion-order independence, mixed-label
group preservation, exact integer ties và duplicate terminology. Ruff PASS. Không chạy
model tests/full suite hoặc bất kỳ classifier/clustering fitting nào.

Để tái lập **đúng lần scan này**, dùng source commit18ddf59 và frozen policy bytes;
output directory phải mới. Snapshot README/commands không cấp quyền training hoặc
thay đổi source labels. Với current checkout, đọc rõ post-scan annotations và giữ lineage
cho lần chạy mới; không ghi đè verification/memberships đã chốt.
