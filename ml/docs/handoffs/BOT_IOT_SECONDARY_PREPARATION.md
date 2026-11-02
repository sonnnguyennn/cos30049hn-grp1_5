# Bot-IoT preparation checkpoint cho Hiếu — 2026-11-02

**PROPOSED_FOR_REVIEW — chưa ADOPTED, chưa READY_FOR_TRAINING.**

Branch: `codex/lr-archive-bot-iot-preparation`, tách từ commit
`ea57689eb73322e2536eb47d3bfa574b68cc6404`. Checkout ban đầu sạch; chỉ tìm thấy
`frontend/AGENTS.md`, không áp dụng cho thay đổi ML này. Đã fetch; `origin/main`
vẫn là `b91a419`. Không merge main, không sửa frontend/backend/Jira.

## VERIFIED — đã thực hiện trong checkpoint này

- Đọc canonical parser, hai G2A contracts và các audit quality, imbalance, duplicates,
  identity-free duplicates, lineage/numeric differences, ports, entities và split feasibility.
  Candidate JSON lưu hashes của evidence được tham chiếu; không sửa audit lịch sử.
- Đọc workbook feature semantics trực tiếp từ XLSX XML, không chạy nội dung tài liệu.
- Implement [assembly/preprocessing](../../src/iotguard/data/bot_iot_secondary.py),
  tái sử dụng canonical parser; không có code fit classifier/clustering.
- [Real-data smoke](../../artifacts/manifests/bot_iot_secondary_smoke.json):
  10.328 dòng được assemble, 48 benign / 10.280 malicious; ports decimal20.508,
  hex64, unresolved-sentinel84 (đếm trên cả hai ports). Sentinel giữ `None`, không đổi thành0.
- Reassembly deterministic, numeric finite, đúng feature order; y/IDs/context ngoài X.
  Diagnostic preprocessing fit trên 8.265 dòng TRAIN fixture và transform 2.063 dòng,
  28 encoded columns. Đây là preprocessing coverage fixture, không phải official split.
- Trong mẫu có 1.365 nhóm X tương đương, 6.164 duplicate-excess rows, không có nhóm
  xung đột binary label. Distinct groups trong mẫu: benign48, malicious4116. Chỉ kết luận trong mẫu; không suy ra full population không conflict.
- Unit tests bao phủ loại labels/IDs, exact feature order/dtype, finite/nonnegative/count
  validation, invalid categories/ports, signed-zero/numeric equivalence, TRAIN-only fitting,
  không học lại khi transform, unknown category fail-closed và contract/code consistency.

## REPORTED — kế thừa từ audit, chưa đo lại toàn bộ

- All-features canonical có 3.668.522 dòng, chỉ477 benign; supplied representations
  không được trộn. Old all-fields-minus-ID/seq duplicate view có0 duplicates; kết quả đó
  không áp dụng cho candidate13 predictors.
- Historical numeric quality audit của10 numeric predictors ghi nhận0 numeric parse
  failures, NaN và negative values. Smoke hiện tại xác nhận thêm validation của mẫu;
  không thay thế kiểm chứng toàn bộ dữ liệu theo candidate mới.
- Old B2 random/subcategory 80/20 có benign382/95; B3 temporal có TEST benign0;
  B4 entity saddr grouped có benign370/107, pair grouped421/56. Đây không phải
  membership của candidate mới và không phải split đã được adopt.
- IP/protocol/state có thể gắn với scenario; bỏ IP không chứng minh khả năng generalise
  sang thiết bị, campaign hay thời gian khác.

## PLANNED — các quyết định cần Hiếu review

Đọc [protocol](../protocols/bot_iot_secondary_experiment_v1.md) và
[candidate JSON](../../artifacts/contracts/bot_iot_secondary_ml_candidate_v1.json).

1. Giữ13 ordered predictors:10 transaction numerics và text `flgs, proto, state`.
   Bỏ numeric aliases để tránh duplicate representation. Không dùng labels, pkSeqID,
   IP, timestamps, seq hoặc ports trong X.
2. Bỏ supplied aggregate fields, kể cả duration `mean/stddev/sum/min/max`, vì phạm vi
   window và khả năng tính tại thời điểm dự đoán chưa rõ. Workbook có mô tả nhóm
   tổng hợp nhưng chưa đủ chứng minh không đi qua split boundary.
3. Dùng float64, StandardScaler + OneHotEncoder, fit TRAIN-only. Invalid/missing values
   fail-closed; không PCA/SMOTE/rebalancing. Unknown held-out categories là blocker,
   không âm thầm encode thành0 hoặc đổi seed để vượt kiểm tra.
4. Đề xuất binary-stratified **effective-X-group 60/20/20**, seed1729. Hashes chỉ dùng
   làm group identifiers; phải confirm exact tuples và không tách equivalent rows.
   Actual supports chưa được tính. Minima đề xuất mỗi class:100/50/50 rows và
   20/10/10 distinct groups. Benign nominal286/95/96 chỉ là ước lượng trước grouping.
5. Sau review, tạo actual membership fingerprints/package namespace riêng, lưu encoded
   feature order và preprocessing hashes. Result luôn bind actual populations, không
   dùng full population hash cho subset. TEST không tham gia model/threshold selection.

Nếu giảm malicious TRAIN vì tài nguyên, cần policy riêng được review trước run;
VALIDATION/TEST giữ nguyên prevalence. Toàn bộ classifier/clustering smoke và full
fitting phải ở Kaggle; local chỉ chuẩn bị và kiểm chứng preprocessing.

## BLOCKED — trước official secondary classifier trên Kaggle

- Chưa có adoption/review predictor/split/preprocessing contract.
- Chưa full scan exact candidate-equivalence tuples, group sizes, label conflicts,
  class/group support hoặc actual three-way membership. Đây là câu hỏi mới, khác
  các duplicate views cũ; chỉ thực hiện targeted scan này, không chạy lại toàn bộ G1/G2.
- Chưa có official secondary package, preprocessor fit trên official TRAIN, integrity
  verification, Kaggle runner/bundle hay resource preflight được chốt cho secondary.
- Bounded smoke có5/9 observed flags,4/5 observed protocols và9 state values;
  chưa bao phủ mọi categorical value trong full corpus. Cần đối chiếu full-domain
  support; pass smoke không giải quyết thiếu benign support ở official evaluation.

Hiếu cần review các lựa chọn trên, chốt evaluation scope/metrics và các support gates;
sau đó implement targeted full equivalence/split preparation, review actual support,
materialise package mới, rồi mới triển khai classifier/Dummy smoke và full trên Kaggle.
Không dùng model scores để lựa split; không áp N-BaIoT primary_split_v1 cho Bot-IoT.

## Phạm vi scan mới và tái lập

Lý do: kiểm chứng candidate13 features, benign records, lexical ports và equivalence
trên dữ liệu thật. Ba shard đầu chỉ đọc prefix2.048 dòng/shard; shard4 đọc668.522 dòng
để lấy prefix, tail2.048 và tối đa32 dòng đầu mỗi coverage kind benign/hex/sentinel.
Tổng đọc674.666 dòng nhưng chỉ assemble10.328 dòng. Không fit model, không xuất full X,
không materialise official package. Raw hashes kế thừa manifest audit, chưa hash lại
cả bốn shard trong smoke. Runtime/code/contract hashes và sample membership hash
có trong JSON; exact sample không phải một stratified training subset.

Lệnh đã chạy từ repository root (đổi output sang fresh path khi tái lập):

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
git fetch origin
git switch -c codex/lr-archive-bot-iot-preparation
ml/.venv/Scripts/python.exe ml/scripts/verify_bot_iot_secondary_smoke.py --root E:/Document/Bot_IoT_Dataset --output <fresh-smoke.json>
ml/.venv/Scripts/python.exe -m pytest ml/tests/unit/test_bot_iot_secondary.py ml/tests/unit/test_bot_iot_preprocessing.py -q
ml/.venv/Scripts/python.exe -m ruff check ml/src/iotguard/data/bot_iot_secondary.py ml/scripts/archive_lr_evidence.py ml/scripts/verify_bot_iot_secondary_smoke.py ml/tests/unit/test_bot_iot_secondary.py
git diff --check
```

Kết quả kiểm tra: **83 tests passed** cho hai module tests trên; Ruff các file Python mới PASS.
Không chạy toàn bộ suite vì checkpoint này chỉ kiểm chứng parser/preprocessing, không fit model.

LR archive lineage và reproduction commands nằm trong
[LR handoff](LR_BASELINE_HANDOFF.md). Không chỉnh receipt/source revision lịch sử,
không rerun LR hoặc mở TEST. Không push/merge ở checkpoint này.
