# A2 classifier acceptance and final evaluation

Ngày 05/11/2026. Phần code/evaluation classifier của Sơn/Hiếu đã hoàn tất với
evidence thực thi: 14 model replay PASS, comparison Full, freeze trước TEST,
final TEST và technical inference handoff được kiểm tra ở môi trường riêng.
Đây là nghiệm thu kỹ thuật tự động; không thay thế review/xác nhận của thành viên,
không tự chuyển Jira Done hay gắn TEAM_VERIFIED.

## Phạm vi và provenance

Branch `feat/a2-classifier-final-evaluation` bắt đầu từ main `3bfed14` sau fetch.
Checkout gốc ở `E:/Document/iotguard-cos30049hn-grp1-5` có thay đổi chưa commit
trong `.gitignore`, `docs/gitinspector.md`, `scripts/` và evidence nhận được;
toàn bộ được giữ nguyên. Công việc thực hiện trong worktree riêng.

- `17c37f6`: inventory, actual membership, acceptance/replay và comparator.
- `07ae461`: implementation final evaluation và regression gates đã kiểm tra.
- `f278ecb`: commit freeze record trước bất kỳ TEST inference nào.
- `aeca4e5`: independent post-run verifier và portable technical inference handoff.

Hiếu thực hiện các thí nghiệm RF/XGBoost gốc. Sơn tích hợp, sửa population identity,
kiểm chứng bằng inference, chọn model theo protocol và thực hiện final evaluation.
LR và Bot-IoT giữ nguyên provenance và phân công thực tế trong receipts lịch sử;
không đổi tên người chạy hoặc source revision để phù hợp một phân công dự kiến.
Không classifier nào được fit/retrain/tune local trong lượt này.

Original RF/XGB notes báo Python 3.12.10, NumPy 2.5.4, scikit-learn 1.9.1 hoặc
XGBoost 3.4.1 và đường dẫn Windows; không có bằng chứng để khẳng định các run này
đã chạy Kaggle. Chúng được tái sử dụng theo yêu cầu giữ thí nghiệm hợp lệ.
Mọi fitting mới bị chặn local bởi runner guard và chỉ được phép chạy trên Kaggle.

## Dữ liệu và nghiệm thu

G3B nguyên bản: `E:/Document/iotguard_primary_packages/g3b_primary_v1`.
Manifest SHA-256:
`6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`.
115 ordered predictors, benign=0, malicious=1, threshold=0.5, observation weighting.

| Partition | Rows | Benign | Malicious |
|---|---:|---:|---:|
| TRAIN | 4,944,968 | 388,965 | 4,556,003 |
| VALIDATION | 1,056,372 | 83,435 | 972,937 |
| TEST | 1,061,266 | 83,532 | 977,734 |

Inventory kiểm tra 65 file nhận được từ 12 run Hiếu và 35 file trong LR Full ZIP.
Các original result/notes/error-analysis có đối chiếu trong Git đều byte-identical.
RF baseline source `b959b19d31b437009c695c4c037579688e497156` dùng tên lịch sử
`ml/scripts/rf_first_run.py`; đây không phải thiếu source. Mọi source commit đều tồn tại.
Original files, LR archive và cả 17 payload của package còn nguyên hash sau evaluation.

12 bộ sampling indices đã được kiểm tra sorted/unique/range, hash bytes,
class supports và tái dựng thuật toán lấy mẫu TRAIN từ seed thực. Full membership
đúng `arange(4944968)`. Sidecars ghi actual TRAIN fingerprint của subset bằng
NumPy v1 selected metadata, giữ parent fingerprint riêng. Original result sai
nhãn parent-as-subset được giữ nguyên, có correction trong sidecars. LR Full
không có `train_sampling`; nghiệm thu dựa trên checksummed full-workflow evidence,
population, convergence và archive, không dựa trên giả định thiếu trường là Full.

Replay toàn VALIDATION bằng từng model; lưu probabilities, predictions, labels,
source-row metadata và payload hashes ngoài Git. RF/XGB cast raw features float32;
LR áp dụng đúng scaler TRAIN và float64. LR replay dùng scikit-learn 1.6.1,
NumPy 2.1.3: chênh probability lớn nhất so với archive là 2.22e-16, quyết định
threshold giống hoàn toàn. Convergence LR 68 iterations được evidence gốc xác nhận.
RF replay dùng scikit-learn 1.9.1. XGB replay dùng 3.2.0, khác bản training được
báo là 3.4.1; mọi confusion count và mọi source-row lỗi có error analysis gốc
khớp chính xác. RF/XGB gốc không lưu probabilities; không tuyên bố parity từng
probability với artifact không tồn tại. Replay mới cung cấp reference có row alignment.
Tất cả model được reload và kiểm tra parity trên toàn VALIDATION; không cần retrain.

## Comparison đã nghiệm thu

Bảng đầy đủ với accuracy, precision/recall/F1/support hai lớp, FPR, confusion counts,
model/source/population/acceptance hashes:
[primary_classifier_comparison_20261105.csv](../../artifacts/manifests/primary_classifier_comparison_20261105.csv).
[Independent acceptance record](../../artifacts/manifests/primary_classifier_acceptance_20261105.json)
giữ tham chiếu immutable tới từng receipt/payload ngoài Git.

| Full candidate | Macro-F1 | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|
| XGB lr01 | 0.9999414464 | 83,435 | 0 | 18 | 972,919 |
| XGB d4 | 0.9999349412 | 83,435 | 0 | 20 | 972,917 |
| XGB baseline | 0.9999089206 | 83,434 | 1 | 27 | 972,910 |
| RF baseline | 0.9999024160 | 83,434 | 1 | 29 | 972,908 |
| XGB d8 | 0.9999024160 | 83,434 | 1 | 29 | 972,908 |
| RF leaf5 | 0.9998731471 | 83,434 | 1 | 38 | 972,899 |
| RF max_features=0.3 | 0.9998308674 | 83,430 | 5 | 47 | 972,890 |
| LR | 0.9984837470 | 83,189 | 246 | 220 | 972,717 |
| Dummy | 0.4794425097 | 0 | 83,435 | 0 | 972,937 |

5 subset runs được giữ trong CSV/evidence nhưng loại khỏi Full pool: RF 5%, 10%,
25%, 50% và XGB 50%. Comparator không chọn majority group để bỏ qua identity
mâu thuẫn; mọi Full candidate phải khớp package, protocol và populations.

Shared selector chọn `xgb_frac1_seed42_lr01`, không remaining tie. Lead so với d4
là 0.00000650524 macro-F1, lớn hơn tolerance 1e-6; cùng 0 false positives và ít
hơn 2 false negatives. So với RF baseline, model giảm FP từ 1 xuống 0 và FN
từ 29 xuống 18; so với LR giảm FP 246 xuống 0 và FN 220 xuống 18. Tuning d8
và RF leaf5/max_features=0.3 không cải thiện baseline tương ứng. Chỉ một seed;
18 errors của winner thuộc 2 exact vectors theo error analysis đã kiểm chứng,
nên chênh lệch vài observation không chứng minh superiority ổn định qua captures/seeds.

## Freeze và final TEST

[Freeze record](../../artifacts/manifests/primary_model_freeze_20261105.json) bind
training revision, evaluation revision, full hyperparameters/input contract,
model/scaler/feature identities, comparison, acceptance và validation payloads.
Freeze SHA-256: `c9d3024579bf68c8c1ac85449a93dcbed07feb745ec89e43d2617c28b33a3397`.
Commit `f278ecb` tồn tại trước execution; receipt/log xác nhận gate PASS trước TEST access.
Decision chỉ dùng TRAIN/VALIDATION; không refit TRAIN+VALIDATION.

Selected training source: `4e2761146a610409d7a956cb82b95aee4dadd78e` (clean).
Evaluation implementation: `07ae461` (exact hashes trong freeze).
300 rounds, learning_rate=0.1, max_depth=6, max_bin=256, min_child_weight=1,
subsample=1, colsample_bytree=1, reg_lambda=1, binary:logistic/hist, seed42,
nthread=2, không balancing, resampling hoặc early stopping, threshold0.5.

Exact original model:
`E:/Document/iotguard-cos30049hn-grp1-5/xgb-rf-experiments/xgb_frac1_seed42_lr01/model.json`

SHA-256: `cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6`
(508,170 bytes). Không thay source revision bằng branch/integration HEAD.

Final inference đã chạy một attempt thành công trên full TEST, sau full VALIDATION
reload parity. XGBoost3.2.0 / NumPy2.4.6 / Python3.11.15, 2 threads.

| TEST metric | Value |
|---|---:|
| TN / FP / FN / TP | 83,531 / 1 / 11 / 977,723 |
| Accuracy | 0.99998869275 |
| Macro-F1 | 0.99996101943 |
| Benign precision / recall / F1 | 0.99986832970 / 0.99998802854 / 0.99992817554 |
| Malicious precision / recall / F1 | 0.99999897722 / 0.99998874950 / 0.99999386333 |
| FPR | 0.00001197146004 (0.001197146%) |

Total final workflow 81.657s (gồm verification và VALIDATION replay), TEST inference
20.350s, process peak RSS 1,312,362,496 bytes. Independent verifier không load model:
tính lại confusion/per-class metrics bằng sklearn.metrics với tolerance1e-15,
kiểm tra toàn payload hashes, exact labels/metadata và thứ tự execution log.
[Final receipt](../../artifacts/manifests/primary_final_test_receipt_20261105.json).
Không dùng kết quả TEST để đổi model, threshold hoặc preprocessing.

Giới hạn: đây là within-corpus evaluation; cả 9 thiết bị xuất hiện trong các
partitions. Exact-X group separation không loại mọi đặc tính capture/device chung.
Không suy ra unseen-device/future-time/operational performance từ accuracy cao.

## Technical inference handoff cho Minh Sơn và Duy

- Directory gốc: `E:/Document/iotguard_run_reviews/a2_final_20261105_01/inference_handoff_01`.
- Relocated copy: `E:/Document/iotguard_model_handoffs/primary_xgb_20261105_01`.
- ZIP: `E:/Document/iotguard_run_reviews/a2_final_20261105_01/IoTGuard_Primary_XGBoost_Handoff.zip`.
- ZIP 144,388 bytes; SHA-256 `6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77`.
- Directory 580,706 bytes; manifest SHA-256
  `9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132`.
- [Release receipt](../../artifacts/manifests/primary_inference_handoff_release_20261105.json)
  và [standalone verification](../../artifacts/manifests/primary_inference_standalone_20261105.json).

Builder tự đóng gói exact model, input/feature contracts, scaler lineage (không áp
dụng cho tree raw view), freeze/final receipt, portable loader, Conda/pip setup,
checksum manifest và 3 ví dụ có source-row lineage từ VALIDATION. Không copy data
package vào handoff. Các expected probabilities được actual portable inference xác nhận:
`[0.0008694713469594717, 0.9999966621398926, 0.36534929275512695]`, labels
`[benign, malicious, benign]`; ví dụ cuối là FN thật, không che giấu lỗi model.

Đã copy và chạy `python -I predict_primary.py ... --verify` cùng inference ví dụ
ở môi trường mới chỉ có NumPy2.4.6/XGBoost3.2.0/SciPy1.17.1. Không có IoTGuard
installed; không cần raw dataset hoặc checkout. Conda recipe được cung cấp nhưng
Conda không được thực thi; kiểm chứng thực tế dùng venv độc lập. Status handoff
`PREPARED_FOR_REVIEW`, không thay thế final group package của Minh Sơn.

```text
python -I predict_primary.py --bundle . --expected-manifest 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 --verify --output <new-external-receipt.json>
python -I predict_primary.py --bundle . --expected-manifest 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 --input example_input.json --output <new-external-predictions.json>
```

Nhận complete G3B package từ custodian hoặc existing verified recipient copy,
đối chiếu manifest hash ở trên rồi chạy `python -I -B verify_primary_package.py .
--output <new-receipt.json>` theo README gốc. Không rebuild G1/G2/G3A để nhận model.
Standalone verifier cơ học không cho phép tuning/selection bằng TEST.

## Bot-IoT được giữ riêng

[Historical Bot-IoT archive](BOT_IOT_SECONDARY_RUN_ARCHIVE.md) và receipt gốc không đổi.
Cả hai archived ZIP vẫn khớp hashes. Run source giữ chính xác `84f3068`, không
thay bởi main hoặc branch hiện tại. Full LR row macro-F1=0.5660063858,
benign recall=7/96, FPR=89/96; equal-group macro-F1=0.5803275395. 96 benign rows
chỉ thuộc 77 groups. Các kết quả này không được gộp vào N-BaIoT selection.
Bot-IoT TEST không được mở/evaluate; structural policy history và package status giữ nguyên.

## Lệnh đã thực thi và evidence ngoài Git

Root evidence: `E:/Document/iotguard_run_reviews/a2_final_20261105_01`.
`inventory.json`, `package_verification.json`, `accepted_01/*`, `comparison_01/*`,
`frozen_model.json`, `final_test_01/*`, `independent_final_verification.json`,
handoff release và standalone receipts đều được giữ ở đây. Original received
models/indices vẫn ở folder Hiếu gửi, không đưa vào Git. Full receipt/payload hashes
nằm trong acceptance/independent records; model, ZIP và raw arrays nằm ngoài Git.

Các CLI source đã thực thi: `inventory_primary_evidence.py`,
`accept_primary_classifiers.py` (RF/XGB và LR dùng hai runtimes), `compare_runs.py`,
`final_primary_evaluation.py freeze`, `final_primary_evaluation.py evaluate`,
`verify_primary_final_evidence.py`, `build_primary_inference_handoff.py`.
Dùng `--help` cho arguments và output paths mới. Không chạy lại final TEST chỉ
để refresh timestamp/receipt hoặc kiểm tra code mới.

Checks cuối và commands/environment chi tiết được lưu trong
`primary_a2_checks_20261105.json` cùng external logs. Chỉ suite unit/config và hai
integration tests export Kaggle được chạy; không claim chạy toàn test suite có
real-source rematerialisation. Đã đọc test calls trước chạy: chỉ preprocessing
fit được phép; không test nào fit classifier.

## Phần còn lại theo owner

- Sơn/Hiếu: human review scientific claims/provenance và giải thích kết quả; không còn
  classifier fitting/evaluation blocker trong phạm vi được giao. Không tự fabricate approval.
- Minh Sơn: clustering results/review, tích hợp final group model/preprocessing/source package,
  dùng exact model và input contract ở handoff này; không refit từ TEST.
- Duy: figures từ CSV/final metrics đã kiểm chứng, human independent README check,
  EDA, report formatting và visual QA theo phân công.
- Sơn: report integration, meeting minutes/contribution/submission QA là workflow khác;
  lượt này hoàn thành code/evaluation, không tự viết/duyệt report hoặc cập nhật Jira.
