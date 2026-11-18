**PM tiếp nhận baseline local ngày 18/11/2026.**

Gói PM_BASELINE_REVIEW_20261118.zip được người dùng gửi trong cuộc trao đổi điều hành. Bản BASELINE_REVIEW.md đính kèm khớp nội dung PM_BASELINE_REVIEW.md trong ZIP. Đây là tiếp nhận/review evidence. Source cleanup chờ được xuất bản trên GitHub để review diff.

| Mốc | Giá trị |
| --- | --- |
| Local branch | codex/local-storage-cleanup |
| Baseline local ban đầu | 3d71f533d652fb2cc3186f33072facf9b778f668 |
| Remote được handoff ghi nhận | 9572d2be0e501dcd4d9596ba9e7c3b1074832ec4 |
| Tested code revision | 3ca90098205c7c9d5c41e5627436b5362f8adb4d |
| Final local HEAD | 6fc7c8709ca7fe7dd611bda88d9970fac154dc4e |
| Pushed tại thời điểm handoff | false |
| Git status trong handoff | rỗng |
| Kết quả GitHub resolve local HEAD khi tiếp nhận | Chưa có commit trên remote |
| Task completion trong report | C01–C14, C16–C18 đã hoàn thành kỹ thuật; C15 còn việc |

**Các kết quả kỹ thuật được cung cấp có phạm vi như sau.**

| Kiểm tra | Kết quả trong handoff | Evidence được tiếp nhận |
| --- | --- | --- |
| ML suite | 489 PASS | [ml-tests.log](evidence/2026-11-18/ml-tests.log), report ghi tested revision |
| Backend active và clean Python 3.12 | 66 PASS | Report, raw logs tiếp tục được đối chiếu khi source/PR lên repo |
| Frontend setup/lint/typegen/tsc/build | PASS theo report | Source/commands/logs chờ review trên PR |
| CSV/JSON inference parity | PASS, khớp ba xác suất | [parity.json](evidence/2026-11-18/parity.json) |
| Browser smoke | PASS, pageErrors rỗng, mobile document=viewport=390 | [browser.json](evidence/2026-11-18/browser.json), ảnh trong gói bàn giao có hashes ở manifest |
| Strict historical G2B | FAIL | [strict-historical.json](evidence/2026-11-18/strict-historical.json) |
| Dependency audit toàn bộ | Còn 1 high dev advisory | [advisories-final.json](evidence/2026-11-18/advisories-final.json) |
| Production-only audit | 0 findings tại snapshot này | [production-advisories.json](evidence/2026-11-18/production-advisories.json) |

Runtime report ghi ML Python 3.11.15, app/clean Python 3.12.13, Node 25.1.0, pnpm 11.25.0, Next/eslint-config-next 16.4.5 và TypeScript 5.9.3. Clean inference resolve NumPy 2.5.5, SciPy 1.18.1, XGBoost 3.2.0. Windows là nền tảng đã chạy trong báo cáo. Linux/macOS và deployment cần được kiểm chứng theo môi trường tương ứng.

Browser report dùng 27 rows lấy từ các mẫu VALIDATION lặp lại. Các thao tác gồm upload/results/details/pagination/sort/filter/clear/export/errors, desktop 1440 và mobile 390. Đây là functional smoke của workflow hiện có.

**Các identities cần bảo toàn khi review.**

| Artifact | Identity |
| --- | --- |
| Classifier xgb_frac1_seed42_lr01 | cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6 |
| Handoff manifest | 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 |
| Handoff ZIP | 6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77 |
| Historical g3b_standard_k8_seed42 estimator | 60934f6896dbe457af52a1fd697efea96c86a094a6ee544e6faaf145a59897b0 |
| Current standard_k8_seed42 estimator identity | 92f365c4e9b6d55940c9bb3045afac998a709ee18850a1a80da3a65fd3fbd738 |

Expected classifier probabilities là 0.0008694713469594717, 0.9999966621398926, 0.36534929275512695, labels benign/malicious/benign. Tolerance được report ghi absolute 1e-12, rtol=0. Ví dụ thứ ba giữ false negative đã ghi nhận. Contract dùng 115 ordered raw features sang float32 và threshold >=0.5.

Historical figures dùng g3b_standard_k8_seed42 với restore 209 file. Current directory Clustering/Result/full có assignments/metrics và chưa có estimator theo report. Hai run có identity khác nhau.

Strict G2B snapshot giữ source_tree_metadata_digests_unchanged_from_a5=false, các check khác trong receipt là true. Unit happy-path đã dùng frozen metadata fixture và drift regression kiểm việc gate từ chối. C16 cần review source/test implementation để xác nhận các assertions và phạm vi.

**Phần còn mở cần được ghi đúng trong quyết định baseline.**

- [C01](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/10) xuất bản branch và PR source, [C18](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/27) review/ghi quyết định PM.
- [C15](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/24) còn picomatch GHSA-fc5q-39xc-vjpf theo snapshot. Paths quan sát nằm trong ESLint/TypeScript tooling. Trạng thái upstream cần kiểm tra lại trước thay đổi tiếp.
- Tracked payload inventory được report ghi 49 file, gồm 44 NPY và 5 model JSON, tổng 359343424 bytes. Giữ theo retention policy, local archive/restore có scope riêng với recipient distribution.
- Các gaps cho bước lập plan A3 gồm Model Evaluation, prediction charts, readiness/history/persistence, Pi benchmark, replay và custody của exact current clustering estimator nếu workflow cần replay. Raw-packet feature extraction là extension cần xem scope/feasibility theo A1.

Các commit local theo thứ tự được report ghi 6b420a3, dfa0465, 12ef8b4, 9cc8682, 4e11e15, addaa1b, 3ca9009 và 6fc7c87. Diff đặc biệt cần review gồm schema/model errors, deletions demo/scaffold staged trong 9cc8682, frontend responsive/hydration, Next patch và minimatch override.

[Gói evidence đã tiếp nhận](evidence/2026-11-18/README.md) có hashes và phạm vi. [Task register](cleanup.md) liên kết toàn bộ C01–C18.
