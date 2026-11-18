**Codex local nhận việc qua issue #9 và task register trong repo.**

[Issue điều phối](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/9) · [C01 xuất bản branch](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/10) · [C18 baseline decision](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/27) · [Task register](cleanup.md)

Bản bàn giao hiện tại ghi branch codex/local-storage-cleanup, local HEAD 6fc7c8709ca7fe7dd611bda88d9970fac154dc4e, tested code revision 3ca90098205c7c9d5c41e5627436b5362f8adb4d và working tree sạch. Đối chiếu trạng thái tại máy trước khi thực hiện.

**Bắt đầu bằng xuất bản phần source đã bàn giao.**

1. Đọc AGENTS.md áp dụng, issue #9, task register và baseline review.
2. Trong checkout đang làm việc, kiểm tra branch/HEAD, git status, worktrees và các commit mới sau mốc bàn giao. Bảo toàn công việc local và managed worktrees.
3. Fetch origin. Main đã nhận các tài liệu PM mới, hãy tích hợp thay đổi remote vào branch cleanup theo graph hiện hành. Khi README conflict, giữ hướng dẫn setup mới đã kiểm chứng và link điều phối PM.
4. Push branch cleanup hiện có lên origin, sau đó mở PR vào main.
5. Cập nhật #9, C01 và C18 bằng PR URL, final HEAD, tested revision, kết quả checks và remaining items.

Các lệnh định hướng được chạy trong checkout phù hợp sau khi kiểm tra trạng thái.

    git status --short
    git branch --show-current
    git log -1 --format=%H
    git worktree list
    git fetch origin
    git push -u origin codex/local-storage-cleanup

Nếu nhánh đã có thay đổi mới, ghi chúng vào bàn giao. Chọn merge/rebase theo graph để giữ commit và công việc gốc truy vết được.

**PR cần có nội dung đủ để review từ repo.**

- Baseline ban đầu và final HEAD, cùng revision đã chạy tests.
- Commit groups và file list, đặc biệt merge delivery Duy, API errors/schema, frontend validation, artifact retention và dependency changes.
- Link docs/BASELINE_REVIEW.md trên branch cleanup. Đính kèm hoặc commit compact receipts/logs còn cần cho review, dùng đúng tracking policy.
- Commands/runtime và kết quả ML/backend/frontend/browser/parity, cùng platform scope.
- C15 advisory còn lại, strict historical G2B verdict và custody gaps được ghi rõ.
- Link tới #9 và các issue C01–C18 có thay đổi tương ứng.

**Dùng đúng identity và phạm vi verification.**

Classifier xgb_frac1_seed42_lr01 có SHA-256 cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6, 115 ordered raw features cast float32 và threshold 0.5.

Historical A2 clustering g3b_standard_k8_seed42 có estimator hash 60934f6896dbe457af52a1fd697efea96c86a094a6ee544e6faaf145a59897b0. Current standard_k8_seed42 có hash 92f365c4e9b6d55940c9bb3045afac998a709ee18850a1a80da3a65fd3fbd738 và directory current chưa có estimator theo report. Dùng đúng artifacts cho từng workflow.

Strict host historical check giữ FAIL tại source_tree_metadata_digests_unchanged_from_a5. Review fixtures/regressions cùng logic verifier, bảo toàn frozen receipts/timestamps.

Local storage migration đã báo cáo PASS cho 28 unit. Kế thừa catalog/config và các kiểm tra đã có, review/rerun phần bị thay đổi hoặc có drift. Existing raw/view files, active env, SQLite và managed worktrees được bảo toàn.

**Bàn giao và tiếp tục qua repo.**

Cập nhật từng issue với kết quả thực tế, commit/PR, commands/runtime/results, blockers và bước tiếp theo. PM review source trên PR rồi ghi baseline decision ở C18/#9. Plan A3 sẽ được lập từ baseline được review, với các gaps đã ghi trong baseline review.
