**Repo là nơi điều phối công việc và bàn giao của IoTGuard.**

Cập nhật ngày 18/11/2026. Đợt hiện hành là cleanup sau A2 và review baseline trước khi lập plan A3.

- [Issue điều phối #9](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/9) ghi bước tiếp theo và quyết định PM.
- [Task register C01–C18](cleanup.md) liên kết tới các issue hiện hành.
- [Hướng dẫn nhận việc của Codex local](agent-handoff.md) ghi cách xuất bản source và bàn giao qua repo.
- [Review baseline local 18/11](baseline-review-2026-11-18.md) tổng hợp evidence đã nhận và phạm vi còn chờ review.
- [Evidence snapshot](evidence/2026-11-18/README.md) có parity, browser, ML log, advisory và strict historical verdict.

**Bước tiếp theo là xuất bản source cleanup để PM review.**

Handoff gửi PM ghi local HEAD 6fc7c8709ca7fe7dd611bda88d9970fac154dc4e trên codex/local-storage-cleanup, tested code revision 3ca90098205c7c9d5c41e5627436b5362f8adb4d và pushed=false. Remote main trước commit tài liệu PM này là 9572d2be0e501dcd4d9596ba9e7c3b1074832ec4. GitHub chưa resolve được local HEAD khi tiếp nhận.

Báo cáo local ghi 17 task hoàn thành kỹ thuật và C15 còn advisory picomatch. Các issue vẫn mở để thực hiện bước xuất bản/review và ghi nhận quyết định theo source commit. Trạng thái local completion nằm trong từng issue.

**Cập nhật công việc qua issue và PR.**

Codex local cập nhật issue liên quan bằng commit/PR, commands/runtime/results, phần còn thiếu và bước tiếp theo. PM ghi review tại PR/issue và cập nhật register khi có mốc mới. Báo cáo cần chỉ rõ revision đã kiểm thử. Những kết quả historical hoặc kiểm tra trên một nền tảng cần giữ đúng phạm vi.

Task có thể ghi Cần làm, Đang làm, Chờ review, Thiếu đầu vào hoặc Đã xong. Đóng issue sau khi có kết quả review/acceptance phù hợp. C15 tiếp tục theo dõi dependency upstream theo trạng thái thực tế.

Các file local chứa dữ liệu/config và custody catalog tiếp tục được quản lý theo [tracking policy](../git-tracking.md). Repo giữ source, task, review decisions và compact evidence. Khi baseline được review, plan A3 sẽ được lập tại đây.
