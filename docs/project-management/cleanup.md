**Theo dõi C01–C18 tại các issue được liên kết dưới đây.**

Mốc bàn giao 18/11/2026. Issue điều phối [#9](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/9). Báo cáo local ghi HEAD 6fc7c8709ca7fe7dd611bda88d9970fac154dc4e, tested code 3ca90098205c7c9d5c41e5627436b5362f8adb4d và source chưa push. PM đã đọc gói evidence được gửi. Review source chờ PR cleanup.

| Task | Issue | Nội dung | Trạng thái tại mốc bàn giao | Bước tiếp theo |
| --- | --- | --- | --- | --- |
| C01 | [#10](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/10) | Xuất bản branch cleanup và đối chiếu baseline | Đã báo cáo xong local, chờ source review | Đối chiếu HEAD/worktree, đưa các commit đã bàn giao lên branch remote codex/local-storage-cleanup và mở PR vào main. Tích hợp các tài liệu PM mới từ origin/main bằng merge/rebase phù hợp với graph hiện tại, giữ công việc local có thể truy vết. |
| C02 | [#11](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/11) | Review delivery A2 của Duy đã tích hợp | Đã báo cáo xong local, chờ source review | Review merge và conflict resolutions trong PR cleanup. Đối chiếu figure index, captions và evidence handoff. |
| C03 | [#12](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/12) | Review hai lineage clustering và resource resolution | Đã báo cáo xong local, chờ source review | Kiểm tra historical g3b_standard_k8_seed42 và current standard_k8_seed42 được resolve riêng theo model hashes. Review archive/restore và rejection regression. |
| C04 | [#13](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/13) | Review pnpm ownership và cài đặt frontend | Đã báo cáo xong local, chờ source review | Review package/lock deletions, packageManager và hướng dẫn frontend trên PR. |
| C05 | [#14](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/14) | Review backend dependencies và clean Python setup | Đã báo cáo xong local, chờ source review | Review metadata và lệnh setup. Giữ phạm vi Windows đã chạy rõ trong acceptance. |
| C06 | [#15](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/15) | Review frozen model loading và unavailable-model errors | Đã báo cáo xong local, chờ source review | Review loader, missing/tampered paths và inference parity trên exact model. |
| C07 | [#16](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/16) | Review prediction response schema và OpenAPI | Đã báo cáo xong local, chờ source review | Review validation/serialization và compatibility của traffic_analysis_v2 với frontend. |
| C08 | [#17](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/17) | Review frontend validation và upload workflow | Đã báo cáo xong local, chờ source review | Review API client và browser evidence, kiểm tra loading/error/success paths. |
| C09 | [#18](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/18) | Review dataset summaries và provenance | Đã báo cáo xong local, chờ source review | Review summary/provenance và totals của corpus/split/device. |
| C10 | [#19](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/19) | Review trạng thái trung thực của các trang chưa hoàn thành | Đã báo cáo xong local, chờ source review | Review UI và backlog gaps từ baseline. |
| C11 | [#20](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/20) | Review demo/dead code và responsive cleanup | Đã báo cáo xong local, chờ source review | Review file deletions và callers, production UI, formatting ổn định giữa server/client. |
| C12 | [#21](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/21) | Review README và hướng dẫn hiện hành | Đã báo cáo xong local, chờ source review | Review các entry points và commands trên PR, giữ đường dẫn tới PM docs khi xử lý conflict README. |
| C13 | [#22](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/22) | Review portability và relocation resolver | Đã báo cáo xong local, chờ source review | Review resolver và raw-source consumer tests trên canonical resources. |
| C14 | [#23](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/23) | Review storage migration và tracked payload retention | Đã báo cáo xong local, chờ source review | Review inventory/ignore/custody và consumer scope. Giữ model/data/evidence cần thiết theo policy và existing verified migration. |
| C15 | [#24](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/24) | Theo dõi picomatch advisory và review dependency fixes | Còn việc | Review các patch đã làm trên PR. Xác nhận trạng thái upstream và dependency paths hiện tại trước thay đổi tiếp. Ghi version/path/reachability và bản vá khả dụng, kiểm tra tương thích nếu có update. |
| C16 | [#25](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/25) | Review regression và strict historical G2B verdict | Đã báo cáo xong local, chờ source review | Review fixture và strict verifier để xác nhận semantics và assertions. Đối chiếu strict receipt với metadata drift và current functional tests. |
| C17 | [#26](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/26) | Review clean-environment và browser acceptance | Đã báo cáo xong local, chờ source review | Review commands/runtime/revision, CI-independent evidence và source; chạy lại checks bị ảnh hưởng nếu PR tiếp tục đổi. |
| C18 | [#27](https://github.com/sonnnguyennn/cos30049hn-grp1_5/issues/27) | Chốt bàn giao cleanup và quyết định baseline | Đã báo cáo xong local, chờ source review | Sau khi source lên PR, PM review diff/evidence, cập nhật C01–C18 và các gaps rồi ghi quyết định baseline trong repo. |

**Thứ tự hiện hành ưu tiên C01 và C18 để source có thể review trên repo.**

1. Codex local đọc [hướng dẫn nhận việc](agent-handoff.md), cập nhật branch cleanup với thay đổi tài liệu PM mới trên main và xuất bản branch.
2. Mở PR với commit history, baseline report, commands/runtime/results và remaining items.
3. PM đối chiếu diff/evidence cho C02–C14, C16–C17, ghi quyết định theo commit.
4. C15 tiếp tục theo dõi advisory. C18 ghi baseline decision và các gaps cho bước lập plan A3.

Các task đã có local evidence cần được đối chiếu với source đã xuất bản. Nếu review tìm lỗi hoặc code tiếp tục đổi, ghi finding và chạy lại các checks bị ảnh hưởng. [Baseline review](baseline-review-2026-11-18.md) giải thích kết quả local, hai lineage clustering và strict historical G2B FAIL.

Issue là nơi ghi trạng thái hiện hành. Bảng này được cập nhật ở các mốc bàn giao/review để người nhận việc truy được issue và evidence.
