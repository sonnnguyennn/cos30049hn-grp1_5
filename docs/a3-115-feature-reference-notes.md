# Kết luận đối chiếu đặc trưng A3

Bảng đối chiếu lấy nguyên 115 tên và thứ tự từ [freeze manifest][freeze] tại `7595843d0e86168446d659615dd8475a4f25c5c5`. Cùng revision đó, [model A2][model] có cấu hình 115 đầu vào và danh sách `learner.feature_names` rỗng. Freeze là nơi xác định tên và thứ tự. [Bảng 115 cột](a3-115-feature-reference.md)

- SHA-256 freeze manifest `c9d3024579bf68c8c1ac85449a93dcbed07feb745ec89e43d2617c28b33a3397`. Git blob `efb2e8edea69d3af821a3e8db19d49fdaad0876f`.
- SHA-256 model `cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6`. Git blob `f50fd4aa98d55caf6fff5b8544c565ea9ba18c6d`.
- Kitsune `7c8ea51e89268d9a20399dca4bf32d663e638eb4`. Đường gọi kiểm là `netStat.updateGetStats` qua `AfterImage.py` tại commit này. [Commit Kitsune][kitsune] · [netStat][netstat] · [AfterImage][afterimage]

## Mức bằng chứng theo nhóm

[Bảng II N-BaIoT][paper-table] mô tả 23 thống kê trên mỗi một trong năm khoảng thời gian, gồm thống kê theo MAC–IP nguồn, IP nguồn, kênh IP–IP và socket, cùng jitter theo kênh. [Mô tả UCI][uci] gọi các giá trị `L` là hệ số decay. Kitsune dùng `λ = 5, 3, 1, 0.1, 0.01` và nhân trạng thái cũ với `2^(-λΔt)` khi thời gian tăng. Năm mốc thời gian trong bài là mô tả phạm vi lịch sử. Cần bằng chứng riêng để nối chúng với từng hệ số và quy tắc trạng thái. [Cấu hình decay][lambdas] · [Cập nhật decay][decay] · [Phần trích đặc trưng trong bài][paper-feature]

| Nhóm | Vị trí freeze | Công thức và đầu ra quan sát ở Kitsune | Bằng chứng giá trị N-BaIoT còn thiếu |
| --- | ---: | --- | --- |
| `MI_dir` | 1–15 | Cả 15 vị trí tham khảo đã kiểm. Khóa `srcMAC + srcIP`, dùng độ dài frame. Bộ ba thực tế là `weight, mean, variance`. [Đường gọi][mi] | PCAP và vector đồng bộ để kiểm định danh, độ dài frame, decay và state. |
| `H` | 16–30 | **0/15 vị trí được trả về.** Bài mô tả thống kê theo IP nguồn. Lời gọi 1D theo IP nguồn đã bị comment. Primitive 1D có công thức tham khảo cho `weight, mean, variance`. [Nhánh bị bỏ][h] | Đầu ra từ extractor có nhóm `H` hoặc vector chuẩn để kiểm đúng phép tính theo IP nguồn. |
| `HH` | 31–65 | Cả 35 vị trí Kitsune đã kiểm. Ba giá trị 1D lấy từ luồng theo `srcIP`, bốn giá trị 2D dựa trên cặp `srcIP` và `dstIP`. Vị trí thứ ba trả variance. Hai vị trí tiếp theo là radius rồi magnitude. [Đường gọi][hh] | Cần giá trị ghép cặp cho toàn nhóm, đặc biệt 5 cột `_std` và 10 cột `magnitude` / `radius`. |
| `HH_jit` | 66–80 | Cả 15 vị trí tham khảo đã kiểm. Khóa hướng `srcIP + dstIP`, dùng khoảng giữa hai timestamp dương và ghi `0` cho mẫu đầu tiên hoặc chênh lệch không dương. Bộ ba thực tế là `weight, mean, variance`. [Đường gọi][jit] · [Xử lý timestamp][decay] | Kiểm cùng PCAP về hướng, đơn vị timestamp, gói đầu và gói đến lệch thứ tự. |
| `HpHp` | 81–115 | Cả 35 vị trí Kitsune đã kiểm trong nhánh có cổng. Ba giá trị 1D theo ID đầu nguồn, bốn giá trị 2D theo cặp ID. ID thường là chuỗi IP + cổng, ARP dùng cặp MAC. Vị trí thứ ba trả variance, sau đó radius rồi magnitude. [Đường gọi][hp] | Cần đối chiếu khóa socket, nhánh ARP và gói thiếu cổng, cũng như 5 cột `_std` và 10 cột `magnitude` / `radius`. |

**Mức sẵn sàng B09.** Tên và thứ tự đã xác nhận cho 115/115. Công thức và slot trả về đã kiểm ở 100/100 đầu ra tham chiếu Kitsune trong ca tổng hợp. Trong 115 cột model có 90 ứng viên ghép theo ý nghĩa, 10 cột `_std` cần phân giải kiểu thống kê và 15 cột `H` thiếu đầu ra. Hiện chưa có bằng chứng đối chiếu giá trị theo cùng gói cho bất kỳ nhóm nào của N-BaIoT.

## Các sai khác ảnh hưởng đến extractor

1. **`H` và trạng thái.** `netStat` ghép bốn khối `MI_dir, HH, HH_jit, HpHp`. Nếu bật lại dòng `H` đã comment trong cùng `HT_H`, ngay sau đó `HH` sẽ cập nhật lại cùng khóa IP nguồn và decay. Cần chốt luồng trạng thái của `H` và kiểm không đếm hai lần trước khi ghép 15 cột. [Nhánh H và HH][h-hh]
2. **`std` và `variance`.** `getHeaders_1D` đặt tên `std`, trong khi `update_get_1D_Stats` gọi `allstats_1D` và trả về `V = abs(CF2/w − mean²)`. Với `MI_dir` và `HH_jit`, tên cột model ghi `variance`. Với `HH` và `HpHp`, 10 tên cột model ghi `std` và kiểu giá trị trong dữ liệu train còn cần xác minh. `std()` lấy căn bậc hai của `V` và được dùng trong mẫu số PCC. [Giá trị và header 1D][one-d] · [Công thức std][decay] · [Đường gọi 1D + 2D][headers] · [PCC][pair]
3. **`magnitude` và `radius`.** Trong mỗi block 7 cột, freeze đặt magnitude ở vị trí 4, radius ở vị trí 5. Kitsune trả radius ở vị trí 4 và magnitude ở vị trí 5, rồi covariance và PCC. Ví dụ `HH_L5_magnitude` là cột model 34, đối chiếu với slot Kitsune 20. `HH_L5_radius` là cột model 35, đối chiếu với slot Kitsune 19. Đường gọi hai chiều dùng `sqrt(V₀² + V₁²)` cho radius và `sqrt(mean₀² + mean₁²)` cho magnitude. Cần ghép theo ý nghĩa và xác nhận bằng giá trị. [Công thức 2D][geometry] · [Thứ tự trả][pair]
4. **Covariance, PCC và parser.** Covariance là ước lượng `CF3/w3` từ tích phần dư tích lũy. PCC chia covariance cho tích hai độ lệch chuẩn, trả 0 khi mẫu số bằng 0. Với tracker đã tồn tại, `incStat.insert` cập nhật callback covariance, rồi `update_get_2D_Stats` gọi cập nhật tường minh. Thứ tự và số lần cập nhật cần được kiểm khi chọn bản tham chiếu. Parser TSV của Kitsune dùng `frame.time_epoch`, `frame.len` và cổng TCP/UDP. Nhánh Scapy đưa `packet.time` và `len(packet)` vào cùng lời gọi. [Cập nhật từ insert][decay] · [State covariance][covstate] · [Đường gọi 2D][headers] · [Parser][parser]

## Kiểm tra đã thực hiện

- **115/115 tên và vị trí**, không trùng, giữ thứ tự và đủ năm hệ số trên mỗi nhóm. 9/9 header `benign_traffic.csv` nguồn N-BaIoT khớp toàn bộ 115 tên. Kiểm này chỉ đọc header. [Dataset UCI][uci]
- **100/100 vị trí Kitsune**, qua tất cả năm hệ số. Chạy tám mẫu metadata gói tự tạo qua `netStat.updateGetStats` và so vector cuối với công thức. Sáu trường của ca kiểm theo thứ tự `nguồn, đích, cổng nguồn, cổng đích, byte, giây` là `A C 20202 8443 70 0`, `A B 12432 443 80 .2`, `B A 443 12432 174 .35`, `A B 12432 443 111 .8`, `B A 443 12432 201 1.25`, `A B 12432 443 145 1.65`, `B A 443 12432 104 2.3`, `A B 12432 443 239 3.2`. Dùng ba IP/MAC phân biệt. Tính độc lập weight, mean và variance từ trọng số decay. Tính radius/magnitude từ các moment và kiểm covariance/PCC từ `CF3/w3` của tracker. Dùng dung sai tương đối `1e-9` và tuyệt đối `1e-10` cho ca này. Python 3.10.7, NumPy 1.26.4, Cython 3.0.12. Parser PCAP và giá trị N-BaIoT nằm ngoài phép kiểm tổng hợp.
- **Kiểm bảng** gồm 115 dòng, 15 dấu thiếu `H`, 10 cảnh báo `std` và 20 đánh dấu vị trí radius/magnitude. SHA-256 bảng `0fefd13c09b36f8328b8cb66ce6189f9106e18ea17667cc55da867673d817bf6`.

## Sơn và PM cần quyết định

1. Chốt extractor tham chiếu có phiên bản hoặc bộ PCAP–vector được phép dùng để nghiệm thu. Chỉ rõ thứ tự packet, timestamp, nguồn capture, phạm vi, phiên bản parser và cách ghép hàng.
2. Chốt nguồn kiểm 15 cột `H`, cách cập nhật state theo IP nguồn, và hành vi khi thiếu giá trị. Điều kiện bàn giao là có bằng chứng cho từng cột `H`.
3. Chốt tiêu chí phân biệt std/variance cho 10 cột `HH`/`HpHp` và dùng ca có radius khác magnitude để kiểm ánh xạ 20 vị trí. Đồng thời chốt khóa socket, frame length, warm-up, reset và dung sai cho B10.
4. Nếu chưa có cặp PCAP–vector đáng tin cậy, ghi phạm vi demo là prototype/replay và giữ phần xác nhận tương thích giá trị N-BaIoT ở trạng thái đang chờ bằng chứng.

[freeze]: https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/7595843d0e86168446d659615dd8475a4f25c5c5/ml/artifacts/manifests/primary_model_freeze_20261105.json
[model]: https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/7595843d0e86168446d659615dd8475a4f25c5c5/ml/experiments/xgb_frac1_seed42_lr01/model.json
[kitsune]: https://github.com/ymirsky/Kitsune-py/commit/7c8ea51e89268d9a20399dca4bf32d663e638eb4
[netstat]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L73-L117
[afterimage]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py
[paper-table]: https://arxiv.org/html/1805.03409v1#S2.T2
[paper-feature]: https://arxiv.org/html/1805.03409v1#S3
[uci]: https://archive.ics.uci.edu/dataset/442/detection+of+iot+botnet+attacks+n+baiot
[lambdas]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L34-L44
[decay]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L19-L68
[mi]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L79-L82
[h]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L73-L77
[h-hh]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L73-L87
[hh]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L84-L87
[jit]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L89-L92
[hp]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/netStat.py#L94-L103
[one-d]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L100-L125
[geometry]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L88-L98
[pair]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L202-L248
[covstate]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L159-L212
[headers]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/AfterImage.py#L371-L414
[parser]: https://github.com/ymirsky/Kitsune-py/blob/7c8ea51e89268d9a20399dca4bf32d663e638eb4/FeatureExtractor.py#L115-L214
