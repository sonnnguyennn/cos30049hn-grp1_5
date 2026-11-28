# Kiểm replay Pi → backend qua Tailscale

Lượt kiểm ngày 28/11/2026 dùng backend từ commit `48a0a5125a108da3a076a78f95b0d5bfeb66266a` và ba mẫu `VALIDATION` của gói inference A2. Pi dự đoán từ các vector 115 đặc trưng đã tính sẵn rồi gửi kết quả qua Tailscale. [Biên nhận JSON](a3-pi-backend-network-result.json)

## 1. Chạy backend trên laptop

Mở PowerShell tại worktree sạch của commit trên. Dùng môi trường backend Windows đã cài và chọn cổng trống trên IPv4 Tailscale của laptop. Lượt kiểm dùng `100.122.150.69:18080`. Giữ nguyên cấu hình Tailscale, firewall và ACL của lab.

```powershell
$source = '48a0a5125a108da3a076a78f95b0d5bfeb66266a'
git merge-base --is-ancestor $source origin/main
if ($LASTEXITCODE -ne 0 -or (git rev-parse HEAD) -ne $source -or (git status --porcelain)) {
    throw 'Open a clean source worktree at the pinned merge commit.'
}
$python = 'E:/Document/iotguard-cos30049hn-grp1-5/backend/.venv/Scripts/python.exe'
$laptopIp = (tailscale ip -4).Trim()
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
$env:IOTGUARD_MODEL_PATH = (Resolve-Path 'ml/experiments/xgb_frac1_seed42_lr01/model.json').Path
$env:IOTGUARD_FREEZE_PATH = (Resolve-Path 'ml/artifacts/manifests/primary_model_freeze_20261105.json').Path
& $python -B -m uvicorn backend.app.main:app --host $laptopIp --port 18080 --workers 1 --no-proxy-headers
```

Để lại terminal backend chạy trong lúc kiểm. Uvicorn dùng một worker vì phiên nằm trong bộ nhớ. `--no-proxy-headers` giữ địa chỉ và cổng TCP thực của client trong access log. Dừng backend bằng `Ctrl+C` sau khi lưu log.

## 2. Chạy bộ kiểm trên Pi

Mở Git Bash tại checkout chứa script. Đổi địa chỉ theo `tailscale ip -4` của hai máy. Pi cần môi trường inference A2 và thư mục `bundle` chứa manifest cùng ba tệp `example_input.json`, `example_expected.json` và `example_lineage.json`.

```bash
set -euo pipefail
ref=48a0a5125a108da3a076a78f95b0d5bfeb66266a
pi_ip=100.70.95.30
backend_ip=100.122.150.69
port=18080
pi="admin@$pi_ip"
stage="$(mktemp -d)"
remote=".local/share/iotguard-a3/pi-backend-network-$(date +%Y%m%d-%H%M%S)"
ssh_args=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes)

git show "$ref:backend/app/predictor.py" > "$stage/predictor.py"
git show "$ref:ml/experiments/xgb_frac1_seed42_lr01/model.json" > "$stage/model.json"
git show "$ref:ml/artifacts/manifests/primary_model_freeze_20261105.json" > "$stage/freeze.json"
git show HEAD:scripts/check_pi_backend_network.py > "$stage/check_pi_backend_network.py"
ssh "${ssh_args[@]}" "$pi" "umask 077; mkdir '$remote' && ip -4 route get '$backend_ip'"
scp "${ssh_args[@]}" "$stage/"{check_pi_backend_network.py,predictor.py,model.json,freeze.json} \
    "$pi:$remote/"
ssh "${ssh_args[@]}" "$pi" "cd \"\$HOME/$remote\" &&
    a2=\"\$HOME/.local/share/iotguard-a3/pi-frozen-handoff-20261123-135517\" &&
    \"\$a2/.venv/bin/python\" -I -B check_pi_backend_network.py \
    --pi-ip '$pi_ip' --backend-ip '$backend_ip' --port '$port' \
    --artifacts . --bundle \"\$a2/bundle\"" | tee "$stage/pi-result.json"
```

Dùng `git show` để sao đúng byte từ Git, kể cả khi checkout Windows đổi xuống dòng. Script xác minh SHA-256 của predictor, model, freeze và fixture trước khi dự đoán. Kết quả `PASS` yêu cầu Pi tạo phiên, gửi ba event, gửi lại cùng payload, đọc lần lượt các cursor `0 → 2 → 3`, heartbeat `204`, dừng và nhận `409 session_stopped` khi gửi lại.

Đối chiếu `http_trace` trong biên nhận Pi với access log backend theo IP/cổng nguồn, method, path và status. Lượt kiểm đã khớp 15 request. Hai đồng hồ máy ghi timestamp riêng.

Log gốc, kết quả Pi và log tuyến lưu trong [thư mục evidence trên laptop](<E:/Document/IoTGuard-Local/audits/a3-pi-backend-network-check-20261128/run-20261128-102421>). SHA-256, kích thước và đường dẫn từng tệp nằm trong `evidence` của biên nhận JSON.
