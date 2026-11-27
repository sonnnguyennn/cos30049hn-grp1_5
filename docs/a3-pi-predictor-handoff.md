# Bàn giao shared predictor IoTGuard A3 trên Raspberry Pi

Lượt kiểm trên Pi lúc 22:43 ngày 27/11/2026 (UTC+7) dùng đúng ba Git blob từ `main` tại `807345b9ec84fd5f5857912e3ec0d458bbbe2817`. Kết quả **PASS** với ba mẫu VALIDATION đã duyệt và hai ca kiểm kiểu dữ liệu. [Biên nhận JSON](a3-pi-predictor-result.json)

| Tệp trong thư mục chạy | Tệp nguồn tại commit đã ghim | SHA-256 |
| --- | --- | --- |
| `predictor.py` | [Shared predictor][predictor] | `6975f6ac90564c884ac442dfd4bd60e436aaec3be319ef6f045ae80da8d0a6b6` |
| `model.json` | [Model A2][model] | `cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6` |
| `freeze.json` | [Freeze manifest A2][freeze] | `c9d3024579bf68c8c1ac85449a93dcbed07feb745ec89e43d2617c28b33a3397` |

## Chuẩn bị thư mục chạy

Trên máy có checkout chứa commit đã ghim, mở Git Bash hoặc Bash tại repo. Gán `pi` theo kết nối SSH của lab. Mỗi lần chạy dùng một thư mục mới dưới `~/.local/share/iotguard-a3/` trên Pi.

```bash
set -e
ref=807345b9ec84fd5f5857912e3ec0d458bbbe2817
pi='user@pi-host'
run="pi-predictor-main-$(date +%Y%m%d-%H%M%S)"
stage="$(mktemp -d)"
git show "$ref:backend/app/predictor.py" > "$stage/predictor.py"
git show "$ref:ml/experiments/xgb_frac1_seed42_lr01/model.json" > "$stage/model.json"
git show "$ref:ml/artifacts/manifests/primary_model_freeze_20261105.json" > "$stage/freeze.json"
ssh "$pi" "umask 077; mkdir ~/.local/share/iotguard-a3/$run"
scp "$stage/predictor.py" "$stage/model.json" "$stage/freeze.json" \
  "$pi:.local/share/iotguard-a3/$run/"
ssh -t "$pi" "cd ~/.local/share/iotguard-a3/$run && exec bash"
```

## Chạy kiểm trên Pi

Lượt đã xác minh chạy trên Raspberry Pi 4 Model B Rev 1.4, Debian 13.6, ARM64 64-bit. Venv A2 hiện có dùng Python 3.11.9, NumPy 2.4.6, XGBoost 3.2.0 và SciPy 1.17.1. Nếu bộ handoff nằm ở vị trí khác trên Pi, chỉnh `a2` trong lệnh bên dưới. Chạy từ thư mục vừa tạo và đặt các đường dẫn trước khi import predictor.

```bash
a2="$HOME/.local/share/iotguard-a3/pi-frozen-handoff-20261123-135517"
export IOTGUARD_PYTHON="$a2/.venv/bin/python"
export IOTGUARD_EXAMPLE_DIR="$a2/bundle"
export IOTGUARD_MODEL_PATH="$PWD/model.json"
export IOTGUARD_FREEZE_PATH="$PWD/freeze.json"
"$IOTGUARD_PYTHON" -I -B - <<'PY'
import hashlib
import json
import os
import platform
import sys
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

root = Path.cwd()
sample = Path(os.environ["IOTGUARD_EXAMPLE_DIR"]).resolve()

def read_json(path):
    return json.loads(path.read_bytes())

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

files = {
    "predictor.py": "6975f6ac90564c884ac442dfd4bd60e436aaec3be319ef6f045ae80da8d0a6b6",
    "model.json": "cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6",
    "freeze.json": "c9d3024579bf68c8c1ac85449a93dcbed07feb745ec89e43d2617c28b33a3397",
}
for name, expected_hash in files.items():
    assert sha256(root / name) == expected_hash, name
assert sha256(sample / "manifest.json") == "9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132"
manifest = read_json(sample / "manifest.json")
for name in ("example_input.json", "example_expected.json"):
    assert sha256(sample / name) == manifest["files"][name]["sha256"], name

sys.path.insert(0, str(root))
import predictor

assert Path(predictor.__file__).resolve() == root / "predictor.py"
assert predictor.MODEL_PATH.resolve() == root / "model.json"
assert predictor.FREEZE_PATH.resolve() == root / "freeze.json"
assert sys.prefix != sys.base_prefix

data = read_json(sample / "example_input.json")
expected = read_json(sample / "example_expected.json")
shared = predictor.get_predictor()
assert data["feature_order"] == shared.feature_order
assert len(data["rows"]) == 3
assert all(len(row) == 115 for row in data["rows"])
actual = shared.predict(data["rows"])
for field in ("labels", "probabilities", "predictions"):
    assert actual[field] == expected[field], (field, actual[field], expected[field])
assert actual["model_sha256"] == files["model.json"] == read_json(root / "freeze.json")["model"]["sha256"]

rejections = {}
for token in (True, "12.5"):
    bad_rows = [data["rows"][0].copy()]
    bad_rows[0][0] = token
    try:
        shared.predict(bad_rows)
    except ValueError as exc:
        rejections[json.dumps(token)] = {"error": type(exc).__name__, "message": str(exc)}
    else:
        raise AssertionError(f"Expected ValueError for {token!r}")

receipt = {
    "status": "PASS",
    "source_commit": "807345b9ec84fd5f5857912e3ec0d458bbbe2817",
    "run_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    "architecture": platform.machine(),
    "python": platform.python_version(),
    "libraries": {name: version(name) for name in ("numpy", "xgboost", "scipy")},
    "input_sha256": sha256(sample / "example_input.json"),
    "expected_output_sha256": sha256(sample / "example_expected.json"),
    "artifact_sha256": files,
    "validation": actual,
    "rejected_inputs": rejections,
}
with (root / "pi-predictor-result.json").open("x", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, allow_nan=False)
    stream.write("\n")
print(json.dumps(receipt, indent=2, allow_nan=False))

PY
```

Lệnh kiểm SHA-256 của ba tệp đã chuyển, manifest của handoff và hai tệp mẫu. Sau đó gọi `FrozenPredictor.predict()` với ba dòng VALIDATION cùng thứ tự 115 cột. Mỗi ca lỗi thay giá trị đầu tiên trong một dòng hợp lệ bằng `True` hoặc `"12.5"` và kiểm `ValueError`. Tệp `pi-predictor-result.json` được ghi trong thư mục chạy sau khi mọi kiểm tra đạt.

| Mẫu VALIDATION | Nhãn dự đoán | Xác suất malicious |
| ---: | --- | ---: |
| 1 | `benign` | `0.0008694713469594717` |
| 2 | `malicious` | `0.9999966621398926` |
| 3 | `benign` | `0.36534929275512695` |

Hai ca đầu vào sai đều trả `ValueError: Rows must contain only numbers`. Đây là kiểm tra shared predictor với vector đã trích sẵn. Bước API ingest và dữ liệu từ extractor nằm ở phần tích hợp tiếp theo.

[predictor]: https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/807345b9ec84fd5f5857912e3ec0d458bbbe2817/backend/app/predictor.py
[model]: https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/807345b9ec84fd5f5857912e3ec0d458bbbe2817/ml/experiments/xgb_frac1_seed42_lr01/model.json
[freeze]: https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/807345b9ec84fd5f5857912e3ec0d458bbbe2817/ml/artifacts/manifests/primary_model_freeze_20261105.json
