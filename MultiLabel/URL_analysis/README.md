# 🔍 URL Analysis Tool

Công cụ phân loại URL độc hại dựa trên **phân tích tĩnh đặc trưng lexical** (Static Lexical Analysis) kết hợp mô hình **LightGBM (Gradient Boosted Decision Trees)**. Hệ thống phân loại URL thành **4 nhóm**: `benign`, `phishing`, `malware`, và `defacement` — hoàn toàn dựa trên cấu trúc chuỗi URL mà **không cần truy cập nội dung trang web**.

---

## 📊 Thông tin mô hình

| Thông số | Giá trị |
|---|---|
| Thuật toán | LightGBM (GBDT) |
| Số lớp | 4 (`benign`, `defacement`, `malware`, `phishing`) |
| Accuracy | **93.46%** |
| Số đặc trưng | 57 features |
| Tập train | 529,580 mẫu |
| Tập validation | 66,198 mẫu |
| Tập test | 66,198 mẫu |
| Best iteration | 738 |

---

## 📁 Cấu trúc Project

```
url-analysis/
│
├── src/                            # Mã nguồn chính
│   ├── __init__.py
│   ├── features/                   # Module trích xuất đặc trưng
│   │   ├── __init__.py
│   │   └── feature_extraction.py   # Trích xuất 57+ đặc trưng từ URL
│   ├── FIlter/                     # Module tiền xử lý URL
│   │   └── Normalize_url.py        # Chuẩn hóa URL đầu vào
│   ├── Optimizer/                  # Module tối ưu hàm mất mát (đang phát triển)
│   │   ├── loss.h                  # Header file cho custom loss function
│   │   └── loss.c                  # Implementation custom loss (C)
│   └── data/                       # Dữ liệu (không được track bởi git)
│       ├── whitelist.txt           # Danh sách domain hợp lệ (dùng cho Levenshtein)
│       ├── malicious_phish.csv     # Dataset URL phishing
│       ├── malware.csv             # Dataset URL malware
│       ├── urlhaus_recent.csv      # Dataset từ URLhaus
│       ├── top-1m.csv              # Top 1 triệu domain phổ biến
│       ├── top-1m.txt              # Top 1 triệu domain (dạng text)
│       ├── new_url_updated.csv     # Dataset URL đã cập nhật
│       ├── processed_url_update.csv# Dataset đã tiền xử lý
│       └── domain.txt              # Danh sách domain
│
├── notebooks/                      # Jupyter Notebooks & model artifacts
│   ├── data_exploration.ipynb      # Khám phá & phân tích dữ liệu
│   ├── test.ipynb                  # Notebook thử nghiệm
│   ├── test_model.ipynb            # Đánh giá & kiểm thử mô hình
│   ├── lgb_url_classifier.txt      # Model LightGBM (dạng text - Booster)
│   ├── lgb_url_classifier.pkl      # Model LightGBM (dạng pickle)
│   ├── lgb_url_classifier_metadata.json  # Metadata: hyperparams, features, accuracy
│   └── label_encoder.joblib        # Label encoder cho 4 lớp
│
├── test/                           # Scripts kiểm thử
│   ├── take url and return result.py  # Script chính: nhập URL → dự đoán kết quả
│   └── test1_array.py              # Script kiểm tra metadata file
│
├── report/                         # Báo cáo khoa học
│   └── MLreport.tex                # Báo cáo LaTeX đầy đủ về phương pháp & kết quả
│
├── build/                          # Build artifacts
│   └── bdist.win-amd64/            # Build distribution cho Windows
│
├── requirements.txt                # Các thư viện Python cần thiết
├── setup.py                        # Cấu hình package Python
├── .gitignore                      # Quy tắc ignore cho Git
└── README.md                       # File này
```

---

## ⚙️ Cài đặt

### Yêu cầu hệ thống
- Python 3.8+
- Windows / Linux / macOS

### Cài đặt thư viện

```bash
pip install -r requirements.txt
```

Các thư viện chính:

| Thư viện | Mục đích |
|---|---|
| `pandas` | Xử lý dữ liệu dạng bảng |
| `numpy` | Tính toán số học |
| `scikit-learn` | Label encoding, tiền xử lý |
| `lightgbm` | Mô hình phân loại chính (GBDT) |
| `tldextract` | Phân tích thành phần domain của URL |
| `rapidfuzz` | Tính khoảng cách Levenshtein (phát hiện typosquatting) |
| `matplotlib` | Trực quan hóa dữ liệu |
| `jupyter` | Chạy notebooks phân tích |

### Cài đặt package nguồn

```bash
pip install -e .
```

---

## 🚀 Sử dụng

### Dự đoán URL từ dòng lệnh

```bash
python "test/take url and return result.py" "https://example.com"
```

Hoặc chạy ở chế độ tương tác (nhập URL khi được hỏi):

```bash
python "test/take url and return result.py"
```

### Kết quả mẫu

```
URL: https://87khq5gx.ravabetensani.site/?ublib=ca0a10e1-15b1-489c-a27f-7703d460170c

----------------------------------------
  malware         :  98.07%
  phishing        :   1.91%
  benign          :   0.01%
  defacement      :   0.00%
----------------------------------------
=> Dự đoán: 'malware' (98.07%)
```

---

## 🧠 Các nhóm đặc trưng (Features)

Hệ thống trích xuất **57 đặc trưng** từ URL, chia thành 6 nhóm chính:

### 1. Thành phần URL (URL Parts Existence)
Kiểm tra sự tồn tại của từng thành phần: `scheme`, `netloc`, `path`, `params`, `query`, `fragment`, `username`, `password`, `port`, `subdomain`, `domain`, `suffix`.

### 2. Độ dài (Length Features)
Độ dài của: `url`, `netloc`, `path`, `query`, `fragment`, `subdomain`, `domain`.

### 3. Entropy (Shannon Entropy)
Đo mức độ ngẫu nhiên/phức tạp của: `url`, `netloc`, `path`, `query`, `subdomain`, `domain`.

### 4. Ký tự đặc biệt (Special Characters)
Đếm số lượng: dấu gạch ngang (`-`), dấu chấm (`.`), dấu `@`, dấu `/`, ký tự lạ, dấu `=`, dấu `&`, kiểm tra Unicode/Punycode.

### 5. Phân tích Lexical / Chuỗi (Lexical & String Analysis)
- **Levenshtein distance**: So sánh domain/subdomain với whitelist → phát hiện typosquatting
- **Tỷ lệ phụ âm (Consonant ratio)**: Phát hiện domain sinh ngẫu nhiên (DGA)
- **Tỷ lệ số (Digit ratio)**: Trong domain và subdomain
- **Tỷ lệ ký tự lặp (Repeated char ratio)**: Phát hiện pattern bất thường
- **IP domain**: Domain là địa chỉ IP
- **Suspicious keywords**: Phát hiện từ khóa đáng ngờ (`login`, `verify`, `banking`, `password`,...)
- **URL rút gọn (Shortened URL)**: Kiểm tra `bit.ly`, `tinyurl.com`,...

### 6. Đặc trưng bổ sung
- **UUID trong path**: Phát hiện C2 server / malware callback
- **Download param**: Tham số tải xuống trong URL
- **Free hosting**: Sử dụng hosting miễn phí (`vercel.app`, `netlify.app`,...)
- **Suspicious TLD**: TLD đáng ngờ (`.tk`, `.ml`, `.xyz`,...)
- **Scheme encoding**: One-hot encode (`is_https`, `is_http`, `is_ftp`, `is_none`, `is_other`)

---

## 📂 Dữ liệu

Dữ liệu được lưu trong `src/data/` (không được track bởi Git). Bao gồm:

- **malicious_phish.csv** — Dataset chứa URL phishing
- **malware.csv** — Dataset chứa URL malware
- **urlhaus_recent.csv** — Dữ liệu từ [URLhaus](https://urlhaus.abuse.ch/)
- **top-1m.csv / top-1m.txt** — Top 1 triệu domain phổ biến nhất (tạo whitelist benign)
- **whitelist.txt** — Danh sách domain hợp lệ (dùng cho tính Levenshtein distance)
- **processed_url_update.csv** — Dataset đã qua trích xuất đặc trưng, sẵn sàng cho training

---

## 📄 Báo cáo

Báo cáo khoa học chi tiết về phương pháp, thí nghiệm và kết quả được viết bằng LaTeX tại:

```
report/MLreport.tex
```

Tiêu đề: **"Malicious URL Classification via Static Lexical Analysis and Gradient Boosted Decision Trees"**

---

## 🛠️ Hyperparameters của mô hình

```json
{
  "objective": "multiclass",
  "class_weight": "balanced",
  "num_class": 4,
  "boosting_type": "gbdt",
  "n_estimators": 4000,
  "learning_rate": 0.025,
  "max_depth": 5,
  "num_leaves": 24,
  "min_data_in_leaf": 50,
  "colsample_bytree": 0.75,
  "subsample": 0.8,
  "early_stopping_rounds": 100,
  "reg_alpha": 0.1,
  "reg_lambda": 1.0
}
```

---

## 📌 Ghi chú

- Module `Optimizer/` (custom loss function bằng C) đang trong giai đoạn phát triển.
- Các file dữ liệu (`.csv`, `.pkl`, `.json`) được ignore bởi `.gitignore` — cần tải riêng.
- Model được lưu dưới 2 định dạng: `.txt` (Booster native) và `.pkl` (pickle) trong `notebooks/`.
