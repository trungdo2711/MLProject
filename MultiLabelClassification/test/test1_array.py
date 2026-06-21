path = r'G:\url-analysis\notebooks\lgb_url_classifier_metadata.json'  # thay đúng đường dẫn bạn đang dùng

import os
print("Tồn tại:", os.path.exists(path))
print("Kích thước:", os.path.getsize(path), "bytes")

with open(path, "rb") as f:
    raw = f.read(80)
print("80 byte đầu (raw):", raw)