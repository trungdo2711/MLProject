from src.predict import predict_single_url

def main():
    print("=" * 65)
    print("       HỆ THỐNG AI PHÁT HIỆN URL LỪA ĐẢO (PHISHING)       ")
    print("=" * 65)

    while True:
        input_url = input("\n👉 Nhập URL cần kiểm tra (hoặc gõ 'exit' để thoát): ")

        if input_url.strip().lower() == 'exit':
            print("👋 Đã thoát hệ thống.")
            break

        if not input_url.strip():
            continue

        try:
            print("⏳ Đang quét đặc trưng và phân tích...")
            result = predict_single_url(input_url)

            print("-" * 65)

            if result['label'] == 'safe':
                print("👉 Phán quyết cuối cùng : [ ✅ SẠCH (SAFE) ]")
            else:
                print("👉 Phán quyết cuối cùng : [ 🚨 LỪA ĐẢO (DANGEROUS) ]")

            prob_str = f"{result['prob']*100:.2f}%"
            print(f"📊 Độ tự tin (Xác suất) : {prob_str}")

            if result.get('prob_rf') is not None:
                print("   [Chi tiết biểu quyết từ các mô hình]:")
                print(f"    ├─ Random Forest : {result['prob_rf']}")
                print(f"    └─ XGBoost       : {result['prob_xgb']}")

            print(f"🧠 Nguồn phán quyết     : {result.get('source', 'unknown')}")

            if result.get('reason'):
                print(f"📝 Lý do                : {result['reason']}")

            print("-" * 65)

        except Exception as e:
            print("❌ Có lỗi xảy ra trong quá trình dự đoán!")
            print(f"Chi tiết lỗi: {e}")
            print("Gợi ý: Hãy kiểm tra xem bạn đã chạy 'python src/training.py' để cập nhật mô hình chưa nhé.")

if __name__ == "__main__":
    main()