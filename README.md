# 🛡️ Malicious URL Detection Suite

Welcome to the **Malicious URL Detection Suite**, a comprehensive machine learning project designed to identify and classify malicious, phishing, and malware-distribution URLs using **Static Lexical Analysis**, **Heuristic Rules**, and **Ensemble Learning**.

This repository contains two main sub-projects, each focusing on a different approach to URL classification without needing to access the actual web page content (zero-day resilient & privacy-preserving).

---

## 📂 Project Modules

The project is divided into two separate applications:

### 1. [Binary Classification (PhishShield)](./BinaryClassification/)
A hybrid **Heuristic Rule Engine + Machine Learning (Ensemble)** solution designed to classify URLs as either `Safe` or `Dangerous` (Phishing/Malware).
- **Core Approach:** Fast whitelist filter → High-priority hard heuristics (Brand Spoofing, C2 Patterns) → ML model fallback.
- **Models Used:** Ensemble of Random Forest, XGBoost, LightGBM, & Logistic Regression.
- **Optimization:** Weights optimized using grid search to maximize the $F_2$-score (prioritizing recall).
- **Features:** 34 extracted features.
- **UI:** Includes a responsive **Flask Web Interface**.
- **Documentation:** [View Binary Classification README](./BinaryClassification/README.md)

### 2. [Multi-class Classification](./MultiLabelClassification/)
A focused Machine Learning pipeline using **LightGBM Gradient Boosted Decision Trees (GBDT)** to classify URLs into **4 specific categories**: `benign`, `phishing`, `malware`, and `defacement`.
- **Core Approach:** Purely data-driven feature engineering and classification with sub-millisecond latency.
- **Model Used:** LightGBM (GBDT) with optimized hyperparameters.
- **Performance:** Achieved **93.46% test accuracy** with zero domain overlap.
- **Features:** 63 advanced numerical features (Structural, Entropy, Lexical, Levenshtein Distance).
- **Data Scale:** Trained on over 661,000 unique URLs.
- **Documentation:** [View Multi-class Classification README](./MultiLabelClassification/README.md)

---

## 🚀 Quick Start

Depending on your goal, navigate to the respective directory to run the systems.

### Run PhishShield Web Interface (Binary)
```bash
cd BinaryClassification
pip install -r requirements.txt
python app.py
# Open http://127.0.0.1:5000/
```

### Run Multi-class Inference CLI
```bash
cd MultiLabelClassification
pip install -r requirements.txt
python "test/take url and return result.py" "https://example.com"
```

---

## 👥 Authors / Research Team
This project is developed by students from Hanoi University of Science and Technology (HUST) — School of Information and Communication Technology.

| Name | Student ID |
|---|---|
| Do Thanh Trung | 20241683 |
| Nguyen Tuan Minh | 20241681 |
| Khong Tuan Anh | 20241677 |
| Nguyen Hoang Anh | 20241677 |
| Pham Duc Linh | 20241680 |

## 📄 Full Research Report
For an in-depth understanding of the algorithms, feature extraction formulas, and evaluation methodologies, please refer to our comprehensive LaTeX reports located within each module.

> **"Malicious URL Classification via Static Lexical Analysis and Gradient Boosted Decision Trees"**
