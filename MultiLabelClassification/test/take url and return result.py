import sys
import json
import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb
from src.features.feature_extraction import features_extraction, load_and_preprocess_whitelist, get_scheme
from src.FIlter.Normalize_url import normalize_input_url

MODEL_PATH = r'G:\url-analysis\notebooks\lgb_url_classifier.txt'
LABEL_PATH = r'G:\url-analysis\notebooks\label_encoder.joblib'
METADATA_PATH = r'G:\url-analysis\notebooks\lgb_url_classifier_metadata.json'
WHITELIST_PATH = r'G:\url-analysis\src\data\whitelist.txt'

def load_artifacts():
    booster = lgb.Booster(model_file=MODEL_PATH)

    le = joblib.load(LABEL_PATH)

    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    feature_columns = metadata["features"]  # đúng thứ tự cột lúc train

    whitelist = load_and_preprocess_whitelist(WHITELIST_PATH)

    return booster, le, feature_columns, whitelist


RAW_TEXT_COLUMNS = {"url", "type", "scheme", "netloc", "path", "query",
                    "fragment", "subdomain", "domain"}


def url_to_feature_row(url: str, feature_columns: list, whitelist: list) -> pd.DataFrame:
    raw_features = features_extraction(url, whitelist)

    # Tên cột tương ứng với output của features_extraction (đúng thứ tự)
    all_column_names = [
        "scheme", "netloc", "path", "query", "fragment", "subdomain", "domain",
        "number_of_part", "has_scheme", "has_netloc", "has_path", "has_params",
        "has_query", "has_fragment", "has_username", "has_password", "has_port",
        "has_subdomain", "has_domain", "has_suffix",
        "netloc_length", "path_length", "query_length", "fragment_length",
        "subdomain_length", "domain_length",
        "url_entropy", "netloc_entropy", "path_entropy", "query_entropy",
        "subdomain_entropy", "domain_entropy",
        "hyphen_in_subdomain", "hyphen_in_domain", "unicode", "punycode",
        "at_sign_in_netloc", "slash_in_path", "dot_in_path", "strange_in_query",
        "equal_in_query", "ampersand_in_query", "number_subdomain",
        "normalized_levenshtein_domain", "normalized_levenshtein_subdomain",
        "random_domain_check", "random_subdomain_check",
        "number_ratio_domain", "number_ratio_subdomain",
        "repeated_domain_check", "repeated_path_check", "repeated_url_check",
        "longest_repeated_chain", "ip_domain", "suspicious_key_domain",
        "suspicious_key_subdomain", "suspicious_key_path", "suspicious_key_query",
        "shortened", "has_uuid_path", "download_param", "free_host",
        "free_host_download", "suspicious suffix"
    ]

    row_dict = dict(zip(all_column_names, raw_features))

    # Loại các cột text thô đã bị drop lúc train (trong RAW_TEXT_COLUMNS)
    row_dict = {k: v for k, v in row_dict.items() if k not in RAW_TEXT_COLUMNS}

    #Thêm url_length (không có trong wrapper features_extraction)
    row_dict["url length"] = len(url)

    #One-hot encode scheme (không có trong wrapper features_extraction)
    scheme_value = get_scheme(url)  # trả về: "https", "http", "ftp", "", hoặc "other"
    row_dict["is_https"] = 1 if scheme_value == "https" else 0
    row_dict["is_http"]  = 1 if scheme_value == "http"  else 0
    row_dict["is_ftp"]   = 1 if scheme_value == "ftp"   else 0
    row_dict["is_none"]  = 1 if scheme_value == ""      else 0
    row_dict["is_other"] = 1 if scheme_value == "other" else 0

    df_row = pd.DataFrame([row_dict])
    df_row = df_row.reindex(columns=feature_columns)  # đảm bảo đúng thứ tự + đủ cột

    missing = df_row.columns[df_row.isna().any()].tolist()
    if missing:
        print(f"[CẢNH BÁO] Các cột sau bị thiếu / NaN sau khi reindex: {missing}")

    return df_row


def predict_url(url: str, booster, le, feature_columns, whitelist):
    X_row = url_to_feature_row(url, feature_columns, whitelist)

    proba = booster.predict(X_row)[0]  #trả về predict cho từng lớp

    labels = le if isinstance(le, np.ndarray) else le.classes_
    result = {label: round(float(p) * 100, 2) for label, p in zip(labels, proba)}
    return result


def main():
    booster, le, feature_columns, whitelist = load_artifacts()

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Nhập URL cần kiểm tra: ").strip()

    url = normalize_input_url(url) #normalized url
    result = predict_url(url, booster, le, feature_columns, whitelist)

    sorted_result = sorted(result.items(), key=lambda x: x[1], reverse=True)

    print(f"\nURL: {url}")
    print("-" * 40)
    for label, pct in sorted_result:
        print(f"  {label:<15}: {pct:6.2f}%")
    print("-" * 40)
    top_label, top_pct = sorted_result[0]
    print(f"=> Dự đoán: '{top_label}' ({top_pct}%)")


if __name__ == "__main__":
    main()
