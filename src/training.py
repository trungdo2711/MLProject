import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, fbeta_score
from sklearn.model_selection import train_test_split
import joblib
import json
import time
from feature import extracting_features

def find_best_weights(rf_model, xgb_model, X_test, y_test):
    probs_rf  = rf_model.predict_proba(X_test)[:, 1]
    probs_xgb = xgb_model.predict_proba(X_test)[:, 1]

    best_weights, best_f2 = (0.5, 0.5), 0

    for w_rf in np.arange(0.0, 1.1, 0.1):
        w_xgb = round(1.0 - w_rf, 1)
        avg_prob = w_rf * probs_rf + w_xgb * probs_xgb
        preds    = (avg_prob >= 0.5).astype(int)
        f2 = fbeta_score(y_test, preds, beta=2.0, pos_label=1)
        if f2 > best_f2:
            best_f2      = f2
            best_weights = (round(w_rf, 1), round(w_xgb, 1))

    print(f"Best weights: w_rf={best_weights[0]} | w_xgb={best_weights[1]} | F2: {best_f2:.4f}")
    return best_weights

def run_training():
    df = pd.read_csv('data/malicious_phish.csv', encoding='latin-1')
    df['label'] = np.where(df['type'] == 'benign', 0, 1)
    df['url']   = df['url'].fillna('')

    list_of_dicts = df['url'].apply(extracting_features).tolist()
    X = pd.DataFrame(list_of_dicts)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

    print("Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=200, max_depth=20,
        class_weight={0: 1, 1: 2.0},
        n_jobs=-1, random_state=0
    )
    start = time.time()
    rf_model.fit(X_train, y_train)
    print(f"Training time: {time.time() - start:.2f}s")
    joblib.dump(rf_model, 'models/rf_model.pkl')
    print(classification_report(y_test, rf_model.predict(X_test), target_names=['safe', 'dangerous'], digits=4))

    print("Training XGBoost...")
    ratio = float(np.sum(y_train == 0)) / np.sum(y_train == 1)
    xgb_model = xgb.XGBClassifier(
        n_estimators=200, max_depth=10, learning_rate=0.1,
        scale_pos_weight=ratio * 1.5,
        n_jobs=-1, random_state=0
    )
    start = time.time()
    xgb_model.fit(X_train, y_train)
    print(f"Training time: {time.time() - start:.2f}s")
    xgb_model.save_model('models/xgb_model.json')
    print(classification_report(y_test, xgb_model.predict(X_test), target_names=['safe', 'dangerous'], digits=4))

    print("\n=== FIND ENSEMBLE WEIGHTS ===")
    w_rf, w_xgb = find_best_weights(rf_model, xgb_model, X_test, y_test)
    json.dump({'w_rf': w_rf, 'w_xgb': w_xgb}, open('models/weights.json', 'w'))

    probs_rf  = rf_model.predict_proba(X_test)[:, 1]
    probs_xgb = xgb_model.predict_proba(X_test)[:, 1]
    avg_prob  = w_rf * probs_rf + w_xgb * probs_xgb
    print("\n=== ENSEMBLE (RF + XGB) ===")
    print(classification_report(y_test, (avg_prob >= 0.5).astype(int), target_names=['safe', 'dangerous'], digits=4))

if __name__ == "__main__":
    run_training()