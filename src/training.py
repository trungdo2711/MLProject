import pandas as pd
import numpy as np
import xgboost as xgb
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, fbeta_score
from sklearn.model_selection import train_test_split
import joblib
import json
import time
from feature import extracting_features

def find_best_weights(rf_model, xgb_model, lgb_model, lr_model, X_test, y_test):
    probs_rf  = rf_model.predict_proba(X_test)[:, 1]
    probs_xgb = xgb_model.predict_proba(X_test)[:, 1]
    probs_lgb = lgb_model.predict_proba(X_test)[:, 1]
    probs_lr  = lr_model.predict_proba(X_test)[:, 1]

    best_weights, best_f2 = (0.25, 0.25, 0.25, 0.25), 0

    # Grid search over 4 weights with step 0.1, constrained to sum = 1.0
    for w_rf in np.arange(0.0, 1.1, 0.1):
        for w_xgb in np.arange(0.0, 1.1 - w_rf, 0.1):
            for w_lgb in np.arange(0.0, 1.1 - w_rf - w_xgb, 0.1):
                w_lr = round(1.0 - w_rf - w_xgb - w_lgb, 1)
                if w_lr < -0.01:
                    continue
                w_lr = max(w_lr, 0.0)

                avg_prob = w_rf * probs_rf + w_xgb * probs_xgb + w_lgb * probs_lgb + w_lr * probs_lr
                preds    = (avg_prob >= 0.5).astype(int)
                f2 = fbeta_score(y_test, preds, beta=2.0, pos_label=1)
                if f2 > best_f2:
                    best_f2      = f2
                    best_weights = (round(w_rf, 1), round(w_xgb, 1), round(w_lgb, 1), round(w_lr, 1))

    print(f"Best weights: w_rf={best_weights[0]} | w_xgb={best_weights[1]} | w_lgb={best_weights[2]} | w_lr={best_weights[3]} | F2: {best_f2:.4f}")
    return best_weights

def run_training():
    df = pd.read_csv('data/malicious_phish.csv', encoding='latin-1')
    df['label'] = np.where(df['type'] == 'benign', 0, 1)
    df['url']   = df['url'].fillna('')

    list_of_dicts = df['url'].apply(extracting_features).tolist()
    X = pd.DataFrame(list_of_dicts)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

    # --- Random Forest ---
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

    # --- XGBoost ---
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

    # --- LightGBM ---
    print("Training LightGBM...")
    lgb_model = lgb.LGBMClassifier(
        n_estimators=200, num_leaves=63, max_depth=-1,
        learning_rate=0.1,
        scale_pos_weight=ratio * 1.5,
        n_jobs=-1, random_state=0, verbose=-1
    )
    start = time.time()
    lgb_model.fit(X_train, y_train)
    print(f"Training time: {time.time() - start:.2f}s")
    joblib.dump(lgb_model, 'models/lgb_model.pkl')
    print(classification_report(y_test, lgb_model.predict(X_test), target_names=['safe', 'dangerous'], digits=4))

    # --- Logistic Regression ---
    print("Training Logistic Regression (Baseline)...")
    lr_model = make_pipeline(
        StandardScaler(), 
        LogisticRegression(max_iter=1000, class_weight='balanced', n_jobs=-1, random_state=0)
    )
    start = time.time()
    lr_model.fit(X_train, y_train)
    print(f"Training time: {time.time() - start:.2f}s")
    joblib.dump(lr_model, 'models/lr_model.pkl')
    print(classification_report(y_test, lr_model.predict(X_test), target_names=['safe', 'dangerous'], digits=4))

    # --- Ensemble Weight Search ---
    print("\n=== FIND ENSEMBLE WEIGHTS ===")
    w_rf, w_xgb, w_lgb, w_lr = find_best_weights(rf_model, xgb_model, lgb_model, lr_model, X_test, y_test)
    json.dump({'w_rf': w_rf, 'w_xgb': w_xgb, 'w_lgb': w_lgb, 'w_lr': w_lr}, open('models/weights.json', 'w'))

    probs_rf  = rf_model.predict_proba(X_test)[:, 1]
    probs_xgb = xgb_model.predict_proba(X_test)[:, 1]
    probs_lgb = lgb_model.predict_proba(X_test)[:, 1]
    probs_lr  = lr_model.predict_proba(X_test)[:, 1]
    avg_prob  = w_rf * probs_rf + w_xgb * probs_xgb + w_lgb * probs_lgb + w_lr * probs_lr
    print("\n=== ENSEMBLE (RF + XGB + LGB + LR) ===")
    print(classification_report(y_test, (avg_prob >= 0.5).astype(int), target_names=['safe', 'dangerous'], digits=4))

if __name__ == "__main__":
    run_training()