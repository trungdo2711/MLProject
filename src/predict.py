import re
import json
from urllib.parse import urlparse

import pandas as pd
import xgboost as xgb
import joblib

from src.feature import extracting_features, is_trusted_domain

# Load models and weights
rf_model  = joblib.load('models/rf_model.pkl')
xgb_model = xgb.XGBClassifier()
xgb_model.load_model('models/xgb_model.json')

_w = json.load(open('models/weights.json'))
W_RF, W_XGB = _w['w_rf'], _w['w_xgb']

TRACKING_PARAMS = [
    'utm_source', 'utm_medium', 'utm_campaign',
    'fbclid', 'gclid', 'sp_atk', 'skuid',
    'ref', 'aid', 'label', 'utm_term', 'utm_content', 'utm_id', 'wbraid', 'gbraid', 'dclid', 
    'ttclid', 'igshid', 'twclid', 'msclkid', 'li_fat_id', 'yclid', 
    'mc_cid', 'mc_eid', 'mkt_tok', 'hsCtaTracking', 
    'aff_id', 'affid', 'click_id', 'clickid', 'cid', 'subid', 'tag', 
    'PHPSESSID', 'JSESSIONID', '_ga', '_gl', 's_kwcid', 'gad_source'
]

def predict_single_url(url: str) -> dict:
    url = str(url).strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Normalize: strip trailing slash khỏi path (vi/ == vi về ngữ nghĩa)
    parsed_norm = urlparse(url)
    if parsed_norm.path.endswith('/') and parsed_norm.path != '/':
        url = url.rstrip('/')

    clean = re.sub(r'^https?://', '', url.lower())
    clean = re.sub(r'^www\.', '', clean)
    try:
        parsed = urlparse('//' + clean)
    except Exception:
        parsed = urlparse('//')
    hostname = parsed.netloc.split(':')[0]
    query    = parsed.query or ''

    # Whitelist check
    if is_trusted_domain(hostname):
        return {
            'prediction': 0, 'label': 'safe', 'prob': 0.0,
            'source': 'whitelist', 'reason': f'Trusted domain: {hostname}',
        }

    feat = extracting_features(url)

    # Hard rules (priority over ML)

    # Brand spoof
    if feat['brand_similarity'] >= 0.75 and feat['tld_suspicious'] == 0:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': f'Brand similarity: {feat["brand_similarity"]}',
        }
    if feat['tld_suspicious'] == 1 and feat['brand_similarity'] >= 0.65:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': f'Suspicious TLD + brand similarity: {feat["brand_similarity"]}',
        }

    # UUID path + subdomain random → C2/malware callback
    if feat['has_uuid_path'] == 1 and feat['subdomain_is_random'] == 1:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': 'Random subdomain + UUID path/query — likely C2 callback',
        }

    # UUID path + high subdomain entropy → C2 callback (subdomain_is_random có thể miss)
    if feat['has_uuid_path'] == 1 and feat['subdomain_entropy'] >= 2.4:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': f'UUID path + high-entropy subdomain ({feat["subdomain_entropy"]}) — likely C2 callback',
        }

    # Executable file + random subdomain → malware served from random VPS
    if feat['has_executable_ext'] == 1 and feat['subdomain_is_random'] == 1:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': 'Executable file extension + random subdomain — likely malware distribution',
        }

    # Executable file + free hosting → malware distribution
    if feat['has_executable_ext'] == 1 and feat['is_free_hosting'] == 1:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': 'Executable file extension + free hosting — likely malware distribution',
        }

    # Free hosting + download → malware distribution
    if feat['free_hosting_download'] == 1:
        return {
            'prediction': 1, 'label': 'dangerous', 'prob': 1.0,
            'source': 'hard_rule',
            'reason': 'Free hosting + download param — likely malware distribution',
        }
    
    # ML prediction
    X     = pd.DataFrame([feat])
    p_rf  = rf_model.predict_proba(X)[0][1]
    p_xgb = xgb_model.predict_proba(X)[0][1]
    prob  = W_RF * p_rf + W_XGB * p_xgb

    # --- Determine threshold ---

    q_count       = len(query.split('&')) if query else 0
    has_tracking  = any(p in query.lower() for p in TRACKING_PARAMS)
    is_short_sus  = feat['is_shortener'] == 1 or (
                        feat['url_len'] < 30 and feat['path_digit_ratio'] > 0.3)
    is_word_salad = feat['url_len'] > 60 and feat['has_suspicious_word'] == 1
    url_long_clean = (
        feat['url_len'] > 80 and q_count > 3 and has_tracking
        and feat['tld_suspicious'] == 0 and feat['is_ip'] == 0
    )


    clean_domain = (
        feat['tld_suspicious'] == 0 and
        feat['brand_similarity'] < 0.55 and
        feat['has_suspicious_word'] == 0 and
        feat['is_ip'] == 0 and
        feat['subdomain_is_random'] == 0 and
        feat['is_free_hosting'] == 0 and
        feat['has_executable_ext'] == 0
    )

    if is_short_sus:
        threshold = 0.30
    elif is_word_salad:
        threshold = 0.35
    elif url_long_clean:
        threshold = 0.60
    elif clean_domain:
        threshold = 0.85  
    else:
        threshold = 0.45


    prediction = 1 if prob >= threshold else 0

    return {
        'prediction': prediction,
        'label':      'dangerous' if prediction == 1 else 'safe',
        'prob':       round(prob, 4),
        'prob_rf':    round(p_rf,  4),
        'prob_xgb':   round(p_xgb, 4),
        'source':     'model',
    }