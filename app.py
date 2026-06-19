import os
from flask import Flask, render_template, request, jsonify
from src.predict import predict_single_url
from src.feature import generate_whitelist, reload_extra_whitelist

app = Flask(__name__)

_WHITELIST_PATH = 'data/whitelist.txt'
_TOP1M_PATH     = 'data/top-1m.csv'

if not os.path.exists(_WHITELIST_PATH):
    if os.path.exists(_TOP1M_PATH):
        print("Gemerating whitelist from top-1m domains...")
        generate_whitelist(src=_TOP1M_PATH, dst=_WHITELIST_PATH)
        reload_extra_whitelist()
    else:
        print(f"Warning: {_WHITELIST_PATH} not found and {_TOP1M_PATH} not available. Whitelist will be empty.")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    try:
        data = request.get_json()

        url = data["url"]

        result = predict_single_url(url)

        return jsonify({
            "prediction": int(result.get("prediction", 0)),
            "label": result.get("label"),
            "prob": float(result.get("prob", 0)),
            "threshold": float(result.get("threshold", 0.5)),
            "prob_rf": float(result["prob_rf"]) if result.get("prob_rf") is not None else None,
            "prob_xgb": float(result["prob_xgb"]) if result.get("prob_xgb") is not None else None,
            "prob_lgb": float(result["prob_lgb"]) if result.get("prob_lgb") is not None else None,
            "prob_lr": float(result["prob_lr"]) if result.get("prob_lr") is not None else None,
            "source": result.get("source"),
            "reason": result.get("reason")
        })

    except Exception as e:
        import traceback
        traceback.print_exc()

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)